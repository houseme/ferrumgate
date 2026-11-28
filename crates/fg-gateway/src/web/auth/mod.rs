//! WP-24 steps 5-9 skeletons: the HTTP basic check, the TOTP step, the
//! self-service password flow, the login page model, and the
//! authenticator glue. Batch 3 wires the reserved auth paths and the
//! login/logout handling into the forwarding pipeline: [`Authenticator::
//! handle_auth_path`] answers every request under [`AUTH_PATH`] when a
//! site enables web authentication, and `proxy::forward` dispatches
//! basic/web session checks ahead of the per-site option transforms.
#![allow(dead_code)]

pub mod basic;
pub mod login_page;
pub mod password;
pub mod reserve;
pub mod session;
pub mod shared;
pub mod totp_step;
pub mod users;

/// The authentication reserve path every auth interaction lives under.
pub const AUTH_PATH: &str = "/__gately_auth";
/// Signed sessions live for seven days.
pub const SESSION_TTL: u64 = 7 * 24 * 3600;
/// The single-sign-on parent-domain cookie name.
pub const SSO_COOKIE: &str = "gately_sso";
/// The cookie carrying the one-time token between the password step and
/// the verification-code step (scoped to the auth path, short-lived).
pub const TOTP_COOKIE: &str = "gately_totp";
/// Lifetime of the one-time TOTP step token cookie.
pub const TOTP_COOKIE_TTL: u64 = 600;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use fg_core::events::EventBus;

use crate::web::auth::login_page::LoginPage;
use reserve::{Reserve, Slot};
use session::{OneTimeTokens, Scope, SiteSession};
use shared::{AuthUser, check_password, cred_fingerprint};
use users::verify_site_user;

/// The authenticator for one config generation: the signing secret, the
/// shared-user snapshot, the reservation state and the TOTP tokens.
pub struct Authenticator {
    secret: Vec<u8>,
    shared: Vec<AuthUser>,
    reserve: Arc<Reserve>,
    tokens: OneTimeTokens,
    events: EventBus,
}

impl Authenticator {
    pub fn new(secret: &[u8], shared: Vec<AuthUser>) -> Self {
        Self::with_events(secret, shared, EventBus::default())
    }

    /// Builds an authenticator that publishes on the given event bus
    /// (auto-ban events are WP-26's concern; the bus rides along here so
    /// one authenticator owns all the auth state).
    pub fn with_events(secret: &[u8], shared: Vec<AuthUser>, events: EventBus) -> Self {
        Self {
            secret: secret.to_vec(),
            shared,
            reserve: Arc::new(Reserve::new()),
            tokens: OneTimeTokens::new(),
            events,
        }
    }

    /// The event bus this authenticator publishes on.
    pub fn events(&self) -> &EventBus {
        &self.events
    }

    pub fn reserve(&self) -> Arc<Reserve> {
        Arc::clone(&self.reserve)
    }

    pub fn tokens(&self) -> &OneTimeTokens {
        &self.tokens
    }

    /// The shared-user snapshot (settings `authUsers`).
    pub fn shared_users(&self) -> &[AuthUser] {
        &self.shared
    }

    /// HTTP basic verification against site users and non-TOTP shared
    /// users, behind the reservation gates.
    pub fn check_basic(
        &self,
        site_users: &[String],
        source: IpAddr,
        user: &str,
        pass: &str,
    ) -> BasicOutcome {
        basic::verify(site_users, &self.shared, &self.reserve, source, user, pass)
    }

    /// Verifies a TOTP code against a shared user's secret.
    pub fn verify_totp(&self, secret: &str, code: &str, timestamp: u64) -> bool {
        totp_step::verify_code(secret, code, timestamp)
    }

    /// Signs a session cookie value for a verified visitor.
    pub fn issue_session(
        &self,
        user: &str,
        host: &str,
        scope: Scope,
        fingerprint: &str,
        now: SystemTime,
    ) -> String {
        session::issue(&self.secret, user, host, scope, fingerprint, now)
    }

    /// Verifies a session cookie value against the host.
    pub fn verify_session(&self, value: &str, host: &str, now: SystemTime) -> Option<SiteSession> {
        session::verify(&self.secret, value, host, now)
    }

    /// The reserved auth paths' entry point (WP-24 §3.3「认证保留路径」):
    /// every request under [`AUTH_PATH`] on an auth-enabled site lands
    /// here regardless of path rules — login page, login submission,
    /// verification-code step and logout; other auth subpaths are
    /// `NotFound` (never proxied). The site snapshot carries what varies
    /// per site (its users, the shared-user switch, the page style and
    /// the session cookie name); everything request-shaped rides in
    /// [`AuthCx`].
    pub fn handle_auth_path(&self, site: &AuthSite<'_>, cx: AuthCx<'_>) -> AuthPathReply {
        let page = LoginPage {
            style: site.login_style.to_owned(),
            ..LoginPage::default()
        };
        let rest = cx.path.strip_prefix(AUTH_PATH).unwrap_or(cx.path);
        match (cx.method, rest) {
            ("GET", "" | "/") => {
                let next = login_page::next_from_query(cx.query);
                login_page::page_reply(&page, None, self.page_needs_code(site), cx.host, &next)
            }
            ("POST", "" | "/") => self.handle_login(site, &page, cx),
            ("POST", "/logout") => login_page::logout_reply(site.cookie_name),
            _ => AuthPathReply::NotFound,
        }
    }

    /// Whether the shared-user pool makes the verification-code box part
    /// of every login page for this site (§3.3: with any TOTP-enabled
    /// shared user, the page shows the code input).
    fn page_needs_code(&self, site: &AuthSite<'_>) -> bool {
        site.shared_users && self.shared.iter().any(AuthUser::has_totp)
    }

    /// The login POST: same-origin check, `next` restriction, then the
    /// credential lookup — site users and shared users; a TOTP shared
    /// user with the right password moves to the verification-code step
    /// behind a one-time token. Misses land in the failure reserve.
    fn handle_login(&self, site: &AuthSite<'_>, page: &LoginPage, cx: AuthCx<'_>) -> AuthPathReply {
        // The form must come from the same host (Origin or Referer); a
        // submission without either is rejected before any verification.
        let same_host = login_page::origin_host(cx.origin)
            .is_some_and(|host| host.eq_ignore_ascii_case(cx.host));
        if !same_host {
            return login_page::page_reply(page, Some("跨站提交被拒绝"), false, cx.host, "/");
        }
        let form = login_page::parse_login_form(cx.body);
        let next = login_page::safe_next(&form.next);

        // A one-time token cookie turns the submission into the
        // verification-code step (a replayed or unknown token is
        // rejected — see the step handler). Without a token the code
        // field is ignored and the password step runs, so the code box
        // the shared-user policy shows stays harmless for site users.
        let has_token = cx.cookies.iter().any(|(name, _)| *name == TOTP_COOKIE);
        if !form.code.is_empty() && has_token {
            return self.handle_totp_step(site, page, cx, &form, next);
        }

        // Password step. The reservation gates run before any bcrypt
        // work: a locked source is refused even with correct
        // credentials, an exhausted gate pool is refused without
        // counting.
        if self.reserve.locked(cx.source, std::time::Instant::now()) {
            return login_page::throttled_reply(page, self.page_needs_code(site), cx.host, next);
        }
        let Some(slot) = self.reserve.try_acquire(cx.source) else {
            return login_page::busy_reply(page, cx.host);
        };
        let hit = self.verify_login(site, &form.username, &form.password);
        drop(slot);
        match hit {
            LoginHit::SiteUser => self.session_reply(site, "", &form.username, cx.host, next),
            LoginHit::Shared(user) => {
                let fingerprint = cred_fingerprint(&self.secret, &user);
                self.session_reply(site, &fingerprint, &user.name, cx.host, next)
            }
            LoginHit::Code(user) => {
                // One-time token bound to (user, host); the cookie
                // carries it to the code step, which consumes it.
                let token = self.tokens.issue(&user, cx.host);
                login_page::code_reply(
                    page,
                    cx.host,
                    next,
                    (
                        TOTP_COOKIE.to_owned(),
                        format!("{token}; Path={AUTH_PATH}; HttpOnly; Max-Age={TOTP_COOKIE_TTL}"),
                    ),
                )
            }
            LoginHit::Miss => {
                self.reserve
                    .record_failure(cx.source, std::time::Instant::now());
                login_page::page_reply(
                    page,
                    Some("用户名或密码错误"),
                    self.page_needs_code(site),
                    cx.host,
                    next,
                )
            }
        }
    }

    /// The verification-code step: the one-time token is consumed first
    /// (replay rejected), then the code is checked against the user's
    /// TOTP secret; success signs the session and clears the token
    /// cookie.
    fn handle_totp_step(
        &self,
        site: &AuthSite<'_>,
        page: &LoginPage,
        cx: AuthCx<'_>,
        form: &login_page::LoginForm,
        next: &str,
    ) -> AuthPathReply {
        let token = cx
            .cookies
            .iter()
            .find(|(name, _)| *name == TOTP_COOKIE)
            .map(|(_, value)| *value);
        let verified = match token {
            Some(token) if self.tokens.consume(token, &form.username, cx.host) => self
                .shared
                .iter()
                .find(|user| user.name == form.username)
                .filter(|user| self.verify_totp(&user.totp_secret, &form.code, unix_seconds_now())),
            _ => None,
        };
        match verified {
            Some(user) => {
                let fingerprint = cred_fingerprint(&self.secret, user);
                let value = self.issue_session(
                    &user.name,
                    cx.host,
                    Scope::Site,
                    &fingerprint,
                    SystemTime::now(),
                );
                login_page::redirect_reply(
                    next,
                    vec![
                        (
                            site.cookie_name.to_owned(),
                            format!(
                                "{value}; Path=/; HttpOnly; Max-Age={SESSION_TTL}; SameSite=Lax"
                            ),
                        ),
                        // The step is done: clear the token cookie.
                        (
                            TOTP_COOKIE.to_owned(),
                            format!("; Path={AUTH_PATH}; HttpOnly; Max-Age=0"),
                        ),
                    ],
                )
            }
            None => {
                self.reserve
                    .record_failure(cx.source, std::time::Instant::now());
                login_page::page_reply(page, Some("验证码错误"), true, cx.host, next)
            }
        }
    }

    /// Credential lookup for the web flow: site users first (plaintext
    /// or bcrypt entries), then shared users; `check_password` hides
    /// TOTP users, so a named, verified TOTP user comes back as
    /// [`LoginHit::Code`].
    fn verify_login(&self, site: &AuthSite<'_>, username: &str, password: &str) -> LoginHit {
        if site
            .users
            .iter()
            .any(|entry| verify_site_user(entry, username, password))
        {
            return LoginHit::SiteUser;
        }
        if site.shared_users
            && let Some(user) = check_password(&self.shared, username, password)
        {
            return LoginHit::Shared(user);
        }
        if site.shared_users {
            let totp_user = self.shared.iter().find(|user| {
                user.name == username
                    && bcrypt::verify(password, &user.password).unwrap_or(false)
                    && user.has_totp()
            });
            if let Some(user) = totp_user {
                return LoginHit::Code(user.name.clone());
            }
        }
        LoginHit::Miss
    }

    /// Signs and redirects after a successful login (site-scope session
    /// cookie on the site's compiled cookie name).
    fn session_reply(
        &self,
        site: &AuthSite<'_>,
        fingerprint: &str,
        user: &str,
        host: &str,
        next: &str,
    ) -> AuthPathReply {
        let value = self.issue_session(user, host, Scope::Site, fingerprint, SystemTime::now());
        login_page::redirect_reply(
            next,
            vec![(
                site.cookie_name.to_owned(),
                format!("{value}; Path=/; HttpOnly; Max-Age={SESSION_TTL}; SameSite=Lax"),
            )],
        )
    }
}

/// What the login POST's credential lookup concluded.
enum LoginHit {
    /// A site user (`users[]` entry) — no second factor exists for them.
    SiteUser,
    /// A shared user without TOTP, verified outright.
    Shared(AuthUser),
    /// A TOTP-enabled shared user with the right password: the
    /// verification-code step follows (carries the user's name).
    Code(String),
    /// Nothing matched — the caller records the failure.
    Miss,
}

/// The per-site authentication snapshot the dispatch needs beyond the
/// request: the `users[]` entries (verbatim), the shared-user switch,
/// the page style override and the compiled session cookie name.
pub struct AuthSite<'a> {
    pub users: &'a [String],
    pub shared_users: bool,
    pub login_style: &'a str,
    pub cookie_name: &'a str,
}

/// The per-request authentication context (WP-24 batch 3): borrowed
/// views into the original request — the caller fills it from the
/// request headers and URI. `origin` carries the Origin header, falling
/// back to Referer (the form's same-source check accepts either);
/// `body` is the buffered form of a POST to the reserved path.
pub struct AuthCx<'a> {
    pub method: &'a str,
    pub host: &'a str,
    /// The origin-form request path.
    pub path: &'a str,
    pub query: &'a str,
    pub source: IpAddr,
    /// POST form bytes (reserved-path submissions only).
    pub body: &'a [u8],
    /// Cookie pairs (name, value) from every Cookie header.
    pub cookies: Vec<(&'a str, &'a str)>,
    pub content_type: &'a str,
    pub origin: Option<&'a str>,
}

/// The reply for one reserved-path request: either the authenticator
/// handled it (status, body, redirect target and cookies to set) or the
/// path is unknown (`NotFound` — never proxied).
pub enum AuthPathReply {
    Handled {
        status: u16,
        content_type: &'static str,
        body: String,
        /// Redirect target for 3xx replies (empty otherwise).
        location: String,
        /// Cookies to set; the pair forms `Set-Cookie: name=value;
        /// Path=/; HttpOnly; Max-Age=...` (the attributes ride in the
        /// value).
        set_cookies: Vec<(String, String)>,
    },
    NotFound,
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|delta| delta.as_secs())
        .unwrap_or(0)
}

/// The basic-auth decision for one request.
#[derive(Debug)]
pub enum BasicOutcome {
    #[allow(clippy::manual_non_exhaustive)]
    /// Credentials verified; the slot must be held for the verification
    /// duration (the caller drops it when the request finishes).
    Allowed(Slot),
    /// Wrong credentials (a failure is recorded by the caller).
    Denied,
    /// The source is locked out (10 failures in the window).
    Locked,
    /// No gate slot available (overloaded — reject without counting).
    Overloaded,
}
