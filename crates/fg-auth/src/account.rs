use std::{
    cmp::Reverse,
    fmt,
    fs::{File, OpenOptions},
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    time::SystemTime,
};

use anyhow::{Context, Result, anyhow, ensure};
use arc_swap::ArcSwap;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use fg_config::{ConfigStore, Loaded};
use fg_core::events::{Event, EventBus, Kind};
use serde::{Deserialize, Serialize};

use crate::{
    lockout::{Completion, KNOWN_FILE, LoginError, LoginLimiter, LoginLimits},
    passkey::StoredPasskey,
    password::{self, MAX_PASSWORD_BYTES, check_password_strength},
    readonly::ReadonlyUser,
    session::{Identity, Role, Session, Snapshot, unix_seconds},
    totp::{PendingTotp, Totp},
};

pub(super) const ACCOUNT: &str = "account";
const LEGACY_DEFAULT_PASSWORD: &str = "gately.cn";
pub(super) const MAX_USERNAME_BYTES: usize = 256;
pub(super) const MAX_REVOKED: usize = 1024;

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Account {
    pub username: String,
    pub password_hash: String,
    pub session_secret: String,
    #[serde(rename = "tokenTTLHours")]
    pub token_ttl_hours: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub totp_secret: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_last_step: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) users: Vec<ReadonlyUser>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) passkeys: Vec<StoredPasskey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) passkey_user_id: Option<webauthn_rs::prelude::Uuid>,
    #[serde(skip_serializing_if = "is_false")]
    onboarding_pending: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub using_default_password: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub weak_password: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub(super) password_login_off: bool,
    pub session_epoch: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub revoked: Vec<Revoked>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) last_reset: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Revoked {
    pub id: String,
    #[serde(rename = "e")]
    pub expires: u64,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug)]
pub struct CredentialChangeRejected(pub &'static str);

impl fmt::Display for CredentialChangeRejected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for CredentialChangeRejected {}

/// Owns the only active writer for one account file.
pub struct AccountManager {
    pub(super) store: Arc<ConfigStore>,
    pub(super) snapshot: ArcSwap<Snapshot>,
    pub(super) writer: Mutex<Option<PendingTotp>>,
    pub(super) limiter: LoginLimiter,
    login_events: Option<EventBus>,
    _owner: File,
}

pub struct SecurityFacts {
    pub password_issue: &'static str,
    pub second_factor: bool,
    pub common_username: bool,
    pub login_limits: LoginLimits,
}

impl AccountManager {
    pub fn security_facts(&self, rp_id: Option<&str>) -> SecurityFacts {
        let snapshot = self.snapshot.load();
        let account = &snapshot.account;
        let password_issue = if !account.must_change_password() {
            ""
        } else if account.using_default_password {
            "default"
        } else {
            "weak"
        };
        SecurityFacts {
            password_issue,
            second_factor: snapshot.totp.is_some()
                || rp_id.is_some_and(|rp| {
                    account
                        .passkeys
                        .iter()
                        .any(|credential| credential.belongs_to(rp))
                }),
            common_username: matches!(
                account.username.to_ascii_lowercase().as_str(),
                "admin" | "administrator" | "root" | "gately" | "ferrumgate" | "user" | "test"
            ),
            login_limits: self.limiter.limits(),
        }
    }
    /// Loads the account or creates it. A random initial password is returned only on creation.
    pub fn open(
        store: Arc<ConfigStore>,
        initial_password: Option<&str>,
    ) -> Result<(Self, Option<String>)> {
        let owner = open_lock(&store, ".account.lock")?;
        owner
            .try_lock()
            .context("account directory already has a writer")?;
        let limiter = LoginLimiter::load(&store)?;
        let (snapshot, generated) = match store.load::<Account>(ACCOUNT)? {
            Loaded::Found(account) => (Snapshot::new(account)?, None),
            Loaded::Missing => {
                let generated = initial_password
                    .is_none()
                    .then(random_urlsafe::<24>)
                    .transpose()?;
                let password = initial_password
                    .or(generated.as_deref())
                    .expect("initial password");
                ensure!(
                    (8..=MAX_PASSWORD_BYTES).contains(&password.len())
                        && password != LEGACY_DEFAULT_PASSWORD,
                    "invalid initial administrator password"
                );
                let account = Account {
                    username: "admin".into(),
                    password_hash: password::hash(password)?,
                    session_secret: random_urlsafe::<32>()?,
                    onboarding_pending: true,
                    using_default_password: true,
                    ..Account::default()
                };
                let snapshot = Snapshot::new(account)?;
                store.save(ACCOUNT, &snapshot.account)?;
                (snapshot, generated)
            }
        };
        Ok((
            Self {
                store,
                snapshot: ArcSwap::from_pointee(snapshot),
                writer: Mutex::new(None),
                limiter,
                login_events: None,
                _owner: owner,
            },
            generated,
        ))
    }

    /// Checks credentials for a local caller. Network callers pass the resolved address to `login_from`.
    pub fn login(&self, username: &str, password: &str) -> Result<Option<Session>> {
        match self.login_from(IpAddr::V4(Ipv4Addr::LOCALHOST), username, password) {
            Ok(session) => Ok(Some(session)),
            Err(LoginError::InvalidCredentials | LoginError::TotpRequired) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn configure_login_limits(&self, limits: LoginLimits) -> Result<()> {
        self.limiter.configure(limits)
    }

    pub fn session_hours(&self) -> u64 {
        self.snapshot.load().ttl.as_secs() / 3600
    }

    pub fn with_login_events(mut self, events: EventBus) -> Self {
        self.login_events = Some(events);
        self
    }

    /// Verifies the administrator password using the trusted client address.
    /// Runs bcrypt and any required persistence synchronously.
    pub fn login_from(
        &self,
        address: IpAddr,
        username: &str,
        password: &str,
    ) -> Result<Session, LoginError> {
        self.login_with_totp_from(address, username, password, None)
    }

    pub fn login_with_totp_from(
        &self,
        address: IpAddr,
        username: &str,
        password: &str,
        code: Option<&str>,
    ) -> Result<Session, LoginError> {
        let attempt = self.limiter.begin(address)?;
        let snapshot = self.snapshot.load_full();
        let account = &snapshot.account;
        let readonly = account.users.iter().find(|user| user.username == username);
        let hash = readonly.map_or(account.password_hash.as_str(), |user| {
            user.password_hash.as_str()
        });
        let verified = password::verify(password, hash).map_err(LoginError::Internal)?;
        if verified && readonly.is_some() {
            // A viewer login leaves the shared failure counters and known-source state intact.
            let session = snapshot
                .issue_readonly(SystemTime::now(), username)
                .map_err(LoginError::Internal)?;
            self.report_login(address, true, &Completion::default());
            return Ok(session);
        }
        let accepted = verified && account.username == username && !account.password_login_off;
        let session = if !accepted {
            None
        } else if account.totp_secret.is_empty() {
            self.issue_password_session(&snapshot, password, None)
                .map_err(LoginError::Internal)?
        } else if snapshot.totp.is_some() {
            let code = code
                .filter(|code| !code.trim().is_empty())
                .ok_or(LoginError::TotpRequired)?;
            self.issue_password_session(&snapshot, password, Some(code))
                .map_err(LoginError::Internal)?
        } else {
            None
        };
        let completion = attempt.complete(session.is_some());
        self.report_login(address, session.is_some(), &completion);
        let session = session.ok_or(LoginError::InvalidCredentials)?;
        if completion.save_known {
            self.save_login_sources();
        }
        Ok(session)
    }

    fn issue_password_session(
        &self,
        verified: &Snapshot,
        password: &str,
        code: Option<&str>,
    ) -> Result<Option<Session>> {
        let flags = verified.account.verified_password_flags(password);
        if code.is_none() && flags == verified.account.password_flags() {
            return verified.issue(SystemTime::now()).map(Some);
        }
        let _writer = self.writer.lock().expect("account writer poisoned");
        let current = self.snapshot.load();
        let account = &current.account;
        let verified = &verified.account;
        if account.username != verified.username
            || account.password_hash != verified.password_hash
            || account.totp_secret != verified.totp_secret
            || account.password_login_off
        {
            return Ok(None);
        }
        let now = SystemTime::now();
        let step = if let Some(code) = code {
            let timestamp = unix_seconds(now).context("system clock predates Unix epoch")?;
            let Some(step) = current.unused_totp_step(code, timestamp) else {
                return Ok(None);
            };
            Some(step)
        } else {
            None
        };
        let session = current.issue(now)?;
        if step.is_some() || flags != account.password_flags() {
            let mut next = account.clone();
            (next.using_default_password, next.weak_password) = flags;
            if let Some(step) = step {
                next.totp_last_step = Some(step);
            }
            self.save(next)?;
        }
        Ok(Some(session))
    }

    pub fn totp_enabled(&self) -> bool {
        !self.snapshot.load().account.totp_secret.is_empty()
    }

    pub fn prepare_totp(&self, token: &str) -> Result<String> {
        let mut writer = self.writer.lock().expect("account writer poisoned");
        let snapshot = self.snapshot.load();
        let timestamp =
            unix_seconds(SystemTime::now()).context("system clock predates Unix epoch")?;
        let id = snapshot
            .verify_admin(token, timestamp)
            .ok_or(CredentialChangeRejected("administrator session is invalid"))?;
        let pending = PendingTotp::new(id)?;
        let secret = pending.secret.clone();
        *writer = Some(pending);
        Ok(secret)
    }

    pub fn set_totp(&self, token: &str, password: &str, code: &str, enabled: bool) -> Result<()> {
        let verified = self.snapshot.load_full();
        let timestamp =
            unix_seconds(SystemTime::now()).context("system clock predates Unix epoch")?;
        ensure!(
            verified.verify_admin(token, timestamp).is_some(),
            CredentialChangeRejected("administrator session is invalid")
        );
        ensure!(
            password::verify(password, &verified.account.password_hash)?,
            CredentialChangeRejected("invalid administrator credentials")
        );
        let mut writer = self.writer.lock().expect("account writer poisoned");
        let current = self.snapshot.load();
        let timestamp =
            unix_seconds(SystemTime::now()).context("system clock predates Unix epoch")?;
        let id = current
            .verify_admin(token, timestamp)
            .ok_or(CredentialChangeRejected("administrator session is invalid"))?;
        ensure!(
            current.account.password_hash == verified.account.password_hash,
            CredentialChangeRejected("administrator credentials changed during verification")
        );
        let mut next = current.account.clone();
        if enabled {
            let pending = writer
                .as_ref()
                .filter(|pending| pending.valid_for(id))
                .ok_or(CredentialChangeRejected(
                    "TOTP enrollment is missing or expired",
                ))?;
            let step = Totp::parse(&pending.secret)
                .and_then(|totp| totp.match_code(code, timestamp))
                .ok_or(CredentialChangeRejected(
                    "invalid two-step verification code",
                ))?;
            next.totp_secret.clone_from(&pending.secret);
            next.totp_last_step = Some(step);
        } else {
            ensure!(
                current.unused_totp_step(code, timestamp).is_some(),
                CredentialChangeRejected("invalid two-step verification code")
            );
            next.totp_secret.clear();
            next.totp_last_step = None;
        }
        next.session_secret = random_urlsafe::<32>()?;
        next.invalidate_sessions()?;
        self.save(next)?;
        *writer = None;
        Ok(())
    }

    pub(super) fn save_login_sources(&self) {
        let _writer = self.writer.lock().expect("account writer poisoned");
        if let Some(mut sources) = self.limiter.take_known() {
            sources.sort_unstable_by_key(|source| Reverse(source.last));
            if self.store.save(KNOWN_FILE, &sources).is_err() {
                self.limiter.retry_known_save();
            }
        }
    }

    pub(super) fn report_login(&self, address: IpAddr, accepted: bool, completion: &Completion) {
        let Some(events) = &self.login_events else {
            return;
        };
        for (publish, kind) in [
            (accepted, Kind::LoginSuccessful),
            (completion.new_source, Kind::LoginNewIp),
            (completion.auth_failed, Kind::AuthFailed),
        ] {
            if publish {
                events.publish_with(|| {
                    let mut event = Event::new(kind, "auth");
                    event
                        .fields
                        .push(("ip", address.to_canonical().to_string()));
                    event
                });
            }
        }
        if let Some(failures) = completion.flood {
            events.publish_with(|| {
                let mut event = Event::new(Kind::AuthFlood, "auth");
                event.args.push(("failures", failures.to_string()));
                event
            });
        }
    }

    pub(super) fn report_reset(&self) {
        if let Some(events) = &self.login_events {
            events.publish_with(|| {
                let mut event = Event::new(Kind::AuditChange, "auth");
                event
                    .fields
                    .push(("operation", "administrator-reset".into()));
                event
            });
        }
    }

    pub fn identify(&self, token: &str) -> Option<Identity> {
        let snapshot = self.snapshot.load();
        let now = unix_seconds(SystemTime::now())?;
        let verified = snapshot.verify(token, now)?;
        let must_change_password =
            verified.role == Role::Admin && snapshot.account.must_change_password();
        Some(Identity {
            username: verified.username.into(),
            role: verified.role,
            initial_password: must_change_password && snapshot.account.using_default_password,
            must_change_password,
        })
    }

    /// Revokes a live token. Repeated revocations and expired tokens require no write.
    pub fn revoke(&self, token: &str) -> Result<()> {
        let _writer = self.writer.lock().expect("account writer poisoned");
        let snapshot = self.snapshot.load();
        let now = unix_seconds(SystemTime::now()).context("system clock predates Unix epoch")?;
        let Some(session) = snapshot.verify(token, now) else {
            return Ok(());
        };
        let mut next = snapshot.account.clone();
        next.revoked.retain(|token| token.expires > now);
        if session.role == Role::Readonly && next.revoked.len() >= MAX_REVOKED / 2 {
            let user = next
                .users
                .iter_mut()
                .find(|user| user.username == session.username)
                .expect("verified read-only account");
            user.session_epoch = user
                .session_epoch
                .checked_add(1)
                .context("read-only session epoch exhausted")?;
        } else if next.revoked.len() == MAX_REVOKED {
            next.invalidate_sessions()?;
        } else {
            next.revoked.push(Revoked {
                id: session.id.into(),
                expires: session.expires,
            });
        }
        self.save(next)
    }

    pub fn revoke_all(&self) -> Result<()> {
        let _writer = self.writer.lock().expect("account writer poisoned");
        let mut next = self.snapshot.load().account.clone();
        next.invalidate_sessions()?;
        self.save(next)
    }

    /// Replaces the administrator credentials after verifying the current password.
    /// Call from a bounded blocking worker.
    pub fn change_credentials(
        &self,
        current_password: &str,
        username: &str,
        new_password: &str,
    ) -> Result<()> {
        let username = username.trim();
        ensure!(
            !username.is_empty() && username.len() <= MAX_USERNAME_BYTES,
            CredentialChangeRejected("invalid administrator username")
        );
        check_password_strength(username, new_password)?;
        ensure!(
            current_password != new_password,
            CredentialChangeRejected("new password must differ from the current password")
        );

        let verified = self.snapshot.load_full();
        ensure!(
            password::verify(current_password, &verified.account.password_hash)?,
            CredentialChangeRejected("invalid administrator credentials")
        );
        let new_hash = password::hash(new_password)?;
        let secret = random_urlsafe::<32>()?;
        let _writer = self.writer.lock().expect("account writer poisoned");
        let active = self.snapshot.load();
        let account = &active.account;
        ensure!(
            account.username == verified.account.username
                && account.password_hash == verified.account.password_hash,
            CredentialChangeRejected("administrator credentials changed during verification")
        );
        ensure!(
            !account.users.iter().any(|user| user.username == username),
            CredentialChangeRejected("administrator username conflicts with an existing user")
        );
        let mut next = account.clone();
        next.username = username.into();
        next.password_hash = new_hash;
        next.session_secret = secret;
        next.using_default_password = false;
        next.weak_password = false;
        next.invalidate_sessions()?;
        self.save(next)
    }

    pub(super) fn save(&self, account: Account) -> Result<()> {
        let next = Snapshot::new(account)?;
        let mut bytes =
            serde_json::to_vec_pretty(&next.account).context("encode administrator account")?;
        bytes.push(b'\n');
        let saved = self.store.write_raw(ACCOUNT, &bytes);
        // A failed directory sync can follow a successful replacement.
        if saved.is_ok() || self.store.load_raw(ACCOUNT).ok().flatten().as_deref() == Some(&bytes) {
            self.snapshot.store(Arc::new(next));
        }
        saved.map(|_| ())
    }
}

impl Account {
    pub(super) fn must_change_password(&self) -> bool {
        !self.password_login_off && (self.using_default_password || self.weak_password)
    }

    fn password_flags(&self) -> (bool, bool) {
        (self.using_default_password, self.weak_password)
    }

    pub(super) fn verified_password_flags(&self, password: &str) -> (bool, bool) {
        if self.using_default_password {
            self.password_flags()
        } else if password == LEGACY_DEFAULT_PASSWORD {
            (true, false)
        } else {
            (
                false,
                check_password_strength(&self.username, password).is_err(),
            )
        }
    }

    pub(super) fn invalidate_sessions(&mut self) -> Result<()> {
        self.session_epoch = self
            .session_epoch
            .checked_add(1)
            .context("session epoch exhausted")?;
        self.revoked.clear();
        Ok(())
    }
}

pub(super) fn random_urlsafe<const N: usize>() -> Result<String> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes)
        .map_err(|_| anyhow!("get randomness for administrator credentials"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(super) fn open_lock(store: &ConfigStore, name: &str) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(store.dir().join(name))
        .context("open authentication lock")?;
    ensure!(
        file.metadata()?.is_file(),
        "authentication lock must be a regular file"
    );
    Ok(file)
}
