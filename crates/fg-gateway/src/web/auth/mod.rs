//! WP-24 steps 5-9 skeletons: the HTTP basic check, the TOTP step, the
//! self-service password flow, the login page model, and the
//! authenticator glue. Pipeline wiring into `forward` lands with them.
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

use std::net::IpAddr;
use std::sync::Arc;

use reserve::{Reserve, Slot};
use session::{OneTimeTokens, SiteSession};
use shared::AuthUser;


/// The authenticator for one config generation: the signing secret, the
/// shared-user snapshot, the reservation state and the TOTP tokens.
pub struct Authenticator {
    secret: Vec<u8>,
    shared: Vec<AuthUser>,
    reserve: Arc<Reserve>,
    tokens: OneTimeTokens,
}

impl Authenticator {
    pub fn new(secret: &[u8], shared: Vec<AuthUser>) -> Self {
        Self {
            secret: secret.to_vec(),
            shared,
            reserve: Arc::new(Reserve::new()),
            tokens: OneTimeTokens::new(),
        }
    }

    pub fn reserve(&self) -> Arc<Reserve> {
        Arc::clone(&self.reserve)
    }

    pub fn tokens(&self) -> &OneTimeTokens {
        &self.tokens
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
        scope: session::Scope,
        fingerprint: &str,
        now: std::time::SystemTime,
    ) -> String {
        session::issue(&self.secret, user, host, scope, fingerprint, now)
    }

    /// Verifies a session cookie value against the host.
    pub fn verify_session(
        &self,
        value: &str,
        host: &str,
        now: std::time::SystemTime,
    ) -> Option<SiteSession> {
        session::verify(&self.secret, value, host, now)
    }
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
