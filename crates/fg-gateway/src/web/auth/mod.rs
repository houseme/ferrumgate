//! WP-24 site authentication core (steps 1-4 land first): site users,
//! shared users with SSO, signed session cookies and the verification
//! reservation (concurrency + failure limits). The authenticator wiring
//! into the serving path is a later batch (steps 5-9).
#![allow(dead_code)]

pub mod reserve;
pub mod session;
pub mod shared;
pub mod users;

/// The authentication reserve path every auth interaction lives under.
pub const AUTH_PATH: &str = "/__gately_auth";
/// Signed sessions live for seven days.
pub const SESSION_TTL: u64 = 7 * 24 * 3600;
/// The single-sign-on parent-domain cookie name.
pub const SSO_COOKIE: &str = "gately_sso";
