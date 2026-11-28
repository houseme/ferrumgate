//! Security controls for Web Terminal (WP-61 §3.3):
//! - User agreement confirmation state.
//! - TOTP 2FA setup / enable / disable / check / verify (RFC 6238 HMAC-SHA1,
//!   6 digits, 30-second step, ±1 step skew window, failure lockout).
//! - Caller privilege model: login session vs write API token vs read-only.
//! - Read-only credential & command masking (hides passwords, keys, passphrases,
//!   proxy passwords, preset credentials, and shortcut commands).

use std::collections::HashMap;
use std::sync::Mutex;

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha1::Sha1;
use subtle::ConstantTimeEq;

use crate::model::{Connection, Preset, Shortcut, limits};
use crate::session::{NowFn, system_clock};
use crate::validate::{ConnectionView, host_key_label, mask_connection, mask_preset};

type HmacSha1 = Hmac<Sha1>;

/// TOTP time step in seconds (RFC 6238 standard).
pub const TOTP_PERIOD_SECS: u64 = 30;
/// Number of decimal digits in TOTP codes.
pub const TOTP_DIGITS: u32 = 6;
/// Number of consecutive wrong TOTP codes before locking out the actor.
pub const TWO_FA_MAX_FAILURES: u32 = 5;
/// Duration of 2FA lockout in seconds (5 minutes).
pub const TWO_FA_LOCKOUT_SECS: i64 = 300;
/// Duration a verified 2FA check remains valid in seconds (30 minutes).
pub const TWO_FA_VERIFIED_TTL_SECS: i64 = 1800;

/// Caller access level resolved from the management request context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallerRole {
    /// Authenticated admin login session (full access including security & settings).
    Session,
    /// API token with `webterminal:write` (terminal/config write, NO security/settings).
    ApiWrite,
    /// Read-only token or read-only identity (view masked lists/sessions only, no input).
    ReadOnly,
}

/// Request caller identity (injected via Axum extension or test headers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallerContext {
    pub role: CallerRole,
    pub actor_id: String,
}

impl Default for CallerContext {
    fn default() -> Self {
        Self {
            role: CallerRole::Session,
            actor_id: "default-session".to_owned(),
        }
    }
}

impl CallerContext {
    pub fn session(actor_id: impl Into<String>) -> Self {
        Self {
            role: CallerRole::Session,
            actor_id: actor_id.into(),
        }
    }

    pub fn api_write(actor_id: impl Into<String>) -> Self {
        Self {
            role: CallerRole::ApiWrite,
            actor_id: actor_id.into(),
        }
    }

    pub fn read_only(actor_id: impl Into<String>) -> Self {
        Self {
            role: CallerRole::ReadOnly,
            actor_id: actor_id.into(),
        }
    }

    /// Whether the caller may create/modify resources or send terminal input.
    pub fn can_write(&self) -> bool {
        matches!(self.role, CallerRole::Session | CallerRole::ApiWrite)
    }

    /// Whether the caller may change security settings / 2FA / `PUT /settings`
    /// (WP-61 §3.3: login session ONLY).
    pub fn can_manage_security(&self) -> bool {
        self.role == CallerRole::Session
    }

    /// Whether the caller is read-only.
    pub fn is_readonly(&self) -> bool {
        self.role == CallerRole::ReadOnly
    }
}

/// Public security status returned by `GET /api/webterminal/security`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityView {
    pub agreement_accepted: bool,
    pub agreement_accepted_at: Option<String>,
    pub two_fa_enabled: bool,
    pub two_fa_verified: bool,
}

/// Setup payload returned by `POST /api/webterminal/security/2fa/setup`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoFaSetupResponse {
    pub secret: String,
    pub otpauth_uri: String,
}

// --- TOTP (RFC 6238) -----------------------------------------------------

/// Generates a 160-bit cryptographically random Base32 TOTP secret.
pub fn generate_totp_secret() -> String {
    let mut bytes = [0u8; 20];
    getrandom::fill(&mut bytes).expect("OS random source");
    BASE32_NOPAD.encode(&bytes)
}

/// Builds a standard `otpauth://totp/...` URI for QR code provisioning.
pub fn otpauth_uri(secret: &str, issuer: &str, account: &str) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD_SECS}"
    )
}

/// Computes the 6-digit TOTP code for `secret_b32` at `unix_secs`.
pub fn totp_code_at(secret_b32: &str, unix_secs: i64) -> Option<String> {
    let normalized = secret_b32
        .trim()
        .replace(' ', "")
        .trim_end_matches('=')
        .to_ascii_uppercase();
    let key = BASE32_NOPAD.decode(normalized.as_bytes()).ok()?;
    let counter = (unix_secs.max(0) as u64) / TOTP_PERIOD_SECS;
    Some(hotp_sha1(&key, counter))
}

fn hotp_sha1(key: &[u8], counter: u64) -> String {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let code = binary % 10u32.pow(TOTP_DIGITS);
    format!("{code:06}")
}

/// Verifies a 6-digit TOTP code against `secret_b32` at `unix_secs` (±1 time step)
/// using constant-time comparison.
pub fn verify_totp(secret_b32: &str, submitted: &str, unix_secs: i64) -> bool {
    let clean = submitted.trim();
    if clean.len() != TOTP_DIGITS as usize || !clean.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut matched = subtle::Choice::from(0u8);
    for delta in [-1i64, 0, 1] {
        let ts = unix_secs + delta * (TOTP_PERIOD_SECS as i64);
        if let Some(expected) = totp_code_at(secret_b32, ts) {
            matched |= expected.as_bytes().ct_eq(clean.as_bytes());
        }
    }
    bool::from(matched)
}

// --- 2FA verification cache & failure lockout ----------------------------

#[derive(Default)]
struct ActorTwoFa {
    verified_until: i64,
    failures: u32,
    locked_until: i64,
}

/// Runtime tracker for 2FA verification TTL and brute-force lockout.
pub struct TwoFaTracker {
    actors: Mutex<HashMap<String, ActorTwoFa>>,
    clock: NowFn,
}

/// Result of attempting a 2FA code verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    Ok,
    Invalid { remaining_attempts: u32 },
    Locked { retry_after_secs: i64 },
}

impl Default for TwoFaTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TwoFaTracker {
    pub fn new() -> Self {
        Self::with_clock(system_clock())
    }

    pub fn with_clock(clock: NowFn) -> Self {
        Self {
            actors: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// Current Unix timestamp from the tracker's clock.
    pub fn now(&self) -> i64 {
        (self.clock)()
    }

    /// Whether `actor_id` currently holds a fresh 2FA verification.
    pub fn is_verified(&self, actor_id: &str) -> bool {
        let now = (self.clock)();
        self.actors
            .lock()
            .expect("2fa lock")
            .get(actor_id)
            .is_some_and(|st| st.verified_until > now)
    }

    /// Verifies `code` against `secret`, updating failure counter / lockout or
    /// granting a verified window on success.
    pub fn verify(&self, actor_id: &str, secret: &str, code: &str) -> VerifyOutcome {
        let now = (self.clock)();
        let mut map = self.actors.lock().expect("2fa lock");
        let entry = map.entry(actor_id.to_owned()).or_default();

        if entry.locked_until > now {
            return VerifyOutcome::Locked {
                retry_after_secs: entry.locked_until - now,
            };
        }
        // Reset failure count once a previous lockout window expired.
        if entry.locked_until > 0 && entry.locked_until <= now {
            entry.locked_until = 0;
            entry.failures = 0;
        }

        if verify_totp(secret, code, now) {
            entry.failures = 0;
            entry.locked_until = 0;
            entry.verified_until = now + TWO_FA_VERIFIED_TTL_SECS;
            VerifyOutcome::Ok
        } else {
            entry.failures += 1;
            if entry.failures >= TWO_FA_MAX_FAILURES {
                entry.locked_until = now + TWO_FA_LOCKOUT_SECS;
                VerifyOutcome::Locked {
                    retry_after_secs: TWO_FA_LOCKOUT_SECS,
                }
            } else {
                VerifyOutcome::Invalid {
                    remaining_attempts: TWO_FA_MAX_FAILURES - entry.failures,
                }
            }
        }
    }

    /// Marks `actor_id` verified (used right after enabling 2FA).
    pub fn mark_verified(&self, actor_id: &str) {
        let now = (self.clock)();
        let mut map = self.actors.lock().expect("2fa lock");
        let entry = map.entry(actor_id.to_owned()).or_default();
        entry.failures = 0;
        entry.locked_until = 0;
        entry.verified_until = now + TWO_FA_VERIFIED_TTL_SECS;
    }

    /// Clears all verification state (e.g. when 2FA is disabled).
    pub fn clear_all(&self) {
        self.actors.lock().expect("2fa lock").clear();
    }
}

// --- Read-only masking (WP-61 §3.3) --------------------------------------

/// Produces a [`ConnectionView`] tailored to the caller's role.
/// Read-only callers never see passwords, private keys, key file paths,
/// passphrases, proxy passwords, or saved commands/shortcuts.
pub fn connection_view_for(conn: &Connection, caller: &CallerContext) -> ConnectionView {
    let mut masked = mask_connection(conn.clone());
    if caller.is_readonly() {
        if !masked.auth.key_file.is_empty() {
            masked.auth.key_file = limits::SECRET_MASK.into();
        }
        masked.shortcuts.clear();
        masked.quick_access.clear();
    }
    ConnectionView {
        host_key_label: conn
            .host_key
            .as_ref()
            .map(host_key_label)
            .unwrap_or_default(),
        trusted: conn.host_key.is_some(),
        connection: masked,
    }
}

/// Masks a preset for API output (same masking for all callers; secrets endpoint
/// is blocked for read-only callers).
pub fn preset_view_for(preset: &Preset, _caller: &CallerContext) -> Preset {
    mask_preset(preset.clone())
}

/// Filters global shortcuts for read-only callers (WP-61 §3.3: read-only identity
/// does not see commands).
pub fn shortcuts_for(shortcuts: &[Shortcut], caller: &CallerContext) -> Vec<Shortcut> {
    if caller.is_readonly() {
        Vec::new()
    } else {
        shortcuts.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::test_support::MutableClock;
    use std::sync::Arc;

    #[test]
    fn totp_generates_and_verifies_rfc6238_codes() {
        let secret = generate_totp_secret();
        let now = 1_700_000_000i64;
        let code = totp_code_at(&secret, now).expect("totp code");
        assert_eq!(code.len(), 6);
        assert!(verify_totp(&secret, &code, now));
        // Adjacent ±30s step also accepted.
        assert!(verify_totp(&secret, &code, now + 30));
        assert!(verify_totp(&secret, &code, now - 30));
        // Wrong code rejected.
        let wrong = if code == "000000" { "111111" } else { "000000" };
        assert!(!verify_totp(&secret, wrong, now));
    }

    #[test]
    fn two_fa_lockout_and_recovery() {
        let clock = Arc::new(MutableClock::at(10_000));
        let tracker = TwoFaTracker::with_clock(clock.fn_pointer());
        let secret = generate_totp_secret();
        let good = totp_code_at(&secret, 10_000).unwrap();
        let bad = if good == "000000" { "999999" } else { "000000" };

        for i in 1..TWO_FA_MAX_FAILURES {
            assert_eq!(
                tracker.verify("u1", &secret, bad),
                VerifyOutcome::Invalid {
                    remaining_attempts: TWO_FA_MAX_FAILURES - i
                }
            );
        }
        // 5th failure triggers lockout.
        assert!(matches!(
            tracker.verify("u1", &secret, bad),
            VerifyOutcome::Locked {
                retry_after_secs: TWO_FA_LOCKOUT_SECS
            }
        ));
        // Even the valid code is rejected during lockout!
        assert!(matches!(
            tracker.verify("u1", &secret, &good),
            VerifyOutcome::Locked { .. }
        ));
        assert!(!tracker.is_verified("u1"));

        // After lockout expires, valid code succeeds.
        clock.advance(TWO_FA_LOCKOUT_SECS);
        let new_good = totp_code_at(&secret, 10_000 + TWO_FA_LOCKOUT_SECS).unwrap();
        assert_eq!(tracker.verify("u1", &secret, &new_good), VerifyOutcome::Ok);
        assert!(tracker.is_verified("u1"));
    }

    #[test]
    fn readonly_masks_credentials_and_hides_commands() {
        let mut conn = Connection::default();
        conn.auth.password = "pw".into();
        conn.auth.key_file = "/root/.ssh/id_ed25519".into();
        conn.shortcuts.push(Shortcut {
            name: "reboot".into(),
            command: "sudo reboot".into(),
        });
        let ro = CallerContext::read_only("ro");
        let view = connection_view_for(&conn, &ro);
        assert_eq!(view.connection.auth.password, limits::SECRET_MASK);
        assert_eq!(view.connection.auth.key_file, limits::SECRET_MASK);
        assert!(view.connection.shortcuts.is_empty());

        let admin = CallerContext::session("admin");
        let admin_view = connection_view_for(&conn, &admin);
        assert_eq!(admin_view.connection.auth.password, limits::SECRET_MASK);
        assert_eq!(admin_view.connection.shortcuts.len(), 1);
    }
}
