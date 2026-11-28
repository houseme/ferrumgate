//! TOTP verification step (WP-24 step 6) — implementation batch.
//!
//! The second login step for TOTP-enabled shared users: a submitted
//! six-digit code is checked against the account's Base32 secret with a
//! ±30 s clock-skew window; every accepted code has already been bound to
//! a one-time token by the caller, so a replayed code cannot re-enter.
#![allow(dead_code)]

use fg_auth::totp::Totp;

/// Verifies a six-digit TOTP `code` for a Base32 `secret` at `timestamp`
/// (unix seconds). A secret that is not valid Base32 (or decodes to fewer
/// than 10 key bytes), a malformed code or a code outside the ±30 s
/// window all verify as `false`.
pub fn verify_code(secret: &str, code: &str, timestamp: u64) -> bool {
    match Totp::parse(secret) {
        Some(totp) => totp.match_code(code, timestamp).is_some(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B SHA-1 seed `"12345678901234567890"` in Base32,
    /// the same vector `fg-auth/src/totp.rs` tests against.
    const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn accepts_known_rfc6238_codes() {
        assert!(verify_code(SEED, "287082", 59));
        assert!(verify_code(SEED, "081804", 1_111_111_109));
        // parse() uppercases and strips spaces, so these still verify.
        assert!(verify_code(&SEED.to_lowercase(), "287082", 59));
        assert!(verify_code(
            &format!("{} {}", &SEED[..16], &SEED[16..]),
            "287082",
            59
        ));
    }

    #[test]
    fn rejects_wrong_or_malformed_code() {
        assert!(!verify_code(SEED, "000000", 59));
        // Right digits of the wrong window position.
        assert!(!verify_code(SEED, "818042", 59));
        // Not six ASCII digits.
        assert!(!verify_code(SEED, "28708", 59));
        assert!(!verify_code(SEED, "28708a", 59));
        assert!(!verify_code(SEED, "", 59));
    }

    #[test]
    fn rejects_code_outside_replay_window() {
        // Valid at 59 s; one period later (90 s) the ±30 s window no
        // longer covers its step, so a replay fails.
        assert!(verify_code(SEED, "287082", 89));
        assert!(!verify_code(SEED, "287082", 90));
        assert!(!verify_code(SEED, "287082", 120));
        // One full period before its window, likewise rejected.
        assert!(!verify_code(SEED, "081804", 1_111_111_049));
    }

    #[test]
    fn rejects_bad_base32_secret() {
        assert!(!verify_code("A!!B", "287082", 59));
        assert!(!verify_code("", "287082", 59));
        // Decodes, but to fewer than the required 10 key bytes.
        assert!(!verify_code("GEZDGNBV", "287082", 59));
    }
}
