//! Trust credentials (WP-25): which of the request's credentials the
//! WAF and intrusion protection may skip. Only Gately-issued credentials
//! count — sessions, the SSO cookie, recently verified basic auth, the
//! backend auth marker and the admin bridge.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ring::hmac;

/// How long a verified basic credential stays trusted.
pub const TRUST_BASIC_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustedCred {
    None,
    SiteSession,
    SsoCookie,
    /// Recently verified basic credentials carry an expiry.
    Basic {
        exp: Instant,
    },
    BackendMarker,
    AdminBridge,
}

/// The basic-auth trust cache: HMAC(scope, username, password) → expiry.
/// No plaintext storage; a changed password produces a new key so the
/// old entry never matches.
pub struct BasicTrustCache {
    entries: Mutex<HashMap<String, Instant>>,
}

impl BasicTrustCache {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// The cache key: HMAC-SHA256 over (site scope, username, password)
    /// joined by newlines, as lowercase hex. The password never leaves
    /// the digest.
    pub fn key(secret: &[u8], scope: &str, user: &str, pass: &str) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
        let mut message = String::with_capacity(scope.len() + user.len() + pass.len() + 2);
        message.push_str(scope);
        message.push('\n');
        message.push_str(user);
        message.push('\n');
        message.push_str(pass);
        let tag = hmac::sign(&key, message.as_bytes());
        hex(tag.as_ref())
    }

    /// Marks a credential trusted for TRUST_BASIC_TTL from `now`.
    pub fn trust(&self, key: &str, now: Instant) {
        self.entries
            .lock()
            .expect("basic trust cache poisoned")
            .insert(key.to_owned(), now + TRUST_BASIC_TTL);
    }

    /// Is the credential still trusted at `now`? Expired entries are
    /// dropped on read, so a stale key never lingers after a miss.
    pub fn trusted(&self, key: &str, now: Instant) -> bool {
        let mut entries = self.entries.lock().expect("basic trust cache poisoned");
        match entries.get(key) {
            Some(&exp) if exp > now => true,
            Some(_) => {
                entries.remove(key);
                false
            }
            None => false,
        }
    }

    /// Drops every entry expired at `now` (periodic sweep).
    pub fn expire(&self, now: Instant) {
        self.entries
            .lock()
            .expect("basic trust cache poisoned")
            .retain(|_, exp| *exp > now);
    }
}

impl Default for BasicTrustCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Lowercase hex, same encoding as `shared.rs` fingerprints.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-secret";

    #[test]
    fn key_varies_per_scope_user_and_pass() {
        let base = BasicTrustCache::key(SECRET, "site.example.com", "alice", "pw");
        // A different field changes the digest — the newline join does not
        // let ("a", "bc") collide with ("ab", "c").
        assert_ne!(
            base,
            BasicTrustCache::key(SECRET, "other.example.com", "alice", "pw")
        );
        assert_ne!(
            base,
            BasicTrustCache::key(SECRET, "site.example.com", "bob", "pw")
        );
        assert_ne!(
            base,
            BasicTrustCache::key(SECRET, "site.example.com", "alice", "pw2")
        );
        assert_ne!(
            base,
            BasicTrustCache::key(SECRET, "site.example.com", "alic", "e pw")
        );
        // A different secret produces a different key too.
        assert_ne!(
            base,
            BasicTrustCache::key(b"other-secret", "site.example.com", "alice", "pw")
        );
    }

    #[test]
    fn key_is_stable_for_same_input() {
        let a = BasicTrustCache::key(SECRET, "site", "alice", "pw");
        let b = BasicTrustCache::key(SECRET, "site", "alice", "pw");
        assert_eq!(a, b);
        // SHA-256 output size as lowercase hex.
        assert_eq!(a.len(), 64);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn trust_then_trusted_roundtrip() {
        let cache = BasicTrustCache::new();
        let key = BasicTrustCache::key(SECRET, "site", "alice", "pw");
        let now = Instant::now();
        assert!(!cache.trusted(&key, now), "unknown key is not trusted");
        cache.trust(&key, now);
        assert!(cache.trusted(&key, now));
        assert!(cache.trusted(&key, now + TRUST_BASIC_TTL - Duration::from_secs(1)));
        // A second credential stays independent.
        let other = BasicTrustCache::key(SECRET, "site", "bob", "pw");
        assert!(!cache.trusted(&other, now));
    }

    #[test]
    fn expired_entry_is_not_trusted() {
        let cache = BasicTrustCache::new();
        let key = BasicTrustCache::key(SECRET, "site", "alice", "pw");
        let now = Instant::now();
        cache.trust(&key, now);
        // At exactly `now + TTL` the entry has expired.
        assert!(!cache.trusted(&key, now + TRUST_BASIC_TTL));
        // The lazy drop removed it: re-trusting and re-checking works.
        cache.trust(&key, now + TRUST_BASIC_TTL);
        assert!(cache.trusted(&key, now + TRUST_BASIC_TTL + Duration::from_secs(1)));
    }

    #[test]
    fn expire_sweeps_only_expired_entries() {
        let cache = BasicTrustCache::new();
        let now = Instant::now();
        let old = BasicTrustCache::key(SECRET, "site", "alice", "pw");
        let fresh = BasicTrustCache::key(SECRET, "site", "bob", "pw");
        cache.trust(&old, now);
        cache.trust(&fresh, now + Duration::from_secs(60));
        cache.expire(now + TRUST_BASIC_TTL);
        // `old` expired exactly at the sweep time; `fresh` is still live.
        assert!(!cache.trusted(&old, now + TRUST_BASIC_TTL));
        assert!(cache.trusted(&fresh, now + TRUST_BASIC_TTL));
    }
}
