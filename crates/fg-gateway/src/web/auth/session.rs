//! Signed session cookies (WP-24 step 3): the value is
//! `base64url(JSON) + "." + HMAC-SHA256`; the cookie name binds a session
//! to its listener/site pair; one-time tokens gate the TOTP step.
#![allow(dead_code)]

use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::{digest, hmac};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use super::SESSION_TTL;

/// Which sessions a cookie authenticates: this site only, or the whole
/// single-sign-on domain (written to the parent-domain `gately_sso`
/// cookie).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Scope {
    Site,
    Sso(String),
}

/// The signed cookie payload. Field names match the upstream session
/// JSON (`u` user, `h` host, `s` scope, `c` credential fingerprint,
/// `a` third-party aliases (WP-25), `sh` shared-user session); `e` is
/// the expiry as unix seconds (SESSION_TTL ahead of issuance).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SiteSession {
    pub u: String,
    pub h: String,
    pub s: Scope,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub c: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub a: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub sh: bool,
    /// Unix seconds expiry.
    pub e: i64,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// The cookie name for a listener/site pair:
/// `gately_site_<sha256[:6]hex>` — different sites or ports never share
/// a login state.
pub fn cookie_name(listener_key: &str, site_key: &str) -> String {
    let seed = format!("{listener_key}/{site_key}");
    let digest = digest::digest(&digest::SHA256, seed.as_bytes());
    format!("gately_site_{}", to_hex(&digest.as_ref()[..6]))
}

/// Signs a session for `host` with a SESSION_TTL lifetime.
pub fn issue(
    secret: &[u8],
    user: &str,
    host: &str,
    scope: Scope,
    fingerprint: &str,
    now: SystemTime,
) -> String {
    let session = SiteSession {
        u: user.to_owned(),
        h: host.to_owned(),
        s: scope,
        c: fingerprint.to_owned(),
        a: Vec::new(),
        sh: false,
        e: unix_seconds(now).saturating_add(i64::try_from(SESSION_TTL).unwrap_or(i64::MAX)),
    };
    sign(secret, &session)
}

/// Verifies signature, expiry and scope; returns the payload or None.
pub fn verify(secret: &[u8], value: &str, host: &str, now: SystemTime) -> Option<SiteSession> {
    let (payload, tag) = value.split_once('.')?;
    let tag = from_hex(tag)?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    // `hmac::verify` compares tags in constant time.
    hmac::verify(&key, payload.as_bytes(), &tag).ok()?;
    let json = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let session: SiteSession = serde_json::from_slice(&json).ok()?;
    if session.e <= unix_seconds(now) {
        return None;
    }
    scope_covers(&session.s, &session.h, host).then_some(session)
}

/// Remaining lifetime of a verified session.
pub fn remaining(session: &SiteSession, now: SystemTime) -> Duration {
    let left = session.e - unix_seconds(now);
    Duration::from_secs(left.max(0) as u64)
}

/// A `Site` scope is bound to its issuing host; an `Sso` scope is valid
/// on any host under the domain (dot-separated, so `notexample.com` is
/// not under `example.com`).
fn scope_covers(scope: &Scope, session_host: &str, host: &str) -> bool {
    match scope {
        Scope::Site => session_host == host,
        Scope::Sso(domain) => session_host == host || host_under(host, domain),
    }
}

/// Is `host` the domain itself or a subdomain of it?
fn host_under(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn sign(secret: &[u8], session: &SiteSession) -> String {
    let payload = serde_json::to_string(session).expect("session serialization cannot fail");
    let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    // The signature covers the base64url text, not the raw JSON — so
    // verification can check it before decoding.
    let tag = hmac::sign(&key, encoded.as_bytes());
    format!("{encoded}.{}", to_hex(tag.as_ref()))
}

fn unix_seconds(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(delta) => delta.as_secs() as i64,
        Err(error) => -(error.duration().as_secs() as i64),
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn from_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[high, low]| Some(hex_value(high)? << 4 | hex_value(low)?))
        .collect()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// One-time tokens binding a user and host for the TOTP step: issued
/// once, consumed once — replay is rejected.
#[derive(Default)]
pub struct OneTimeTokens {
    inner: Mutex<Vec<(String, String)>>,
}

impl OneTimeTokens {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issues a token for the (user, host) pair.
    pub fn issue(&self, user: &str, host: &str) -> String {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("OS randomness unavailable");
        let token = to_hex(&bytes);
        self.lock().push((token.clone(), format!("{user}:{host}")));
        token
    }

    /// Consumes a token; a second use (or an unknown token) fails.
    pub fn consume(&self, token: &str, user: &str, host: &str) -> bool {
        let bound = format!("{user}:{host}");
        let mut tokens = self.lock();
        match tokens
            .iter()
            .position(|(known, binding)| known.as_str() == token && binding.as_str() == bound)
        {
            Some(index) => {
                tokens.remove(index);
                true
            }
            None => false,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Vec<(String, String)>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-signing-secret";
    const HOST: &str = "example.com";

    fn at(seconds: i64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds as u64)
    }

    fn now() -> SystemTime {
        at(1_000_000)
    }

    /// The base64url payload part of a signed cookie value, decoded.
    fn payload_of(value: &str) -> String {
        let (payload, _) = value.split_once('.').expect("dotted value");
        String::from_utf8(URL_SAFE_NO_PAD.decode(payload).expect("valid base64"))
            .expect("utf8 payload")
    }

    #[test]
    fn cookie_name_shape_and_binding() {
        // Known answer: sha256("listener/site")[:6] = 8b57e3f18dcc.
        assert_eq!(cookie_name("listener", "site"), "gately_site_8b57e3f18dcc");

        // Shape: prefix + 12 lowercase hex characters.
        let name = cookie_name("web-1", "blog");
        let hash = name.strip_prefix("gately_site_").expect("prefix");
        assert_eq!(hash.len(), 12);
        assert!(
            hash.bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );

        // Different listener or site keys never share a cookie name.
        assert_ne!(cookie_name("l", "s"), cookie_name("l2", "s"));
        assert_ne!(cookie_name("l", "s"), cookie_name("l", "s2"));
    }

    #[test]
    fn session_roundtrip_preserves_fields() {
        let value = issue(
            SECRET,
            "alice",
            HOST,
            Scope::Site,
            "cred-fingerprint",
            now(),
        );
        let session = verify(SECRET, &value, HOST, now()).expect("valid session");
        assert_eq!(session.u, "alice");
        assert_eq!(session.h, HOST);
        assert_eq!(session.s, Scope::Site);
        assert_eq!(session.c, "cred-fingerprint");
        assert_eq!(session.e, 1_000_000 + SESSION_TTL as i64);
        assert!(session.a.is_empty());
        assert!(!session.sh);
    }

    #[test]
    fn session_payload_omits_empty_fields() {
        let value = issue(SECRET, "alice", HOST, Scope::Site, "", now());
        let payload = payload_of(&value);
        assert!(!payload.contains("\"c\""));
        assert!(!payload.contains("\"a\""));
        assert!(!payload.contains("\"sh\""));
        assert!(payload.contains("\"u\":\"alice\""));
    }

    #[test]
    fn tampered_payload_rejected() {
        let mut value = issue(SECRET, "alice", HOST, Scope::Site, "fp", now());
        // Flip the first payload character (stays valid base64url).
        value.replace_range(..1, if value.starts_with('A') { "B" } else { "A" });
        assert_ne!(
            value,
            issue(SECRET, "alice", HOST, Scope::Site, "fp", now())
        );
        assert!(verify(SECRET, &value, HOST, now()).is_none());
    }

    #[test]
    fn tampered_signature_rejected() {
        let value = issue(SECRET, "alice", HOST, Scope::Site, "fp", now());
        let (payload, tag) = value.split_once('.').expect("dotted value");

        // A flipped hex character in the signature.
        let mut bad_tag = tag.to_owned();
        bad_tag.replace_range(0..1, if tag.starts_with('0') { "1" } else { "0" });
        assert!(verify(SECRET, &format!("{payload}.{bad_tag}"), HOST, now()).is_none());

        // A wrong signing key.
        assert!(verify(b"other-secret", &value, HOST, now()).is_none());

        // A non-hex or missing signature.
        assert!(verify(SECRET, &format!("{payload}.zz"), HOST, now()).is_none());
        assert!(verify(SECRET, payload, HOST, now()).is_none());
    }

    #[test]
    fn expired_session_rejected() {
        let value = issue(SECRET, "alice", HOST, Scope::Site, "fp", now());
        let expiry = 1_000_000 + SESSION_TTL as i64;

        // Still valid shortly before expiry.
        assert!(verify(SECRET, &value, HOST, at(expiry - 1)).is_some());
        // Expiry is strict (`e > now`): valid up to and including the
        // second before, gone at the expiry second itself.
        assert!(verify(SECRET, &value, HOST, at(expiry)).is_none());
        assert!(verify(SECRET, &value, HOST, at(expiry + 1)).is_none());
    }

    #[test]
    fn site_scope_bound_to_issuing_host() {
        let value = issue(SECRET, "alice", HOST, Scope::Site, "fp", now());
        // A different site's host must not accept this cookie.
        assert!(verify(SECRET, &value, "other.com", now()).is_none());
        assert!(verify(SECRET, &value, "sub.example.com", now()).is_none());
    }

    #[test]
    fn sso_scope_matches_parent_and_siblings_only() {
        let value = issue(
            SECRET,
            "alice",
            "a.example.com",
            Scope::Sso("example.com".to_owned()),
            "fp",
            now(),
        );

        // The issuing host and its domain siblings all accept.
        assert!(verify(SECRET, &value, "a.example.com", now()).is_some());
        assert!(verify(SECRET, &value, "b.example.com", now()).is_some());
        assert!(verify(SECRET, &value, "deep.sub.example.com", now()).is_some());
        // The parent domain itself is inside the scope.
        assert!(verify(SECRET, &value, "example.com", now()).is_some());

        // Dot boundaries keep look-alike hosts out.
        for host in [
            "notexample.com",
            "badexample.com",
            "example.com.evil.io",
            "example.org",
        ] {
            assert!(
                verify(SECRET, &value, host, now()).is_none(),
                "host must be outside the SSO domain: {host}"
            );
        }

        // A session scoped to another SSO domain does not cover ours.
        let other = issue(
            SECRET,
            "alice",
            "a.example.com",
            Scope::Sso("other.com".to_owned()),
            "fp",
            now(),
        );
        assert!(verify(SECRET, &other, "b.example.com", now()).is_none());
    }

    #[test]
    fn one_time_tokens_single_use_and_bound() {
        let tokens = OneTimeTokens::new();

        // Issue-consume works once; replay is rejected.
        let first = tokens.issue("alice", HOST);
        assert_eq!(first.len(), 32);
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert!(tokens.consume(&first, "alice", HOST));
        assert!(!tokens.consume(&first, "alice", HOST));

        // Tokens are bound to their (user, host) pair.
        let second = tokens.issue("alice", HOST);
        assert!(!tokens.consume(&second, "alice", "other.com"));
        assert!(!tokens.consume(&second, "bob", HOST));
        // The failed attempts did not consume it.
        assert!(tokens.consume(&second, "alice", HOST));
        assert!(!tokens.consume(&second, "alice", HOST));

        // Unknown tokens are rejected.
        assert!(!tokens.consume("deadbeef", "alice", HOST));
    }

    #[test]
    fn remaining_reports_leftover_lifetime() {
        let issued = issue(SECRET, "alice", HOST, Scope::Site, "fp", now());
        let session = verify(SECRET, &issued, HOST, now()).expect("valid session");
        assert_eq!(remaining(&session, now()), Duration::from_secs(SESSION_TTL));

        // Halfway through the lifetime.
        let half = SESSION_TTL / 2;
        assert_eq!(
            remaining(&session, at(1_000_000 + half as i64)),
            Duration::from_secs(half)
        );

        // Expired (or expired at the exact boundary) reads as zero.
        let expiry = session.e;
        assert_eq!(remaining(&session, at(expiry)), Duration::ZERO);
        assert_eq!(remaining(&session, at(expiry + 60)), Duration::ZERO);
    }
}
