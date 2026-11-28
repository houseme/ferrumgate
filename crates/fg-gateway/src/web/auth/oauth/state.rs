//! The signed OAuth `state` (WP-25): provider, origin, scope, next,
//! nonce and a format version, valid for 10 minutes.
#![allow(dead_code)]

use std::fmt::Write as _;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use serde::{Deserialize, Serialize};

/// The state lifetime.
pub const STATE_TTL: u64 = 10 * 60;

/// The state format version; `verify_state` rejects any other value.
pub const STATE_VERSION: u8 = 1;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OAuthState {
    pub provider: String,
    pub origin: String,
    pub scope: String,
    pub next: String,
    pub nonce: String,
    pub v: u8,
}

/// Signs the state as `base64url(JSON) + "." + HMAC-SHA256`.
pub fn sign_state(secret: &[u8], state: &OAuthState) -> String {
    let json = serde_json::to_string(state).expect("state serialization cannot fail");
    let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    // The signature covers the base64url text, not the raw JSON — so
    // verification can check it before decoding.
    let tag = hmac::sign(&key, encoded.as_bytes());
    format!("{encoded}.{}", to_hex(tag.as_ref()))
}

/// Verifies signature (constant time) and returns the state; the 10
/// minute lifetime is checked by the caller against its clock. States
/// with a version other than [`STATE_VERSION`] are rejected.
pub fn verify_state(secret: &[u8], value: &str) -> Option<OAuthState> {
    let (payload, tag) = value.split_once('.')?;
    let tag = from_hex(tag)?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    // `hmac::verify` compares tags in constant time.
    hmac::verify(&key, payload.as_bytes(), &tag).ok()?;
    let json = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let state: OAuthState = serde_json::from_slice(&json).ok()?;
    (state.v == STATE_VERSION).then_some(state)
}

/// Lowercase hex.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"oauth-state-signing-secret";

    fn sample() -> OAuthState {
        OAuthState {
            provider: "github".to_owned(),
            origin: "https://site.example.com/login".to_owned(),
            scope: "site:blog".to_owned(),
            next: "/dashboard".to_owned(),
            nonce: "a-random-nonce".to_owned(),
            v: STATE_VERSION,
        }
    }

    /// The hex tag for an arbitrary (possibly invalid) payload.
    fn sign_payload(payload: &str) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, SECRET);
        to_hex(hmac::sign(&key, payload.as_bytes()).as_ref())
    }

    #[test]
    fn roundtrip_preserves_fields() {
        let value = sign_state(SECRET, &sample());

        // Shape: base64url payload without padding + "." + 64 lowercase
        // hex characters.
        let (payload, tag) = value.split_once('.').expect("dotted value");
        assert_eq!(tag.len(), 64, "SHA-256 摘要的 hex 为 64 字符");
        assert!(
            tag.bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "签名应为小写 hex：{tag}"
        );
        assert!(!payload.contains('='), "base64url 无填充：{payload}");

        let state = verify_state(SECRET, &value).expect("valid state");
        assert_eq!(state, sample(), "往返保留全部字段");

        // Signing is deterministic.
        assert_eq!(value, sign_state(SECRET, &sample()));
    }

    #[test]
    fn tampered_payload_rejected() {
        let mut value = sign_state(SECRET, &sample());
        // Flip the first payload character (stays valid base64url).
        value.replace_range(..1, if value.starts_with('A') { "B" } else { "A" });
        assert_ne!(value, sign_state(SECRET, &sample()));
        assert!(verify_state(SECRET, &value).is_none());
    }

    #[test]
    fn tampered_signature_and_wrong_key_rejected() {
        let value = sign_state(SECRET, &sample());
        let (payload, tag) = value.split_once('.').expect("dotted value");

        // A flipped hex character in the signature.
        let mut bad_tag = tag.to_owned();
        bad_tag.replace_range(0..1, if tag.starts_with('0') { "1" } else { "0" });
        assert!(verify_state(SECRET, &format!("{payload}.{bad_tag}")).is_none());

        // A wrong signing key.
        assert!(verify_state(b"other-secret", &value).is_none());
    }

    #[test]
    fn bad_formats_rejected() {
        let value = sign_state(SECRET, &sample());
        let (payload, tag) = value.split_once('.').expect("dotted value");

        // Missing dot / missing signature.
        assert!(verify_state(SECRET, payload).is_none());
        assert!(verify_state(SECRET, "").is_none());

        // Non-hex and odd-length signatures.
        assert!(verify_state(SECRET, &format!("{payload}.zz")).is_none());
        assert!(verify_state(SECRET, &format!("{payload}.a")).is_none());

        // A well-formed hex tag of the wrong length.
        assert!(verify_state(SECRET, &format!("{payload}.{}", &tag[..32])).is_none());

        // Payload that is not valid base64url.
        assert!(verify_state(SECRET, &format!("@@not-base64@@.{tag}")).is_none());

        // Valid base64url with a valid signature, but not JSON.
        let not_json = URL_SAFE_NO_PAD.encode(b"not json");
        assert!(verify_state(SECRET, &format!("{not_json}.{}", sign_payload(&not_json))).is_none());

        // JSON with the wrong shape (missing fields).
        let wrong_shape = URL_SAFE_NO_PAD.encode(br#"{"provider":"github"}"#);
        assert!(
            verify_state(SECRET, &format!("{wrong_shape}.{}", sign_payload(&wrong_shape))).is_none()
        );
    }

    #[test]
    fn wrong_version_rejected() {
        // Future version.
        let mut newer = sample();
        newer.v = STATE_VERSION + 1;
        assert!(verify_state(SECRET, &sign_state(SECRET, &newer)).is_none());
        // Version zero.
        let mut older = sample();
        older.v = 0;
        assert!(verify_state(SECRET, &sign_state(SECRET, &older)).is_none());
        // The current version passes.
        assert!(verify_state(SECRET, &sign_state(SECRET, &sample())).is_some());
    }
}
