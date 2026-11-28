//! The safe-entry gate: visiting the configured entry path plants a
//! signed marker cookie; requests carrying a valid marker pass the gate.

use std::time::Duration;

use axum::http::HeaderMap;
use hmac::{KeyInit, Mac, SimpleHmac};

/// Marker cookie lifetime once planted.
pub const MARKER_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
pub const MARKER_COOKIE: &str = "gately_entry";

/// Entry-path rules: at least 3 characters, must not start with the API
/// or asset namespaces, no spaces, `?` or `#`; must start with `/`.
pub fn validate_entry_path(path: &str) -> Result<(), &'static str> {
    let Some(rest) = path.strip_prefix('/') else {
        return Err("入口路径必须以 / 开头");
    };
    if rest.len() < 3 {
        return Err("入口路径至少 3 个字符");
    }
    if rest.starts_with("api") || rest.starts_with("assets") {
        return Err("入口路径不能以 /api 或 /assets 开头");
    }
    if path.chars().any(|c| matches!(c, ' ' | '?' | '#')) {
        return Err("入口路径不能包含空格、? 或 #");
    }
    Ok(())
}

/// Builds the signed marker value for an entry planting: an expiry stamp
/// plus an HMAC tag over it. The key is derived from the account file so
/// session-key rotations do not disturb the marker.
pub fn plant_marker(key: &[u8], now: std::time::SystemTime) -> String {
    let expiry = now
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|delta| delta.as_secs() + MARKER_TTL.as_secs())
        .unwrap_or(MARKER_TTL.as_secs());
    let payload = expiry.to_string();
    let mut mac = SimpleHmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC key");
    mac.update(payload.as_bytes());
    let tag = mac.finalize().into_bytes();
    format!("{payload}.{}", data_encoding::BASE64URL_NOPAD.encode(&tag))
}

/// Validates a marker value against the key; expired or forged markers
/// fail.
pub fn marker_valid(value: &str, key: &[u8], now: std::time::SystemTime) -> bool {
    use subtle::ConstantTimeEq as _;
    let Some((payload, tag)) = value.rsplit_once('.') else {
        return false;
    };
    let Ok(expiry) = payload.parse::<u64>() else {
        return false;
    };
    let Ok(expected) = data_encoding::BASE64URL_NOPAD.decode(tag.as_bytes()) else {
        return false;
    };
    let mut mac = match SimpleHmac::<sha2::Sha256>::new_from_slice(key) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(payload.as_bytes());
    if bool::from(mac.finalize().into_bytes().as_slice().ct_eq(&expected)) {
        let Some(deadline) =
            std::time::SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(expiry))
        else {
            return false;
        };
        now < deadline
    } else {
        false
    }
}

/// Whether the request already carries a valid entry marker. The key
/// lives with the guard's owner; here it is supplied per call.
pub fn marker_present(headers: &HeaderMap, key: &[u8]) -> bool {
    for header in headers.get_all(axum::http::header::COOKIE) {
        let Ok(raw) = header.to_str() else {
            continue;
        };
        for pair in raw.split(';') {
            if let Some((name, value)) = pair.trim().split_once('=')
                && name == MARKER_COOKIE
                && marker_valid(value, key, std::time::SystemTime::now())
            {
                return true;
            }
        }
    }
    false
}

/// The `Set-Cookie` header planting the marker on the entry path.
pub fn marker_set_cookie(value: &str) -> String {
    format!(
        "{MARKER_COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        MARKER_TTL.as_secs()
    )
}

/// The expired `Set-Cookie` clearing the marker (entry disabled).
pub fn marker_clear_cookie() -> String {
    format!("{MARKER_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use axum::http::{HeaderMap, HeaderValue};

    use super::*;

    fn test_key() -> Vec<u8> {
        b"entry-marker-test-key".to_vec()
    }

    #[test]
    fn entry_path_accepts_normal_paths() {
        assert!(validate_entry_path("/hidden-entry").is_ok());
        assert!(validate_entry_path("/abc").is_ok());
    }

    #[test]
    fn entry_path_rejects_bad_paths() {
        assert!(validate_entry_path("hidden-entry").is_err());
        assert!(validate_entry_path("/ab").is_err());
        // "api" prefix check matches by `starts_with`, so /api-x is rejected too.
        assert!(validate_entry_path("/api-x").is_err());
        assert!(validate_entry_path("/assets/logo.png").is_err());
        assert!(validate_entry_path("/a b").is_err());
        assert!(validate_entry_path("/a?b").is_err());
        assert!(validate_entry_path("/a#b").is_err());
    }

    #[test]
    fn marker_roundtrip_with_same_key_is_valid() {
        let key = test_key();
        let now = SystemTime::now();
        let marker = plant_marker(&key, now);
        assert!(marker_valid(&marker, &key, now));
    }

    #[test]
    fn marker_with_different_key_fails() {
        let now = SystemTime::now();
        let marker = plant_marker(b"key-one", now);
        assert!(!marker_valid(&marker, b"key-two", now));
    }

    #[test]
    fn tampered_expiry_fails() {
        let key = test_key();
        let now = SystemTime::now();
        let marker = plant_marker(&key, now);
        let (payload, tag) = marker.rsplit_once('.').expect("planted marker has a dot");
        let shifted: u64 = payload.parse::<u64>().expect("payload is numeric") + 1;
        let tampered = format!("{shifted}.{tag}");
        assert_ne!(tampered, marker);
        assert!(!marker_valid(&tampered, &key, now));
    }

    #[test]
    fn expired_marker_fails() {
        let key = test_key();
        let now = SystemTime::now();
        let marker = plant_marker(&key, now);
        // plant_marker stamps expiry = now + MARKER_TTL, so validating just
        // past the deadline (plus a 2s slack for second rounding) must fail.
        let late = now + MARKER_TTL + Duration::from_secs(2);
        assert!(!marker_valid(&marker, &key, late));
    }

    #[test]
    fn value_without_dot_fails() {
        let key = test_key();
        let now = SystemTime::now();
        assert!(!marker_valid("nodotvalue", &key, now));
    }

    #[test]
    fn non_numeric_payload_fails() {
        let key = test_key();
        let now = SystemTime::now();
        let marker = plant_marker(&key, now);
        let tag = marker.rsplit_once('.').expect("dot").1;
        let forged = format!("not-a-number.{tag}");
        assert!(!marker_valid(&forged, &key, now));
    }

    #[test]
    fn set_cookie_carries_security_attributes() {
        let cookie = marker_set_cookie("abc.xyz");
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains(&format!("Max-Age={}", MARKER_TTL.as_secs())));
    }

    #[test]
    fn clear_cookie_expires_immediately() {
        let cookie = marker_clear_cookie();
        assert!(cookie.ends_with("Max-Age=0"));
    }

    #[test]
    fn marker_present_accepts_valid_cookie() {
        let key = test_key();
        let marker = plant_marker(&key, SystemTime::now());
        let mut headers = HeaderMap::new();
        let raw = format!("gately_token=x; {MARKER_COOKIE}={marker}");
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&raw).expect("marker is header-safe"),
        );
        assert!(marker_present(&headers, &key));
    }

    #[test]
    fn marker_present_rejects_invalid_marker() {
        let key = test_key();
        let mut headers = HeaderMap::new();
        let raw = format!("{MARKER_COOKIE}=forged.badpayload");
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&raw).unwrap(),
        );
        assert!(!marker_present(&headers, &key));
    }

    #[test]
    fn marker_present_rejects_missing_cookie() {
        let key = test_key();
        let headers = HeaderMap::new();
        assert!(!marker_present(&headers, &key));
    }
}
