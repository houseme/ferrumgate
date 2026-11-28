//! Temporary share links (WP-26): `任意路径?_gs=token` exchanges for a
//! no-login cookie; the session lives at most 24h and never past the
//! link's expiry. Invalid tokens read as a normal visit — the failure
//! never leaks. Visitors admitted this way are NOT authenticated.
#![allow(dead_code)]

use std::time::{Duration, SystemTime};

/// The query parameter carrying the share token.
pub const TOKEN_PARAM: &str = "_gs";
/// The share session cap (§3.4: 会话 24 小时).
pub const SESSION_TTL: Duration = Duration::from_secs(24 * 3600);
/// The token floor (§3.4: 至少 16 位).
pub const MIN_TOKEN_LEN: usize = 16;

#[derive(Clone, Debug)]
pub struct ShareLink {
    pub key: String,
    /// Generated on save, at least 16 characters.
    pub token: String,
    pub expires_at: Option<SystemTime>,
    /// 0 = unlimited (the counter resets on restart).
    pub max_uses: u32,
    /// Non-empty restricts the session to this prefix.
    pub path_prefix: String,
}

pub fn valid(link: &ShareLink, token: &str, now: SystemTime) -> bool {
    if token.len() < MIN_TOKEN_LEN || token != link.token {
        return false;
    }
    match link.expires_at {
        Some(expires_at) => expires_at > now,
        None => true,
    }
}

/// The session expiry for a link admitted at `now`: SESSION_TTL capped
/// by the link's own expiry.
pub fn session_expiry(link: &ShareLink, now: SystemTime) -> SystemTime {
    match link.expires_at {
        Some(expires_at) => {
            let cap = now + SESSION_TTL;
            if expires_at < cap { expires_at } else { cap }
        }
        None => now + SESSION_TTL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn link(token: &str, expires_at: Option<SystemTime>) -> ShareLink {
        ShareLink {
            key: "l".to_owned(),
            token: token.to_owned(),
            expires_at,
            max_uses: 0,
            path_prefix: String::new(),
        }
    }

    #[test]
    fn token_must_match_and_be_long_enough() {
        let now = SystemTime::UNIX_EPOCH;
        let share = link("0123456789abcdef", None);
        assert!(valid(&share, "0123456789abcdef", now));
        assert!(!valid(&share, "short", now), "below the token floor");
        assert!(!valid(&share, "0123456789abcdeg", now), "wrong token");
        // A valid-looking token never validates against the wrong link.
        assert!(!valid(&share, "0123456789abcdefg", now));
    }

    #[test]
    fn expired_links_are_invalid() {
        let now = SystemTime::UNIX_EPOCH;
        let expired = link("0123456789abcdef", Some(now - Duration::from_secs(1)));
        assert!(!valid(&expired, "0123456789abcdef", now));
        let live = link("0123456789abcdef", Some(now + Duration::from_secs(3600)));
        assert!(valid(&live, "0123456789abcdef", now));
    }

    #[test]
    fn session_expiry_is_capped_by_the_link() {
        let now = SystemTime::UNIX_EPOCH;
        let unlimited = link("0123456789abcdef", None);
        assert_eq!(session_expiry(&unlimited, now), now + SESSION_TTL);
        let short = link("0123456789abcdef", Some(now + Duration::from_secs(3600)));
        assert_eq!(session_expiry(&short, now), now + Duration::from_secs(3600));
    }
}
