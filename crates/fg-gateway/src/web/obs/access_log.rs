//! Structured combined-style access log formatting and sanitization
//! (WP-28 §3.3 step 3).
//!
//! Guarantees:
//! - Visitor-controlled fields (`Referer`, `User-Agent`, path) have control
//!   characters (`\r`, `\n`, `\t`, `< 0x20`, `0x7f`) escaped and length
//!   truncated so untrusted headers cannot forge log lines.
//! - Authentication paths (`/__gately_auth/...`) always have their query
//!   string and fragment stripped before logging so tickets / OAuth codes
//!   never leak to logs.
//! - Entries carry `is_admin` and `is_banned` flags for WP-09 log filters
//!   (`hide_admin`, `hide_banned`).

use std::{
    fmt::Write as _,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use serde::{Deserialize, Serialize};

use super::recorder::DenyKind;

/// Maximum characters kept for the Referer header before truncation.
pub const MAX_REFERER_CHARS: usize = 512;
/// Maximum characters kept for the User-Agent header before truncation.
pub const MAX_USER_AGENT_CHARS: usize = 256;
/// Maximum characters kept for the logged request path.
pub const MAX_LOG_PATH_CHARS: usize = 1024;
/// Authentication endpoint prefix whose query string contains sensitive tokens.
pub const AUTH_PATH_PREFIX: &str = "/__gately_auth";

/// Callback invoked when a site with `accessLog` enabled completes a request.
pub type AccessLogSink = Arc<dyn Fn(AccessLogEntry) + Send + Sync>;

/// Filter flags provided to WP-09 (`fg-logging`) for access-log queries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessLogFilter {
    pub hide_admin: bool,
    pub hide_banned: bool,
}

impl AccessLogFilter {
    /// Returns true if `entry` should be visible under this filter.
    pub fn matches(&self, entry: &AccessLogEntry) -> bool {
        if self.hide_admin && entry.is_admin {
            return false;
        }
        if self.hide_banned && entry.is_banned {
            return false;
        }
        true
    }
}

/// Structured access log record for one completed HTTP request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessLogEntry {
    /// Listener log source tag (e.g. `listenerName#key`).
    pub source: String,
    pub client_ip: IpAddr,
    pub via: Option<SocketAddr>,
    pub host: String,
    pub method: String,
    /// Request path (query stripped for `/__gately_auth/...`, control chars
    /// escaped and truncated).
    pub path: String,
    pub proto: String,
    pub status: u16,
    pub bytes_out: u64,
    pub duration_ms: u64,
    pub deny: DenyKind,
    pub admin: Option<String>,
    pub identity: Option<String>,
    /// Escaped and truncated `Referer` header (`""` rendered as `"-"`).
    pub referer: String,
    /// Escaped and truncated `User-Agent` header (`""` rendered as `"-"`).
    pub user_agent: String,
    /// Tag for WP-09 `hide_admin` filtering.
    pub is_admin: bool,
    /// Tag for WP-09 `hide_banned` filtering.
    pub is_banned: bool,
}

impl AccessLogEntry {
    /// Formats a single-line log entry: structured fields followed by the
    /// nginx combined tail `"<referer>" "<user_agent>"`.
    pub fn format_line(&self) -> String {
        let mut line = String::with_capacity(256);
        let _ = write!(
            line,
            "source={} ip={}",
            escape_and_truncate(&self.source, 128),
            self.client_ip
        );
        if let Some(via) = self.via {
            let _ = write!(line, " via={via}");
        }
        let _ = write!(
            line,
            " host={} method={} path=\"{}\" proto={} status={} bytes={} ms={}",
            escape_and_truncate(&self.host, 255),
            escape_and_truncate(&self.method, 16),
            self.path,
            escape_and_truncate(&self.proto, 16),
            self.status,
            self.bytes_out,
            self.duration_ms
        );
        if self.deny.is_denied() {
            let _ = write!(line, " deny={}", self.deny.as_str());
        }
        if let Some(admin) = &self.admin {
            let _ = write!(line, " admin={}", escape_and_truncate(admin, 64));
        }
        if let Some(identity) = &self.identity {
            let _ = write!(line, " user={}", escape_and_truncate(identity, 64));
        }
        let referer = if self.referer.is_empty() {
            "-"
        } else {
            &self.referer
        };
        let ua = if self.user_agent.is_empty() {
            "-"
        } else {
            &self.user_agent
        };
        let _ = write!(line, " \"{referer}\" \"{ua}\"");
        line
    }
}

/// Sanitizes a request URI/path for access logging:
/// - Strips `?query` and `#fragment` whenever the path is `/__gately_auth` or
///   under `/__gately_auth/`.
/// - Escapes control characters and quotes, then truncates to
///   [`MAX_LOG_PATH_CHARS`].
pub fn sanitize_log_path(raw: &str) -> String {
    let path_only = raw.split(['?', '#']).next().unwrap_or(raw);
    let effective = if is_auth_path(path_only) {
        path_only
    } else {
        raw.split('#').next().unwrap_or(raw)
    };
    escape_and_truncate(effective, MAX_LOG_PATH_CHARS)
}

/// Returns true if `path` is an internal Gately/FerrumGate auth endpoint.
pub fn is_auth_path(path: &str) -> bool {
    path == AUTH_PATH_PREFIX || path.starts_with("/__gately_auth/")
}

/// Escapes ASCII control characters (`< 0x20`, `0x7f`), backslashes, and
/// double quotes, truncating input to at most `max_chars` Unicode scalar values
/// before escaping.
pub fn escape_and_truncate(input: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(input.len().min(max_chars));
    for (idx, ch) in input.chars().enumerate() {
        if idx >= max_chars {
            break;
        }
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\r' => out.push_str("\\x0d"),
            '\n' => out.push_str("\\x0a"),
            '\t' => out.push_str("\\x09"),
            c if (c as u32) < 0x20 || c == '\x7f' => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            // Strip Unicode line/paragraph separators as well so logs remain strictly single-line.
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out
}

/// Helper to construct a sanitized [`AccessLogEntry`] from raw request fields.
#[allow(clippy::too_many_arguments)]
pub fn build_entry(
    source: impl Into<String>,
    client_ip: IpAddr,
    via: Option<SocketAddr>,
    host: &str,
    method: &str,
    raw_path: &str,
    proto: &str,
    status: u16,
    bytes_out: u64,
    duration_ms: u64,
    deny: DenyKind,
    admin: Option<String>,
    identity: Option<String>,
    referer: Option<&str>,
    user_agent: Option<&str>,
) -> AccessLogEntry {
    let is_admin = admin.is_some();
    let is_banned = matches!(deny, DenyKind::Ban);
    AccessLogEntry {
        source: source.into(),
        client_ip,
        via,
        host: escape_and_truncate(host, 255),
        method: escape_and_truncate(method, 16),
        path: sanitize_log_path(raw_path),
        proto: escape_and_truncate(proto, 16),
        status,
        bytes_out,
        duration_ms,
        deny,
        admin,
        identity,
        referer: referer
            .map(|r| escape_and_truncate(r, MAX_REFERER_CHARS))
            .unwrap_or_default(),
        user_agent: user_agent
            .map(|ua| escape_and_truncate(ua, MAX_USER_AGENT_CHARS))
            .unwrap_or_default(),
        is_admin,
        is_banned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn sanitize_strips_auth_query_only() {
        assert_eq!(
            sanitize_log_path("/__gately_auth/callback?code=secret123&state=xyz"),
            "/__gately_auth/callback"
        );
        assert_eq!(
            sanitize_log_path("/__gately_auth?ticket=abc"),
            "/__gately_auth"
        );
        assert_eq!(
            sanitize_log_path("/app/search?q=rust"),
            "/app/search?q=rust"
        );
    }

    #[test]
    fn escape_prevents_log_injection_and_truncates() {
        let evil = format!("Mozilla/5.0\r\nFAKE LINE \"injected\" {}", "x".repeat(400));
        let escaped = escape_and_truncate(&evil, MAX_USER_AGENT_CHARS);
        assert!(!escaped.contains('\n'));
        assert!(!escaped.contains('\r'));
        assert!(escaped.contains("\\x0d\\x0a"));
        assert!(escaped.contains("\\\"injected\\\""));
        assert!(escaped.len() < 300);
    }

    #[test]
    fn filter_hides_admin_and_banned() {
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let admin_entry = build_entry(
            "main#1",
            ip,
            None,
            "a.test",
            "GET",
            "/",
            "h2",
            200,
            10,
            1,
            DenyKind::None,
            Some("root".into()),
            None,
            None,
            None,
        );
        let ban_entry = build_entry(
            "main#1",
            ip,
            None,
            "a.test",
            "GET",
            "/",
            "h1",
            403,
            0,
            1,
            DenyKind::Ban,
            None,
            None,
            None,
            None,
        );
        let f_admin = AccessLogFilter {
            hide_admin: true,
            hide_banned: false,
        };
        assert!(!f_admin.matches(&admin_entry));
        assert!(f_admin.matches(&ban_entry));

        let f_ban = AccessLogFilter {
            hide_admin: false,
            hide_banned: true,
        };
        assert!(f_ban.matches(&admin_entry));
        assert!(!f_ban.matches(&ban_entry));
    }
}
