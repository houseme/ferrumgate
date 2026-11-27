//! Backend address lines: `http://host:port weight=3 backup` (WP-23
//! step 1). One target per line; credentials are allowed in the URI but
//! never shown — `display_url` strips them for logs, events and metrics.
#![allow(dead_code)]

use hyper::{Uri, header::HeaderValue};

/// Address parse failure, rendered in validate output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    Empty,
    InvalidUri(String),
    /// Only http/https origins: path must be "/" and query/fragment absent.
    NotOrigin(String),
    BadWeight(String),
    UnknownParam(String),
}

impl std::fmt::Display for TargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "后端地址为空"),
            Self::InvalidUri(text) => write!(f, "后端地址无效：{text}"),
            Self::NotOrigin(text) => write!(f, "后端地址必须是 http(s) 源地址：{text}"),
            Self::BadWeight(text) => write!(f, "weight 必须是 1..=100：{text}"),
            Self::UnknownParam(text) => write!(f, "未知参数：{text}"),
        }
    }
}

impl std::error::Error for TargetError {}

/// A backend address with its pool parameters.
#[derive(Clone, Debug)]
pub struct Target {
    /// HTTP(S) origin URI; userinfo may be present (stripped on display).
    pub uri: Uri,
    /// 1..=100, default 1.
    pub weight: u32,
    /// Backup backends only serve when every primary is unavailable.
    pub backup: bool,
}

/// Splits a validated authority into `host` (brackets kept for IPv6) and
/// its optional explicit port. Manual splitting because `Authority::port`
/// uses `rfind(':')`, which misreads a portless IPv6 host like `[::1]`.
/// Userinfo (`user:pass@`) is stripped here — it never reaches callers.
fn split_host_port(authority: &str) -> (&str, Option<u16>) {
    let host_port = match authority.rsplit_once('@') {
        Some((_userinfo, rest)) => rest,
        None => authority,
    };
    let (host, port_text) = match host_port.rfind(']') {
        // Bracketed IPv6: only a `:port` after the closing bracket counts.
        Some(close) => {
            let (host, rest) = host_port.split_at(close + 1);
            (host, rest.strip_prefix(':'))
        }
        None => match host_port.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (host_port, None),
        },
    };
    (host, port_text.and_then(|port| port.parse().ok()))
}

/// `host[:port]` of the target with any userinfo removed — the value for
/// `useTargetHost` (`Host` = 目标地址).
pub fn host_of(target: &Target) -> String {
    let authority = target.uri.authority().expect("validated authority");
    let text = authority.as_str();
    match text.rsplit_once('@') {
        Some((_userinfo, host)) => host.to_owned(),
        None => text.to_owned(),
    }
}

/// The `Host` header value sent to this backend (credentials stripped).
pub fn host_header(target: &Target) -> HeaderValue {
    HeaderValue::from_str(&host_of(target)).expect("validated authority")
}

/// Parses one address line: `URL [weight=N] [backup]`.
pub fn parse_target(line: &str) -> Result<Target, TargetError> {
    let line = line.trim();
    let mut parts = line.split_whitespace();
    let url_text = parts.next().ok_or(TargetError::Empty)?;
    let mut weight = 1u32;
    let mut weight_seen = false;
    let mut backup = false;
    for param in parts {
        if param == "backup" {
            backup = true;
            continue;
        }
        if let Some(value) = param.strip_prefix("weight=") {
            // Duplicate `weight=` is a config error, not a silent override.
            if weight_seen {
                return Err(TargetError::BadWeight(param.to_string()));
            }
            weight_seen = true;
            weight = value
                .parse::<u32>()
                .ok()
                .filter(|weight| (1..=100).contains(weight))
                .ok_or_else(|| TargetError::BadWeight(param.to_string()))?;
            continue;
        }
        return Err(TargetError::UnknownParam(param.to_string()));
    }
    // Fragments are rejected before parsing: the `http` crate reports them
    // as invalid characters, but semantically they make it a non-origin.
    if url_text.contains('#') {
        return Err(TargetError::NotOrigin(url_text.to_string()));
    }
    let uri: Uri = url_text
        .parse::<Uri>()
        .map_err(|error| TargetError::InvalidUri(format!("{url_text}: {error}")))?;
    let valid = matches!(uri.scheme_str(), Some("http" | "https"))
        && matches!(uri.path(), "/" | "")
        && uri.query().is_none();
    if !valid {
        return Err(TargetError::NotOrigin(url_text.to_string()));
    }
    if uri.authority().is_none() {
        return Err(TargetError::InvalidUri(format!("{url_text}: missing host")));
    }
    Ok(Target {
        uri,
        weight,
        backup,
    })
}

/// Parses every line, reporting the first failure.
pub fn parse_targets(lines: &[String]) -> Result<Vec<Target>, TargetError> {
    lines.iter().map(|line| parse_target(line)).collect()
}

/// Display address: scheme://host[:port] — userinfo, query and fragment
/// stripped (default ports 80/443 dropped). Used for logs, events and
/// Prometheus labels (query strings often carry tokens and Prometheus
/// text is never redacted).
pub fn display_url(target: &Target) -> String {
    let uri = &target.uri;
    let scheme = uri.scheme_str().unwrap_or("http");
    let authority = uri.authority().expect("validated authority");
    let (host, explicit_port) = split_host_port(authority.as_str());
    let port =
        explicit_port.unwrap_or(if scheme == "https" { 443 } else { 80 });
    let default = matches!((scheme, port), ("http", 80) | ("https", 443));
    if default {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(line: &str) -> Target {
        parse_target(line).expect("valid target line")
    }

    #[test]
    fn target_parses_weight_and_backup() {
        let parsed = target("http://10.0.0.2:8080 weight=3 backup");
        assert_eq!(parsed.uri, "http://10.0.0.2:8080");
        assert_eq!(parsed.weight, 3);
        assert!(parsed.backup);
        // Without parameters both default: weight 1, primary (not backup).
        let plain = target("https://backend.internal:8443");
        assert_eq!(plain.weight, 1);
        assert!(!plain.backup);
    }

    #[test]
    fn display_url_strips_credentials_and_query() {
        // A query string makes it a non-origin address, rejected outright.
        let query_error = parse_target("http://user:pass@host:8080/?token=x")
            .expect_err("query strings are rejected");
        assert_eq!(
            query_error,
            TargetError::NotOrigin("http://user:pass@host:8080/?token=x".to_string())
        );
        let credentialed = target("http://user:pass@host:8080/");
        assert_eq!(display_url(&credentialed), "http://host:8080");
        assert_eq!(host_of(&credentialed), "host:8080");
        assert_eq!(host_header(&credentialed), HeaderValue::from_static("host:8080"));
        // Default port 80 is omitted; https likewise hides 443.
        assert_eq!(display_url(&target("http://host/")), "http://host");
        assert_eq!(
            display_url(&target("https://user:pass@example.com:443/")),
            "https://example.com"
        );
        // Non-default ports survive, on either scheme.
        assert_eq!(
            display_url(&target("https://example.com:8443/")),
            "https://example.com:8443"
        );
        assert_eq!(
            display_url(&target("http://example.com:443/")),
            "http://example.com:443"
        );
    }

    #[test]
    fn rejects_invalid_target_lines() {
        let expect = |line: &str, error: TargetError| {
            assert_eq!(parse_target(line).expect_err("line rejected"), error);
        };
        expect("", TargetError::Empty);
        expect("   ", TargetError::Empty);
        expect("ftp://x", TargetError::NotOrigin("ftp://x".to_string()));
        expect(
            "http://x/y/z",
            TargetError::NotOrigin("http://x/y/z".to_string()),
        );
        expect(
            "http://x/#fragment",
            TargetError::NotOrigin("http://x/#fragment".to_string()),
        );
        expect(
            "http://x weight=0",
            TargetError::BadWeight("weight=0".to_string()),
        );
        expect(
            "http://x weight=101",
            TargetError::BadWeight("weight=101".to_string()),
        );
        expect(
            "http://x weight=abc",
            TargetError::BadWeight("weight=abc".to_string()),
        );
        expect(
            "http://x weight=2 weight=3",
            TargetError::BadWeight("weight=3".to_string()),
        );
        expect(
            "http://x foo=bar",
            TargetError::UnknownParam("foo=bar".to_string()),
        );
        assert!(matches!(
            parse_target("http://"),
            Err(TargetError::InvalidUri(_))
        ));
    }

    #[test]
    fn host_of_strips_userinfo() {
        let parsed = target("https://admin:secret@example.com:9000/");
        assert_eq!(host_of(&parsed), "example.com:9000");
        assert_eq!(
            host_header(&parsed),
            HeaderValue::from_static("example.com:9000")
        );
        // Userinfo without a password keeps the same stripping.
        let named = target("http://ops@example.com/");
        assert_eq!(host_of(&named), "example.com");
    }

    #[test]
    fn ipv6_target_parses_and_displays() {
        let with_port = target("http://[::1]:8080/");
        assert_eq!(host_of(&with_port), "[::1]:8080");
        assert_eq!(display_url(&with_port), "http://[::1]:8080");
        assert_eq!(
            host_header(&with_port),
            HeaderValue::from_static("[::1]:8080")
        );
        // Portless IPv6 must not grow a bogus port (the colon belongs to
        // the address itself).
        let no_port = target("http://[::1]/");
        assert_eq!(host_of(&no_port), "[::1]");
        assert_eq!(display_url(&no_port), "http://[::1]");
        // And the https default port is hidden behind brackets too.
        assert_eq!(
            display_url(&target("https://[2001:db8::1]:443/")),
            "https://[2001:db8::1]"
        );
    }

    #[test]
    fn parse_targets_preserves_order_and_propagates_errors() {
        let lines: Vec<String> = [
            "http://a:1/",
            "http://b:2 weight=5 backup",
            "https://c:3/",
        ]
        .iter()
        .map(|line| line.to_string())
        .collect();
        let parsed = parse_targets(&lines).expect("all lines valid");
        let urls: Vec<String> = parsed.iter().map(display_url).collect();
        assert_eq!(urls, ["http://a:1", "http://b:2", "https://c:3"]);
        assert_eq!(parsed[1].weight, 5);
        assert!(parsed[1].backup);
        // The first bad line surfaces unchanged; order of the rest is moot.
        let broken: Vec<String> = [
            "http://a:1/".to_string(),
            "http://b:2 foo=bar".to_string(),
            "nonsense".to_string(),
        ]
        .to_vec();
        let broken_error =
            parse_targets(&broken).expect_err("first bad line propagates");
        assert_eq!(
            broken_error,
            TargetError::UnknownParam("foo=bar".to_string())
        );
    }
}
