//! Management-entry access control: the deny decision, the five deny
//! modes and the custom-page sanitizer. Pure where possible; the HTTP
//! middleware at the bottom ties it into the router.

pub mod entry;
pub mod listener;

use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use fg_net::ClientAddr;
use schemars::JsonSchema;
use serde::Serialize;

/// Why a request was denied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    EntryNotPassed,
    Banned,
    LanOnly,
    Custom(&'static str),
}

/// How denials present to the client.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DenyMode {
    /// Entry misses get the minimal 404 page; LAN/ban gets plain 403.
    #[default]
    Default,
    /// A generic 404 resembling stock web servers, no product information.
    NotFound,
    Blank,
    /// No response at all: the connection closes immediately.
    Close,
    /// The connection is held silently until the client gives up.
    Drop,
    /// A sanitized operator-provided page with a fixed status code.
    Custom,
}

/// The access decision for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(DenyReason),
}

/// Entry settings resolved from the global settings snapshot.
#[derive(Clone, Debug)]
pub struct AccessConfig {
    /// The safe-entry path (starts with `/`); absent means no entry gate.
    pub safe_path: Option<String>,
    pub lan_only: bool,
    pub deny_mode: DenyMode,
    /// Only meaningful for `DenyMode::Custom`; one of the allowed statuses.
    pub deny_status: StatusCode,
    /// Sanitized custom page HTML (empty unless `DenyMode::Custom`).
    pub deny_page: String,
}

impl Default for AccessConfig {
    fn default() -> Self {
        Self {
            safe_path: None,
            lan_only: false,
            deny_mode: DenyMode::Default,
            deny_status: StatusCode::NOT_FOUND,
            deny_page: String::new(),
        }
    }
}

/// Decides one request. Ban takes precedence over everything; LAN-only
/// uses the resolved client address, never a raw forwarded header. The
/// safe-entry gate applies to the page and to credential-bearing paths.
pub fn decide(
    path: &str,
    addr: &ClientAddr,
    entry_passed: bool,
    banned: bool,
    cfg: &AccessConfig,
) -> Decision {
    if banned {
        return Decision::Deny(DenyReason::Banned);
    }
    if cfg.lan_only && !fg_net::client_addr::is_internal(addr.ip) {
        return Decision::Deny(DenyReason::LanOnly);
    }
    if let Some(safe_path) = &cfg.safe_path
        && !entry_passed
        // The entry path itself stays reachable: visiting it plants the
        // marker cookie.
        && path != safe_path
        && !path.starts_with(&format!("{safe_path}/"))
    {
        return Decision::Deny(DenyReason::EntryNotPassed);
    }
    Decision::Allow
}

/// Statuses the operator may pick for a custom deny page.
pub const CUSTOM_STATUSES: [StatusCode; 7] = [
    StatusCode::OK,
    StatusCode::FORBIDDEN,
    StatusCode::NOT_FOUND,
    StatusCode::GONE,
    StatusCode::INTERNAL_SERVER_ERROR,
    StatusCode::BAD_GATEWAY,
    StatusCode::SERVICE_UNAVAILABLE,
];

/// Largest accepted custom page.
pub const MAX_DENY_PAGE: usize = 64 * 1024;

/// Sandbox CSP for the operator page: inline styles only, data: images
/// and fonts, nothing else.
pub const DENY_PAGE_CSP: &str =
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; sandbox";

/// Removes active content from an operator-supplied page. Returns the
/// sanitized HTML plus the list of removals (for the settings response).
pub fn sanitize_deny_page(html: &str) -> Result<String, Vec<String>> {
    let mut removals = Vec::new();
    if html.len() > MAX_DENY_PAGE {
        removals.push(format!("页面超过 {} 字节上限", MAX_DENY_PAGE));
        return Err(removals);
    }
    let mut cleaned = html.to_owned();
    for (pattern, label) in [
        ("<script", "script 元素"),
        ("<iframe", "内嵌框架"),
        ("<form", "表单"),
        ("<base", "base 元素"),
        ("<meta http-equiv", "meta http-equiv"),
    ] {
        while let Some(start) = cleaned.to_lowercase().find(pattern) {
            let Some(end_rel) = cleaned[start..].find('>') else {
                break;
            };
            let end = start + end_rel + 1;
            cleaned.replace_range(start..end, "");
            removals.push(label.to_owned());
        }
    }
    // Event handlers on*="…" / on*='…'
    let lower = cleaned.to_lowercase();
    let mut ranges = Vec::new();
    let mut search_from = 0usize;
    while let Some(position) = lower[search_from..].find(" on") {
        let at = search_from + position;
        let rest = &lower[at + 3..];
        let name_end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .unwrap_or(rest.len());
        if name_end > 0
            && rest[..name_end].chars().all(|c| c.is_ascii_lowercase())
            && rest[name_end..].starts_with('=')
        {
            let quote = rest[name_end + 1..].chars().next();
            if matches!(quote, Some('"') | Some('\'')) {
                let quote_char = quote.unwrap();
                let after_quote = at + 3 + name_end + 1 + 1;
                if let Some(close) = cleaned[after_quote..].find(quote_char) {
                    ranges.push(at..after_quote + close + 1);
                }
            }
        }
        search_from = at + 3;
    }
    for range in ranges.into_iter().rev() {
        cleaned.replace_range(range, "");
        removals.push("事件属性".to_owned());
    }
    // javascript: hrefs
    let lower = cleaned.to_lowercase();
    if lower.contains("javascript:") {
        removals.push("javascript: 链接".to_owned());
        let mut result = String::with_capacity(cleaned.len());
        let mut rest = cleaned.as_str();
        while let Some(found) = lower_offset(&rest.to_lowercase(), "javascript:") {
            // Remove the whole attribute value up to the next quote.
            let quote = rest[found..].chars().find(|c| *c == '"' || *c == '\'');
            match quote {
                Some(quote_char) => {
                    let value_start = found + rest[found..].find(quote_char).unwrap();
                    let close = rest[value_start + 1..]
                        .find(quote_char)
                        .map(|p| value_start + 1 + p);
                    match close {
                        Some(close) => {
                            result.push_str(&rest[..found]);
                            rest = &rest[close + 1..];
                        }
                        None => {
                            result.push_str(&rest[..found]);
                            rest = "";
                        }
                    }
                }
                None => {
                    result.push_str(&rest[..found]);
                    rest = &rest[found + "javascript:".len()..];
                }
            }
        }
        result.push_str(rest);
        cleaned = result;
    }
    if removals.is_empty() {
        Ok(cleaned)
    } else {
        Err(removals)
    }
}

fn lower_offset(lower: &str, needle: &str) -> Option<usize> {
    lower.find(needle)
}

/// Renders the denial response for a decided request (not used for
/// `Close`/`Drop`, which never reach HTTP).
pub fn render(reason: DenyReason, cfg: &AccessConfig) -> Response {
    let mut response = match cfg.deny_mode {
        DenyMode::Custom => {
            let body = if cfg.deny_page.is_empty() {
                " ".to_owned()
            } else {
                cfg.deny_page.clone()
            };
            (
                [
                    (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                    (header::CONTENT_SECURITY_POLICY, DENY_PAGE_CSP),
                ],
                body,
            )
                .into_response()
        }
        DenyMode::NotFound => (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            "<html>\r\n<head><title>404 Not Found</title></head>\r\n\
             <body>\r\n<center><h1>404 Not Found</h1></center>\r\n\
             <hr><center>web server</center>\r\n</body>\r\n</html>\r\n",
        )
            .into_response(),
        DenyMode::Blank => (HeaderMap::new(), String::new()).into_response(),
        DenyMode::Default => match reason {
            DenyReason::EntryNotPassed => (
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                "<!DOCTYPE html><html><head><title>404 Not Found</title>\
                 <meta name=\"robots\" content=\"noindex\"></head>\
                 <body><h1>404 Not Found</h1></body></html>",
            )
                .into_response(),
            _ => (
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                "403 Forbidden".to_owned(),
            )
                .into_response(),
        },
        // Close/Drop never reach the HTTP layer; fall back to plain 403.
        DenyMode::Close | DenyMode::Drop => (
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "403 Forbidden".to_owned(),
        )
            .into_response(),
    };
    let status = match cfg.deny_mode {
        DenyMode::Custom => cfg.deny_status,
        // The stealth mode answers every denial with the same generic 404.
        DenyMode::NotFound => StatusCode::NOT_FOUND,
        _ => match reason {
            DenyReason::EntryNotPassed => StatusCode::NOT_FOUND,
            _ => StatusCode::FORBIDDEN,
        },
    };
    *response.status_mut() = status;
    {
        let headers = response.headers_mut();
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        headers.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("same-origin"),
        );
        if headers.get("x-frame-options").is_none() {
            headers.insert(
                header::HeaderName::from_static("x-frame-options"),
                HeaderValue::from_static("DENY"),
            );
        }
    }
    response
}

/// Per-router state for the guard middleware: the access settings plus
/// the marker-signing key (derived from the account file).
#[derive(Clone)]
pub struct GuardConfig(pub AccessConfig, pub Arc<Vec<u8>>);

/// Axum middleware applying `decide` and rendering denials. Close/Drop
/// still render an HTTP denial here when they reach this layer (they are
/// also handled at accept time when only the peer address is needed).
pub async fn guard(State(config): State<GuardConfig>, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let peer = request.extensions().get::<SocketAddr>().copied();
    let client = request
        .extensions()
        .get::<ClientAddr>()
        .cloned()
        .unwrap_or_else(|| ClientAddr {
            ip: peer.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap()).ip(),
            via: None,
            verified: false,
        });
    let passed = crate::access::entry::marker_present(request.headers(), &config.1);
    let banned = false; // ban-list integration arrives with WP-26/WP-50
    // Visiting the entry path itself plants the signed marker cookie so
    // the next request passes the gate.
    let plant = passed || decide(&path, &client, passed, banned, &config.0) == Decision::Allow;
    let plant = plant
        && config
            .0
            .safe_path
            .as_deref()
            .is_some_and(|safe| path == safe || path.starts_with(&format!("{safe}/")));
    match decide(&path, &client, passed, banned, &config.0) {
        Decision::Allow => {
            let mut response = next.run(request).await;
            if plant {
                let marker =
                    crate::access::entry::plant_marker(&config.1, std::time::SystemTime::now());
                if let Ok(value) =
                    HeaderValue::from_str(&crate::access::entry::marker_set_cookie(&marker))
                {
                    response.headers_mut().append(header::SET_COOKIE, value);
                }
            }
            response
        }
        Decision::Deny(reason) => {
            if matches!(config.0.deny_mode, DenyMode::Close | DenyMode::Drop)
                && matches!(reason, DenyReason::LanOnly | DenyReason::Banned)
            {
                // Determinable from the peer alone: refuse without an HTTP
                // response (the accept layer normally caught this first).
                return Response::new(Body::empty());
            }
            render(reason, &config.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> AccessConfig {
        AccessConfig::default()
    }

    #[test]
    fn banned_wins_over_everything() {
        let mut config = cfg();
        config.lan_only = false;
        let client = ClientAddr {
            ip: "127.0.0.1".parse().unwrap(),
            via: None,
            verified: false,
        };
        assert_eq!(
            decide("/api/session", &client, true, true, &config),
            Decision::Deny(DenyReason::Banned)
        );
    }

    #[test]
    fn lan_only_uses_resolved_client_address() {
        let mut config = cfg();
        config.lan_only = true;
        let lan = ClientAddr {
            ip: "192.168.1.10".parse().unwrap(),
            via: Some("127.0.0.1:1".parse().unwrap()),
            verified: true,
        };
        let outsider = ClientAddr {
            ip: "203.0.113.9".parse().unwrap(),
            via: None,
            verified: false,
        };
        assert_eq!(
            decide("/api/session", &lan, true, false, &config),
            Decision::Allow
        );
        assert_eq!(
            decide("/api/session", &outsider, true, false, &config),
            Decision::Deny(DenyReason::LanOnly)
        );
    }

    #[test]
    fn entry_gate_allows_only_the_entry_path_until_passed() {
        let mut config = cfg();
        config.safe_path = Some("/hidden-entry".to_owned());
        let client = ClientAddr {
            ip: "203.0.113.9".parse().unwrap(),
            via: None,
            verified: false,
        };
        assert_eq!(
            decide("/", &client, false, false, &config),
            Decision::Deny(DenyReason::EntryNotPassed)
        );
        assert_eq!(
            decide("/api/login", &client, false, false, &config),
            Decision::Deny(DenyReason::EntryNotPassed)
        );
        // Visiting the entry path is what plants the marker.
        assert_eq!(
            decide("/hidden-entry", &client, false, false, &config),
            Decision::Allow
        );
        assert_eq!(decide("/", &client, true, false, &config), Decision::Allow);
    }

    #[test]
    fn sanitize_removes_active_content_and_reports() {
        let dirty = "<p onclick=\"evil()\">hi</p><script>alert(1)</script>\
                     <a href=\"javascript:alert(2)\">x</a>\
                     <iframe src=\"//evil\"></iframe><form action=\"/steal\"></form>\
                     <base href=\"//evil/\"><meta http-equiv=\"refresh\" content=\"0\">ok";
        let removals = sanitize_deny_page(dirty).unwrap_err();
        assert!(removals.iter().any(|r| r == "script 元素"), "{removals:?}");
        assert!(removals.iter().any(|r| r == "事件属性"), "{removals:?}");
        assert!(
            removals.iter().any(|r| r == "javascript: 链接"),
            "{removals:?}"
        );
        assert!(removals.iter().any(|r| r == "内嵌框架"), "{removals:?}");
        let clean = sanitize_deny_page("<p style=\"color:red\">欢迎</p>").unwrap();
        assert_eq!(clean, "<p style=\"color:red\">欢迎</p>");
        assert!(sanitize_deny_page(&"x".repeat(MAX_DENY_PAGE + 1)).is_err());
    }

    #[test]
    fn custom_mode_uses_operator_status_and_sandbox_csp() {
        let mut config = cfg();
        config.deny_mode = DenyMode::Custom;
        config.deny_status = StatusCode::GONE;
        config.deny_page = "<p>gone</p>".to_owned();
        let response = render(DenyReason::LanOnly, &config);
        assert_eq!(response.status(), StatusCode::GONE);
        assert!(
            response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("sandbox")
        );
        // Default mode keeps 403 for LAN/ban and 404 for entry misses.
        let mut config = cfg();
        config.deny_mode = DenyMode::NotFound;
        assert_eq!(
            render(DenyReason::EntryNotPassed, &config).status(),
            StatusCode::NOT_FOUND
        );
        // The stealth mode 404s every denial, whatever the reason.
        assert_eq!(
            render(DenyReason::LanOnly, &config).status(),
            StatusCode::NOT_FOUND
        );
    }
}
