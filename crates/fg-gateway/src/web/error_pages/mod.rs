//! Error pages subsystem (WP-27): 10 built-in themes, custom HTML page
//! library with sanitization + sandbox CSP, browser HTML detection, default
//! site fallback for unknown hosts, and backend error interception.

pub mod builtin;
pub mod custom;
pub mod sanitize;

use std::time::SystemTime;

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::Response,
};
use serde::{Deserialize, Serialize};

pub use builtin::{
    ErrorCtx, Lang, StyleId, StyleInfo, builtin_template, escape_html, format_utc_rfc3339, render,
    render_builtin,
};
pub use custom::{
    CustomPageView, ErrorPageStore, MAX_CUSTOM_PAGES, Source, StoreError, mount_error_page_routes,
};
pub use sanitize::{
    ERROR_PAGE_CSP, MAX_CUSTOM_PAGE_BYTES, PLACEHOLDERS, Sanitized, sanitize, sanitize_bytes,
};

/// Maximum number of status code tokens allowed in an intercept specification.
pub const MAX_INTERCEPT_TOKENS: usize = 50;

/// One status-code match token in a site's backend error interception config
/// (WP-27 §3.2): single code (`404`), inclusive range (`500-599`), or class
/// shorthand (`4xx`, `5xx`). Restricted to `400..=599`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StatusSpec {
    Code(u16),
    Range(u16, u16),
    Class(u8),
}

impl StatusSpec {
    /// Parses a comma-separated list of status specs (e.g. `"404, 500-599, 5xx"`).
    ///
    /// Enforces `400..=599` bounds and at most [`MAX_INTERCEPT_TOKENS`] tokens.
    pub fn parse_list(input: &str) -> Result<Vec<Self>, String> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(Vec::new());
        }
        let mut specs = Vec::new();
        for raw in trimmed.split(',') {
            let tok = raw.trim();
            if tok.is_empty() {
                return Err("empty status code token in intercept list".to_owned());
            }
            specs.push(Self::parse_one(tok)?);
            if specs.len() > MAX_INTERCEPT_TOKENS {
                return Err(format!(
                    "intercept status list exceeds maximum {MAX_INTERCEPT_TOKENS} tokens"
                ));
            }
        }
        Ok(specs)
    }

    /// Parses one status spec token (`404`, `500-599`, `4xx`, or `5xx`).
    pub fn parse_one(token: &str) -> Result<Self, String> {
        let tok = token.trim().to_ascii_lowercase();
        if let Some(prefix) = tok.strip_suffix("xx") {
            if prefix.len() == 1 {
                let digit = prefix.as_bytes()[0];
                if digit == b'4' || digit == b'5' {
                    return Ok(Self::Class(digit - b'0'));
                }
            }
            return Err(format!(
                "invalid status class '{token}': only 4xx and 5xx are allowed"
            ));
        }
        if let Some((lo_s, hi_s)) = tok.split_once('-') {
            let lo: u16 = lo_s
                .trim()
                .parse()
                .map_err(|_| format!("invalid status range start in '{token}'"))?;
            let hi: u16 = hi_s
                .trim()
                .parse()
                .map_err(|_| format!("invalid status range end in '{token}'"))?;
            if !(400..=599).contains(&lo) || !(400..=599).contains(&hi) || lo > hi {
                return Err(format!(
                    "status range '{token}' must satisfy 400 <= start <= end <= 599"
                ));
            }
            return Ok(Self::Range(lo, hi));
        }
        let code: u16 = tok
            .parse()
            .map_err(|_| format!("invalid status code '{token}'"))?;
        if !(400..=599).contains(&code) {
            return Err(format!("status code {code} out of allowed range 400..=599"));
        }
        Ok(Self::Code(code))
    }

    /// Returns `true` if `code` matches this spec.
    pub fn matches(self, code: u16) -> bool {
        match self {
            Self::Code(c) => code == c,
            Self::Range(lo, hi) => (lo..=hi).contains(&code),
            Self::Class(cls) => code / 100 == u16::from(cls),
        }
    }
}

/// Site-level error page configuration (WP-27 §3.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ErrorPageOptions {
    pub style: StyleId,
    /// Optional custom page library key; falls back to `style` when missing or
    /// unavailable.
    pub custom: Option<String>,
    /// Backend error statuses to intercept (reverse-proxy sites only).
    pub intercept: Vec<StatusSpec>,
}

/// Returns `true` if the client explicitly accepts `text/html` (browser
/// navigation). Clients such as `curl` sending `*/*` or JSON API callers
/// sending `application/json` return `false`.
pub fn accepts_html(headers: &HeaderMap) -> bool {
    for val in headers.get_all(header::ACCEPT) {
        let Ok(raw) = val.to_str() else {
            continue;
        };
        for item in raw.split(',') {
            let mut parts = item.split(';');
            let media = parts.next().unwrap_or("").trim();
            if !media.eq_ignore_ascii_case("text/html") {
                continue;
            }
            let mut rejected = false;
            for param in parts {
                if let Some((k, v)) = param.trim().split_once('=')
                    && k.trim().eq_ignore_ascii_case("q")
                    && v.trim().parse::<f32>().ok() == Some(0.0)
                {
                    rejected = true;
                }
            }
            if !rejected {
                return true;
            }
        }
    }
    false
}

/// Request context required when rendering or intercepting an error page.
#[derive(Clone, Copy, Debug)]
pub struct RequestMeta<'a> {
    pub method: &'a Method,
    pub headers: &'a HeaderMap,
    pub host: &'a str,
    pub path: &'a str,
    pub now: SystemTime,
}

/// Renders a gateway-generated error response (e.g. 404, 502, 503, or unknown
/// host falling back to the default site's error page options).
///
/// - Browsers (`Accept` containing `text/html`) receive the configured custom
///   page (falling back to the built-in style when unavailable) with the
///   sandbox [`ERROR_PAGE_CSP`] header.
/// - Non-browser clients receive plain text (`"{code} {reason}\n"`).
/// - `HEAD` requests return response headers with an empty body.
pub fn render_error_response(
    opts: &ErrorPageOptions,
    store: Option<&ErrorPageStore>,
    req: &RequestMeta<'_>,
    status: StatusCode,
) -> Response {
    let is_head = req.method == Method::HEAD;

    if !accepts_html(req.headers) {
        let reason = status.canonical_reason().unwrap_or("Error");
        let text = format!("{} {reason}\n", status.as_u16());
        let mut resp = Response::new(if is_head {
            Body::empty()
        } else {
            Body::from(text.clone())
        });
        *resp.status_mut() = status;
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        resp.headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from(text.len()));
        return resp;
    }

    let lang = Lang::from_accept_language(req.headers.get(header::ACCEPT_LANGUAGE));
    let ctx = ErrorCtx::new(status, req.host, req.path, lang, req.now);
    let html = opts
        .custom
        .as_deref()
        .and_then(|key| store.and_then(|s| s.resolve_html(key)))
        .map(|tpl| render(&tpl, &ctx))
        .unwrap_or_else(|| render_builtin(opts.style, &ctx));

    let len = html.len();
    let mut resp = Response::new(if is_head {
        Body::empty()
    } else {
        Body::from(html)
    });
    *resp.status_mut() = status;
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(ERROR_PAGE_CSP),
    );
    resp
}

/// Decides whether a backend error status should be replaced with the site's
/// error page.
pub fn should_intercept(
    opts: &ErrorPageOptions,
    req_headers: &HeaderMap,
    backend_status: StatusCode,
) -> bool {
    if opts.intercept.is_empty() || !accepts_html(req_headers) {
        return false;
    }
    let code = backend_status.as_u16();
    opts.intercept.iter().any(|spec| spec.matches(code))
}

/// Headers that describe the original backend response body and must be
/// stripped when replacing that body with a rendered error page.
fn is_body_describing_header(name: &header::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "content-type"
            | "content-length"
            | "content-encoding"
            | "content-md5"
            | "content-range"
            | "content-disposition"
            | "etag"
            | "last-modified"
            | "transfer-encoding"
            | "content-security-policy"
            | "content-security-policy-report-only"
    )
}

/// Intercepts a backend error response for a reverse-proxy site when
/// `backend_status` matches `opts.intercept` and the visitor accepts HTML.
///
/// Returns `None` when the backend response should pass through untouched
/// (e.g. non-HTML / JSON / API clients or non-matching status codes).
/// When intercepting:
/// - Preserves backend status code and non-body headers such as `Set-Cookie`
///   and `Retry-After` (including multi-valued headers).
/// - Strips body-describing headers (`Content-Encoding`, `ETag`,
///   `Content-Length`, `Content-Type`, etc.).
/// - Returns headers only (empty body) for `HEAD` requests.
pub fn intercept_backend_error(
    opts: &ErrorPageOptions,
    store: Option<&ErrorPageStore>,
    req: &RequestMeta<'_>,
    backend_status: StatusCode,
    backend_headers: &HeaderMap,
) -> Option<Response> {
    if !should_intercept(opts, req.headers, backend_status) {
        return None;
    }

    let mut resp = render_error_response(opts, store, req, backend_status);

    let out_headers = resp.headers_mut();
    for (name, value) in backend_headers {
        if !is_body_describing_header(name) {
            out_headers.append(name.clone(), value.clone());
        }
    }

    Some(resp)
}

/// Resolves error page options for an incoming host, falling back to the
/// default site's options (even when the default site is disabled) when no
/// host matches (WP-27 §3.3).
pub fn resolve_error_page_options<'a>(
    matched_site: Option<&'a ErrorPageOptions>,
    default_site: Option<&'a ErrorPageOptions>,
) -> &'a ErrorPageOptions {
    static FALLBACK: ErrorPageOptions = ErrorPageOptions {
        style: StyleId::Minimal,
        custom: None,
        intercept: Vec::new(),
    };
    matched_site.or(default_site).unwrap_or(&FALLBACK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_spec_parses_code_range_class() {
        let specs = StatusSpec::parse_list("404, 500-599, 5xx, 4XX").unwrap();
        assert_eq!(
            specs,
            vec![
                StatusSpec::Code(404),
                StatusSpec::Range(500, 599),
                StatusSpec::Class(5),
                StatusSpec::Class(4),
            ]
        );
        assert!(specs[0].matches(404));
        assert!(!specs[0].matches(403));
        assert!(specs[1].matches(502));
        assert!(specs[2].matches(504));
        assert!(!specs[2].matches(404));
        assert!(specs[3].matches(429));

        // Out-of-range codes and invalid classes rejected.
        assert!(StatusSpec::parse_list("200").is_err());
        assert!(StatusSpec::parse_list("399").is_err());
        assert!(StatusSpec::parse_list("600").is_err());
        assert!(StatusSpec::parse_list("2xx").is_err());
        assert!(StatusSpec::parse_list("3xx").is_err());
        assert!(StatusSpec::parse_list("550-500").is_err());
        assert!(StatusSpec::parse_list("300-500").is_err());

        // Max 50 tokens enforced.
        let fifty = vec!["404"; 50].join(",");
        assert_eq!(StatusSpec::parse_list(&fifty).unwrap().len(), 50);
        let fifty_one = vec!["404"; 51].join(",");
        assert!(StatusSpec::parse_list(&fifty_one).is_err());
    }

    #[test]
    fn accepts_html_distinguishes_browser_and_curl() {
        let mut browser = HeaderMap::new();
        browser.insert(
            header::ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        assert!(accepts_html(&browser));

        let mut curl = HeaderMap::new();
        curl.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        assert!(!accepts_html(&curl));

        let mut json = HeaderMap::new();
        json.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        assert!(!accepts_html(&json));

        let mut refused = HeaderMap::new();
        refused.insert(header::ACCEPT, HeaderValue::from_static("text/html;q=0"));
        assert!(!accepts_html(&refused));
    }
}
