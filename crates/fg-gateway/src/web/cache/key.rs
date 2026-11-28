//! Cache key construction, request/response cacheability predicates, and
//! freshness computation (WP-27 §3.3).

use std::time::{Duration, SystemTime};

use axum::http::{HeaderMap, Method, StatusCode, Uri, header};

use crate::web::auth::session;

use super::rule::{CacheRule, MAX_CACHE_TTL};

/// Twelve credential-bearing request headers (case-insensitive) that disable
/// caching. `cookie` is handled separately for the FerrumGate login-cookie
/// exception.
pub const CREDENTIAL_HEADERS: [&str; 12] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-emby-token",
    "x-emby-authorization",
    "x-mediabrowser-token",
    "x-plex-token",
    "x-jellyfin-token",
];

/// Four credential-bearing query parameter names (case-insensitive) that
/// disable caching.
pub const CREDENTIAL_QUERY_PARAMS: [&str; 4] = ["api_key", "x-plex-token", "token", "access_token"];

/// Cache lookup key separating responses by host, full URI, `Accept-Encoding`,
/// selected user route, and outgoing identity headers.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub host: String,
    pub uri: String,
    pub accept_encoding: String,
    pub user_route: Option<String>,
    pub identity_headers: Vec<(String, String)>,
}

impl CacheKey {
    /// Builds a canonical [`CacheKey`]: lowercases host and identity header
    /// names, and sorts identity headers deterministically.
    pub fn new(
        host: impl AsRef<str>,
        uri: impl AsRef<str>,
        accept_encoding: impl AsRef<str>,
        user_route: Option<String>,
        mut identity_headers: Vec<(String, String)>,
    ) -> Self {
        for (name, _) in &mut identity_headers {
            *name = name.to_ascii_lowercase();
        }
        identity_headers.sort();
        Self {
            host: host.as_ref().to_ascii_lowercase(),
            uri: uri.as_ref().to_owned(),
            accept_encoding: accept_encoding.as_ref().trim().to_ascii_lowercase(),
            user_route,
            identity_headers,
        }
    }

    /// Returns the path component of `uri` (without query string).
    pub fn path(&self) -> &str {
        self.uri.split('?').next().unwrap_or("/")
    }
}

/// Policy for checking FerrumGate's own login cookies when evaluating whether
/// a request's `Cookie` header carries backend credentials.
pub struct OwnCookiePolicy<'a> {
    /// When `true`, FerrumGate forwards `gately_sso`, `gately_site_*`, and
    /// `gately_oauth_nonce` to the backend, so they count as credentials.
    /// `gately_admin` is always exempt.
    pub pass_auth_cookies: bool,
    /// Signing secret used by this instance to verify `gately_sso` and
    /// `gately_site_*` cookies via [`session::verify`].
    pub auth_secret: Option<&'a [u8]>,
    /// Request host used when verifying session cookie scope.
    pub host: &'a str,
    /// Current wall clock used when verifying session cookie expiry.
    pub now: SystemTime,
    /// Optional verifier for `gately_admin` cookie values. When `None`, any
    /// non-empty `gately_admin` value is treated as valid.
    pub verify_admin: Option<&'a dyn Fn(&str) -> bool>,
    /// Optional verifier for `gately_oauth_nonce` cookie values. When `None`,
    /// any non-empty value is treated as valid.
    pub verify_oauth_nonce: Option<&'a dyn Fn(&str) -> bool>,
}

impl Default for OwnCookiePolicy<'static> {
    fn default() -> Self {
        Self {
            pass_auth_cookies: false,
            auth_secret: None,
            host: "",
            now: SystemTime::UNIX_EPOCH,
            verify_admin: None,
            verify_oauth_nonce: None,
        }
    }
}

/// Checks if the raw request path (before normalization) contains special bytes
/// (`;`, `\`, `%2F`, `%5C`, case-insensitive) that may be interpreted
/// differently by the backend after normalization.
pub fn has_special_path_bytes(raw_path: &str) -> bool {
    if raw_path.contains(';') || raw_path.contains('\\') {
        return true;
    }
    let lower = raw_path.to_ascii_lowercase();
    lower.contains("%2f") || lower.contains("%5c")
}

/// Returns `true` if `Cache-Control` headers contain a specific directive
/// (case-insensitive, ignoring optional `=value`).
fn has_cache_control_directive(headers: &HeaderMap, target: &str) -> bool {
    headers
        .get_all(header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .any(|dir| {
            let name = dir.split('=').next().unwrap_or("").trim();
            name.eq_ignore_ascii_case(target)
        })
}

/// Extracts a numeric `Cache-Control` directive value (e.g. `s-maxage=60`).
fn cache_control_seconds(headers: &HeaderMap, target: &str) -> Option<u64> {
    for val in headers.get_all(header::CACHE_CONTROL) {
        let Ok(s) = val.to_str() else {
            continue;
        };
        for dir in s.split(',') {
            if let Some((k, v)) = dir.split_once('=')
                && k.trim().eq_ignore_ascii_case(target)
            {
                let v = v.trim().trim_matches('"');
                if let Ok(secs) = v.parse::<u64>() {
                    return Some(secs);
                }
            }
        }
    }
    None
}

/// Checks whether a request's `Cookie` headers contain only exempt FerrumGate
/// login cookies under `policy`.
fn cookies_are_exempt(headers: &HeaderMap, policy: &OwnCookiePolicy<'_>) -> bool {
    for cookie_hdr in headers.get_all(header::COOKIE) {
        let Ok(raw) = cookie_hdr.to_str() else {
            return false;
        };
        for pair in raw.split(';') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            let Some((name, value)) = pair.split_once('=') else {
                return false;
            };
            let name = name.trim();
            let value = value.trim();
            if !is_own_exempt_cookie(name, value, policy) {
                return false;
            }
        }
    }
    true
}

fn is_own_exempt_cookie(name: &str, value: &str, policy: &OwnCookiePolicy<'_>) -> bool {
    if name == "gately_admin" {
        return match policy.verify_admin {
            Some(f) => f(value),
            None => !value.is_empty(),
        };
    }
    if policy.pass_auth_cookies {
        return false;
    }
    if name == "gately_sso" || name.starts_with("gately_site_") {
        let Some(secret) = policy.auth_secret else {
            return false;
        };
        return session::verify(secret, value, policy.host, policy.now).is_some();
    }
    if name == "gately_oauth_nonce" {
        return match policy.verify_oauth_nonce {
            Some(f) => f(value),
            None => !value.is_empty(),
        };
    }
    false
}

/// Checks if the request query string carries any of the 4 credential query
/// parameter names (case-insensitive).
fn has_credential_query_param(query: Option<&str>) -> bool {
    let Some(q) = query else {
        return false;
    };
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let raw_key = pair.split('=').next().unwrap_or("");
        let decoded = percent_encoding::percent_decode_str(raw_key).decode_utf8_lossy();
        if CREDENTIAL_QUERY_PARAMS
            .iter()
            .any(|cred| decoded.eq_ignore_ascii_case(cred))
        {
            return true;
        }
    }
    false
}

/// Evaluates whether an incoming HTTP request is eligible for cache lookup and
/// storage (WP-27 §3.3).
pub fn is_request_cacheable(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    cookie_policy: &OwnCookiePolicy<'_>,
) -> bool {
    if method != Method::GET {
        return false;
    }
    if headers.contains_key(header::RANGE) {
        return false;
    }
    if has_cache_control_directive(headers, "no-cache") {
        return false;
    }
    if has_special_path_bytes(uri.path()) {
        return false;
    }
    if has_credential_query_param(uri.query()) {
        return false;
    }
    for &hdr in &CREDENTIAL_HEADERS {
        if hdr == "cookie" {
            if headers.contains_key(header::COOKIE) && !cookies_are_exempt(headers, cookie_policy) {
                return false;
            }
        } else if headers.contains_key(hdr) {
            return false;
        }
    }
    true
}

/// Evaluates whether a backend HTTP response is eligible to be stored in the
/// response cache (WP-27 §3.3).
///
/// - Only `200 OK` is cacheable.
/// - `Set-Cookie`, `Vary: *`, and `Cache-Control: private` ALWAYS disqualify
///   the response, even when `override_cache == true`.
/// - `Cache-Control: no-store` and `no-cache` disqualify the response unless
///   `override_cache == true`.
/// - `Vary` may only list `Accept-Encoding` (and `Origin` when `cors_enabled`).
/// - Backend `Access-Control-Allow-Origin` other than `*` disqualifies caching.
pub fn is_response_cacheable(
    status: StatusCode,
    headers: &HeaderMap,
    cors_enabled: bool,
    override_cache: bool,
) -> bool {
    if status != StatusCode::OK {
        return false;
    }
    if headers.contains_key(header::SET_COOKIE) {
        return false;
    }
    if has_cache_control_directive(headers, "private") {
        return false;
    }
    if !override_cache
        && (has_cache_control_directive(headers, "no-store")
            || has_cache_control_directive(headers, "no-cache"))
    {
        return false;
    }

    // Validate Vary headers.
    for val in headers.get_all(header::VARY) {
        let Ok(s) = val.to_str() else {
            return false;
        };
        for tok in s.split(',') {
            let tok = tok.trim();
            if tok.is_empty() {
                continue;
            }
            if tok == "*" {
                return false;
            }
            let allowed = tok.eq_ignore_ascii_case("accept-encoding")
                || (cors_enabled && tok.eq_ignore_ascii_case("origin"));
            if !allowed {
                return false;
            }
        }
    }

    // Backend-sent Access-Control-Allow-Origin other than `*` cannot be shared.
    for val in headers.get_all(header::ACCESS_CONTROL_ALLOW_ORIGIN) {
        let Ok(s) = val.to_str() else {
            return false;
        };
        if s.trim() != "*" {
            return false;
        }
    }

    true
}

/// Returns `true` if the response headers include `Vary: Origin`.
pub fn response_varies_on_origin(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .any(|tok| tok.trim().eq_ignore_ascii_case("origin"))
}

/// Computes the cache lifetime for a cacheable 200 response.
///
/// Priority:
/// - If the matched rule has `no_cache`, returns `None`.
/// - If the matched rule has `override_`, ignores backend `s-maxage` /
///   `max-age` and uses the rule TTL (or site TTL if rule TTL is 0/None).
/// - Otherwise checks `s-maxage`, then `max-age`, then rule/site `ttl`.
///   A zero directive (`s-maxage=0` / `max-age=0`) or zero fallback TTL
///   returns `None`. Results are capped at 30 days.
pub fn compute_freshness(
    headers: &HeaderMap,
    site_ttl: Duration,
    rule: Option<&CacheRule>,
) -> Option<Duration> {
    if let Some(r) = rule
        && r.no_cache
    {
        return None;
    }

    let configured_ttl = match rule.and_then(|r| r.ttl).filter(|d| !d.is_zero()) {
        Some(rule_ttl) => rule_ttl,
        None => site_ttl,
    };

    if rule.is_some_and(|r| r.override_) {
        return (!configured_ttl.is_zero()).then(|| configured_ttl.min(MAX_CACHE_TTL));
    }

    if let Some(smax) = cache_control_seconds(headers, "s-maxage") {
        return (smax > 0).then(|| Duration::from_secs(smax).min(MAX_CACHE_TTL));
    }
    if let Some(max_age) = cache_control_seconds(headers, "max-age") {
        return (max_age > 0).then(|| Duration::from_secs(max_age).min(MAX_CACHE_TTL));
    }
    (!configured_ttl.is_zero()).then(|| configured_ttl.min(MAX_CACHE_TTL))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::auth::session::{Scope, cookie_name, issue};
    use axum::http::HeaderValue;
    use std::time::UNIX_EPOCH;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    fn hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }

    #[test]
    fn cache_request_must_be_get_without_range_or_no_cache() {
        let policy = OwnCookiePolicy::default();
        let empty = HeaderMap::new();

        assert!(is_request_cacheable(
            &Method::GET,
            &uri("/index.html"),
            &empty,
            &policy
        ));
        for method in [
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::HEAD,
            Method::OPTIONS,
        ] {
            assert!(
                !is_request_cacheable(&method, &uri("/index.html"), &empty, &policy),
                "method {method} must not be cacheable"
            );
        }

        let mut range = HeaderMap::new();
        range.insert(header::RANGE, hv("bytes=0-100"));
        assert!(!is_request_cacheable(
            &Method::GET,
            &uri("/file.bin"),
            &range,
            &policy
        ));

        let mut no_cache = HeaderMap::new();
        no_cache.insert(header::CACHE_CONTROL, hv("max-age=0, no-cache"));
        assert!(!is_request_cacheable(
            &Method::GET,
            &uri("/file.bin"),
            &no_cache,
            &policy
        ));
    }

    #[test]
    fn cache_request_with_credentials_not_cached() {
        let policy = OwnCookiePolicy::default();
        for &hdr in &CREDENTIAL_HEADERS {
            let mut h = HeaderMap::new();
            let val = if hdr == "cookie" {
                "session=abc"
            } else {
                "secret"
            };
            h.insert(
                axum::http::header::HeaderName::from_bytes(hdr.as_bytes()).unwrap(),
                hv(val),
            );
            assert!(
                !is_request_cacheable(&Method::GET, &uri("/data"), &h, &policy),
                "header {hdr} must disable caching"
            );
        }

        let empty = HeaderMap::new();
        for &param in &CREDENTIAL_QUERY_PARAMS {
            let u = uri(&format!("/data?foo=1&{param}=xyz"));
            assert!(
                !is_request_cacheable(&Method::GET, &u, &empty, &policy),
                "query param {param} must disable caching"
            );
            // Case-insensitive match.
            let upper = uri(&format!("/data?{}=xyz", param.to_ascii_uppercase()));
            assert!(
                !is_request_cacheable(&Method::GET, &upper, &empty, &policy),
                "uppercase query param {param} must disable caching"
            );
        }
    }

    #[test]
    fn cache_own_login_cookies_do_not_count_as_credentials() {
        let secret = b"instance-signing-secret";
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let host = "app.example.com";
        let site_cookie_name = cookie_name("web", "app");
        let site_val = issue(secret, "alice", host, Scope::Site, "fp", now);
        let sso_val = issue(
            secret,
            "alice",
            host,
            Scope::Sso("example.com".to_owned()),
            "fp",
            now,
        );

        let policy_no_pass = OwnCookiePolicy {
            pass_auth_cookies: false,
            auth_secret: Some(secret),
            host,
            now,
            verify_admin: None,
            verify_oauth_nonce: None,
        };

        // Valid gately_site_* + gately_sso + gately_admin + gately_oauth_nonce -> cacheable.
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            hv(&format!(
                "gately_admin=adm1; gately_sso={sso_val}; {site_cookie_name}={site_val}; gately_oauth_nonce=n1"
            )),
        );
        assert!(is_request_cacheable(
            &Method::GET,
            &uri("/dash"),
            &h,
            &policy_no_pass
        ));

        // Same cookie when pass_auth_cookies = true -> NOT cacheable.
        let policy_pass = OwnCookiePolicy {
            pass_auth_cookies: true,
            ..policy_no_pass
        };
        assert!(!is_request_cacheable(
            &Method::GET,
            &uri("/dash"),
            &h,
            &policy_pass
        ));

        // gately_admin alone remains exempt even when pass_auth_cookies = true.
        let mut admin_only = HeaderMap::new();
        admin_only.insert(header::COOKIE, hv("gately_admin=adm1"));
        assert!(is_request_cacheable(
            &Method::GET,
            &uri("/dash"),
            &admin_only,
            &policy_pass
        ));

        // Foreign / tampered gately_site_* cookie counts as credential!
        let foreign_val = issue(b"other-secret", "alice", host, Scope::Site, "fp", now);
        let mut foreign = HeaderMap::new();
        foreign.insert(
            header::COOKIE,
            hv(&format!("{site_cookie_name}={foreign_val}")),
        );
        assert!(!is_request_cacheable(
            &Method::GET,
            &uri("/dash"),
            &foreign,
            &policy_no_pass
        ));

        // Extra unknown cookie alongside valid site cookie -> NOT cacheable.
        let mut mixed = HeaderMap::new();
        mixed.insert(
            header::COOKIE,
            hv(&format!("{site_cookie_name}={site_val}; app_sess=1")),
        );
        assert!(!is_request_cacheable(
            &Method::GET,
            &uri("/dash"),
            &mixed,
            &policy_no_pass
        ));
    }

    #[test]
    fn cache_path_with_special_bytes_not_cached() {
        let policy = OwnCookiePolicy::default();
        let empty = HeaderMap::new();
        for bad in ["/a;b", "/a%2Fb", "/a%2fb", "/a%5Cb", "/a%5cb"] {
            assert!(
                !is_request_cacheable(&Method::GET, &uri(bad), &empty, &policy),
                "path {bad} must not be cacheable"
            );
        }
        assert!(has_special_path_bytes("/a\\b"));
        assert!(!has_special_path_bytes("/normal/path-123"));
    }

    #[test]
    fn cache_response_conditions() {
        let empty = HeaderMap::new();
        assert!(is_response_cacheable(StatusCode::OK, &empty, false, false));
        for status in [
            StatusCode::CREATED,
            StatusCode::MOVED_PERMANENTLY,
            StatusCode::NOT_MODIFIED,
            StatusCode::NOT_FOUND,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            assert!(!is_response_cacheable(status, &empty, false, false));
        }

        let mut set_cookie = HeaderMap::new();
        set_cookie.insert(header::SET_COOKIE, hv("a=1"));
        assert!(!is_response_cacheable(
            StatusCode::OK,
            &set_cookie,
            false,
            false
        ));
        assert!(!is_response_cacheable(
            StatusCode::OK,
            &set_cookie,
            false,
            true
        ));

        let mut vary_star = HeaderMap::new();
        vary_star.insert(header::VARY, hv("*"));
        assert!(!is_response_cacheable(
            StatusCode::OK,
            &vary_star,
            false,
            false
        ));
        assert!(!is_response_cacheable(
            StatusCode::OK,
            &vary_star,
            false,
            true
        ));

        for cc in ["no-store", "private", "no-cache"] {
            let mut h = HeaderMap::new();
            h.insert(header::CACHE_CONTROL, hv(cc));
            assert!(!is_response_cacheable(StatusCode::OK, &h, false, false));
        }
        // override ignores no-store and no-cache, but STILL respects private!
        let mut h_private = HeaderMap::new();
        h_private.insert(header::CACHE_CONTROL, hv("private, max-age=60"));
        assert!(!is_response_cacheable(
            StatusCode::OK,
            &h_private,
            false,
            true
        ));

        let mut h_nostore = HeaderMap::new();
        h_nostore.insert(header::CACHE_CONTROL, hv("no-store"));
        assert!(is_response_cacheable(
            StatusCode::OK,
            &h_nostore,
            false,
            true
        ));

        let mut h_nocache = HeaderMap::new();
        h_nocache.insert(header::CACHE_CONTROL, hv("no-cache"));
        assert!(is_response_cacheable(
            StatusCode::OK,
            &h_nocache,
            false,
            true
        ));

        // Backend non-`*` ACAO is rejected; `*` is allowed.
        let mut acao_specific = HeaderMap::new();
        acao_specific.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, hv("https://a.example"));
        assert!(!is_response_cacheable(
            StatusCode::OK,
            &acao_specific,
            true,
            false
        ));
        let mut acao_star = HeaderMap::new();
        acao_star.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, hv("*"));
        assert!(is_response_cacheable(
            StatusCode::OK,
            &acao_star,
            true,
            false
        ));
    }

    #[test]
    fn cache_vary_limited_to_accept_encoding_and_origin() {
        let mut ae = HeaderMap::new();
        ae.insert(header::VARY, hv("Accept-Encoding"));
        assert!(is_response_cacheable(StatusCode::OK, &ae, false, false));

        let mut ae_origin = HeaderMap::new();
        ae_origin.insert(header::VARY, hv("Accept-Encoding, Origin"));
        assert!(!is_response_cacheable(
            StatusCode::OK,
            &ae_origin,
            false,
            false
        ));
        assert!(is_response_cacheable(
            StatusCode::OK,
            &ae_origin,
            true,
            false
        ));

        let mut other = HeaderMap::new();
        other.insert(header::VARY, hv("Accept-Encoding, Accept-Language"));
        assert!(!is_response_cacheable(StatusCode::OK, &other, true, false));
    }

    #[test]
    fn cache_freshness_smaxage_then_maxage_then_ttl() {
        let mut h = HeaderMap::new();
        h.insert(header::CACHE_CONTROL, hv("max-age=60, s-maxage=120"));
        assert_eq!(
            compute_freshness(&h, Duration::from_secs(30), None),
            Some(Duration::from_secs(120))
        );

        let mut h2 = HeaderMap::new();
        h2.insert(header::CACHE_CONTROL, hv("public, max-age=45"));
        assert_eq!(
            compute_freshness(&h2, Duration::from_secs(30), None),
            Some(Duration::from_secs(45))
        );

        let empty = HeaderMap::new();
        assert_eq!(
            compute_freshness(&empty, Duration::from_secs(30), None),
            Some(Duration::from_secs(30))
        );
        // Site TTL = 0 caches only when upstream gives positive max-age/s-maxage.
        assert_eq!(compute_freshness(&empty, Duration::ZERO, None), None);
        assert_eq!(
            compute_freshness(&h2, Duration::ZERO, None),
            Some(Duration::from_secs(45))
        );

        // Rule override ignores upstream max-age.
        let override_rule = CacheRule {
            path: "/force".to_owned(),
            ttl: Some(Duration::from_secs(600)),
            override_: true,
            no_cache: false,
        };
        assert_eq!(
            compute_freshness(&h2, Duration::from_secs(30), Some(&override_rule)),
            Some(Duration::from_secs(600))
        );
    }
}
