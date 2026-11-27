//! Cross-origin resource sharing (WP-23 step 10): when the request's
//! `Origin` matches the site's allow list, CORS headers are written back
//! and preflight requests are answered directly (never proxied).
#![allow(dead_code)]

use hyper::header::{
    HeaderName, HeaderValue, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
    ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_MAX_AGE, VARY,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cors {
    /// Origin allow list; `*` allows every origin.
    pub allow_origins: Vec<String>,
    pub allow_methods: Vec<String>,
    pub allow_headers: Vec<String>,
    pub allow_credentials: bool,
    /// Preflight cache lifetime in seconds (0 omits the header).
    pub max_age_secs: u32,
}

/// Is this an OPTIONS preflight (has `Origin` and
/// `Access-Control-Request-Method`)?
pub fn is_preflight(method: &str, request_method: Option<&str>) -> bool {
    method.eq_ignore_ascii_case("OPTIONS") && request_method.is_some()
}

impl Cors {
    /// Exact match or the wildcard. Empty list allows nothing.
    pub fn origin_allowed(&self, origin: &str) -> bool {
        self.allow_origins
            .iter()
            .any(|allowed| allowed == "*" || allowed.eq_ignore_ascii_case(origin))
    }

    /// CORS headers for a regular (non-preflight) response with a matching
    /// origin. Empty when origin is not allowed.
    pub fn response_headers(&self, origin: &str) -> Vec<(HeaderName, HeaderValue)> {
        self.headers(origin, false)
    }

    /// Complete preflight answer headers for a matching origin: allow
    /// origin/methods/headers (+ credentials, + max age when set), plus
    /// `Vary: Origin` whenever the origin is echoed rather than `*`.
    /// Empty method/header lists declare nothing (the corresponding header
    /// is omitted). Empty when origin is not allowed.
    pub fn preflight_headers(&self, origin: &str) -> Vec<(HeaderName, HeaderValue)> {
        let mut headers = self.headers(origin, true);
        if !headers.is_empty() && self.max_age_secs > 0 {
            headers.push((ACCESS_CONTROL_MAX_AGE, HeaderValue::from(self.max_age_secs)));
        }
        headers
    }

    /// Shared body of both header sets. `preflight` additionally drops the
    /// method/header declarations when their configured lists are empty:
    /// nothing configured means nothing declared.
    fn headers(&self, origin: &str, preflight: bool) -> Vec<(HeaderName, HeaderValue)> {
        if !self.origin_allowed(origin) {
            return Vec::new();
        }
        let wildcard = self.allow_origins.iter().any(|allowed| allowed == "*");
        let mut headers = Vec::new();
        // `*` stays `*`; a concrete allow list echoes the request origin.
        let allow_origin = if wildcard { "*" } else { origin };
        if let Ok(value) = HeaderValue::from_str(allow_origin) {
            headers.push((ACCESS_CONTROL_ALLOW_ORIGIN, value));
        }
        if !preflight || !self.allow_methods.is_empty() {
            headers.push((
                ACCESS_CONTROL_ALLOW_METHODS,
                joined_value(&self.allow_methods),
            ));
        }
        if !preflight || !self.allow_headers.is_empty() {
            headers.push((
                ACCESS_CONTROL_ALLOW_HEADERS,
                joined_value(&self.allow_headers),
            ));
        }
        if self.allow_credentials {
            headers.push((
                ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            ));
        }
        // The answer depends on the request origin, so caches must vary on
        // it; `*` treats every origin alike and needs no such hint.
        if !wildcard {
            headers.push((VARY, HeaderValue::from_static("Origin")));
        }
        headers
    }
}

/// Comma-space joined header value; values that cannot legally appear in a
/// header (never expected from validated config) collapse to empty.
fn joined_value(list: &[String]) -> HeaderValue {
    let joined = list.join(", ");
    HeaderValue::from_str(&joined).unwrap_or_else(|_| HeaderValue::from_static(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Looks up a header value by its lowercase wire name.
    fn get<'a>(
        headers: &'a [(HeaderName, HeaderValue)],
        name: &str,
    ) -> Option<&'a HeaderValue> {
        headers
            .iter()
            .find(|(header, _)| header.as_str() == name)
            .map(|(_, value)| value)
    }

    #[test]
    fn cors_preflight_and_origin() {
        let cors = Cors {
            allow_origins: vec!["https://app.example.com".into()],
            allow_methods: vec!["GET".into(), "POST".into()],
            allow_headers: vec!["X-Request-Id".into()],
            allow_credentials: true,
            max_age_secs: 600,
        };
        // A preflight is OPTIONS *with* Access-Control-Request-Method.
        assert!(is_preflight("OPTIONS", Some("DELETE")));
        assert!(!is_preflight("GET", None));
        assert!(!is_preflight("OPTIONS", None), "plain OPTIONS is not a preflight");

        let pre = cors.preflight_headers("https://app.example.com");
        assert_eq!(
            get(&pre, "access-control-allow-origin").unwrap(),
            "https://app.example.com"
        );
        assert_eq!(get(&pre, "access-control-allow-methods").unwrap(), "GET, POST");
        assert_eq!(get(&pre, "access-control-allow-headers").unwrap(), "X-Request-Id");
        assert_eq!(get(&pre, "access-control-max-age").unwrap(), "600");
        assert_eq!(get(&pre, "access-control-allow-credentials").unwrap(), "true");
    }

    #[test]
    fn cors_wildcard() {
        let cors = Cors {
            allow_origins: vec!["*".into()],
            allow_methods: vec!["GET".into(), "PUT".into()],
            ..Default::default()
        };
        let resp = cors.response_headers("https://any.example.com");
        assert_eq!(get(&resp, "access-control-allow-origin").unwrap(), "*");
        assert!(get(&resp, "vary").is_none(), "`*` never varies on Origin");
        let pre = cors.preflight_headers("https://other.example.com");
        assert_eq!(get(&pre, "access-control-allow-origin").unwrap(), "*");
        assert!(get(&pre, "vary").is_none());
    }

    #[test]
    fn cors_origin_not_allowed() {
        let empty = Cors::default();
        assert!(empty.response_headers("https://a.example.com").is_empty());
        assert!(empty.preflight_headers("https://a.example.com").is_empty());

        let cors = Cors {
            allow_origins: vec!["https://a.example.com".into()],
            allow_methods: vec!["GET".into()],
            ..Default::default()
        };
        assert!(cors.response_headers("https://b.example.com").is_empty());
        assert!(cors.preflight_headers("https://b.example.com").is_empty());
    }

    #[test]
    fn cors_empty_method_list_omits_header() {
        let cors = Cors {
            allow_origins: vec!["https://a.example.com".into()],
            allow_headers: vec!["X-Token".into()],
            ..Default::default()
        };
        let pre = cors.preflight_headers("https://a.example.com");
        assert!(get(&pre, "access-control-allow-methods").is_none());
        assert_eq!(get(&pre, "access-control-allow-headers").unwrap(), "X-Token");
    }

    #[test]
    fn vary_origin_when_echoing() {
        let cors = Cors {
            allow_origins: vec!["https://a.example.com".into()],
            allow_methods: vec!["GET".into()],
            ..Default::default()
        };
        let resp = cors.response_headers("https://a.example.com");
        assert_eq!(
            get(&resp, "access-control-allow-origin").unwrap(),
            "https://a.example.com"
        );
        assert_eq!(get(&resp, "vary").unwrap(), "Origin");
        // No credentials were configured, so none are promised.
        assert!(get(&resp, "access-control-allow-credentials").is_none());
    }
}
