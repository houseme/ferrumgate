//! Forward authentication (WP-25): the Authelia-style sub-request — a
//! bodyless GET with the visitor's headers and the X-Original-* set.
//! Config validation and login-URL expansion are local; the sub-request
//! itself wires with the pipeline.
#![allow(dead_code)]

use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;

use http_body_util::Empty;
use hyper::{
    HeaderMap, Method, Request, StatusCode,
    body::Bytes,
    header::{AUTHORIZATION, COOKIE, HeaderName, HeaderValue, LOCATION, SET_COOKIE},
};
use tokio::time::timeout;

/// The identity headers copied from a 2xx auth response to the backend.
pub const DEFAULT_COPY_HEADERS: &[&str] = &[
    "Remote-User",
    "Remote-Groups",
    "Remote-Email",
    "Remote-Name",
];

/// Identity headers the ecosystem also uses outside the `Remote-*`
/// namespace: oauth2-proxy's `X-Auth-Request-*`, the `X-Forwarded-User`
/// family and Traefik's `X-Webauth-User`. Matched lowercase against
/// [`HeaderName::as_str`].
const KNOWN_IDENTITY_HEADERS: &[&str] = &[
    "x-auth-request-email",
    "x-auth-request-groups",
    "x-auth-request-preferred-username",
    "x-auth-request-user",
    "x-forwarded-email",
    "x-forwarded-groups",
    "x-forwarded-preferred-username",
    "x-forwarded-user",
    "x-webauth-user",
];

#[derive(Clone, Debug)]
pub struct ForwardAuth {
    /// Outbound GET per authenticated request (timeout 10s, dial 5s).
    pub url: String,
    /// 401 redirect target (`{url}` / `{method}` placeholders).
    pub login_url: Option<String>,
    /// Take the login address from the 401's Location instead.
    pub login_from_location: bool,
    /// Headers copied from the auth response; defaults to
    /// [`DEFAULT_COPY_HEADERS`].
    pub copy_headers: Vec<HeaderName>,
    /// Cached deduped, sorted view of `copy_headers` for
    /// [`ForwardAuth::allowed_identity_headers`]. Filled on first call;
    /// `copy_headers` is treated as frozen after configuration
    /// compilation (sites are built once, then shared read-only), so the
    /// cache cannot go stale in practice.
    identity_view: OnceLock<Vec<HeaderName>>,
}

impl ForwardAuth {
    /// Assembles a compiled configuration (the bridge's entry point;
    /// fields stay private so the identity view stays consistent).
    pub fn new(
        url: String,
        login_url: Option<String>,
        login_from_location: bool,
        copy_headers: Vec<HeaderName>,
    ) -> Self {
        Self {
            url,
            login_url,
            login_from_location,
            copy_headers,
            identity_view: OnceLock::new(),
        }
    }
}

impl Default for ForwardAuth {
    fn default() -> Self {
        Self {
            url: String::new(),
            login_url: None,
            login_from_location: false,
            copy_headers: DEFAULT_COPY_HEADERS
                .iter()
                // `from_static` demands lowercase; the display-case
                // constants go through the case-insensitive parse instead.
                .map(|h| HeaderName::from_bytes(h.as_bytes()).expect("valid header name"))
                .collect(),
            identity_view: OnceLock::new(),
        }
    }
}

/// `Remote-*` or one of [`KNOWN_IDENTITY_HEADERS`]; a [`HeaderName`] is
/// always lowercase, so plain string checks suffice.
fn is_known_identity_header(name: &HeaderName) -> bool {
    name.as_str().starts_with("remote-") || KNOWN_IDENTITY_HEADERS.contains(&name.as_str())
}

impl ForwardAuth {
    /// Visitor headers forwarded on the auth request; visitor-supplied
    /// identity headers are never among them.
    pub fn auth_request_headers(&self) -> Vec<HeaderName> {
        vec![
            HeaderName::from_static("x-original-method"),
            HeaderName::from_static("x-original-url"),
            HeaderName::from_static("x-original-uri"),
            HeaderName::from_static("x-forwarded-method"),
            HeaderName::from_static("x-forwarded-proto"),
            HeaderName::from_static("x-forwarded-host"),
            HeaderName::from_static("x-forwarded-uri"),
            HeaderName::from_static("x-forwarded-for"),
            HeaderName::from_static("x-real-ip"),
        ]
    }

    /// Configuration problems (WP-25 §3.3/§3.4): `url` must be an
    /// absolute http(s) address; `login_url` and `login_from_location`
    /// are mutually exclusive; every `copy_headers` entry must be an
    /// identity header (`Remote-*` or [`KNOWN_IDENTITY_HEADERS`]). One
    /// Chinese problem per finding; every finding is reported.
    pub fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let url_ok = matches!(
            self.url.parse::<hyper::Uri>(),
            Ok(uri)
                if matches!(uri.scheme_str(), Some("http" | "https"))
                    && uri.authority().is_some()
        );
        if !url_ok {
            problems.push(format!(
                "转发认证地址须是 http(s) 绝对地址，当前 `{}`",
                self.url
            ));
        }
        if self.login_url.is_some() && self.login_from_location {
            problems.push(
                "loginUrl 与 loginFromLocation 只能设其一：401 的跳转地址要么固定填写，要么取认证响应的 Location"
                    .to_string(),
            );
        }
        for name in &self.copy_headers {
            if !is_known_identity_header(name) {
                problems.push(format!(
                    "复制的身份头 `{}` 不是已知身份头：须为 Remote-* 或 {} 之一",
                    name,
                    KNOWN_IDENTITY_HEADERS.join("、")
                ));
            }
        }
        problems
    }

    /// Renders the login URL: `{url}` and `{method}` placeholders expand,
    /// everything else stays literal. `None` when there is no `login_url`
    /// (the caller falls back to the 401's `Location` per
    /// `login_from_location`). Single pass, so a `{method}` arriving
    /// inside `url` is not re-expanded.
    pub fn login_redirect(&self, url: &str, method: &str) -> Option<String> {
        let template = self.login_url.as_ref()?;
        let mut out = String::with_capacity(template.len() + url.len() + method.len());
        let mut rest = template.as_str();
        while let Some(open) = rest.find('{') {
            out.push_str(&rest[..open]);
            let tail = &rest[open..];
            if let Some(after) = tail.strip_prefix("{url}") {
                out.push_str(url);
                rest = after;
            } else if let Some(after) = tail.strip_prefix("{method}") {
                out.push_str(method);
                rest = after;
            } else {
                out.push('{');
                rest = &tail[1..];
            }
        }
        out.push_str(rest);
        Some(out)
    }

    /// Identity headers the backend may end up with: the deduped, sorted
    /// view of `copy_headers` (§3.4 defaults: `Remote-User`、
    /// `Remote-Groups`、`Remote-Email`、`Remote-Name`). §3.3: the
    /// visitor's own copies of these headers are always stripped from the
    /// proxied request first — only headers copied back from a 2xx auth
    /// response are ever forwarded, so `Remote-User` cannot be forged.
    pub fn allowed_identity_headers(&self) -> &[HeaderName] {
        self.identity_view.get_or_init(|| {
            let mut headers = self.copy_headers.clone();
            // `HeaderName` has no `Ord`; its lowercase `as_str` does.
            headers.sort_by(|a, b| a.as_str().cmp(b.as_str()));
            headers.dedup();
            headers
        })
    }
}

/// The result of one authentication sub-request (§3.3: 2xx 放行并复制
/// 身份头；401 跳登录；其他状态原样回访客；无法连接 502).
#[derive(Debug)]
pub enum SubRequestOutcome {
    /// The auth service accepted the visitor. `identity` carries the
    /// allowed identity headers present in the response (comma-joined
    /// when repeated); `set_cookies` passes the auth service's cookies
    /// through (Casdoor-style login flows rely on it).
    Allowed {
        identity: Vec<(HeaderName, String)>,
        set_cookies: Vec<String>,
    },
    /// 401 with a login address resolved from `loginUrl` or (when
    /// `loginFromLocation` is on and the Location is the only absolute
    /// http(s) address) from the response itself.
    Redirect {
        location: String,
        set_cookies: Vec<String>,
    },
    /// Any other status answers the visitor verbatim.
    Status(u16),
    /// The auth service could not be reached (→ 502).
    Unreachable,
}

/// The outbound auth request timeout (§3.4: 单次 10 秒).
const SUB_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

type SubClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Empty<Bytes>,
>;

static SUB_CLIENT: OnceLock<SubClient> = OnceLock::new();

fn sub_client() -> SubClient {
    let mut connector = hyper_util::client::legacy::connect::HttpConnector::new();
    connector.set_nodelay(true);
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_native_roots(rustls::crypto::aws_lc_rs::default_provider())
        .expect("native roots")
        .https_or_http()
        .enable_http1()
        .wrap_connector(connector);
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(https)
}

/// Runs the authentication sub-request: a bodyless `GET` to the auth
/// service carrying the visitor's `Cookie`/`Authorization` plus the
/// `X-Original-*` / `X-Forwarded-*` / `X-Real-IP` set. The visitor's own
/// identity headers are never among them (§3.3 — they cannot be forged
/// into the backend).
pub async fn sub_request(
    auth: &ForwardAuth,
    visitor_headers: &HeaderMap,
    original: (&str, &str, &str),
    source: IpAddr,
) -> SubRequestOutcome {
    let (method, full_url, uri) = original;
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(&auth.url)
        .body(Empty::<Bytes>::new())
        .expect("static body");
    let headers = request.headers_mut();
    for name in auth.auth_request_headers() {
        let value = match name.as_str() {
            "x-original-method" | "x-forwarded-method" => Some(method.to_owned()),
            "x-original-url" => Some(full_url.to_owned()),
            "x-original-uri" | "x-forwarded-uri" => Some(uri.to_owned()),
            "x-forwarded-for" | "x-real-ip" => Some(source.to_string()),
            _ => None,
        };
        if let Some(value) = value
            && let Ok(value) = HeaderValue::from_str(&value)
        {
            headers.insert(name, value);
        }
    }
    // Forward proto/host from the visitor's own headers when present.
    for name in ["x-forwarded-proto", "x-forwarded-host"] {
        if let Some(value) = visitor_headers.get(name) {
            headers.insert(HeaderName::from_static(name), value.clone());
        }
    }
    // The credentials the auth service judges: cookies and the
    // Authorization header, verbatim.
    for name in [COOKIE, AUTHORIZATION] {
        for value in visitor_headers.get_all(&name) {
            headers.append(&name, value.clone());
        }
    }
    let client = SUB_CLIENT.get_or_init(sub_client);
    let pending = client.request(request);
    let response = match timeout(SUB_REQUEST_TIMEOUT, pending).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            tracing::debug!(%error, url = %auth.url, "forward-auth sub-request failed");
            return SubRequestOutcome::Unreachable;
        }
        Err(_) => {
            tracing::debug!(url = %auth.url, "forward-auth sub-request timed out");
            return SubRequestOutcome::Unreachable;
        }
    };
    let status = response.status();
    let set_cookies: Vec<String> = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect();
    if status.is_success() {
        let identity = auth
            .allowed_identity_headers()
            .iter()
            .filter_map(|name| {
                let values: Vec<&str> = response
                    .headers()
                    .get_all(name)
                    .iter()
                    .filter_map(|value| value.to_str().ok())
                    .collect();
                (!values.is_empty()).then(|| (name.clone(), values.join(", ")))
            })
            .collect();
        return SubRequestOutcome::Allowed {
            identity,
            set_cookies,
        };
    }
    if status == StatusCode::UNAUTHORIZED {
        if let Some(location) = auth.login_redirect(full_url, method) {
            return SubRequestOutcome::Redirect {
                location,
                set_cookies,
            };
        }
        if auth.login_from_location {
            let locations: Vec<&str> = response
                .headers()
                .get_all(LOCATION)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect();
            let absolute = |text: &str| {
                text.parse::<hyper::Uri>().ok().is_some_and(|uri| {
                    matches!(uri.scheme_str(), Some("http" | "https")) && uri.authority().is_some()
                })
            };
            if locations.len() == 1 && absolute(locations[0]) {
                return SubRequestOutcome::Redirect {
                    location: locations[0].to_owned(),
                    set_cookies,
                };
            }
        }
        return SubRequestOutcome::Status(StatusCode::UNAUTHORIZED.as_u16());
    }
    SubRequestOutcome::Status(status.as_u16())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> ForwardAuth {
        ForwardAuth {
            url: "https://auth.example.com/api/verify".to_string(),
            ..ForwardAuth::default()
        }
    }

    // --- validate -------------------------------------------------------

    #[test]
    fn good_config_has_no_problems() {
        let mut fa = good();
        assert!(fa.validate().is_empty());
        // login_url alone is fine…
        fa.login_url = Some("https://auth.example.com/login?rd={url}&m={method}".to_string());
        assert!(fa.validate().is_empty());
        // …and so is login_from_location alone.
        fa.login_url = None;
        fa.login_from_location = true;
        assert!(fa.validate().is_empty());
    }

    #[test]
    fn login_sources_are_mutually_exclusive() {
        let fa = ForwardAuth {
            login_url: Some("https://auth.example.com/login".to_string()),
            login_from_location: true,
            ..good()
        };
        let problems = fa.validate();
        assert_eq!(problems.len(), 1, "exactly one problem: {problems:?}");
        assert!(problems[0].contains("loginUrl"));
        assert!(problems[0].contains("loginFromLocation"));
    }

    #[test]
    fn url_must_be_absolute_http_s() {
        let bad = [
            // No scheme.
            "auth.example.com/api/verify",
            // Wrong scheme.
            "ftp://auth.example.com/api/verify",
            // Scheme without a host is not an absolute address.
            "https:api/verify",
            // Empty.
            "",
        ];
        for url in bad {
            let fa = ForwardAuth {
                url: url.to_string(),
                ..ForwardAuth::default()
            };
            let problems = fa.validate();
            assert_eq!(problems.len(), 1, "url {url:?} → {problems:?}");
            assert!(
                problems[0].contains("http(s) 绝对地址"),
                "url {url:?} → {}",
                problems[0]
            );
        }
    }

    #[test]
    fn unknown_identity_headers_are_reported_individually() {
        let fa = ForwardAuth {
            copy_headers: vec![
                HeaderName::from_static("remote-user"),
                HeaderName::from_static("x-bogus-user"),
                HeaderName::from_static("cookie"),
            ],
            ..good()
        };
        let problems = fa.validate();
        assert_eq!(problems.len(), 2, "each bad header gets its own problem");
        assert!(problems[0].contains("x-bogus-user"), "{}", problems[0]);
        assert!(problems[1].contains("cookie"), "{}", problems[1]);
    }

    #[test]
    fn known_non_remote_identity_headers_pass() {
        let fa = ForwardAuth {
            copy_headers: vec![
                HeaderName::from_static("x-auth-request-user"),
                HeaderName::from_static("x-auth-request-groups"),
                HeaderName::from_static("x-webauth-user"),
                HeaderName::from_static("x-forwarded-preferred-username"),
            ],
            ..good()
        };
        assert!(fa.validate().is_empty());
    }

    // --- login_redirect ---------------------------------------------------

    #[test]
    fn placeholders_expand_and_the_rest_stays_literal() {
        let fa = ForwardAuth {
            login_url: Some("https://auth.example.com/login?rd={url}&m={method}".to_string()),
            ..good()
        };
        assert_eq!(
            fa.login_redirect("https://site.example.com/docs?a=b", "GET"),
            Some(
                "https://auth.example.com/login?rd=https://site.example.com/docs?a=b&m=GET"
                    .to_string()
            )
        );
    }

    #[test]
    fn repeated_and_unknown_placeholders() {
        let fa = ForwardAuth {
            login_url: Some("{url}|{method}|{url}|{bogus}|{".to_string()),
            ..good()
        };
        // Single pass: `{method}` inside the substituted url is not
        // re-expanded; unknown `{bogus}` and a lone `{` stay literal.
        assert_eq!(
            fa.login_redirect("u{method}x", "POST"),
            Some("u{method}x|POST|u{method}x|{bogus}|{".to_string())
        );
    }

    #[test]
    fn no_login_url_means_no_redirect() {
        let fa = good();
        assert_eq!(fa.login_redirect("https://site.example.com/x", "GET"), None);
        // login_from_location is the caller's signal, not a login_url.
        let fa = ForwardAuth {
            login_from_location: true,
            ..good()
        };
        assert_eq!(fa.login_redirect("https://site.example.com/x", "GET"), None);
    }

    // --- allowed_identity_headers -----------------------------------------

    #[test]
    fn default_copy_headers_sorted_and_deduped() {
        let fa = ForwardAuth::default();
        let expected = [
            HeaderName::from_static("remote-email"),
            HeaderName::from_static("remote-groups"),
            HeaderName::from_static("remote-name"),
            HeaderName::from_static("remote-user"),
        ];
        assert_eq!(fa.allowed_identity_headers(), expected.as_slice());
    }

    #[test]
    fn view_is_sorted_and_deduped() {
        let fa = ForwardAuth {
            copy_headers: vec![
                HeaderName::from_static("remote-user"),
                HeaderName::from_static("x-webauth-user"),
                HeaderName::from_static("remote-user"),
                HeaderName::from_static("remote-email"),
                HeaderName::from_static("x-webauth-user"),
            ],
            ..good()
        };
        let expected = [
            HeaderName::from_static("remote-email"),
            HeaderName::from_static("remote-user"),
            HeaderName::from_static("x-webauth-user"),
        ];
        assert_eq!(fa.allowed_identity_headers(), expected.as_slice());
    }

    #[test]
    fn auth_request_headers_carry_no_identity_headers() {
        // §3.3: the visitor's own identity headers are stripped before the
        // sub-request, so the auth request never carries a header that
        // would be mistaken for a copied-back identity.
        let fa = ForwardAuth::default();
        for name in fa.auth_request_headers() {
            assert!(!fa.allowed_identity_headers().contains(&name));
        }
    }
}
