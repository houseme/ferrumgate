use std::{
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime},
};

use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::{
    Method, Request, Response, StatusCode, Uri, Version,
    body::{Body, Bytes, Frame, Incoming, SizeHint},
    header::{
        ACCEPT, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, HeaderMap,
        HeaderName, HeaderValue, LOCATION, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, SET_COOKIE, TE,
        TRAILER, TRANSFER_ENCODING, UPGRADE, VIA, WWW_AUTHENTICATE,
    },
    http::uri::{Authority, PathAndQuery, Scheme},
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, Error as SendError, connect::HttpConnector},
    rt::{TokioExecutor, TokioTimer},
};
use tokio::time::timeout;

use crate::{
    config::{self, RouteAction, Routes, Settings, milliseconds},
    static_files::LocalBody,
    tls::ConnectionIdentity,
    web::{
        auth::{self, AuthPathReply, AuthSite, Authenticator, BasicOutcome},
        identity,
        proxy::{
            cors, headers,
            rewrite::{self, Outcome},
        },
    },
    websocket::{Handshake, Tunnel},
};

/// The request bodies the proxy clients accept (WP-23 3b): the streaming
/// downstream body, a buffered body that can be replayed on the next
/// backend after a dial failure, and the empty body of bodyless requests.
pub(crate) enum RequestBody {
    Data(DataBody),
    Replay(ReplayBody),
    Empty(Empty<Bytes>),
}

/// Probe requests (health checks) arrive in the legacy `Either` shape;
/// this conversion keeps `probe_http` callers unchanged.
impl From<Either<DataBody, Empty<Bytes>>> for RequestBody {
    fn from(body: Either<DataBody, Empty<Bytes>>) -> Self {
        match body {
            Either::Left(inner) => Self::Data(inner),
            Either::Right(empty) => Self::Empty(empty),
        }
    }
}

type Reply = Response<Either<DataBody, LocalBody>>;

/// Buffer size above which a request body is no longer replayed and the
/// attempt plan collapses to a single backend (WP-23 3b).
const MAX_REPLAY_BYTES: usize = 256 * 1024;

pub(crate) struct Proxy {
    routes: Routes,
    authenticator: Arc<Authenticator>,
    client: Client<HttpsConnector<HttpConnector>, RequestBody>,
    upgrade_client: Client<HttpsConnector<HttpConnector>, RequestBody>,
    h2c_client: Client<HttpConnector, RequestBody>,
    response_header_timeout: Duration,
}

impl Proxy {
    pub fn new(routes: Routes, settings: &Settings, tls: rustls::ClientConfig) -> Self {
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        connector.set_connect_timeout(Some(milliseconds(settings.connect_timeout_ms)));
        connector.set_nodelay(true);
        let http1 = HttpsConnectorBuilder::new()
            .with_tls_config(tls.clone())
            .https_or_http()
            .enable_http1()
            .wrap_connector(connector.clone());
        let negotiated = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(connector.clone());
        connector.enforce_http(true);

        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(8)
            .retry_canceled_requests(false)
            .http2_initial_stream_window_size(65_535)
            .http2_initial_connection_window_size(1024 * 1024)
            .http2_max_header_list_size(32 * 1024)
            .http2_max_send_buf_size(64 * 1024);

        Self {
            routes,
            // WP-24: the TOML path carries no auth users — an empty
            // authenticator behind the default options never dispatches,
            // keeping legacy requests byte-for-byte unchanged. The
            // webservice configuration path attaches its
            // settings-derived authenticator via `with_authenticator`.
            authenticator: Arc::new(Authenticator::new(&[], Vec::new())),
            client: builder.build(negotiated),
            upgrade_client: builder.build(http1),
            h2c_client: builder.http2_only(true).build(connector),
            response_header_timeout: milliseconds(settings.response_header_timeout_ms),
        }
    }

    /// Attaches the generation's authenticator (built from the
    /// webservice settings' `authSecret` + `authUsers`).
    // Only the pipeline tests call it so far; the webservice
    // configuration wiring (dir_config) attaches it in production.
    #[allow(dead_code)]
    pub(crate) fn with_authenticator(mut self, authenticator: Arc<Authenticator>) -> Self {
        self.authenticator = authenticator;
        self
    }

    pub async fn monitor_health(&self, events: &fg_core::events::EventBus) {
        crate::health::monitor(self, &self.routes, events).await;
    }

    pub async fn probe_http<B>(&self, request: Request<B>, h2c: bool) -> bool
    where
        RequestBody: From<B>,
    {
        let request = request.map(RequestBody::from);
        let response = if h2c {
            self.h2c_client.request(request)
        } else {
            self.client.request(request)
        };
        response
            .await
            .is_ok_and(|response| response.status().as_u16() < 400)
    }

    pub async fn forward(
        &self,
        mut request: Request<Incoming>,
        peer: SocketAddr,
        tls_identity: Option<&ConnectionIdentity>,
        tunnel: Option<&OnceLock<Tunnel>>,
    ) -> Reply {
        let downstream_version = request.version();
        let downstream_h2 = downstream_version == Version::HTTP_2;
        if downstream_version != Version::HTTP_11 && !downstream_h2 {
            return reply(StatusCode::HTTP_VERSION_NOT_SUPPORTED);
        }
        if request.method() == Method::CONNECT {
            return reply(StatusCode::NOT_IMPLEMENTED);
        }
        let uri = request.uri();
        // Owned so a site rewrite can replace the forwarded path (WP-23).
        let Some(mut target) = uri
            .path_and_query()
            .filter(|target| target.path().starts_with('/'))
            .cloned()
        else {
            return reply(StatusCode::BAD_REQUEST);
        };
        let mut hosts = request.headers().get_all(HOST).iter();
        let host_header = hosts.next();
        if hosts.next().is_some() {
            return reply(StatusCode::BAD_REQUEST);
        }
        let (authority, original_host) = if downstream_h2 {
            let Some(authority) = uri
                .authority()
                .filter(|_| uri.scheme() == Some(&Scheme::HTTPS))
            else {
                return reply(StatusCode::BAD_REQUEST);
            };
            if host_header.is_some_and(|host| {
                !host
                    .as_bytes()
                    .eq_ignore_ascii_case(authority.as_str().as_bytes())
            }) {
                return reply(StatusCode::BAD_REQUEST);
            }
            let Ok(host) = HeaderValue::from_str(authority.as_str()) else {
                return reply(StatusCode::BAD_REQUEST);
            };
            (authority.clone(), host)
        } else {
            if uri.scheme().is_some() || uri.authority().is_some() {
                return reply(StatusCode::BAD_REQUEST);
            }
            let Some(host) = host_header else {
                return reply(StatusCode::BAD_REQUEST);
            };
            let Some(authority) = host
                .to_str()
                .ok()
                .and_then(|value| value.parse::<Authority>().ok())
            else {
                return reply(StatusCode::BAD_REQUEST);
            };
            (authority, host.clone())
        };
        if !config::valid_authority(&authority) {
            return reply(StatusCode::BAD_REQUEST);
        }
        let (route, mut attempts) = {
            let host = config::canonical_host(authority.host()).expect("validated authority");
            if tls_identity.is_some_and(|identity| !identity.matches(&host)) {
                return reply(StatusCode::MISDIRECTED_REQUEST);
            }
            let Some(route) = self.routes.find(&host, target.path()) else {
                return reply(StatusCode::NOT_FOUND);
            };
            let route = match &route.action {
                RouteAction::Proxy(route) => route,
                RouteAction::Response(site) => {
                    if request.headers().contains_key(UPGRADE) {
                        return reply(StatusCode::NOT_IMPLEMENTED);
                    }
                    return match site
                        .serve(
                            request.method(),
                            &host,
                            &target,
                            route.prefix.as_str(),
                            request.headers(),
                        )
                        .await
                    {
                        Ok(response) => response.map(Either::Right),
                        Err(status) => reply(status),
                    };
                }
            };
            // WP-23 per-site options. Every step below is a no-op on the
            // TOML path (`SiteProxyOptions::default`), so legacy routes
            // behave byte-for-byte as before.
            let options = &route.options;
            // WP-24: authentication dispatch — the reserved auth paths,
            // the web session cookie and the basic authorization all run
            // before any option transform, so the authenticator sees the
            // visitor's original headers. Every auth branch answers with
            // its own response; unconfigured sites never enter here.
            if options.web_auth || options.basic_auth {
                if target.path().starts_with(auth::AUTH_PATH) {
                    // The reserved auth paths never proxy: the body is
                    // buffered here (the login form) and the reply comes
                    // straight from the authenticator — 404 for unknown
                    // auth subpaths.
                    let (parts, incoming) = request.into_parts();
                    let bytes = auth_form_body(incoming).await;
                    let cx = auth_cx(&parts, &host, peer.ip(), &bytes);
                    let site = AuthSite {
                        users: &options.site_users,
                        shared_users: options.shared_users,
                        login_style: &options.login_style,
                        cookie_name: &options.cookie_name,
                    };
                    return auth_reply(self.authenticator.handle_auth_path(&site, cx));
                }
                if let Some(response) =
                    self.authenticate(options, &request, &host, peer.ip(), &target)
                {
                    return response;
                }
            }
            // Forged identity headers go first, before anything reads them.
            identity::strip(request.headers_mut(), &options.identity);
            // Rewrites and redirects; the host parameter is the original
            // `Host` as text (empty when it is not valid UTF-8).
            let original_host_str = original_host.to_str().unwrap_or("");
            match rewrite::apply_all(&options.rewrites, target.as_str(), original_host_str) {
                Outcome::None => {}
                Outcome::Rewritten(rewritten) => {
                    // `to` is validated to start with `/`, so the parse
                    // only fails on pathological config; keep the old path.
                    if let Ok(parsed) = rewritten.parse::<PathAndQuery>() {
                        target = parsed;
                    }
                }
                Outcome::Redirect { target, code } => {
                    if let (Ok(status), Ok(location)) =
                        (StatusCode::from_u16(code), HeaderValue::from_str(&target))
                    {
                        let mut response = reply(status);
                        response.headers_mut().insert(LOCATION, location);
                        return response;
                    }
                    // An unusable target/code falls through to plain proxying.
                }
            }
            // A CORS preflight is answered here and never proxied; a
            // preflight without `Origin` is treated as a plain OPTIONS.
            if let Some(cors) = &options.cors {
                let requested = request
                    .headers()
                    .get("access-control-request-method")
                    .and_then(|value| value.to_str().ok());
                if cors::is_preflight(request.method().as_str(), requested)
                    && let Some(origin) = request
                        .headers()
                        .get("origin")
                        .and_then(|value| value.to_str().ok())
                {
                    let mut response = reply(StatusCode::OK);
                    for (name, value) in cors.preflight_headers(origin) {
                        response.headers_mut().insert(name, value);
                    }
                    return response;
                }
            }
            // WP-23 3b: retryable sites plan up to three backends, led by
            // the pool policy's pick; `attempts` never comes back empty,
            // so the plan replaces the legacy selection outright (calling
            // `select` too would burn a round-robin ticket per request).
            // The legacy path (`retry = false`) keeps exactly the selected
            // backend and behaves as before.
            if options.retry {
                let attempts = route.backends.attempts(route.health.is_some(), peer.ip());
                (route, attempts)
            } else {
                let Some(backend) = route.backends.select(route.health.is_some()) else {
                    return reply(StatusCode::SERVICE_UNAVAILABLE);
                };
                (route, vec![backend])
            }
        };
        let grpc = is_grpc(request.headers());
        if grpc && !downstream_h2 {
            return reply(StatusCode::HTTP_VERSION_NOT_SUPPORTED);
        }
        // The lead attempt stands in for the legacy single selection.
        if grpc && !route.upstream_h2c && attempts[0].scheme != Scheme::HTTPS {
            return reply(StatusCode::BAD_GATEWAY);
        }
        let (handshake, chunked) = if request.headers().contains_key(UPGRADE) {
            if downstream_h2 {
                return reply(StatusCode::BAD_REQUEST);
            }
            match Handshake::prepare(&mut request, route.websocket) {
                Ok(handshake) => (Some(handshake), false),
                Err(status) => return reply(status),
            }
        } else {
            match strip_hop_headers(request.headers_mut()) {
                Ok(chunked) => (None, chunked),
                Err(()) => return reply(StatusCode::BAD_REQUEST),
            }
        };
        // Upgrade handshakes are bound to the connection that completes
        // them, so they never retry: one backend, one attempt.
        if handshake.is_some() {
            attempts.truncate(1);
        }
        let headers = request.headers_mut();
        let forwarding_headers: Vec<_> = headers
            .keys()
            .filter(|name| is_forwarding_header(name))
            .cloned()
            .collect();
        for name in forwarding_headers {
            headers.remove(name);
        }
        // `use_target_host` keeps the legacy backend address as `Host`;
        // otherwise the visitor's original authority is passed through.
        // `original_host` is cloned because X-Forwarded-Host still needs it.
        // The template carries the lead attempt's address; the loop below
        // re-inserts it per attempt.
        headers.insert(
            HOST,
            if route.options.use_target_host {
                attempts[0].host.clone()
            } else {
                original_host.clone()
            },
        );
        if route.options.forwarded_headers {
            headers.insert("x-forwarded-host", original_host);
            headers.insert(
                "x-forwarded-proto",
                HeaderValue::from_static(if tls_identity.is_some() {
                    "https"
                } else {
                    "http"
                }),
            );
            headers.insert(
                "x-forwarded-for",
                HeaderValue::from_str(&peer.ip().to_string())
                    .expect("IP address is a header value"),
            );
        }
        headers.append(
            VIA,
            HeaderValue::from_static(if downstream_h2 {
                "2 ferrumgate"
            } else {
                "1.1 ferrumgate"
            }),
        );
        // Site-requested header edits run after the forwarded set is in
        // place, so they have the final say about what the backend sees.
        headers::apply(headers, &route.options.request_headers);
        let upstream_h2_required = handshake.is_none() && (route.upstream_h2c || grpc);
        let upstream_trailers = downstream_h2 && upstream_h2_required;
        if upstream_trailers {
            headers.insert(TE, HeaderValue::from_static("trailers"));
        }
        let body_needs_framing =
            !request.body().is_end_stream() && request.body().size_hint().exact().is_none();
        if !upstream_h2_required && (chunked || body_needs_framing) {
            request
                .headers_mut()
                .insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        }
        // A matching `Origin` earns CORS headers on every successful
        // response (regular and 101 alike); captured before the body moves.
        let cors_origin = route.options.cors.as_ref().and_then(|cors| {
            let origin = request.headers().get("origin")?;
            let origin = origin.to_str().ok()?;
            if cors.origin_allowed(origin) {
                Some(origin.to_owned())
            } else {
                None
            }
        });
        // The request template is frozen here: method, version and the
        // fully edited headers (strip, forwarding, identity, edits). Each
        // attempt clones it and only swaps the `Host`/target authority.
        let (mut template, body) = request.into_parts();
        template.version = if upstream_h2_required {
            Version::HTTP_2
        } else {
            Version::HTTP_11
        };
        // Streaming bodies cannot be resent, so they cap the plan at one
        // attempt; bodyless requests need no replay and small exact-sized
        // bodies are buffered for it.
        let mut body_plan = if attempts.len() > 1 {
            if body.is_end_stream() {
                BodyPlan::Empty
            } else if body
                .size_hint()
                .exact()
                .is_some_and(|length| length <= MAX_REPLAY_BYTES as u64)
            {
                match BodyExt::collect(body).await {
                    Ok(collected) => BodyPlan::Replay(collected.to_bytes()),
                    // The client aborted mid-body; nothing to forward.
                    Err(_) => return reply(StatusCode::BAD_REQUEST),
                }
            } else {
                attempts.truncate(1);
                BodyPlan::Stream(Some(body))
            }
        } else {
            BodyPlan::Stream(Some(body))
        };
        let deadline = route
            .options
            .response_header_timeout
            .unwrap_or(self.response_header_timeout);
        let active = route.health.is_some();
        let mut outcome = None;
        for (index, &backend) in attempts.iter().enumerate() {
            route.backends.enter(backend);
            let mut parts = template.clone();
            // `use_target_host` keeps the legacy backend address as
            // `Host`, so it follows the attempt; otherwise the visitor's
            // original authority (already in the template) passes through.
            if route.options.use_target_host {
                parts.headers.insert(HOST, backend.host.clone());
            }
            parts.uri = Uri::builder()
                .scheme(backend.scheme.clone())
                .authority(backend.authority.clone())
                .path_and_query(target.clone())
                .build()
                .expect("validated authority and origin-form target");
            let request = Request::from_parts(parts, body_plan.take_body(upstream_trailers));
            let pending = if handshake.is_some() {
                self.upgrade_client.request(request)
            } else if route.upstream_h2c {
                self.h2c_client.request(request)
            } else {
                self.client.request(request)
            };
            let result = timeout(deadline, pending).await;
            route.backends.leave(backend);
            match result {
                Ok(Ok(response)) => {
                    route.backends.connected(backend, active);
                    outcome = Some(AttemptOutcome::Served(response));
                    break;
                }
                // Only a dial failure switches backends: nothing was sent,
                // so re-issuing is safe even for POST (WP-23 step 5).
                Ok(Err(error)) if error.is_connect() && index + 1 < attempts.len() => {
                    route.backends.connection_failed(backend);
                    tracing::debug!(
                        backend = %backend.authority,
                        error = %error,
                        "upstream dial failed; retrying the next backend"
                    );
                    continue;
                }
                Ok(Err(error)) => {
                    if error.is_connect() {
                        route.backends.connection_failed(backend);
                    }
                    outcome = Some(AttemptOutcome::Failed(error));
                    break;
                }
                Err(_) => {
                    outcome = Some(AttemptOutcome::TimedOut);
                    break;
                }
            }
        }
        let outcome =
            outcome.expect("the attempt plan is never empty, so the loop always concludes");

        match outcome {
            AttemptOutcome::Served(mut response)
                if response.status() == StatusCode::SWITCHING_PROTOCOLS =>
            {
                let (Some(handshake), Some(tunnel)) = (handshake, tunnel) else {
                    return reply(StatusCode::BAD_GATEWAY);
                };
                let Ok(upgraded) = handshake.complete(&mut response) else {
                    return reply(StatusCode::BAD_GATEWAY);
                };
                if tunnel.set(upgraded).is_err() {
                    return reply(StatusCode::BAD_GATEWAY);
                }
                if let Some(origin) = cors_origin.as_deref()
                    && let Some(cors) = route.options.cors.as_ref()
                {
                    let fields = response.headers_mut();
                    for (name, value) in cors.response_headers(origin) {
                        fields.insert(name, value);
                    }
                }
                response.map(|_| Either::Right(Either::Left(Full::default())))
            }
            AttemptOutcome::Served(mut response) if !response.status().is_informational() => {
                if strip_hop_headers(response.headers_mut()).is_err() {
                    return reply(StatusCode::BAD_GATEWAY);
                }
                headers::apply(response.headers_mut(), &route.options.response_headers);
                if let Some(origin) = cors_origin.as_deref()
                    && let Some(cors) = route.options.cors.as_ref()
                {
                    let fields = response.headers_mut();
                    for (name, value) in cors.response_headers(origin) {
                        fields.insert(name, value);
                    }
                }
                let trailers = downstream_h2 && response.version() == Version::HTTP_2;
                *response.version_mut() = downstream_version;
                response.map(|body| Either::Left(DataBody::new(body, trailers)))
            }
            AttemptOutcome::Served(_) => reply(StatusCode::BAD_GATEWAY),
            AttemptOutcome::Failed(error) => {
                tracing::debug!(
                    connect_error = error.is_connect(),
                    "upstream request failed"
                );
                reply(StatusCode::BAD_GATEWAY)
            }
            AttemptOutcome::TimedOut => {
                tracing::debug!("upstream response header deadline expired");
                reply(StatusCode::GATEWAY_TIMEOUT)
            }
        }
    }

    /// WP-24: the session/basic checks for requests outside the reserved
    /// auth paths. A valid web session or basic authorization lets the
    /// request through; browsers (`Accept: text/html`) without a session
    /// are bounced to the login page with the original target riding in
    /// `next`; other clients are refused. With basic and web configured
    /// together the session wins and basic stays the fallback. Basic
    /// failures land in the failure reserve (Denied → 401 with the
    /// challenge, Locked → 429, Overloaded → 503).
    fn authenticate(
        &self,
        options: &config::SiteProxyOptions,
        request: &Request<Incoming>,
        host: &str,
        source: IpAddr,
        target: &PathAndQuery,
    ) -> Option<Reply> {
        let authenticator = &self.authenticator;
        let mut authenticated = false;
        if options.web_auth
            && let Some(value) = cookie_value(request.headers(), &options.cookie_name)
            && authenticator
                .verify_session(value, host, SystemTime::now())
                .is_some()
        {
            authenticated = true;
        }
        if !authenticated
            && options.basic_auth
            && let Some((user, pass)) = request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(auth::basic::parse_header)
        {
            // TODO(WP-24 wiring): the bcrypt verification currently
            // runs inline on the request path; move it to the
            // blocking pool when the production settings wiring
            // lands (the plan puts verification on a thread pool).
            match authenticator.check_basic(&options.site_users, source, &user, &pass) {
                BasicOutcome::Allowed(slot) => {
                    // The verification is done; the slot releases.
                    drop(slot);
                    authenticated = true;
                }
                BasicOutcome::Denied => {
                    authenticator
                        .reserve()
                        .record_failure(source, Instant::now());
                    return Some(basic_challenge(StatusCode::UNAUTHORIZED));
                }
                BasicOutcome::Locked => return Some(reply(StatusCode::TOO_MANY_REQUESTS)),
                BasicOutcome::Overloaded => {
                    return Some(reply(StatusCode::SERVICE_UNAVAILABLE));
                }
            }
        }
        if authenticated {
            return None;
        }
        // Browsers get the login page; the original target rides along
        // (encoded, so `&`/`=` inside it cannot break the query).
        if options.web_auth && accepts_html(request.headers()) {
            let next = auth::login_page::encode_next(target.as_str());
            return Some(auth_reply(auth::login_page::redirect_reply(
                &format!("{}?next={next}", auth::AUTH_PATH),
                Vec::new(),
            )));
        }
        // Non-browser refusal; with basic auth configured the challenge
        // doubles as the password prompt.
        Some(if options.basic_auth {
            basic_challenge(StatusCode::UNAUTHORIZED)
        } else {
            reply(StatusCode::UNAUTHORIZED)
        })
    }
}

/// Buffers the login-form body, capped (a login form is a few hundred
/// bytes; anything larger — or an aborted body — reads as garbage and
/// fails verification).
async fn auth_form_body(body: Incoming) -> Bytes {
    const MAX_AUTH_FORM_BYTES: usize = 64 * 1024;
    http_body_util::Limited::new(body, MAX_AUTH_FORM_BYTES)
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default()
}

/// Fills the auth context from the original request parts: cookies and
/// the same-source header come from the headers, path/query from the
/// URI. The Origin header wins over Referer for the same-source check.
fn auth_cx<'a>(
    parts: &'a hyper::http::request::Parts,
    host: &'a str,
    source: IpAddr,
    body: &'a [u8],
) -> auth::AuthCx<'a> {
    let headers = &parts.headers;
    let mut cookies = Vec::new();
    for value in headers.get_all(COOKIE) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for pair in value.split(';') {
            if let Some((name, value)) = pair.trim().split_once('=') {
                cookies.push((name, value));
            }
        }
    }
    let origin = headers
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .or_else(|| headers.get("referer").and_then(|value| value.to_str().ok()));
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    auth::AuthCx {
        method: parts.method.as_str(),
        host,
        path: parts.uri.path(),
        query: parts.uri.query().unwrap_or(""),
        source,
        body,
        cookies,
        content_type,
        origin,
    }
}

/// The first `name` cookie across every Cookie header (the value keeps
/// any `=`, so signed cookie values with base64 padding survive).
fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|cookies| {
            cookies
                .split(';')
                .filter_map(|pair| {
                    let (pair_name, pair_value) = pair.trim().split_once('=')?;
                    (pair_name == name).then_some(pair_value)
                })
                .next()
        })
}

/// Does the client present as a browser (HTML-capable Accept)?
fn accepts_html(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"))
}

/// A basic-auth challenge response.
fn basic_challenge(status: StatusCode) -> Reply {
    let mut response = reply(status);
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Basic"));
    response
}

/// Shapes an authenticator reply into a response: unknown reserved-path
/// requests fall back to the plain 404; handled replies carry the
/// status, content type, body, redirect target and every Set-Cookie.
fn auth_reply(outcome: AuthPathReply) -> Reply {
    match outcome {
        AuthPathReply::NotFound => reply(StatusCode::NOT_FOUND),
        AuthPathReply::Handled {
            status,
            content_type,
            body,
            location,
            set_cookies,
        } => {
            let Ok(status) = StatusCode::from_u16(status) else {
                return reply(StatusCode::BAD_GATEWAY);
            };
            let mut response =
                Response::new(Either::Right(Either::Left(Full::new(Bytes::from(body)))));
            *response.status_mut() = status;
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
            if !location.is_empty()
                && let Ok(value) = HeaderValue::from_str(&location)
            {
                response.headers_mut().insert(LOCATION, value);
            }
            for (name, value) in set_cookies {
                if let Ok(cookie) = HeaderValue::from_str(&format!("{name}={value}")) {
                    response.headers_mut().append(SET_COOKIE, cookie);
                }
            }
            response
        }
    }
}

pub(crate) fn strip_hop_headers(headers: &mut HeaderMap) -> Result<bool, ()> {
    // Each HTTP connection is framed independently. Hyper decodes chunked data.
    let mut encodings = headers.get_all(TRANSFER_ENCODING).iter();
    let chunked = match encodings.next() {
        None => false,
        Some(encoding)
            if encoding.as_bytes().eq_ignore_ascii_case(b"chunked")
                && encodings.next().is_none()
                && !headers.contains_key(CONTENT_LENGTH) =>
        {
            true
        }
        Some(_) => return Err(()),
    };

    let mut nominated = Vec::new();
    for value in headers.get_all(CONNECTION) {
        for field in value.to_str().map_err(|_| ())?.split(',') {
            let field = field.trim_matches([' ', '\t']);
            if field.is_empty() {
                continue;
            }
            let name = HeaderName::from_bytes(field.as_bytes()).map_err(|_| ())?;
            if matches!(name, HOST | CONTENT_LENGTH | TRANSFER_ENCODING) {
                return Err(());
            }
            nominated.push(name);
        }
    }
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        CONNECTION,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        headers.remove(name);
    }
    Ok(chunked)
}

fn reply(status: StatusCode) -> Reply {
    let mut response = Response::new(Either::Right(Either::Left(Full::new(Bytes::from_static(
        status
            .canonical_reason()
            .unwrap_or("Gateway error")
            .as_bytes(),
    )))));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn is_forwarding_header(name: &HeaderName) -> bool {
    matches!(name.as_str(), "forwarded" | "x-real-ip") || name.as_str().starts_with("x-forwarded-")
}

fn is_grpc(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let media_type = value.split(';').next().unwrap_or_default().trim();
            let (base, suffix) = media_type.split_once('+').unwrap_or((media_type, ""));
            base.eq_ignore_ascii_case("application/grpc")
                && (media_type == base || !suffix.is_empty())
        })
}

/// How the attempt loop concluded (WP-23 3b). `Served` carries the first
/// response the pool produced; the failure variants mirror the two error
/// branches of the legacy single-attempt send.
enum AttemptOutcome {
    Served(Response<Incoming>),
    Failed(SendError),
    TimedOut,
}

/// One request's upstream body across attempts. A streaming body is
/// single-shot (callers cap the plan at one attempt), an empty body needs
/// nothing, and a small buffered body is replayed per backend.
enum BodyPlan {
    Stream(Option<Incoming>),
    Replay(Bytes),
    Empty,
}

impl BodyPlan {
    /// Builds the body for one attempt. The stream slot is taken at most
    /// once — streaming requests never retry.
    fn take_body(&mut self, trailers: bool) -> RequestBody {
        match self {
            Self::Stream(slot) => RequestBody::Data(DataBody::new(
                slot.take().expect("streaming bodies are single-shot"),
                trailers,
            )),
            // `Bytes` clones are reference-counted, so each attempt gets
            // an independent cursor over the same buffer.
            Self::Replay(bytes) => RequestBody::Replay(ReplayBody::new(bytes.clone())),
            Self::Empty => RequestBody::Empty(Empty::new()),
        }
    }
}

pub(crate) struct DataBody {
    inner: Incoming,
    trailers: bool,
}

impl DataBody {
    fn new(inner: Incoming, trailers: bool) -> Self {
        Self { inner, trailers }
    }
}

impl Body for DataBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        loop {
            match std::task::ready!(Pin::new(&mut self.inner).poll_frame(cx)) {
                Some(Ok(frame)) if frame.is_trailers() => {
                    if self.trailers {
                        let mut fields = frame.into_trailers().expect("trailer frame");
                        if strip_hop_headers(&mut fields).is_ok() {
                            for name in [
                                HOST,
                                CONTENT_LENGTH,
                                CONTENT_TYPE,
                                hyper::header::AUTHORIZATION,
                                hyper::header::COOKIE,
                                hyper::header::SET_COOKIE,
                                hyper::header::CONTENT_ENCODING,
                            ] {
                                fields.remove(name);
                            }
                            let forwarding: Vec<_> = fields
                                .keys()
                                .filter(|name| is_forwarding_header(name))
                                .cloned()
                                .collect();
                            for name in forwarding {
                                fields.remove(name);
                            }
                            return Poll::Ready(Some(Ok(Frame::trailers(fields))));
                        }
                    }
                }
                frame => return Poll::Ready(frame),
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Body for RequestBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        match &mut *self {
            Self::Data(inner) => Pin::new(inner).poll_frame(cx),
            Self::Replay(inner) => Pin::new(inner).poll_frame(cx),
            // `Empty` never fails: its infallible error coerces away.
            Self::Empty(inner) => Pin::new(inner)
                .poll_frame(cx)
                .map(|frame| frame.map(|result| result.map_err(|never| match never {}))),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Data(inner) => inner.is_end_stream(),
            Self::Replay(inner) => inner.sent,
            Self::Empty(inner) => inner.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Data(inner) => inner.size_hint(),
            Self::Replay(inner) => inner.size_hint(),
            Self::Empty(inner) => inner.size_hint(),
        }
    }
}

/// A buffered request body (WP-23 3b): the whole payload in the first
/// frame, nothing afterwards. The attempt loop clones the shared `Bytes`
/// per backend, so a dial failure can resend the identical payload.
pub(crate) struct ReplayBody {
    bytes: Bytes,
    sent: bool,
}

impl ReplayBody {
    fn new(bytes: Bytes) -> Self {
        Self { bytes, sent: false }
    }
}

impl Body for ReplayBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.sent {
            return Poll::Ready(None);
        }
        self.sent = true;
        Poll::Ready(Some(Ok(Frame::data(std::mem::take(&mut self.bytes)))))
    }

    fn is_end_stream(&self) -> bool {
        self.sent
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(if self.sent {
            0
        } else {
            u64::try_from(self.bytes.len()).expect("body length fits u64")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_all_connection_values_and_only_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.append(CONNECTION, HeaderValue::from_static("X-A, keep-alive"));
        headers.append(CONNECTION, HeaderValue::from_static("X-B"));
        headers.insert("x-a", HeaderValue::from_static("hop header"));
        headers.insert("x-b", HeaderValue::from_static("hop header"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=3"));
        headers.insert(
            PROXY_AUTHORIZATION,
            HeaderValue::from_static("local credential"),
        );
        headers.insert("x-app", HeaderValue::from_static("end to end"));

        assert_eq!(strip_hop_headers(&mut headers), Ok(false));
        assert_eq!(headers.len(), 1);
        assert_eq!(headers["x-app"], "end to end");
    }

    #[test]
    fn only_accepts_supported_transfer_framing() {
        let mut headers = HeaderMap::new();
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        assert_eq!(strip_hop_headers(&mut headers), Ok(true));
        assert!(!headers.contains_key(TRANSFER_ENCODING));

        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("gzip, chunked"));
        assert!(strip_hop_headers(&mut headers).is_err());

        headers.clear();
        headers.insert(CONNECTION, HeaderValue::from_static("content-length"));
        assert!(strip_hop_headers(&mut headers).is_err());
    }
}

// WP-23 per-site options are compiled by `web::bridge` (pub(crate)) and
// consumed here, so the end-to-end forwarding tests live in the shared
// workspace harness file `tests/gateway/wp23_options.rs` and are compiled
// into this crate's unit-test binary via `#[path]`.
#[cfg(test)]
#[path = "../../../tests/gateway/wp23_options.rs"]
mod wp23_options;

// WP-23 3b: dial-failure retry and the load policies, exercised the same
// way (`tests/gateway/wp23_retry.rs`, crate-private pipeline).
#[cfg(test)]
#[path = "../../../tests/gateway/wp23_retry.rs"]
mod wp23_retry;

// WP-24 batch 3: the authentication pipeline — reserved paths, login
// flow, session binding, basic auth — driven end-to-end through
// `Proxy::forward` the same way (`tests/gateway/wp24_auth.rs`).
#[cfg(test)]
#[path = "../../../tests/gateway/wp24_auth.rs"]
mod wp24_auth;
