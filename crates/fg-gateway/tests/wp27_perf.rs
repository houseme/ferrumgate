//! Integration tests for WP-27 (Web Performance: Compression, Rate Limiting,
//! Response Cache & Error Pages).

use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri, header},
    response::Response,
    routing::get,
};
use flate2::read::GzDecoder;
use http_body_util::{BodyExt, Full};
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use serde_json::Value;
use tempfile::TempDir;
use tokio::sync::Notify;

use fg_gateway::web::{
    cache::{
        CacheConfig, CacheKey, CacheRegistry, CacheRule, Entry, OwnCookiePolicy, ResponseCache,
        X_CACHE, apply_cache_hit_headers, apply_cache_miss_header, apply_cors_headers,
        compute_freshness, is_request_cacheable, is_response_cacheable, mount_cache_routes,
        response_varies_on_origin, select_rule, strip_cors_headers,
    },
    compress::{CompressConfig, compress_response},
    error_pages::{
        ERROR_PAGE_CSP, ErrorPageOptions, ErrorPageStore, MAX_CUSTOM_PAGES, RequestMeta, Source,
        StatusSpec, StyleId, intercept_backend_error, mount_error_page_routes,
        render_error_response, resolve_error_page_options,
    },
    proxy::cors::Cors,
    rate_limit::{Limiter, RateLimit, RateLimited, too_many_requests_response},
};

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn hv(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).unwrap()
}

/// Sends a real HTTP/1.1 request to an Axum `Router` over an in-memory duplex
/// stream (no OS socket bind required) and returns `(status, headers, body)`.
async fn send_http(
    app: &Router,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: impl Into<Bytes>,
) -> (StatusCode, HeaderMap, Bytes) {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let svc = TowerToHyperService::new(app.clone());
    tokio::spawn(async move {
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(server_io), svc)
            .await;
    });

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "127.0.0.1");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Full::new(body.into())).unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let resp_body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, resp_headers, resp_body)
}

fn gunzip(data: &[u8]) -> Vec<u8> {
    let mut decoder = GzDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).unwrap();
    out
}

// ---------------------------------------------------------------------------
// 1. Compression integration tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn compress_skips_short_and_pre_encoded() {
    let cfg = CompressConfig { enabled: true };
    let mut req_headers = HeaderMap::new();
    req_headers.insert(header::ACCEPT_ENCODING, hv("br, gzip"));

    // 255 bytes -> NOT compressed.
    let short_body = "a".repeat(255);
    let resp_short = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, "255")
        .body(Body::from(short_body.clone()))
        .unwrap();
    let out_short = compress_response(&cfg, &req_headers, resp_short).await;
    assert!(out_short.headers().get(header::CONTENT_ENCODING).is_none());
    let out_short_bytes = out_short.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(out_short_bytes.as_ref(), short_body.as_bytes());

    // 256 bytes -> compressed with gzip (and decompresses back verbatim).
    let ok_body = "a".repeat(256);
    let resp_ok = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(ok_body.clone()))
        .unwrap();
    let out_ok = compress_response(&cfg, &req_headers, resp_ok).await;
    assert_eq!(
        out_ok.headers().get(header::CONTENT_ENCODING).unwrap(),
        "gzip"
    );
    let compressed_bytes = out_ok.into_body().collect().await.unwrap().to_bytes();
    assert!(compressed_bytes.len() < ok_body.len());
    assert_eq!(gunzip(&compressed_bytes), ok_body.as_bytes());

    // Already encoded (`Content-Encoding: br`) -> left untouched.
    let pre_body = Bytes::from(vec![0x42u8; 512]);
    let resp_pre = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html")
        .header(header::CONTENT_ENCODING, "br")
        .body(Body::from(pre_body.clone()))
        .unwrap();
    let out_pre = compress_response(&cfg, &req_headers, resp_pre).await;
    assert_eq!(
        out_pre.headers().get(header::CONTENT_ENCODING).unwrap(),
        "br"
    );
    let out_pre_bytes = out_pre.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(out_pre_bytes, pre_body);
}

#[tokio::test]
async fn compress_weakens_strong_etag() {
    let cfg = CompressConfig { enabled: true };
    let mut req_headers = HeaderMap::new();
    req_headers.insert(header::ACCEPT_ENCODING, hv("gzip"));

    let payload = "hello world ".repeat(64);
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ETAG, "\"strong-v1\"")
        .body(Body::from(payload.clone()))
        .unwrap();

    let out = compress_response(&cfg, &req_headers, resp).await;
    assert_eq!(out.headers().get(header::CONTENT_ENCODING).unwrap(), "gzip");
    assert_eq!(out.headers().get(header::ETAG).unwrap(), "W/\"strong-v1\"");
    assert!(
        out.headers()
            .get_all(header::VARY)
            .iter()
            .any(|v| v.to_str().unwrap().eq_ignore_ascii_case("accept-encoding"))
    );
    let body = out.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(gunzip(&body), payload.as_bytes());
}

#[tokio::test]
async fn compress_passes_websocket_upgrade() {
    let cfg = CompressConfig { enabled: true };
    let mut req_headers = HeaderMap::new();
    req_headers.insert(header::ACCEPT_ENCODING, hv("gzip"));
    req_headers.insert(header::CONNECTION, hv("Upgrade"));
    req_headers.insert(header::UPGRADE, hv("websocket"));

    let body_text = "x".repeat(512);
    let resp = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(body_text.clone()))
        .unwrap();

    let out = compress_response(&cfg, &req_headers, resp).await;
    assert_eq!(out.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert!(out.headers().get(header::CONTENT_ENCODING).is_none());
    let bytes = out.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(bytes.as_ref(), body_text.as_bytes());
}

// ---------------------------------------------------------------------------
// 2. Rate limiting integration tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn limiter_max_conns_released_on_finish() {
    let limiter = Limiter::try_new(RateLimit {
        rate: None,
        burst: 0,
        max_conns: 1,
    })
    .unwrap();
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

    // Normal completion releases the concurrency slot.
    {
        let _p1 = limiter.acquire(ip, at(1000)).unwrap();
        assert_eq!(limiter.active_conns(ip), 1);
        assert_eq!(
            limiter.acquire(ip, at(1000)).err(),
            Some(RateLimited::MaxConnsExceeded)
        );
        let resp = too_many_requests_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
    assert_eq!(limiter.active_conns(ip), 0);

    // Simulated mid-flight client disconnect (task aborted while holding Permit).
    let acquired = Arc::new(Notify::new());
    let acquired_bg = Arc::clone(&acquired);
    let limiter_bg = limiter.clone();
    let handle = tokio::spawn(async move {
        let _permit = limiter_bg.acquire(ip, at(1001)).unwrap();
        acquired_bg.notify_one();
        // Hold indefinitely until aborted (simulates stalled request dropped on disconnect).
        std::future::pending::<()>().await;
    });
    acquired.notified().await;
    assert_eq!(limiter.active_conns(ip), 1);
    assert_eq!(
        limiter.acquire(ip, at(1001)).err(),
        Some(RateLimited::MaxConnsExceeded)
    );

    handle.abort();
    let _ = handle.await;
    assert_eq!(limiter.active_conns(ip), 0);

    // Slot is immediately available again.
    let _p2 = limiter.acquire(ip, at(1002)).unwrap();
    assert_eq!(limiter.active_conns(ip), 1);
}

// ---------------------------------------------------------------------------
// 3. Response cache integration tests
// ---------------------------------------------------------------------------

#[test]
fn cache_hit_miss_headers() {
    let cfg = CacheConfig {
        enabled: true,
        ttl: Duration::from_secs(60),
        max_mb: 1,
        rules: Vec::new(),
    };
    let cache = ResponseCache::new(&cfg);
    let key = CacheKey::new("example.com", "/hello", "gzip", None, Vec::new());

    // First lookup -> miss.
    assert!(cache.lookup(&key, at(1000)).is_none());
    let mut miss_headers = HeaderMap::new();
    apply_cache_miss_header(&mut miss_headers);
    assert_eq!(miss_headers.get(&X_CACHE).unwrap(), "MISS");
    assert!(miss_headers.get(header::AGE).is_none());

    // Store backend 200 response.
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::CONTENT_TYPE, hv("text/plain"));
    assert!(is_response_cacheable(
        StatusCode::OK,
        &resp_headers,
        false,
        false
    ));
    let ttl = compute_freshness(&resp_headers, cfg.ttl, None).unwrap();
    assert!(cache.store(
        key.clone(),
        Entry {
            status: StatusCode::OK,
            headers: resp_headers,
            body: Bytes::from_static(b"cached-body"),
            stored_at: at(1000),
            ttl,
            vary_origin: false,
        },
        at(1000),
    ));

    // Second lookup 17 seconds later -> HIT with Age: 17.
    let (entry, age) = cache.lookup(&key, at(1017)).expect("cache hit");
    assert_eq!(entry.body, Bytes::from_static(b"cached-body"));
    assert_eq!(age, 17);
    let mut hit_headers = entry.headers.clone();
    apply_cache_hit_headers(&mut hit_headers, age);
    assert_eq!(hit_headers.get(&X_CACHE).unwrap(), "HIT");
    assert_eq!(hit_headers.get(header::AGE).unwrap(), "17");
}

#[test]
fn cache_key_separates_users_and_identity() {
    let cache = ResponseCache::with_max_bytes(true, 1024 * 1024);
    let t0 = at(2000);

    let key_alice = CacheKey::new(
        "app.example.com",
        "/me",
        "gzip",
        Some("backend-a".to_owned()),
        vec![("X-Auth-User".to_owned(), "alice".to_owned())],
    );
    let key_bob = CacheKey::new(
        "app.example.com",
        "/me",
        "gzip",
        Some("backend-a".to_owned()),
        vec![("X-Auth-User".to_owned(), "bob".to_owned())],
    );
    let key_alice_other_route = CacheKey::new(
        "app.example.com",
        "/me",
        "gzip",
        Some("backend-b".to_owned()),
        vec![("X-Auth-User".to_owned(), "alice".to_owned())],
    );

    cache.store(
        key_alice.clone(),
        Entry {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"alice-secret"),
            stored_at: t0,
            ttl: Duration::from_secs(60),
            vary_origin: false,
        },
        t0,
    );

    assert_eq!(
        cache.lookup(&key_alice, at(2001)).unwrap().0.body,
        Bytes::from_static(b"alice-secret")
    );
    assert!(cache.lookup(&key_bob, at(2001)).is_none());
    assert!(cache.lookup(&key_alice_other_route, at(2001)).is_none());
}

#[test]
fn cache_rule_no_cache_ttl_override() {
    let rules = vec![
        CacheRule {
            path: "/".to_owned(),
            no_cache: true,
            ttl: None,
            override_: false,
        },
        CacheRule {
            path: "/public/*".to_owned(),
            no_cache: false,
            ttl: Some(Duration::from_secs(120)),
            override_: false,
        },
        CacheRule {
            path: "/force/*".to_owned(),
            no_cache: false,
            ttl: Some(Duration::from_secs(300)),
            override_: true,
        },
    ];
    let site_ttl = Duration::from_secs(30);

    // Unmatched path hits `/` with no_cache -> freshness is None.
    let r_root = select_rule(&rules, "/admin/panel").unwrap();
    assert!(r_root.no_cache);
    assert_eq!(
        compute_freshness(&HeaderMap::new(), site_ttl, Some(r_root)),
        None
    );

    // `/public/img.png` uses rule TTL 120s.
    let r_pub = select_rule(&rules, "/public/img.png").unwrap();
    assert_eq!(
        compute_freshness(&HeaderMap::new(), site_ttl, Some(r_pub)),
        Some(Duration::from_secs(120))
    );

    // `/force/doc` with override=true caches `no-store` & `no-cache` with 300s,
    // ignoring upstream `max-age=5`, but STILL refuses `private` and `Set-Cookie`.
    let r_force = select_rule(&rules, "/force/doc").unwrap();
    assert!(r_force.override_);

    let mut no_store = HeaderMap::new();
    no_store.insert(header::CACHE_CONTROL, hv("no-store, max-age=5"));
    assert!(is_response_cacheable(
        StatusCode::OK,
        &no_store,
        false,
        r_force.override_
    ));
    assert_eq!(
        compute_freshness(&no_store, site_ttl, Some(r_force)),
        Some(Duration::from_secs(300))
    );

    let mut private = HeaderMap::new();
    private.insert(header::CACHE_CONTROL, hv("private, max-age=60"));
    assert!(!is_response_cacheable(
        StatusCode::OK,
        &private,
        false,
        r_force.override_
    ));

    let mut set_cookie = HeaderMap::new();
    set_cookie.insert(header::SET_COOKIE, hv("sid=1"));
    assert!(!is_response_cacheable(
        StatusCode::OK,
        &set_cookie,
        false,
        r_force.override_
    ));
}

#[test]
fn cache_cors_headers_regenerated_on_hit() {
    let cors = Cors {
        allow_origins: vec![
            "https://a.example.com".to_owned(),
            "https://b.example.com".to_owned(),
        ],
        allow_methods: vec!["GET".to_owned()],
        allow_headers: vec!["X-Custom".to_owned()],
        allow_credentials: true,
        max_age_secs: 600,
    };
    let cache = ResponseCache::with_max_bytes(true, 1024 * 1024);
    let t0 = at(3000);
    let key = CacheKey::new("api.example.com", "/items", "identity", None, Vec::new());

    // Simulate backend response + site CORS applied for Origin A, then stripped before caching.
    let mut stored_headers = HeaderMap::new();
    stored_headers.insert(header::CONTENT_TYPE, hv("application/json"));
    apply_cors_headers(&mut stored_headers, &cors, Some("https://a.example.com"));
    assert_eq!(
        stored_headers
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://a.example.com"
    );

    strip_cors_headers(&mut stored_headers);
    assert!(
        stored_headers
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );
    assert!(is_response_cacheable(
        StatusCode::OK,
        &stored_headers,
        true,
        false
    ));
    let vary_origin = response_varies_on_origin(&stored_headers);
    assert!(vary_origin);

    cache.store(
        key.clone(),
        Entry {
            status: StatusCode::OK,
            headers: stored_headers,
            body: Bytes::from_static(b"{\"ok\":true}"),
            stored_at: t0,
            ttl: Duration::from_secs(60),
            vary_origin,
        },
        t0,
    );

    // Hit from Origin B regenerates Origin B's CORS headers.
    let (entry, age) = cache.lookup(&key, at(3010)).unwrap();
    let mut resp_b = entry.headers.clone();
    apply_cors_headers(&mut resp_b, &cors, Some("https://b.example.com"));
    apply_cache_hit_headers(&mut resp_b, age);
    assert_eq!(
        resp_b.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
        "https://b.example.com"
    );
    assert_eq!(resp_b.get(&X_CACHE).unwrap(), "HIT");

    // Hit from disallowed Origin C produces NO Access-Control-Allow-Origin.
    let mut resp_c = entry.headers.clone();
    apply_cors_headers(&mut resp_c, &cors, Some("https://evil.example.com"));
    assert!(resp_c.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
}

#[tokio::test]
async fn cache_purge_by_path_and_all() {
    let registry = Arc::new(CacheRegistry::new());
    let enabled_cache = Arc::new(ResponseCache::with_max_bytes(true, 1024 * 1024));
    let disabled_cache = Arc::new(ResponseCache::with_max_bytes(false, 1024 * 1024));

    let t0 = at(4000);
    for path in ["/api/v1", "/api/v2", "/static/app.js", "/static/style.css"] {
        enabled_cache.store(
            CacheKey::new("example.com", path, "gzip", None, Vec::new()),
            Entry {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"payload"),
                stored_at: t0,
                ttl: Duration::from_secs(300),
                vary_origin: false,
            },
            t0,
        );
    }

    registry.register("web", "default", Arc::clone(&enabled_cache));
    registry.register("web", "nocache", Arc::clone(&disabled_cache));

    let app = mount_cache_routes(Router::new(), registry);

    // 404 when listener or site does not exist.
    let (status, _, _) = send_http(
        &app,
        Method::GET,
        "/api/webservice/cache?listener=missing&site=default",
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // 200 status for default site (omitting `site` defaults to "default").
    let (status, _, body) = send_http(
        &app,
        Method::GET,
        "/api/webservice/cache?listener=web",
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["enabled"], true);
    assert_eq!(v["entries"], 4);
    assert_eq!(v["maxBytes"], 1024 * 1024);

    // 400 when purging a site with caching disabled.
    let (status, _, _) = send_http(
        &app,
        Method::POST,
        "/api/webservice/cache/purge",
        &[("content-type", "application/json")],
        r#"{"listener":"web","site":"nocache","path":""}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Purge by path prefix `/api` -> removes 2 entries, leaves 2.
    let (status, _, body) = send_http(
        &app,
        Method::POST,
        "/api/webservice/cache/purge",
        &[("content-type", "application/json")],
        r#"{"listener":"web","site":"default","path":"/api"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["removed"], 2);
    assert_eq!(v["entries"], 2);

    // Purge by wildcard `/static/*.js` -> removes 1 entry, leaves 1.
    let (status, _, body) = send_http(
        &app,
        Method::POST,
        "/api/webservice/cache/purge",
        &[("content-type", "application/json")],
        r#"{"listener":"web","site":"default","path":"/static/*.js"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["removed"], 1);
    assert_eq!(v["entries"], 1);

    // Empty path purges remaining entries.
    let (status, _, body) = send_http(
        &app,
        Method::POST,
        "/api/webservice/cache/purge",
        &[("content-type", "application/json")],
        r#"{"listener":"web","site":"default","path":""}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["removed"], 1);
    assert_eq!(v["entries"], 0);
    assert_eq!(v["bytes"], 0);
}

// ---------------------------------------------------------------------------
// 4. Error pages integration tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn error_page_rendered_for_browser_only() {
    let opts = ErrorPageOptions {
        style: StyleId::Terminal,
        custom: None,
        intercept: Vec::new(),
    };

    // Browser receives HTML error page.
    let mut browser_hdrs = HeaderMap::new();
    browser_hdrs.insert(header::ACCEPT, hv("text/html,application/xhtml+xml"));
    browser_hdrs.insert(header::ACCEPT_LANGUAGE, hv("zh-CN,zh;q=0.9"));
    let resp = render_error_response(
        &opts,
        None,
        &RequestMeta {
            method: &Method::GET,
            headers: &browser_hdrs,
            host: "app.example.com",
            path: "/api",
            now: at(1_700_000_000),
        },
        StatusCode::BAD_GATEWAY,
    );
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert!(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    let html = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("data-style=\"terminal\""));
    assert!(html.contains("502"));
    assert!(html.contains("网关错误"));

    // curl (`Accept: */*`) receives plain text.
    let mut curl_hdrs = HeaderMap::new();
    curl_hdrs.insert(header::ACCEPT, hv("*/*"));
    let resp_curl = render_error_response(
        &opts,
        None,
        &RequestMeta {
            method: &Method::GET,
            headers: &curl_hdrs,
            host: "app.example.com",
            path: "/api",
            now: at(1_700_000_000),
        },
        StatusCode::BAD_GATEWAY,
    );
    assert_eq!(resp_curl.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        resp_curl.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain; charset=utf-8"
    );
    let text = String::from_utf8(
        resp_curl
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(text, "502 Bad Gateway\n");
}

#[tokio::test]
async fn default_site_error_page_used_for_unknown_host() {
    // Even when the default site is disabled, its error-page options serve 404
    // for requests whose Host matches no site.
    let default_site_opts = ErrorPageOptions {
        style: StyleId::Neon,
        custom: None,
        intercept: Vec::new(),
    };
    let resolved = resolve_error_page_options(None, Some(&default_site_opts));
    assert_eq!(resolved.style, StyleId::Neon);

    let mut browser_hdrs = HeaderMap::new();
    browser_hdrs.insert(header::ACCEPT, hv("text/html"));
    let resp = render_error_response(
        resolved,
        None,
        &RequestMeta {
            method: &Method::GET,
            headers: &browser_hdrs,
            host: "unknown.example.com",
            path: "/missing",
            now: at(1_700_000_000),
        },
        StatusCode::NOT_FOUND,
    );
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("data-style=\"neon\""));
    assert!(body.contains("unknown.example.com"));
}

#[tokio::test]
async fn intercept_backend_errors_html_only() {
    let opts = ErrorPageOptions {
        style: StyleId::Blueprint,
        custom: None,
        intercept: StatusSpec::parse_list("404, 5xx").unwrap(),
    };

    let mut backend_headers = HeaderMap::new();
    backend_headers.insert(header::CONTENT_TYPE, hv("application/json"));
    backend_headers.insert(header::CONTENT_ENCODING, hv("gzip"));
    backend_headers.insert(header::ETAG, hv("\"backend-etag\""));
    backend_headers.insert(header::RETRY_AFTER, hv("30"));
    backend_headers.append(header::SET_COOKIE, hv("a=1; Path=/"));
    backend_headers.append(header::SET_COOKIE, hv("b=2; Path=/"));

    // JSON client (`Accept: application/json`) -> NOT intercepted (returns None).
    let mut json_req = HeaderMap::new();
    json_req.insert(header::ACCEPT, hv("application/json"));
    assert!(
        intercept_backend_error(
            &opts,
            None,
            &RequestMeta {
                method: &Method::GET,
                headers: &json_req,
                host: "api.example.com",
                path: "/v1/item",
                now: at(1_700_000_000),
            },
            StatusCode::NOT_FOUND,
            &backend_headers,
        )
        .is_none()
    );

    // Browser GET 503 -> intercepted, strips body-describing headers, keeps Set-Cookie & Retry-After.
    let mut html_req = HeaderMap::new();
    html_req.insert(header::ACCEPT, hv("text/html"));
    let intercepted = intercept_backend_error(
        &opts,
        None,
        &RequestMeta {
            method: &Method::GET,
            headers: &html_req,
            host: "api.example.com",
            path: "/v1/item",
            now: at(1_700_000_000),
        },
        StatusCode::SERVICE_UNAVAILABLE,
        &backend_headers,
    )
    .expect("must intercept browser 503");

    assert_eq!(intercepted.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        intercepted
            .headers()
            .get(header::CONTENT_ENCODING)
            .is_none()
    );
    assert!(intercepted.headers().get(header::ETAG).is_none());
    assert_eq!(
        intercepted.headers().get(header::RETRY_AFTER).unwrap(),
        "30"
    );
    let cookies: Vec<&str> = intercepted
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(cookies, vec!["a=1; Path=/", "b=2; Path=/"]);
    let body = String::from_utf8(
        intercepted
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("data-style=\"blueprint\""));
    assert!(body.contains("503"));

    // Browser HEAD 404 -> intercepted headers only, empty body.
    let head_resp = intercept_backend_error(
        &opts,
        None,
        &RequestMeta {
            method: &Method::HEAD,
            headers: &html_req,
            host: "api.example.com",
            path: "/v1/item",
            now: at(1_700_000_000),
        },
        StatusCode::NOT_FOUND,
        &backend_headers,
    )
    .expect("must intercept browser HEAD 404");
    assert_eq!(head_resp.status(), StatusCode::NOT_FOUND);
    assert!(
        head_resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    let head_body = head_resp.into_body().collect().await.unwrap().to_bytes();
    assert!(head_body.is_empty());
}

#[tokio::test]
async fn sanitize_output_has_sandbox_csp() {
    let store = Arc::new(ErrorPageStore::new());
    let created = store
        .create(Source::Inline {
            name: "custom-ops".to_owned(),
            html: r#"<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head><body onclick="evil()"><script>alert(1)</script><h1>Custom {code} on {path}</h1></body></html>"#.to_owned(),
        })
        .unwrap();
    assert!(created.removed.iter().any(|r| r == "<script>"));
    assert!(created.removed.iter().any(|r| r == "on* event attribute"));

    let opts = ErrorPageOptions {
        style: StyleId::Minimal,
        custom: Some(created.key.clone()),
        intercept: Vec::new(),
    };
    let mut browser = HeaderMap::new();
    browser.insert(header::ACCEPT, hv("text/html"));
    let resp = render_error_response(
        &opts,
        Some(&store),
        &RequestMeta {
            method: &Method::GET,
            headers: &browser,
            host: "site.example.com",
            path: "/<b>bad</b>",
            now: at(1_700_000_000),
        },
        StatusCode::NOT_FOUND,
    );
    assert_eq!(
        resp.headers().get(header::CONTENT_SECURITY_POLICY).unwrap(),
        ERROR_PAGE_CSP
    );
    let html = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(!html.contains("<script>"));
    assert!(!html.contains("onclick="));
    assert!(html.contains("Custom 404 on /&lt;b&gt;bad&lt;/b&gt;"));

    // Also verify the management API routes (/styles, /check, /preview, CRUD).
    let app = mount_error_page_routes(Router::new(), Arc::clone(&store));

    let (status, hdrs, body) = send_http(
        &app,
        Method::GET,
        &format!("/api/webservice/errorpages/{}/preview", created.key),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        hdrs.get(header::CONTENT_SECURITY_POLICY).unwrap(),
        ERROR_PAGE_CSP
    );
    assert!(String::from_utf8_lossy(&body).contains("Custom 502"));

    let (status, _, body) = send_http(
        &app,
        Method::GET,
        "/api/webservice/errorpages/styles",
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let styles: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(styles.as_array().unwrap().len(), 10);

    let (status, _, body) = send_http(
        &app,
        Method::POST,
        "/api/webservice/errorpages/check",
        &[("content-type", "application/json")],
        r#"{"html":"<html><body><script>x()</script><p>{code}</p></body></html>"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let checked: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        checked["removed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "<script>")
    );
}

#[tokio::test]
async fn custom_page_from_file_reloads_on_change() {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("err.html");
    std::fs::write(
        &file_path,
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head><body><h1>V1 {code}</h1></body></html>"#,
    )
    .unwrap();

    let store = ErrorPageStore::new();
    let view = store
        .create(Source::File {
            name: "from-disk".to_owned(),
            path: file_path.clone(),
        })
        .unwrap();
    assert!(view.available);

    let opts = ErrorPageOptions {
        style: StyleId::Minimal,
        custom: Some(view.key.clone()),
        intercept: Vec::new(),
    };
    let mut browser = HeaderMap::new();
    browser.insert(header::ACCEPT, hv("text/html"));

    // Serve V1.
    let resp1 = render_error_response(
        &opts,
        Some(&store),
        &RequestMeta {
            method: &Method::GET,
            headers: &browser,
            host: "example.com",
            path: "/",
            now: at(1_700_000_000),
        },
        StatusCode::BAD_GATEWAY,
    );
    let body1 = String::from_utf8(
        resp1
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body1.contains("V1 502"));

    // Overwrite file with different length + active script -> reloads and sanitizes automatically!
    std::fs::write(
        &file_path,
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head><body><script>bad()</script><h1>V2 UPDATED {code}</h1></body></html>"#,
    )
    .unwrap();
    let resp2 = render_error_response(
        &opts,
        Some(&store),
        &RequestMeta {
            method: &Method::GET,
            headers: &browser,
            host: "example.com",
            path: "/",
            now: at(1_700_000_001),
        },
        StatusCode::BAD_GATEWAY,
    );
    let body2 = String::from_utf8(
        resp2
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body2.contains("V2 UPDATED 502"));
    assert!(!body2.contains("<script>"));

    // Delete file -> falls back to default built-in style and marks page unavailable!
    std::fs::remove_file(&file_path).unwrap();
    let resp3 = render_error_response(
        &opts,
        Some(&store),
        &RequestMeta {
            method: &Method::GET,
            headers: &browser,
            host: "example.com",
            path: "/",
            now: at(1_700_000_002),
        },
        StatusCode::BAD_GATEWAY,
    );
    let body3 = String::from_utf8(
        resp3
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body3.contains("data-style=\"minimal\""));
    assert!(!store.get(&view.key).unwrap().available);

    // Non-HTML file rejected.
    let txt_path = dir.path().join("notes.txt");
    std::fs::write(&txt_path, "<html><body>hi</body></html>").unwrap();
    assert!(
        store
            .create(Source::File {
                name: "bad-ext".to_owned(),
                path: txt_path,
            })
            .is_err()
    );

    // Library enforces max 32 pages.
    let cap_store = ErrorPageStore::new();
    for i in 0..MAX_CUSTOM_PAGES {
        cap_store
            .create(Source::Inline {
                name: format!("p{i}"),
                html: "<html><body>{code}</body></html>".to_owned(),
            })
            .unwrap();
    }
    assert!(
        cap_store
            .create(Source::Inline {
                name: "overflow".to_owned(),
                html: "<html><body>{code}</body></html>".to_owned(),
            })
            .is_err()
    );
}

#[test]
fn cache_request_check_smoke_with_uri_and_headers() {
    let uri: Uri = "/static/bundle.js".parse().unwrap();
    assert!(is_request_cacheable(
        &Method::GET,
        &uri,
        &HeaderMap::new(),
        &OwnCookiePolicy::default()
    ));
}

#[tokio::test]
async fn error_pages_crud_routes_end_to_end() {
    let store = Arc::new(ErrorPageStore::new());
    let app = mount_error_page_routes(
        Router::new().route("/health", get(|| async { "ok" })),
        store,
    );

    // Create.
    let (status, _, body) = send_http(
        &app,
        Method::POST,
        "/api/webservice/errorpages",
        &[("content-type", "application/json")],
        r#"{"sourceType":"inline","name":"brand","html":"<html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"></head><body>{code}</body></html>"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: Value = serde_json::from_slice(&body).unwrap();
    let key = created["key"].as_str().unwrap().to_owned();
    assert_eq!(created["name"], "brand");

    // List.
    let (status, _, body) = send_http(
        &app,
        Method::GET,
        "/api/webservice/errorpages",
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let list: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);

    // Update.
    let (status, _, body) = send_http(
        &app,
        Method::PUT,
        &format!("/api/webservice/errorpages/{key}"),
        &[("content-type", "application/json")],
        r#"{"sourceType":"inline","name":"brand-v2","html":"<html><body>{code} updated</body></html>"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let updated: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(updated["name"], "brand-v2");

    // Delete.
    let (status, _, body) = send_http(
        &app,
        Method::DELETE,
        &format!("/api/webservice/errorpages/{key}"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let deleted: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(deleted["removed"], 1);

    // Second delete -> 404.
    let (status, _, _) = send_http(
        &app,
        Method::DELETE,
        &format!("/api/webservice/errorpages/{key}"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
