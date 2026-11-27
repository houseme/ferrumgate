//! WP-23 per-site proxy options, driven end-to-end through
//! [`Proxy::forward`]: identity stripping, rewrites/redirects, CORS,
//! header edits, the Host switch, the forwarded-header switch and the
//! per-site response header deadline.
//!
//! The options are produced by `web::bridge` from a [`Site`] (same shape
//! the webservice model compiles), so each test builds a `Site` with
//! `..Site::default()` and assigns the option fields directly. The file
//! sits next to the shared `tests/gateway/` harness, but it is compiled
//! into the `fg-gateway` unit-test binary (`cargo test -p fg-gateway`)
//! through the `#[path]` module declared at the bottom of `src/proxy.rs`;
//! the options pipeline is crate-private (`pub(crate)` bridge, private
//! proxy module), so a standalone integration target could not reach it.

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{
    HeaderMap, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};

use super::Proxy;
use crate::{
    config::Settings,
    web::{
        compile_routes,
        model::{CorsSite, IdentitySite, Listener, RewriteSite, Site},
    },
};

const DEADLINE: Duration = Duration::from_secs(5);

/// An HTTP/1.1 backend that answers every request with a JSON echo of the
/// pieces the assertions need: the received `Host`, the request target
/// and every received header (`seen`). Always sends `x-trace-resp` so
/// response edits have something to delete.
struct EchoBackend {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    _task: JoinHandle<()>,
}

async fn echo_backend(delay: Duration) -> Result<EchoBackend> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let hits = Arc::new(AtomicUsize::new(0));
    let serving = hits.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let serving = serving.clone();
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |request: Request<Incoming>| {
                            let serving = serving.clone();
                            async move {
                                serving.fetch_add(1, Ordering::SeqCst);
                                if delay > Duration::ZERO {
                                    sleep(delay).await;
                                }
                                Ok::<_, Infallible>(echo(request))
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    Ok(EchoBackend {
        addr,
        hits,
        _task: task,
    })
}

fn echo(request: Request<Incoming>) -> Response<Full<Bytes>> {
    let host = request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let mut seen = serde_json::Map::new();
    for (name, value) in request.headers() {
        seen.entry(name.as_str().to_owned())
            .or_insert_with(|| json!(value.to_str().unwrap_or_default()));
    }
    let body = json!({
        "host": host,
        "target": request
            .uri()
            .path_and_query()
            .map(|target| target.as_str())
            .unwrap_or_default(),
        "seen": Value::Object(seen),
    });
    Response::builder()
        .header("x-trace-resp", "leak")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("static echo response")
}

/// Serves [`Proxy::forward`] over plain loopback HTTP/1.1, the same
/// service shape the webservice listener uses (no TLS, no tunnels).
async fn spawn_frontend(proxy: Proxy) -> Result<SocketAddr> {
    let proxy = Arc::new(proxy);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            let proxy = proxy.clone();
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |request: Request<Incoming>| {
                            let proxy = proxy.clone();
                            async move {
                                Ok::<_, Infallible>(proxy.forward(request, peer, None, None).await)
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    Ok(addr)
}

/// Compiles the sites through the webservice bridge (exactly what the
/// listener pipeline would store) and fronts them with one proxy.
async fn spawn_gateway(sites: Vec<Site>) -> Result<SocketAddr> {
    let listener = Listener {
        key: "wp23".to_owned(),
        enable: true,
        sites,
        ..Listener::default()
    };
    let routes = compile_routes(&listener)
        .await
        .map_err(|errors| anyhow::anyhow!("site compile failed: {errors:?}"))?;
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    spawn_frontend(Proxy::new(routes, &Settings::default(), tls)).await
}

/// A proxy site on `domain` towards `backend`, with the WP-23 option
/// fields assigned by `shape` on top of `Site::default()`.
fn proxy_site(domain: &str, backend: SocketAddr, shape: impl FnOnce(&mut Site)) -> Site {
    let mut site = Site {
        key: "wp23".to_owned(),
        enable: true,
        domains: vec![domain.to_owned()],
        site_type: "proxy".to_owned(),
        targets: vec![format!("http://{backend}")],
        ..Site::default()
    };
    shape(&mut site);
    site
}

/// One fresh HTTP/1.1 request to the gateway; returns the status, the
/// response headers and the backend's echo (JSON, or `Null` for the
/// gateway's plain-text error replies).
async fn send_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    host: &str,
    headers: &[(&str, &str)],
) -> Result<(StatusCode, HeaderMap, Value)> {
    let stream = timeout(DEADLINE, TcpStream::connect(addr)).await??;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(Empty::<Bytes>::new())?;
    let response = timeout(DEADLINE, sender.send_request(request)).await??;
    let status = response.status();
    let fields = response.headers().clone();
    let body = timeout(DEADLINE, response.into_body().collect())
        .await??
        .to_bytes();
    let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
    Ok((status, fields, body))
}

fn header<'a>(fields: &'a HeaderMap, name: &'a str) -> Option<&'a str> {
    fields.get(name).and_then(|value| value.to_str().ok())
}

#[tokio::test]
async fn use_target_host_switch() -> Result<()> {
    let backend = echo_backend(Duration::ZERO).await?;
    // `Site::default()` keeps the visitor's Host (use_target_host = false).
    let keep = proxy_site("keep.test", backend.addr, |site| {
        site.use_target_host = false;
    });
    // The legacy switch sends the backend's own authority instead.
    let replace = proxy_site("target.test", backend.addr, |site| {
        site.use_target_host = true;
    });
    let gateway = spawn_gateway(vec![keep, replace]).await?;

    let (_, _, body) = send_request(gateway, "GET", "/", "keep.test", &[]).await?;
    assert_eq!(body["seen"]["host"], "keep.test", "client Host preserved");
    let (_, _, body) = send_request(gateway, "GET", "/", "target.test", &[]).await?;
    assert_eq!(
        body["seen"]["host"],
        backend.addr.to_string(),
        "backend authority replaces the Host"
    );
    Ok(())
}

#[tokio::test]
async fn forwarded_headers_switch() -> Result<()> {
    let backend = echo_backend(Duration::ZERO).await?;
    let on = proxy_site("on.test", backend.addr, |site| {
        site.forwarded_headers = true;
    });
    let off = proxy_site("off.test", backend.addr, |site| {
        site.forwarded_headers = false;
    });
    let gateway = spawn_gateway(vec![on, off]).await?;

    let (_, _, body) = send_request(gateway, "GET", "/", "on.test", &[]).await?;
    assert_eq!(body["seen"]["x-forwarded-for"], "127.0.0.1");
    assert_eq!(body["seen"]["x-forwarded-proto"], "http");
    assert_eq!(body["seen"]["x-forwarded-host"], "on.test");
    assert_eq!(body["seen"]["via"], "1.1 ferrumgate");

    let (_, _, body) = send_request(gateway, "GET", "/", "off.test", &[]).await?;
    for name in ["x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"] {
        assert!(body["seen"].get(name).is_none(), "{name} must be absent");
    }
    assert_eq!(body["seen"]["via"], "1.1 ferrumgate", "VIA stays on");
    Ok(())
}

#[tokio::test]
async fn request_response_header_edits() -> Result<()> {
    let backend = echo_backend(Duration::ZERO).await?;
    let site = proxy_site("edit.test", backend.addr, |site| {
        site.forwarded_headers = true;
        site.request_headers = vec!["X-Extra: hello".to_owned(), "X-Trace:".to_owned()];
        site.response_headers = vec!["X-Resp: yes".to_owned(), "X-Trace-Resp:".to_owned()];
    });
    let gateway = spawn_gateway(vec![site]).await?;

    let (status, fields, body) =
        send_request(gateway, "GET", "/", "edit.test", &[("x-trace", "forged")]).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["seen"]["x-extra"], "hello", "request edit added");
    assert!(
        body["seen"].get("x-trace").is_none(),
        "client X-Trace deleted before the backend"
    );
    assert_eq!(
        header(&fields, "x-resp"),
        Some("yes"),
        "response edit added"
    );
    assert!(
        fields.get("x-trace-resp").is_none(),
        "backend X-Trace-Resp deleted"
    );
    Ok(())
}

#[tokio::test]
async fn rewrite_redirect_and_internal() -> Result<()> {
    let backend = echo_backend(Duration::ZERO).await?;
    let site = proxy_site("r.test", backend.addr, |site| {
        site.rewrites = vec![
            RewriteSite {
                pattern: "^/old".to_owned(),
                to: "https://{host}/new".to_owned(),
                redirect: true,
                code: 302,
            },
            RewriteSite {
                pattern: "^/api/(.*)".to_owned(),
                to: "/v2/$1".to_owned(),
                redirect: false,
                code: 0,
            },
        ];
    });
    let gateway = spawn_gateway(vec![site]).await?;

    let hits = backend.hits.load(Ordering::SeqCst);
    let (status, fields, _) = send_request(gateway, "GET", "/old?a=b", "r.test", &[]).await?;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        header(&fields, "location"),
        Some("https://r.test/new?a=b"),
        "query preserved and {{host}} expanded"
    );
    assert_eq!(
        backend.hits.load(Ordering::SeqCst),
        hits,
        "the redirect is answered without touching the backend"
    );

    let (_, _, body) = send_request(gateway, "GET", "/api/users?q=1", "r.test", &[]).await?;
    assert_eq!(
        body["target"], "/v2/users?q=1",
        "the internal rewrite changes the path the backend sees"
    );
    Ok(())
}

#[tokio::test]
async fn cors_preflight_and_origin() -> Result<()> {
    let backend = echo_backend(Duration::ZERO).await?;
    let site = proxy_site("c.test", backend.addr, |site| {
        site.forwarded_headers = true;
        site.cors = CorsSite {
            allow_origins: vec!["https://app.test".to_owned()],
            allow_methods: vec!["GET".to_owned()],
            allow_headers: vec!["X-Token".to_owned()],
            allow_credentials: false,
            max_age_secs: 600,
        };
    });
    let gateway = spawn_gateway(vec![site]).await?;

    let hits = backend.hits.load(Ordering::SeqCst);
    let (status, fields, _) = send_request(
        gateway,
        "OPTIONS",
        "/",
        "c.test",
        &[
            ("origin", "https://app.test"),
            ("access-control-request-method", "DELETE"),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header(&fields, "access-control-allow-origin"),
        Some("https://app.test")
    );
    assert_eq!(header(&fields, "access-control-allow-methods"), Some("GET"));
    assert_eq!(header(&fields, "access-control-max-age"), Some("600"));
    assert_eq!(
        backend.hits.load(Ordering::SeqCst),
        hits,
        "the preflight is answered at the gateway"
    );

    let (status, fields, _) = send_request(
        gateway,
        "GET",
        "/",
        "c.test",
        &[("origin", "https://app.test")],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header(&fields, "access-control-allow-origin"),
        Some("https://app.test"),
        "a matching Origin earns the CORS headers"
    );

    let (_, fields, _) = send_request(
        gateway,
        "GET",
        "/",
        "c.test",
        &[("origin", "https://evil.test")],
    )
    .await?;
    assert!(fields.get("access-control-allow-origin").is_none());
    Ok(())
}

#[tokio::test]
async fn identity_strip_forged() -> Result<()> {
    let backend = echo_backend(Duration::ZERO).await?;
    let site = proxy_site("id.test", backend.addr, |site| {
        site.identity_headers = vec![IdentitySite {
            header: "X-User".to_owned(),
            field: "user".to_owned(),
        }];
    });
    let gateway = spawn_gateway(vec![site]).await?;

    let (_, _, body) = send_request(
        gateway,
        "GET",
        "/",
        "id.test",
        &[("x-user", "forged"), ("x_user", "forged2")],
    )
    .await?;
    assert!(
        body["seen"].get("x-user").is_none(),
        "canonical spelling stripped"
    );
    assert!(
        body["seen"].get("x_user").is_none(),
        "underscore spelling stripped"
    );
    Ok(())
}

#[tokio::test]
async fn site_response_header_timeout() -> Result<()> {
    // The settings-level default is 30s; the site's 1s deadline must win.
    let backend = echo_backend(Duration::from_secs(2)).await?;
    let site = proxy_site("slow.test", backend.addr, |site| {
        site.timeouts_response_secs = 1;
    });
    let gateway = spawn_gateway(vec![site]).await?;

    let (status, _, body) = send_request(gateway, "GET", "/slow", "slow.test", &[]).await?;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(
        body,
        Value::Null,
        "the 504 reply is the gateway's plain-text body, not the echo"
    );
    Ok(())
}
