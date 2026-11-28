//! WP-25 forward-authentication pipeline tests: the mock auth service
//! answers the sub-request, the gateway proxies per its verdict, and
//! visitor-supplied identity headers can never reach the backend.
//!
//! Compiled into the fg-gateway unit-test binary via `#[path]` (same
//! precedent as `wp23_options.rs` / `wp24_auth.rs` — the site compiler
//! is `pub(crate)`).
#![allow(dead_code)]

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::Relaxed},
    },
    time::Duration,
};

use anyhow::Result;
use http_body_util::{Full, combinators::BoxBody};
use http_body_util::BodyExt;
use std::convert::Infallible;
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::{net::{TcpListener, TcpStream}, time::timeout};


use super::Proxy;
use crate::config::Settings;
use crate::web::{

    compile_routes,
    model::{ForwardAuthSite, Listener, Site},
};

const DEADLINE: Duration = Duration::from_secs(5);

/// The mock auth service: routes by request path, echoing a scripted
/// status/headers. Headers of every auth request are counted.
struct MockAuth {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    last_headers: Arc<std::sync::Mutex<Vec<(String, String)>>>,
}

impl MockAuth {
    /// Spawns a mock that answers `/ok` with 200 + Remote-User,
    /// `/login` with 401 + Location, `/dynamic` with 401 + Location +
    /// Set-Cookie, `/forbidden` with 403 — and counts every request.
    async fn spawn() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let hits = Arc::new(AtomicUsize::new(0));
        let last_headers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let return_hits = hits.clone();
        let return_headers = last_headers.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let hits = hits.clone();
                let last_headers = last_headers.clone();
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(move |request: Request<Incoming>| {
                                let hits = hits.clone();
                                let last_headers = last_headers.clone();
                                async move {
                                    hits.fetch_add(1, Relaxed);
                                    {
                                        let mut seen = last_headers.lock().expect("lock");
                                        seen.clear();
                                        for (name, value) in request.headers() {
                                            seen.push((
                                                name.as_str().to_owned(),
                                                value.to_str().unwrap_or_default().to_owned(),
                                            ));
                                        }
                                    }
                                    let path = request.uri().path();
                                    let response = match path {
                                        "/ok" => Response::builder()
                                            .status(200)
                                            .header("Remote-User", "alice")
                                            .body(empty()),
                                        "/remote-group" => Response::builder()
                                            .status(200)
                                            .header("Remote-User", "bob")
                                            .header("Remote-Groups", "devs, ops")
                                            .body(empty()),
                                        "/login" => Response::builder()
                                            .status(401)
                                            .header(
                                                "Location",
                                                "https://auth.example.com/login?from=here",
                                            )
                                            .body(empty()),
                                        "/dynamic" => Response::builder()
                                            .status(401)
                                            .header(
                                                "Location",
                                                "https://casdoor.example.com/login?next=x",
                                            )
                                            .header("Set-Cookie", "casdoor=1; Path=/")
                                            .body(empty()),
                                        _ => Response::builder().status(403).body(empty()),
                                    };
                                    Ok::<_, hyper::Error>(
                                        response.expect("static mock response"),
                                    )
                                }
                            }),
                        )
                        .await;
                });
            }
        });
        Ok(Self {
            addr,
            hits: return_hits,
            last_headers: return_headers,
        })
    }
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    BoxBody::new(
        Full::new(Bytes::from_static(b""))
            .map_err(|never| match never {}),
    )
}

/// A proxy site on `domain` forwarding authentication to the mock's
/// `path`, with the extra shape applied.
async fn spawn_fa(
    domain: &str,
    mock: &MockAuth,
    path: &str,
    shape: impl FnOnce(&mut ForwardAuthSite, &mut Site),
    backend: SocketAddr,
) -> Result<SocketAddr> {
    let mut site = Site {
        key: "fa".to_owned(),
        enable: true,
        domains: vec![domain.to_owned()],
        site_type: "proxy".to_owned(),
        targets: vec![format!("http://{backend}")],
        ..Site::default()
    };
    let mut fa = ForwardAuthSite {
        url: format!("http://{}{path}", mock.addr),
        ..ForwardAuthSite::default()
    };
    shape(&mut fa, &mut site);
    site.forward_auth = Some(fa);
    let listener = Listener {
        key: "wp25".to_owned(),
        enable: true,
        sites: vec![site],
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

/// A fresh HTTP/1.1 request; returns the status, header map and body.
async fn send(
    addr: SocketAddr,
    method: &str,
    path: &str,
    host: &str,
    headers: &[(&str, String)],
) -> Result<(StatusCode, hyper::HeaderMap, String)> {
    let stream = timeout(DEADLINE, TcpStream::connect(addr)).await??;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", host)
        .header("Accept", "text/html");
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let request = builder.body(Full::new(Bytes::from_static(b"")))?;
    let response = timeout(DEADLINE, sender.send_request(request)).await??;
    let status = response.status();
    let headers = response.headers().clone();
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await?
        .to_bytes();
    Ok((status, headers, String::from_utf8_lossy(&body).into_owned()))
}

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
                let _ = hyper::server::conn::http1::Builder::new()
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

/// An echo backend reporting its received headers as JSON.
async fn spawn_echo() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|request: Request<Incoming>| async move {
                            let mut headers = String::new();
                            for (name, value) in request.headers() {
                                headers.push_str(&format!(
                                    "{}={}\n",
                                    name.as_str(),
                                    value.to_str().unwrap_or_default()
                                ));
                            }
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(200)
                                    .body(BoxBody::new(Full::new(Bytes::from(headers))))
                                    .expect("static"),
                            )
                        }),
                    )
                    .await;
            });
        }
    });
    Ok(addr)
}

#[tokio::test]
async fn forward_auth_allowed_copies_identity_and_strips_forged() -> Result<()> {
    let mock = MockAuth::spawn().await?;
    let backend = spawn_echo().await?;
    let gateway = spawn_fa("app.test", &mock, "/ok", |_, _| {}, backend).await?;
    // A visitor-supplied Remote-User must never reach the backend; the
    // approved value from the auth service replaces it.
    let (status, _, body) = send(
        gateway,
        "GET",
        "/",
        "app.test",
        &[("Remote-User", "forged".to_owned()), ("Cookie", "sid=1".to_owned())],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mock.hits.load(Relaxed), 1, "the sub-request ran");
    assert!(body.contains("remote-user=alice"), "approved identity copied: {body}");
    assert!(!body.contains("forged"), "forged identity stripped: {body}");
    assert!(body.contains("cookie=sid=1"), "visitor cookie forwarded: {body}");
    Ok(())
}

#[tokio::test]
async fn forward_auth_401_redirects_via_login_url() -> Result<()> {
    let mock = MockAuth::spawn().await?;
    let backend = spawn_echo().await?;
    let gateway = spawn_fa(
        "app.test",
        &mock,
        "/login",
        |fa, _| {
            fa.login_url = "https://auth.example.com/login?from={url}".to_owned();
        },
        backend,
    )
    .await?;
    let (status, headers, _) = send(gateway, "GET", "/", "app.test", &[]).await?;
    assert_eq!(status, StatusCode::FOUND);
    let location = headers.get("Location").expect("login redirect");
    assert!(location.to_str().unwrap().starts_with("https://auth.example.com/login?from=http://app.test"), "{location:?}");
    Ok(())
}

#[tokio::test]
async fn forward_auth_401_location_login_passes_cookies() -> Result<()> {
    let mock = MockAuth::spawn().await?;
    let backend = spawn_echo().await?;
    let gateway = spawn_fa(
        "app.test",
        &mock,
        "/dynamic",
        |fa, _| fa.login_from_location = true,
        backend,
    )
    .await?;
    let (status, headers, _) = send(gateway, "GET", "/", "app.test", &[]).await?;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        headers.get("Location").expect("dynamic location"),
        "https://casdoor.example.com/login?next=x"
    );
    let cookies: Vec<_> = headers.get_all("Set-Cookie").iter().collect();
    assert!(
        cookies.iter().any(|c| c.to_str().unwrap().contains("casdoor=1")),
        "auth service cookies pass through: {cookies:?}"
    );
    Ok(())
}

#[tokio::test]
async fn forward_auth_other_status_answers_verbatim() -> Result<()> {
    let mock = MockAuth::spawn().await?;
    let backend = spawn_echo().await?;
    let gateway = spawn_fa("app.test", &mock, "/forbidden", |_, _| {}, backend).await?;
    let (status, _, _) = send(gateway, "GET", "/", "app.test", &[]).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "403 answers verbatim");
    assert_eq!(mock.hits.load(Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn forward_auth_carries_original_target_headers() -> Result<()> {
    let mock = MockAuth::spawn().await?;
    let backend = spawn_echo().await?;
    let gateway = spawn_fa("app.test", &mock, "/ok", |_, _| {}, backend).await?;
    send(
        gateway,
        "POST",
        "/some/path?q=1",
        "app.test",
        &[("X-Forwarded-Host", "app.test".to_owned())],
    )
    .await?;
    let seen = mock.last_headers.lock().expect("lock");
    for expected in [
        ("x-original-method", "POST"),
        ("x-original-uri", "/some/path?q=1"),
        ("x-forwarded-host", "app.test"),
        ("x-real-ip", "127.0.0.1"),
    ] {
        assert!(
            seen.iter().any(|(name, value)| name == expected.0 && value == expected.1),
            "{expected:?} missing among {seen:?}"
        );
    }
    Ok(())
}
