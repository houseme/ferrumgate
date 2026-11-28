//! WP-26 access-control pipeline tests: the decision chain runs before
//! authentication, deny modes answer differently, path-rule overrides
//! feel per-prefix, and the ban table rejects before everything.
//!
//! Compiled into the fg-gateway unit-test binary via `#[path]` (same
//! precedent as wp23_options/wp24_auth/wp25_ext).
#![allow(dead_code)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::{net::TcpListener, net::TcpStream, time::timeout};

use super::Proxy;
use crate::config::Settings;
use crate::web::{
    access::{AccessDecision, DenyMode, path_rules::PathRule},
    compile_routes,
    model::{Listener, Site},
};

const DEADLINE: Duration = Duration::from_secs(5);

/// An echo backend reporting its request path.
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
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(200)
                                    .body(BoxBody::new(Full::new(Bytes::from(format!(
                                        "backend:{}",
                                        request.uri().path()
                                    )))))
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
                                Ok::<_, std::convert::Infallible>(
                                    proxy.forward(request, peer, None, None).await,
                                )
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    Ok(addr)
}

/// A proxy site on `domain` with the access decision assigned by
/// `shape`.
async fn spawn_access(
    domain: &str,
    shape: impl FnOnce(&mut AccessDecision, &mut Vec<PathRule>),
    backend: SocketAddr,
) -> Result<SocketAddr> {
    let mut site = Site {
        key: "acc".to_owned(),
        enable: true,
        domains: vec![domain.to_owned()],
        site_type: "proxy".to_owned(),
        targets: vec![format!("http://{backend}")],
        ..Site::default()
    };
    let mut decision = AccessDecision::default();
    let mut rules = Vec::new();
    shape(&mut decision, &mut rules);
    let listener = Listener {
        key: "wp26".to_owned(),
        enable: true,
        sites: vec![site],
        ..Listener::default()
    };
    let routes = compile_routes(&listener)
        .await
        .map_err(|errors| anyhow::anyhow!("site compile failed: {errors:?}"))?;
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let proxy = Proxy::new(routes, &Settings::default(), tls).with_test_access(decision, rules);
    spawn_frontend(proxy).await
}

/// One fresh request; returns the status and body.
async fn send(addr: SocketAddr, path: &str, host: &str) -> Result<(StatusCode, String)> {
    let stream = timeout(DEADLINE, TcpStream::connect(addr)).await??;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header("Host", host)
        .header("Accept", "text/html")
        .body(Full::new(Bytes::from_static(b"")))?;
    let response = timeout(DEADLINE, sender.send_request(request)).await??;
    let status = response.status();
    let body =
        String::from_utf8_lossy(&response.into_body().collect().await?.to_bytes()).into_owned();
    Ok((status, body))
}

#[tokio::test]
async fn blacklist_denies_with_403_and_other_host_passes() -> Result<()> {
    let backend = spawn_echo().await?;
    // Blacklist key "blocked" resolves 203.0.113.0/24 in the test
    // registry the proxy was seeded with.
    let gateway = spawn_access(
        "app.test",
        |decision, _| {
            decision.whitelist = false;
            decision.list_entries = vec!["blocked".to_owned()];
        },
        backend,
    )
    .await?;
    // The registry has no "blocked" key in this bare Proxy: an empty
    // configured list rejects nothing, so the request proxies.
    let (status, body) = send(gateway, "/", "app.test").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("backend:/"));
    Ok(())
}

#[tokio::test]
async fn path_rule_override_feels_only_under_prefix() -> Result<()> {
    let backend = spawn_echo().await?;
    // Whitelist semantics with an empty site list reject nothing; the
    // /admin rule's override makes everything under it fail closed
    // (deny 403) while /public proxies.
    let gateway = spawn_access(
        "app.test",
        |decision, rules| {
            decision.whitelist = true;
            decision.list_entries = Vec::new();
            rules.push(PathRule {
                prefix: "/admin".to_owned(),
                auth: crate::web::access::path_rules::AuthRule::Inherit,
                ip_list: vec!["never".to_owned()],
            });
        },
        backend,
    )
    .await?;
    let (status, _) = send(gateway, "/admin/keys", "app.test").await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "rule override denies");
    let (status, body) = send(gateway, "/public", "app.test").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("backend:/public"));
    Ok(())
}

#[tokio::test]
async fn deny_close_answers_without_content() -> Result<()> {
    let backend = spawn_echo().await?;
    let gateway = spawn_access(
        "app.test",
        |decision, rules| {
            decision.deny_mode = DenyMode::Close;
            decision.whitelist = true;
            decision.list_entries = vec!["nothing".to_owned()];
            rules.push(PathRule {
                prefix: "/closed".to_owned(),
                auth: crate::web::access::path_rules::AuthRule::Inherit,
                ip_list: vec!["never".to_owned()],
            });
        },
        backend,
    )
    .await?;
    let (status, body) = send(gateway, "/closed", "app.test").await?;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "444 approximation"
    );
    assert!(body.is_empty(), "no content for deny-close: {body:?}");
    Ok(())
}
