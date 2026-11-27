//! WP-23 3b: dial-failure retry and the four load policies, driven
//! end-to-end through [`Proxy::forward`] exactly like the per-site
//! options in `wp23_options.rs`: sites compile through the webservice
//! bridge (`compile_routes`) and are served by an in-process proxy. The
//! file lives next to the shared `tests/gateway/` harness but is compiled
//! into the `fg-gateway` unit-test binary through the `#[path]` module at
//! the bottom of `src/proxy.rs` (the bridge and the proxy are
//! crate-private, so a standalone integration target cannot reach them).
//!
//! Scenarios:
//! - a dial failure (nothing was sent) switches to the next backend, up
//!   to three attempts;
//! - a failure after the request went out (backend half-closes) never
//!   retries — other backends stay untouched;
//! - `least_conn` sends concurrent requests to the less occupied backend;
//! - `ip_hash` pins one client to one backend;
//! - `weight=N` and `backup` target lines drive the distribution and the
//!   backup takes over once every primary is out of rotation.

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
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    client::conn::http1::SendRequest,
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};

use super::Proxy;
use crate::{
    config::Settings,
    web::{
        compile_routes,
        model::{Listener, Site},
    },
};

const DEADLINE: Duration = Duration::from_secs(5);

/// An HTTP/1.1 backend that answers every request with a JSON echo of
/// its own port (so tests can tell which backend answered) and counts
/// its hits. `delay` holds every response back, simulating occupancy.
struct EchoBackend {
    port: u16,
    hits: Arc<AtomicUsize>,
    _task: JoinHandle<()>,
}

async fn echo_backend(delay: Duration) -> Result<EchoBackend> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
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
                                Ok::<_, Infallible>(echo(port, request))
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    Ok(EchoBackend {
        port,
        hits,
        _task: task,
    })
}

fn echo(port: u16, request: Request<Incoming>) -> Response<Full<Bytes>> {
    let mut seen = serde_json::Map::new();
    for (name, value) in request.headers() {
        seen.entry(name.as_str().to_owned())
            .or_insert_with(|| json!(value.to_str().unwrap_or_default()));
    }
    let body = json!({
        "port": port,
        "target": request
            .uri()
            .path_and_query()
            .map(|target| target.as_str())
            .unwrap_or_default(),
        "seen": Value::Object(seen),
    });
    Response::builder()
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("static echo response")
}

/// A backend that accepts the connection, reads the request head and then
/// half-closes without answering. The gateway has already sent the
/// request, so this is a post-connect failure — never a retry trigger.
struct ClosingBackend {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    _task: JoinHandle<()>,
}

async fn closing_backend() -> Result<ClosingBackend> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let accepted = Arc::new(AtomicUsize::new(0));
    let counting = accepted.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            counting.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                // Drain the request head, then send FIN without a reply.
                let mut buffer = [0u8; 8192];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) if buffer[..n].windows(4).any(|end| end == b"\r\n\r\n") => break,
                        Ok(_) => {}
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    Ok(ClosingBackend {
        addr,
        accepted,
        _task: task,
    })
}

/// Reserves a loopback port and releases it: connections to it are
/// refused, which is the retryable dial failure.
async fn dead_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    Ok(listener.local_addr()?.port())
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
        key: "wp23-retry".to_owned(),
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

/// A proxy site on `domain` towards `targets`, with extra fields assigned
/// by `shape` on top of `Site::default()`. Targets are raw lines so the
/// tests exercise the bare `host:port` and the `weight`/`backup` forms.
fn site(domain: &str, targets: Vec<String>, shape: impl FnOnce(&mut Site)) -> Site {
    let mut site = Site {
        key: domain.to_owned(),
        enable: true,
        domains: vec![domain.to_owned()],
        site_type: "proxy".to_owned(),
        targets,
        ..Site::default()
    };
    shape(&mut site);
    site
}

async fn open(addr: SocketAddr) -> Result<SendRequest<Empty<Bytes>>> {
    let stream = timeout(DEADLINE, TcpStream::connect(addr)).await??;
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(sender)
}

/// One GET to the gateway; returns the status and the backend's echo
/// (JSON, or `Null` for the gateway's plain-text error replies).
async fn get_json(addr: SocketAddr, host: &str, path: &str) -> Result<(StatusCode, Value)> {
    let mut sender = open(addr).await?;
    let request = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("host", host)
        .body(Empty::<Bytes>::new())?;
    let response = timeout(DEADLINE, sender.send_request(request)).await??;
    let status = response.status();
    let body = timeout(DEADLINE, response.into_body().collect())
        .await??
        .to_bytes();
    Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
}

fn port(body: &Value) -> u16 {
    body["port"].as_u64().unwrap_or_default() as u16
}

#[tokio::test]
async fn dial_failure_switches_backend_up_to_three() -> Result<()> {
    let first_dead = dead_port().await?;
    let second_dead = dead_port().await?;
    let alive = echo_backend(Duration::ZERO).await?;
    // Bare `host:port` lines: the bridge defaults them to plain HTTP.
    let gateway = spawn_gateway(vec![site(
        "retry.test",
        vec![
            format!("127.0.0.1:{first_dead}"),
            format!("127.0.0.1:{second_dead}"),
            format!("127.0.0.1:{}", alive.port),
        ],
        |_| {},
    )])
    .await?;

    let hits = alive.hits.load(Ordering::SeqCst);
    let (status, body) = get_json(gateway, "retry.test", "/").await?;
    assert_eq!(status, StatusCode::OK, "the third attempt must land");
    assert_eq!(port(&body), alive.port);
    assert_eq!(
        alive.hits.load(Ordering::SeqCst),
        hits + 1,
        "the live backend serves the request exactly once"
    );
    Ok(())
}

#[tokio::test]
async fn retry_only_on_connect_failure() -> Result<()> {
    let closing = closing_backend().await?;
    let healthy = echo_backend(Duration::ZERO).await?;
    // Round-robin leads with the closing backend, so the failure happens
    // on attempt one; a post-connect failure must not switch backends.
    let gateway = spawn_gateway(vec![site(
        "close.test",
        vec![
            format!("127.0.0.1:{}", closing.addr.port()),
            format!("127.0.0.1:{}", healthy.port),
        ],
        |_| {},
    )])
    .await?;

    let (status, body) = get_json(gateway, "close.test", "/").await?;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body, Value::Null, "the 502 is the gateway's plain text");
    assert_eq!(closing.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(
        healthy.hits.load(Ordering::SeqCst),
        0,
        "a non-connect failure never retries the next backend"
    );
    Ok(())
}

#[tokio::test]
async fn policy_least_conn_picks_the_idle_backend() -> Result<()> {
    let slow = echo_backend(Duration::from_millis(200)).await?;
    let fast = echo_backend(Duration::ZERO).await?;
    let gateway = spawn_gateway(vec![site(
        "lc.test",
        vec![
            format!("127.0.0.1:{}", slow.port),
            format!("127.0.0.1:{}", fast.port),
        ],
        |site| site.lb_policy = "least_conn".to_owned(),
    )])
    .await?;

    // Request one occupies the slow backend (least_conn breaks the idle
    // tie towards the first candidate); while it is still in flight its
    // conn count pushes the second request to the idle backend.
    let mut sender = open(gateway).await?;
    let first = Request::builder()
        .method(Method::GET)
        .uri("/slow")
        .header("host", "lc.test")
        .body(Empty::<Bytes>::new())?;
    let pending = sender.send_request(first);
    sleep(Duration::from_millis(100)).await;
    let (fast_status, fast_body) = get_json(gateway, "lc.test", "/fast").await?;
    let response = timeout(DEADLINE, pending).await??;
    let slow_status = response.status();
    let slow_body: Value = serde_json::from_slice(
        &timeout(DEADLINE, response.into_body().collect())
            .await??
            .to_bytes(),
    )
    .unwrap_or(Value::Null);

    assert_eq!(slow_status, StatusCode::OK);
    assert_eq!(fast_status, StatusCode::OK);
    assert_eq!(
        port(&slow_body),
        slow.port,
        "the idle tie goes to the first"
    );
    assert_eq!(
        port(&fast_body),
        fast.port,
        "an occupied backend loses the next pick"
    );
    Ok(())
}

#[tokio::test]
async fn policy_ip_hash_pins_one_client_to_one_backend() -> Result<()> {
    let first = echo_backend(Duration::ZERO).await?;
    let second = echo_backend(Duration::ZERO).await?;
    let gateway = spawn_gateway(vec![site(
        "ih.test",
        vec![
            format!("127.0.0.1:{}", first.port),
            format!("127.0.0.1:{}", second.port),
        ],
        |site| site.lb_policy = "ip_hash".to_owned(),
    )])
    .await?;

    let mut pinned = None;
    for _ in 0..4 {
        let (_, body) = get_json(gateway, "ih.test", "/").await?;
        let answered = port(&body);
        match pinned {
            Some(previous) => assert_eq!(answered, previous, "same client, same backend"),
            None => pinned = Some(answered),
        }
    }
    let pinned = pinned.expect("at least one request");
    assert!(
        pinned == first.port || pinned == second.port,
        "the pin must be one of the pool members: {pinned}"
    );
    Ok(())
}

#[tokio::test]
async fn weight_and_backup_from_target_lines() -> Result<()> {
    let heavy = echo_backend(Duration::ZERO).await?;
    let light = echo_backend(Duration::ZERO).await?;
    let standby = echo_backend(Duration::ZERO).await?;
    let dead = dead_port().await?;
    let gateway = spawn_gateway(vec![
        // Full URL lines with `weight=N`: 3:1 round-robin over a shared
        // cursor lands exactly 6:2 in eight requests.
        site(
            "weight.test",
            vec![
                format!("http://127.0.0.1:{} weight=3", heavy.port),
                format!("http://127.0.0.1:{} weight=1", light.port),
            ],
            |_| {},
        ),
        // The weighted primary is a closed port: three dial failures trip
        // the passive check before the `backup` line takes over.
        site(
            "backup.test",
            vec![
                format!("http://127.0.0.1:{dead} weight=3"),
                format!("http://127.0.0.1:{} backup", standby.port),
            ],
            |_| {},
        ),
    ])
    .await?;

    let mut heavy_hits = 0;
    for _ in 0..8 {
        let (status, body) = get_json(gateway, "weight.test", "/").await?;
        assert_eq!(status, StatusCode::OK);
        match port(&body) {
            port if port == heavy.port => heavy_hits += 1,
            port if port == light.port => {}
            other => panic!("unexpected backend: {other}"),
        }
    }
    assert_eq!(heavy_hits, 6, "weight 3:1 over eight requests");

    for attempt in 1..=3 {
        let (status, body) = get_json(gateway, "backup.test", "/").await?;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "attempt {attempt}");
        assert_eq!(body, Value::Null);
    }
    assert_eq!(standby.hits.load(Ordering::SeqCst), 0, "backup waits");
    let (status, body) = get_json(gateway, "backup.test", "/").await?;
    assert_eq!(status, StatusCode::OK, "the backup serves after the pause");
    assert_eq!(port(&body), standby.port);
    assert_eq!(standby.hits.load(Ordering::SeqCst), 1);
    Ok(())
}
