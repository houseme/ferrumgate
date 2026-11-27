//! Execution integration tests (WP-62 §6): command environment injection,
//! timeout kill, output truncation and the HTTP task checks against fake
//! servers (plain and self-signed TLS). All child processes go through the
//! real `sh -c` path with a small Rust fixture executable.

#![cfg(unix)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_util::sync::CancellationToken;

use common::{fixture, sh_quote};
use fg_cron::exec;
use fg_cron::exec::http::{HttpRequest, HttpResponse};
use fg_cron::model::{HttpTask, limits};

fn never_cancelled() -> CancellationToken {
    CancellationToken::new()
}

#[tokio::test]
async fn command_env_has_task_name() {
    let program = sh_quote(&fixture());
    let outcome = exec::command::run(
        &format!("{program} env"),
        "夜间备份",
        Duration::from_secs(30),
        &never_cancelled(),
    )
    .await;
    assert!(outcome.success, "{}", outcome.output);
    assert!(
        outcome
            .output
            .lines()
            .any(|line| line == "taskName=夜间备份"),
        "literal taskName is injected: {}",
        outcome.output
    );
    assert!(
        outcome
            .output
            .lines()
            .any(|line| line == "prefixed=夜间备份"),
        "FERRUMGATE_TASKNAME carries the same value: {}",
        outcome.output
    );
}

#[tokio::test]
async fn command_env_carries_prefixed_uppercase() {
    let program = sh_quote(&fixture());
    let outcome = exec::command::run(
        &format!("{program} env"),
        "backup",
        Duration::from_secs(30),
        &never_cancelled(),
    )
    .await;
    let prefixed = outcome
        .output
        .lines()
        .find(|line| line.starts_with("prefixed="))
        .expect("prefixed line");
    assert_eq!(
        prefixed, "prefixed=backup",
        "FERRUMGATE_TASKNAME mirrors taskName"
    );
}

#[tokio::test]
async fn command_timeout_kills() {
    let program = sh_quote(&fixture());
    let begun = std::time::Instant::now();
    let outcome = exec::command::run(
        &format!("{program} sleep 30"),
        "slow",
        Duration::from_millis(400),
        &never_cancelled(),
    )
    .await;
    assert!(!outcome.success);
    assert!(outcome.output.contains("命令超时"), "{}", outcome.output);
    assert!(
        begun.elapsed() < Duration::from_secs(10),
        "the child was killed, not waited out: {:?}",
        begun.elapsed()
    );
}

#[tokio::test]
async fn command_output_truncated_4000() {
    let program = sh_quote(&fixture());
    let outcome = exec::command::run(
        &format!("{program} emit 5000"),
        "chatty",
        Duration::from_secs(30),
        &never_cancelled(),
    )
    .await;
    assert_eq!(
        outcome.output.chars().count(),
        limits::OUTPUT_MAX_CHARS,
        "output is truncated to the 4000-char summary cap"
    );
}

#[tokio::test]
async fn command_failure_marks_unsuccessful() {
    let program = sh_quote(&fixture());
    let outcome = exec::command::run(
        &format!("{program} exit 3"),
        "failing",
        Duration::from_secs(30),
        &never_cancelled(),
    )
    .await;
    assert!(!outcome.success);
}

/// Spawns a one-shot plain HTTP server answering with `response` after
/// `hold`; returns its address.
async fn fake_http_server(response: &'static [u8], hold: Duration) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        // Drain the request head so the client can send it.
        let mut buf = vec![0u8; 8192];
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let read = stream.read(&mut buf).await.unwrap_or(0);
                if read == 0 || buf[..read].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        })
        .await;
        if !hold.is_zero() {
            tokio::time::sleep(hold).await;
        }
        let _ = stream.write_all(response).await;
    });
    addr
}

/// One-shot TLS server with a self-signed certificate (rcgen); answers
/// with `response` once the handshake completes.
async fn fake_tls_server(response: &'static [u8]) -> std::net::SocketAddr {
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
            .expect("self-signed cert");
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key)
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut tls) = acceptor.accept(stream).await else {
            return;
        };
        let mut buf = vec![0u8; 8192];
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let read = tls.read(&mut buf).await.unwrap_or(0);
                if read == 0 || buf[..read].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        })
        .await;
        let _ = tls.write_all(response).await;
    });
    addr
}

fn http_task(url: String, success_content: &[&str], timeout_secs: u32, insecure: bool) -> HttpTask {
    HttpTask {
        url,
        method: "GET".into(),
        headers: Vec::new(),
        body: String::new(),
        success_content: success_content.iter().map(|s| (*s).to_owned()).collect(),
        timeout: timeout_secs,
        insecure_skip_verify: insecure,
    }
}

const OK_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nbody ok end";

#[tokio::test]
async fn http_success_content() {
    let addr = fake_http_server(OK_RESPONSE, Duration::ZERO).await;
    // Any one match is enough.
    let task = http_task(format!("http://{addr}/hook"), &["nope", "ok"], 5, false);
    let outcome = exec::http::run(&task, None, &never_cancelled()).await;
    assert!(outcome.success, "{}", outcome.output);
    assert!(outcome.output.contains("HTTP 200"));
    // No match fails even on 2xx.
    let addr = fake_http_server(OK_RESPONSE, Duration::ZERO).await;
    let task = http_task(format!("http://{addr}/hook"), &["absent"], 5, false);
    let outcome = exec::http::run(&task, None, &never_cancelled()).await;
    assert!(!outcome.success);
    assert!(
        outcome.output.contains("successContent 中的任何一项"),
        "{}",
        outcome.output
    );
    // Empty successContent: 2xx alone succeeds.
    let addr = fake_http_server(OK_RESPONSE, Duration::ZERO).await;
    let task = http_task(format!("http://{addr}/hook"), &[], 5, false);
    let outcome = exec::http::run(&task, None, &never_cancelled()).await;
    assert!(outcome.success);
    // Non-2xx fails.
    let addr = fake_http_server(
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno",
        Duration::ZERO,
    )
    .await;
    let task = http_task(format!("http://{addr}/hook"), &[], 5, false);
    let outcome = exec::http::run(&task, None, &never_cancelled()).await;
    assert!(!outcome.success);
    assert!(outcome.output.contains("HTTP 500"), "{}", outcome.output);
}

#[tokio::test]
async fn http_timeout_and_skip_verify() {
    // A server that holds the connection: the per-request timeout aborts.
    let addr = fake_http_server(OK_RESPONSE, Duration::from_secs(30)).await;
    let task = http_task(format!("http://{addr}/hook"), &[], 1, false);
    let begun = std::time::Instant::now();
    let outcome = exec::http::run(&task, None, &never_cancelled()).await;
    assert!(!outcome.success, "{}", outcome.output);
    assert!(
        begun.elapsed() < Duration::from_secs(10),
        "the request timed out instead of hanging: {:?}",
        begun.elapsed()
    );
    // Self-signed TLS: verification fails without the skip flag.
    let addr = fake_tls_server(OK_RESPONSE).await;
    let task = http_task(format!("https://{addr}/hook"), &[], 5, false);
    let outcome = exec::http::run(&task, None, &never_cancelled()).await;
    assert!(!outcome.success, "{}", outcome.output);
    // With insecureSkipVerify the request succeeds.
    let addr = fake_tls_server(OK_RESPONSE).await;
    let task = http_task(format!("https://{addr}/hook"), &[], 5, true);
    let outcome = exec::http::run(&task, None, &never_cancelled()).await;
    assert!(outcome.success, "{}", outcome.output);
}

#[tokio::test]
async fn injected_executor_answers_and_is_used() {
    // The assembler can replace the built-in client (fg-net OutboundHttp).
    let executor: exec::http::HttpExecutor = Arc::new(|request: HttpRequest| {
        assert_eq!(request.url, "https://example.com/injected");
        Box::pin(async {
            Ok(HttpResponse {
                status: 200,
                body: "injected ok".into(),
            })
        })
    });
    let task = http_task("https://example.com/injected".into(), &["ok"], 5, false);
    let outcome = exec::http::run(&task, Some(executor), &never_cancelled()).await;
    assert!(outcome.success, "{}", outcome.output);
}
