//! Integration tests for `gateway::listen_unix` (WP-14): a stale socket
//! file left by an abnormal exit is removed and rebound, a non-socket
//! file at the path is refused without touching it, and the socket
//! really serves HTTP round-trips.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use anyhow::Result;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;

#[tokio::test]
async fn listen_unix_removes_a_stale_socket_and_refuses_other_files() -> Result<()> {
    // Dropping a UnixListener leaves its socket file behind: the situation
    // after an abnormal exit. listen_unix must remove it and rebind.
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("gateway.sock");
    drop(std::os::unix::net::UnixListener::bind(&path)?);
    assert!(path.exists(), "stale socket file should remain after drop");

    let listener = fg_admin::gateway::listen_unix(&path).await?;
    // The new listener is live: a client connects and the accept succeeds.
    let client = tokio::net::UnixStream::connect(&path).await?;
    let (accepted, _addr) = listener.accept().await?;
    drop((client, accepted));

    let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
    assert_eq!(mode, 0o660, "socket permissions must be 0660");

    // A regular file at the path is refused, and its content is untouched.
    let other = dir.path().join("plain.sock");
    let content = b"just a regular file";
    std::fs::write(&other, content)?;
    let error = fg_admin::gateway::listen_unix(&other)
        .await
        .expect_err("listen_unix must refuse a non-socket file");
    assert!(
        error.to_string().contains("同名文件不是 Socket"),
        "unexpected error: {error}"
    );
    assert_eq!(
        std::fs::read(&other)?,
        content,
        "regular file must be left unchanged"
    );
    Ok(())
}

#[tokio::test]
async fn serves_http_over_the_socket() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("gateway.sock");
    let listener = fg_admin::gateway::listen_unix(&path).await?;

    let app = axum::Router::new().route(
        "/app/gately/",
        axum::routing::get(|| async { "gately over unix socket" }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await });

    // Same transport fnOS's gateway uses on the other side: HTTP/1 over UDS.
    let stream = tokio::net::UnixStream::connect(&path).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::builder()
        .uri("http://localhost/app/gately/")
        .body(Full::new(Bytes::new()))?;
    let response = sender.send_request(request).await?;
    assert_eq!(response.status(), hyper::StatusCode::OK);
    let body = response.into_body().collect().await?.to_bytes();
    assert_eq!(body, "gately over unix socket");
    server.abort();
    Ok(())
}
