use std::{sync::Arc, time::Duration};

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use hyper::{Response, header::HeaderValue};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Notify,
    time::timeout,
};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async, client_async,
    tungstenite::{
        Error, Message,
        client::IntoClientRequest,
        handshake::{client, derive_accept_key, server},
        protocol::CloseFrame,
    },
};

use super::common::*;

#[expect(
    clippy::result_large_err,
    reason = "the Tungstenite callback owns its HTTP rejection response"
)]
pub(super) async fn echo(
    io: impl AsyncRead + AsyncWrite + Unpin,
    closed: Arc<Notify>,
) -> Result<()> {
    let mut socket = accept_hdr_async(
        io,
        |request: &server::Request, mut response: server::Response| {
            assert_eq!(request.headers()["origin"], "https://app.test");
            assert!(!request.headers().contains_key("sec-websocket-extensions"));
            assert!(!request.headers().contains_key("x-client-hop"));
            assert!(matches!(
                request.headers()["x-forwarded-proto"].to_str(),
                Ok("http" | "https")
            ));
            response
                .headers_mut()
                .insert("sec-websocket-protocol", HeaderValue::from_static("echo"));
            response
                .headers_mut()
                .append("connection", HeaderValue::from_static("x-backend-hop"));
            response
                .headers_mut()
                .insert("x-backend-hop", HeaderValue::from_static("remove"));
            Ok(response)
        },
    )
    .await?;
    socket.send(Message::text("ready")).await?;
    while let Some(Ok(message)) = socket.next().await {
        match message {
            Message::Text(_) | Message::Binary(_) => socket.send(message).await?,
            Message::Ping(_) => socket.flush().await?,
            Message::Close(_) => {
                let _ = socket.flush().await;
                break;
            }
            _ => {}
        }
    }
    closed.notify_one();
    Ok(())
}

pub(super) async fn websocket_client<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    path: &str,
    malformed_key: bool,
) -> Result<(WebSocketStream<S>, client::Response), Error> {
    let mut request = format!("ws://app.test{path}").into_client_request()?;
    let headers = request.headers_mut();
    headers.insert("origin", HeaderValue::from_static("https://app.test"));
    headers.insert(
        "sec-websocket-protocol",
        HeaderValue::from_static("other, echo"),
    );
    headers.insert(
        "sec-websocket-extensions",
        HeaderValue::from_static("permessage-deflate"),
    );
    headers.insert(
        "connection",
        HeaderValue::from_static("keep-alive, Upgrade, X-Client-Hop"),
    );
    headers.insert("x-client-hop", HeaderValue::from_static("remove"));
    if malformed_key {
        headers.insert("sec-websocket-key", HeaderValue::from_static("bad"));
    }
    timeout(DEADLINE, client_async(request, stream))
        .await
        .expect("WebSocket handshake deadline")
}

async fn start_echo() -> Result<(Origin, Arc<Notify>)> {
    let closed = Arc::new(Notify::new());
    let origin = Origin::spawn({
        let closed = closed.clone();
        move |stream| echo(stream, closed.clone())
    })
    .await?;
    Ok((origin, closed))
}

async fn status(address: std::net::SocketAddr, path: &str, malformed_key: bool) -> Result<u16> {
    match websocket_client(connect(address).await?, path, malformed_key).await {
        Err(Error::Http(response)) => Ok(response.status().as_u16()),
        Err(error) => Err(error.into()),
        Ok((_, response)) => Ok(response.status().as_u16()),
    }
}

#[tokio::test]
async fn validates_upgrades_and_relays_text_binary_ping_and_close() -> Result<()> {
    let (origin, _) = start_echo().await?;
    let bad = Origin::spawn(|socket| async move {
        serve_http(socket, |request| async move {
            if request.uri().path() == "/bad/refused" {
                return Response::builder()
                    .status(403)
                    .body(full("refused"))
                    .unwrap();
            }
            let accept = if request.uri().path() == "/bad/proof" {
                "invalid".into()
            } else {
                derive_accept_key(request.headers()["sec-websocket-key"].as_bytes())
            };
            Response::builder()
                .status(101)
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-accept", accept)
                .header("sec-websocket-protocol", "not-offered")
                .body(full(""))
                .unwrap()
        })
        .await
    })
    .await?;
    let routes = route("app.test", origin.addr, "/")
        + &route("app.test", origin.addr, "/ws")
        + "websocket = true\n"
        + &route("app.test", bad.addr, "/bad")
        + "websocket = true\n";
    #[allow(unused_mut)]
    let mut gateway = Gateway::spawn(&config(&routes, "", "")).await?;
    for (path, malformed, code) in [
        ("/", false, 501),
        ("/ws", true, 400),
        ("/bad/proof", false, 502),
        ("/bad/protocol", false, 502),
        ("/bad/refused", false, 403),
    ] {
        assert_eq!(status(gateway.addr, path, malformed).await?, code, "{path}");
    }
    let (mut client, handshake) =
        websocket_client(connect(gateway.addr).await?, "/ws", false).await?;
    assert_eq!(handshake.headers()["sec-websocket-protocol"], "echo");
    assert!(!handshake.headers().contains_key("x-backend-hop"));
    assert_eq!(
        timeout(DEADLINE, client.next()).await?.unwrap()?,
        Message::text("ready")
    );
    #[cfg(unix)]
    {
        gateway.replace(&config(
            &routes.replace("websocket = true", "websocket = false"),
            "",
            "",
        ))?;
        gateway.signal("-HUP").await?;
        gateway.wait_log("configuration reloaded").await?;
        assert_eq!(status(gateway.addr, "/ws", false).await?, 501);
    }

    for (send, receive) in [
        (Message::text("hello"), Message::text("hello")),
        (Message::binary(vec![0, 255]), Message::binary(vec![0, 255])),
        (Message::Ping(vec![1].into()), Message::Pong(vec![1].into())),
    ] {
        client.send(send).await?;
        assert_eq!(timeout(DEADLINE, client.next()).await?.unwrap()?, receive);
    }
    let close = Message::Close(Some(CloseFrame {
        code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
        reason: "".into(),
    }));
    client.send(close.clone()).await?;
    assert_eq!(timeout(DEADLINE, client.next()).await?.unwrap()?, close);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn retains_admission_slot_and_closes_both_ends_on_shutdown() -> Result<()> {
    let (origin, closed) = start_echo().await?;
    let routes = route("app.test", origin.addr, "/ws") + "websocket = true\n";
    let mut gateway = Gateway::spawn(&config(
        &routes,
        "max_connections = 1\nshutdown_timeout_ms = 500",
        "",
    ))
    .await?;
    let (mut client, _) = websocket_client(connect(gateway.addr).await?, "/ws", false).await?;
    timeout(DEADLINE, client.next()).await?.unwrap()?;
    let mut waiting = http_client(connect(gateway.addr).await?).await?;
    assert!(
        timeout(
            Duration::from_millis(200),
            get(&mut waiting, "app.test", "/")
        )
        .await
        .is_err()
    );
    gateway.signal("-TERM").await?;
    let end = timeout(DEADLINE, client.next()).await?;
    assert!(end.is_none_or(|message| message.is_err()));
    timeout(DEADLINE, closed.notified()).await?;
    gateway.wait_exit().await?;
    Ok(())
}

#[tokio::test]
async fn websocket_expires_with_the_connection_lifetime() -> Result<()> {
    let (origin, closed) = start_echo().await?;
    let routes = route("app.test", origin.addr, "/ws") + "websocket = true\n";
    let gateway = Gateway::spawn(&config(&routes, "connection_lifetime_ms = 800", "")).await?;
    let (mut client, _) = websocket_client(connect(gateway.addr).await?, "/ws", false).await?;
    timeout(DEADLINE, client.next()).await?.unwrap()?;
    assert!(
        timeout(DEADLINE, client.next())
            .await?
            .is_none_or(|message| message.is_err())
    );
    timeout(DEADLINE, closed.notified()).await?;
    Ok(())
}

#[tokio::test]
async fn forwards_websocket_over_tls_to_a_verified_tls_origin() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let ca = Ca::new()?;
    ca.write(dir.path())?;
    ca.identity("app.test")?.write(dir.path(), "app")?;
    let acceptor = ca.identity("localhost")?.acceptor(b"http/1.1")?;
    let backend = Origin::spawn(move |socket| {
        let acceptor = acceptor.clone();
        async move { echo(acceptor.accept(socket).await?, Arc::new(Notify::new())).await }
    })
    .await?;
    let routes = format!(
        "\n[[routes]]\nhost = \"app.test\"\nupstream = \"https://localhost:{}\"\nwebsocket = true\n",
        backend.addr.port()
    ) + &certificate("app.test", "app");
    let gateway = Gateway::with_dir(
        &config(&routes, "tls = true", "upstream_ca_file = \"ca.pem\""),
        dir,
    )
    .await?;
    let stream = ca.connect(gateway.addr, "app.test", b"http/1.1").await?;
    let (mut client, _) = websocket_client(stream, "/ws", false).await?;
    assert_eq!(
        timeout(DEADLINE, client.next()).await?.unwrap()?,
        Message::text("ready")
    );
    client.send(Message::text("secure")).await?;
    assert_eq!(
        timeout(DEADLINE, client.next()).await?.unwrap()?,
        Message::text("secure")
    );
    Ok(())
}
