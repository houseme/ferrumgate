use std::sync::Arc;

use anyhow::{Result, ensure};
use futures_util::StreamExt;
use h2::{Reason, RecvStream, SendStream, client::SendRequest, server::SendResponse};
use hyper::{
    Request, Response,
    body::Bytes,
    header::{HeaderMap, HeaderValue},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Notify,
    task::JoinSet,
    time::timeout,
};
use tokio_tungstenite::tungstenite::Message;

use super::{
    common::*,
    websocket::{echo, websocket_client},
};

async fn h2_origin(io: impl AsyncRead + AsyncWrite + Unpin, cancelled: Arc<Notify>) -> Result<()> {
    let mut connection = h2::server::handshake(io).await?;
    let mut tasks = JoinSet::new();
    while let Some(stream) = connection.accept().await {
        let (request, respond) = stream?;
        let cancelled = cancelled.clone();
        tasks.spawn(async move {
            let result = h2_reply(request, respond).await;
            if result.is_err_and(|error| error.reason() == Some(Reason::CANCEL)) {
                cancelled.notify_one();
            }
        });
    }
    Ok(())
}

async fn h2_reply(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
) -> Result<(), h2::Error> {
    if !request.headers().contains_key("content-type") {
        let mut reply = respond.send_response(Response::new(()), false)?;
        return reply.send_data(Bytes::from_static(b"h2 origin"), true);
    }
    assert_eq!(request.headers()["x-forwarded-proto"], "https");
    assert_eq!(request.headers()["te"], "trailers");
    assert_eq!(
        request.uri().path_and_query().unwrap().as_str(),
        "/echo.Service/Chat?name=%2F"
    );
    let mut outgoing = respond.send_response(
        Response::builder()
            .header("content-type", "application/grpc")
            .body(())
            .unwrap(),
        false,
    )?;
    let mut incoming = request.into_body();
    while let Some(chunk) = incoming.data().await {
        let chunk = chunk?;
        incoming.flow_control().release_capacity(chunk.len())?;
        outgoing.send_data(chunk, false)?;
    }
    let sent = incoming.trailers().await?.unwrap_or_default();
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("0"));
    trailers.insert("x-backend-tail", HeaderValue::from_static("complete"));
    trailers.insert(
        "x-request-tail",
        sent.get("x-client-tail")
            .cloned()
            .unwrap_or(HeaderValue::from_static("missing")),
    );
    outgoing.send_trailers(trailers)
}

async fn h2_client(
    io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
) -> Result<SendRequest<Bytes>> {
    let (sender, connection) = timeout(DEADLINE, h2::client::handshake(io)).await??;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(sender)
}

fn h2_request(host: &str, grpc: bool) -> Request<()> {
    let request = Request::builder().uri(format!("https://{host}/echo.Service/Chat?name=%2F"));
    if grpc {
        request
            .method("POST")
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .unwrap()
    } else {
        request.body(()).unwrap()
    }
}

fn setup_tls() -> Result<(tempfile::TempDir, Ca)> {
    let temp = tempfile::tempdir()?;
    let ca = Ca::new()?;
    ca.write(temp.path())?;
    ca.identity("app.test")?.write(temp.path(), "app")?;
    Ok((temp, ca))
}

fn tls_settings(routes: String) -> String {
    config(
        &(routes + &certificate("app.test", "app")),
        "tls = true",
        "upstream_ca_file = \"ca.pem\"",
    )
}

async fn grpc_stream(
    sender: &SendRequest<Bytes>,
) -> Result<(h2::client::ResponseFuture, SendStream<Bytes>)> {
    Ok(timeout(DEADLINE, sender.clone().ready())
        .await??
        .send_request(h2_request("app.test", true), false)?)
}

async fn exchange(
    send: &mut SendStream<Bytes>,
    receive: &mut RecvStream,
    payload: &[u8],
) -> Result<()> {
    let mut record = vec![0];
    record.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    record.extend_from_slice(payload);
    let record = Bytes::from(record);
    send.send_data(record.clone(), false)?;
    let echoed = timeout(DEADLINE, receive.data())
        .await?
        .expect("gRPC echo data")?;
    receive.flow_control().release_capacity(echoed.len())?;
    assert_eq!(echoed, record);
    Ok(())
}

async fn complete(mut send: SendStream<Bytes>, mut receive: RecvStream) -> Result<()> {
    let mut trailers = HeaderMap::new();
    trailers.insert("x-client-tail", HeaderValue::from_static("request"));
    send.send_trailers(trailers)?;
    assert!(timeout(DEADLINE, receive.data()).await?.is_none());
    let end = timeout(DEADLINE, receive.trailers())
        .await??
        .expect("gRPC trailers");
    assert_eq!(end["grpc-status"], "0");
    assert_eq!(end["x-backend-tail"], "complete");
    assert_eq!(end["x-request-tail"], "request");
    Ok(())
}

#[tokio::test]
async fn h2c_multiplexes_grpc_and_keeps_websocket_on_http1() -> Result<()> {
    let (temp, ca) = setup_tls()?;
    let cancelled = Arc::new(Notify::new());
    let origin = Origin::spawn({
        let cancelled = cancelled.clone();
        move |socket| {
            let cancelled = cancelled.clone();
            async move {
                let mut first = [0];
                ensure!(socket.peek(&mut first).await? != 0, "empty upstream");
                if first == *b"G" {
                    echo(socket, Arc::new(Notify::new())).await
                } else {
                    h2_origin(socket, cancelled).await
                }
            }
        }
    })
    .await?;
    let routes = route("app.test", origin.addr, "/") + "upstream_h2c = true\nwebsocket = true\n";
    let gateway = Gateway::with_dir(&tls_settings(routes), temp).await?;
    let sender = h2_client(ca.connect(gateway.addr, "app.test", b"h2").await?).await?;
    let (a, mut send_a) = grpc_stream(&sender).await?;
    let (b, mut send_b) = grpc_stream(&sender).await?;
    let mut recv_a = timeout(DEADLINE, a).await??.into_body();
    let mut recv_b = timeout(DEADLINE, b).await??.into_body();
    exchange(&mut send_a, &mut recv_a, b"first").await?;
    exchange(&mut send_b, &mut recv_b, b"second").await?;
    send_b.send_reset(Reason::CANCEL);
    timeout(DEADLINE, cancelled.notified()).await?;
    exchange(&mut send_a, &mut recv_a, b"third").await?;
    complete(send_a, recv_a).await?;

    let (mut websocket, _) = websocket_client(
        ca.connect(gateway.addr, "app.test", b"http/1.1").await?,
        "/ws",
        false,
    )
    .await?;
    assert_eq!(
        timeout(DEADLINE, websocket.next()).await?.unwrap()?,
        Message::text("ready")
    );
    Ok(())
}

#[tokio::test]
async fn https_origin_negotiates_h2_and_checks_authority() -> Result<()> {
    let (temp, ca) = setup_tls()?;
    let acceptor = ca.identity("localhost")?.acceptor(b"h2")?;
    let origin = Origin::spawn(move |socket| {
        let acceptor = acceptor.clone();
        async move { h2_origin(acceptor.accept(socket).await?, Arc::new(Notify::new())).await }
    })
    .await?;
    let routes = format!(
        "[[routes]]\nhost = \"app.test\"\nupstream = \"https://localhost:{}\"\n",
        origin.addr.port()
    );
    let gateway = Gateway::with_dir(&tls_settings(routes), temp).await?;
    let mut sender = h2_client(ca.connect(gateway.addr, "app.test", b"h2").await?).await?;
    let (wrong, _) = sender.send_request(h2_request("other.test", false), true)?;
    assert_eq!(timeout(DEADLINE, wrong).await??.status(), 421);
    let (headers, mut send) = grpc_stream(&sender).await?;
    let result = timeout(DEADLINE, headers).await??;
    assert_eq!(result.status(), 200);
    let mut body = result.into_body();
    exchange(&mut send, &mut body, b"secure grpc").await?;
    complete(send, body).await
}

#[tokio::test]
async fn h2_ingress_proxies_http1_and_rejects_grpc_to_http1() -> Result<()> {
    let (temp, ca) = setup_tls()?;
    let origin = Origin::http("http1 origin").await?;
    let gateway =
        Gateway::with_dir(&tls_settings(route("app.test", origin.addr, "/")), temp).await?;
    let mut sender = h2_client(ca.connect(gateway.addr, "app.test", b"h2").await?).await?;
    let (plain, _) = sender.send_request(h2_request("app.test", false), true)?;
    let response = timeout(DEADLINE, plain).await??;
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    assert_eq!(
        timeout(DEADLINE, body.data()).await?.unwrap()?,
        "http1 origin"
    );
    let (grpc, _) = grpc_stream(&sender).await?;
    assert_eq!(timeout(DEADLINE, grpc).await??.status(), 502);
    Ok(())
}
