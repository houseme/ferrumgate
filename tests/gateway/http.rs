use std::sync::Arc;

use anyhow::Result;
use futures_util::stream;
use http_body_util::{BodyExt, StreamBody};
use hyper::{
    Method, Response,
    body::{Bytes, Frame},
    header::{CONNECTION, CONTENT_LENGTH, HeaderMap, HeaderValue, TRAILER},
};
use tokio::{sync::Notify, task::JoinSet, time::timeout};

use super::common::*;

#[tokio::test]
async fn rejects_invalid_schema() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let upstream = "127.0.0.1:9000".parse()?;
    let base = route("app.test", upstream, "/");
    assert!(Gateway::check(dir.path(), &config(&base, "", "")).await?);
    for invalid in [
        config(&base, "unknown = true", ""),
        config(
            &format!("{base}{}", route("APP.TEST.", upstream, "/")),
            "",
            "",
        ),
        config(&base.replace("http://", "http://user@"), "", ""),
        config(
            &base.replace("path_prefix = \"/\"", "path_prefix = \"/api?\""),
            "",
            "",
        ),
        config(&base, "max_connections = 0", ""),
    ] {
        assert!(!Gateway::check(dir.path(), &invalid).await?, "{invalid}");
    }
    Ok(())
}

#[tokio::test]
async fn forwards_routes_headers_bodies_and_reuses_connections() -> Result<()> {
    let root = Origin::http("root").await?;
    let api = Origin::spawn(|stream| async move {
        let peer = stream.peer_addr()?.port();
        serve_http(stream, |request| async move {
            let (head, body) = request.into_parts();
            let bytes = body.collect().await.unwrap().to_bytes();
            let mut builder = Response::builder()
                .header("x-target", head.uri.to_string())
                .header("x-peer-port", peer.to_string())
                .header("connection", "x-backend-hop")
                .header("connection", "x-other-backend-hop")
                .header("x-backend-hop", "remove")
                .header("x-other-backend-hop", "remove");
            for (name, value) in head.headers.iter() {
                builder = builder.header(format!("x-seen-{name}"), value);
            }
            builder.body(full(bytes)).unwrap()
        })
        .await
    })
    .await?;
    let routes = route("app.test", root.addr, "/") + &route("app.test", api.addr, "/api");
    let gateway = Gateway::spawn(&config(&routes, "", "")).await?;
    let mut client = http_client(connect(gateway.addr).await?).await?;
    let mut upload = request(
        Method::POST,
        "/api/v1?q=%2F",
        "APP.TEST.:9010",
        frames([
            Frame::data(Bytes::from_static(b"hello")),
            Frame::data(Bytes::from_static(b"world")),
        ]),
    );
    upload.headers_mut().append(
        CONNECTION,
        HeaderValue::from_static("x-client-hop, x-other-hop"),
    );
    for header in [
        "x-client-hop",
        "x-other-hop",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-extra",
        "x-real-ip",
    ] {
        upload
            .headers_mut()
            .insert(header, HeaderValue::from_static("untrusted.test"));
    }
    let response = send(&mut client, upload).await?;
    assert_eq!(response.status(), 200);
    let headers = response.headers();
    assert_eq!(headers["x-target"], "/api/v1?q=%2F");
    assert_eq!(headers["x-seen-host"], api.addr.to_string());
    assert_eq!(headers["x-seen-x-forwarded-for"], "127.0.0.1");
    assert_eq!(headers["x-seen-x-forwarded-host"], "APP.TEST.:9010");
    assert_eq!(headers["x-seen-x-forwarded-proto"], "http");
    for header in [
        "x-seen-x-client-hop",
        "x-seen-x-other-hop",
        "x-seen-forwarded",
        "x-seen-x-forwarded-extra",
        "x-seen-x-real-ip",
        "x-backend-hop",
        "x-other-backend-hop",
    ] {
        assert!(!headers.contains_key(header), "{header}");
    }
    let peer = headers["x-peer-port"].clone();
    assert_eq!(
        response.into_body().collect().await?.to_bytes(),
        "helloworld"
    );

    let mut chunked_get = request(
        Method::GET,
        "/api",
        "app.test",
        frames([Frame::data(Bytes::from_static(b"get data"))]),
    );
    chunked_get
        .headers_mut()
        .insert("transfer-encoding", HeaderValue::from_static("chunked"));
    let returned = send(&mut client, chunked_get).await?;
    assert_eq!(returned.headers()["x-peer-port"], peer);
    assert_eq!(returned.into_body().collect().await?.to_bytes(), "get data");

    let large = Bytes::from(vec![b'x'; 1024 * 1024]);
    let returned = send(
        &mut client,
        request(Method::POST, "/api", "app.test", full(large.clone())),
    )
    .await?;
    assert_eq!(returned.into_body().collect().await?.to_bytes(), large);
    assert_eq!(
        get(&mut client, "app.test", "/apiv2").await?,
        (200, Bytes::from_static(b"root"))
    );
    assert_eq!(get(&mut client, "unknown.test", "/").await?.0, 404);
    assert_eq!(get(&mut client, "bad.test:", "/").await?.0, 400);
    assert_eq!(
        get(&mut client, "app.test", "http://app.test/").await?.0,
        400
    );
    Ok(())
}

#[tokio::test]
async fn streams_before_the_origin_finishes_and_preserves_head() -> Result<()> {
    let release = Arc::new(Notify::new());
    let backend = Origin::spawn({
        let release = release.clone();
        move |socket| {
            let release = release.clone();
            async move {
                serve_http(socket, move |request| {
                    let release = release.clone();
                    async move {
                        if request.method() == Method::HEAD {
                            return Response::builder()
                                .header(CONTENT_LENGTH, "42")
                                .body(full(Bytes::new()))
                                .unwrap();
                        }
                        let mut trailers = HeaderMap::new();
                        trailers.insert("x-trailer", HeaderValue::from_static("ignored"));
                        let chunks = stream::unfold(
                            (0, release, trailers),
                            |(part, release, trailers)| async move {
                                let next = match part {
                                    0 => Frame::data(Bytes::from_static(b"first")),
                                    1 => {
                                        release.notified().await;
                                        Frame::data(Bytes::from_static(b"second"))
                                    }
                                    2 => Frame::trailers(trailers.clone()),
                                    _ => return None,
                                };
                                Some((Ok(next), (part + 1, release, trailers)))
                            },
                        );
                        Response::builder()
                            .header(TRAILER, "x-trailer")
                            .body(StreamBody::new(chunks).boxed_unsync())
                            .unwrap()
                    }
                })
                .await
            }
        }
    })
    .await?;
    let gateway = Gateway::spawn(&config(&route("app.test", backend.addr, "/"), "", "")).await?;
    let mut client = http_client(connect(gateway.addr).await?).await?;
    let response = send(
        &mut client,
        request(Method::GET, "/", "app.test", full(Bytes::new())),
    )
    .await?;
    assert!(!response.headers().contains_key(TRAILER));
    let mut body = response.into_body();
    assert_eq!(
        timeout(DEADLINE, body.frame())
            .await?
            .unwrap()?
            .into_data()
            .unwrap(),
        "first"
    );
    release.notify_one();
    let rest = timeout(DEADLINE, body.collect()).await??;
    assert!(rest.trailers().is_none());
    assert_eq!(rest.to_bytes(), "second");
    let head = send(
        &mut client,
        request(Method::HEAD, "/", "app.test", full(Bytes::new())),
    )
    .await?;
    assert_eq!(head.headers()[CONTENT_LENGTH], "42");
    assert!(head.into_body().collect().await?.to_bytes().is_empty());
    Ok(())
}

#[tokio::test]
async fn handles_parallel_keep_alive_clients() -> Result<()> {
    let backend = Origin::http("alive").await?;
    let gateway = Gateway::spawn(&config(&route("app.test", backend.addr, "/"), "", "")).await?;
    let mut clients = JoinSet::new();
    for _ in 0..16 {
        let address = gateway.addr;
        clients.spawn(async move {
            let mut client = http_client(connect(address).await?).await?;
            for _ in 0..25 {
                assert_eq!(
                    get(&mut client, "app.test", "/").await?,
                    (200, Bytes::from_static(b"alive"))
                );
            }
            Ok::<_, anyhow::Error>(())
        });
    }
    while let Some(result) = timeout(DEADLINE, clients.join_next()).await? {
        result??;
    }
    Ok(())
}

#[tokio::test]
async fn returns_504_for_upstream_header_timeout() -> Result<()> {
    let backend = Origin::spawn(|socket| async move {
        serve_http(socket, |_| async { std::future::pending().await }).await
    })
    .await?;
    let gateway = Gateway::spawn(&config(
        &route("app.test", backend.addr, "/"),
        "response_header_timeout_ms = 200",
        "",
    ))
    .await?;
    let mut client = http_client(connect(gateway.addr).await?).await?;
    assert_eq!(get(&mut client, "app.test", "/").await?.0, 504);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn keeps_last_config_and_drains_inflight_requests() -> Result<()> {
    let old = Origin::http("old").await?;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let new = Origin::spawn({
        let (entered, release) = (entered.clone(), release.clone());
        move |socket| {
            let (entered, release) = (entered.clone(), release.clone());
            async move {
                serve_http(socket, move |request| {
                    let (entered, release) = (entered.clone(), release.clone());
                    async move {
                        if request.uri().path() == "/hold" {
                            entered.notify_one();
                            release.notified().await;
                        }
                        response("new")
                    }
                })
                .await
            }
        }
    })
    .await?;
    // Legacy runtime: the replace+SIGHUP reload parity lives on the TOML path.
    let mut gateway = Gateway::spawn_toml(&config(&route("app.test", old.addr, "/"), "", "")).await?;
    let mut client = http_client(connect(gateway.addr).await?).await?;
    assert_eq!(get(&mut client, "app.test", "/").await?.1, "old");
    gateway.replace("malformed data")?;
    gateway.signal("-HUP").await?;
    gateway.wait_log("configuration reload rejected").await?;
    assert_eq!(get(&mut client, "app.test", "/").await?.1, "old");
    gateway.replace(&config(&route("app.test", new.addr, "/"), "", ""))?;
    gateway.signal("-HUP").await?;
    gateway.wait_log("configuration reloaded").await?;
    assert_eq!(get(&mut client, "app.test", "/").await?.1, "new");

    let pending = tokio::spawn(async move { get(&mut client, "app.test", "/hold").await });
    timeout(DEADLINE, entered.notified()).await?;
    gateway.signal("-TERM").await?;
    gateway.wait_log("gateway draining connections").await?;
    release.notify_one();
    assert_eq!(timeout(DEADLINE, pending).await???.1, "new");
    gateway.wait_exit().await?;
    Ok(())
}
