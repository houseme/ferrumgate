use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result};
use http_body_util::BodyExt;
use hyper::{Method, StatusCode, header::CONTENT_TYPE};
use serde_json::json;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UdpSocket,
    time::{sleep, timeout},
};

use super::common::*;

async fn scrape(addr: SocketAddr) -> Result<String> {
    let mut client = http_client(connect(addr).await?).await?;
    let response = send(
        &mut client,
        request(Method::GET, "/api/metrics", "localhost", full("")),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[CONTENT_TYPE],
        "text/plain; version=0.0.4; charset=utf-8"
    );
    let body = timeout(DEADLINE, response.into_body().collect())
        .await??
        .to_bytes();
    Ok(String::from_utf8(body.to_vec())?)
}

async fn wait_for(addr: SocketAddr, expected: &[String]) -> Result<()> {
    timeout(DEADLINE, async {
        loop {
            let text = scrape(addr).await?;
            if expected.iter().all(|sample| {
                text.lines().any(|line| {
                    line.strip_prefix("ferrumgate_portforward_")
                        .is_some_and(|value| value == sample)
                })
            }) {
                return Ok(());
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .with_context(|| format!("waiting for metrics {expected:?}"))?
}

#[tokio::test]
async fn tcp_metrics_track_live_bytes_exclude_proxy_header_and_release_on_timeout() -> Result<()> {
    let upstream = Origin::spawn(|socket| async move {
        let mut socket = BufReader::new(socket);
        let mut header = String::new();
        socket.read_line(&mut header).await?;
        assert!(header.starts_with("PROXY TCP4 "));
        let mut payload = [0; 3];
        socket.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"req");
        socket.get_mut().write_all(b"reply").await?;
        let mut byte = [0];
        assert_eq!(socket.read(&mut byte).await?, 0);
        Ok(())
    })
    .await?;
    let forwarding = forwarding_json(
        json!({}),
        &[tcp_rule(
            &format!("127.0.0.1:{}", free_tcp_ports(1)?[0]),
            &[upstream.addr.to_string()],
            json!({"proxy_protocol": "v1"}),
        )],
    );
    let gateway = Gateway::spawn_forwarding(
        &config(
            "",
            "http_enabled = false\nmetrics_listen = \"127.0.0.1:0\"",
            "",
        ),
        &forwarding,
    )
    .await?;
    let metrics = gateway.metrics_addr.context("metrics listener address")?;
    let listen = gateway.addr;
    let labels = format!("protocol=\"tcp\",listen=\"{listen}\"");
    let mut client = connect(listen).await?;
    client.write_all(b"req").await?;
    let mut response = [0; 5];
    timeout(DEADLINE, client.read_exact(&mut response)).await??;
    assert_eq!(&response, b"reply");
    let bytes_in = format!("bytes_total{{{labels},direction=\"in\"}} 3");
    let bytes_out = format!("bytes_total{{{labels},direction=\"out\"}} 5");
    wait_for(
        metrics,
        &[
            format!("active_connections{{{labels}}} 1"),
            format!("connections_total{{{labels}}} 1"),
            bytes_in.clone(),
            bytes_out.clone(),
        ],
    )
    .await?;
    // Close the flow so the relay releases its counters.
    drop(client);
    wait_for(
        metrics,
        &[
            format!("active_connections{{{labels}}} 0"),
            bytes_in,
            bytes_out,
        ],
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn udp_metrics_track_sessions_and_policy_denials() -> Result<()> {
    let upstream = UdpSocket::bind("127.0.0.1:0").await?;
    let target = upstream.local_addr()?;
    let toml = config(
        "",
        "http_enabled = false\nmetrics_listen = \"127.0.0.1:0\"",
        "",
    );
    let listen = format!("127.0.0.1:{}", free_udp_ports(1)?[0]);
    let settings = |policy: serde_json::Value| -> Result<String> {
        let mut options = json!({"udp_session_timeout": 1});
        if let (Some(base), Some(extra)) = (options.as_object_mut(), policy.as_object()) {
            base.extend(extra.clone());
        }
        Ok(forwarding_json(
            json!({}),
            &[udp_rule(&listen, &[target.to_string()], options)],
        ))
    };
    let gateway = Gateway::spawn_forwarding(&toml, &settings(json!({}))?).await?;
    let metrics = gateway.metrics_addr.context("metrics listener address")?;
    let labels = format!("protocol=\"udp\",listen=\"{}\"", gateway.addr);
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(b"sample", gateway.addr).await?;
    let mut buffer = [0; 16];
    let (length, relay) = timeout(DEADLINE, upstream.recv_from(&mut buffer)).await??;
    assert_eq!(&buffer[..length], b"sample");
    upstream.send_to(b"ok", relay).await?;
    let (length, _) = timeout(DEADLINE, client.recv_from(&mut buffer)).await??;
    assert_eq!(&buffer[..length], b"ok");
    wait_for(
        metrics,
        &[
            format!("active_connections{{{labels}}} 1"),
            format!("connections_total{{{labels}}} 1"),
            format!("bytes_total{{{labels},direction=\"in\"}} 6"),
            format!("bytes_total{{{labels},direction=\"out\"}} 2"),
        ],
    )
    .await?;
    wait_for(metrics, &[format!("active_connections{{{labels}}} 0")]).await?;

    #[cfg(unix)]
    {
        let mut gateway = gateway;
        gateway.replace_forwarding(&settings(json!({"deny": ["127.0.0.1"]}))?)?;
        gateway.signal("-HUP").await?;
        gateway.wait_log("configuration reloaded").await?;
        client.send_to(b"denied", gateway.addr).await?;
        wait_for(
            metrics,
            &[
                format!("source_denied_total{{{labels}}} 1"),
                format!("connections_total{{{labels}}} 1"),
                format!("bytes_total{{{labels},direction=\"in\"}} 6"),
            ],
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn metrics_require_a_separate_loopback_socket() -> Result<()> {
    let routes = "\n[[routes]]\nhost = \"app.test\"\nupstream = \"http://127.0.0.1:9000\"\n";
    let dir = tempfile::tempdir()?;
    for listen in [
        "0.0.0.0:9090",
        "[::]:9090",
        "192.0.2.1:9090",
        "127.0.0.1:8080",
    ] {
        let settings = format!("metrics_listen = \"{listen}\"");
        let contents = config(routes, &settings, "")
            .replace("listen = \"127.0.0.1:0\"", "listen = \"127.0.0.1:8080\"");
        assert!(!Gateway::check(dir.path(), &contents).await?, "{listen}");
    }
    let gateway = Gateway::spawn(&config(routes, "metrics_listen = \"127.0.0.1:0\"", "")).await?;
    let metrics = gateway.metrics_addr.context("metrics listener address")?;
    assert_ne!(gateway.addr, metrics);
    for (method, path, status) in [
        (Method::GET, "/", StatusCode::NOT_FOUND),
        (Method::POST, "/api/metrics", StatusCode::METHOD_NOT_ALLOWED),
    ] {
        let mut client = http_client(connect(metrics).await?).await?;
        let response = send(&mut client, request(method, path, "localhost", full(""))).await?;
        assert_eq!(response.status(), status);
    }
    assert!(
        scrape(metrics)
            .await?
            .contains("# TYPE ferrumgate_portforward_bytes_total counter")
    );
    Ok(())
}
