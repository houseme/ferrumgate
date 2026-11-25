use std::net::SocketAddr;

use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use super::common::*;

fn forwarding(listen: &str, targets: &[SocketAddr], options: &str) -> String {
    let targets = targets
        .iter()
        .map(|target| format!("\"{target}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!("\n[[tcp_forward]]\nlisten = \"{listen}\"\ntargets = [{targets}]\n{options}\n")
}

#[tokio::test]
async fn forwards_tcp_after_a_failed_dial_and_preserves_half_close() -> Result<()> {
    let echo = Origin::spawn(|mut socket| async move {
        let mut received = Vec::new();
        socket.read_to_end(&mut received).await?;
        socket.write_all(&received).await?;
        socket.shutdown().await?;
        Ok(())
    })
    .await?;
    let dead = std::net::TcpListener::bind("127.0.0.1:0")?;
    let dead_address = dead.local_addr()?;
    drop(dead);
    let rule = forwarding("127.0.0.1:0", &[dead_address, echo.addr], "");
    let gateway = Gateway::spawn(&config(&rule, "http_enabled = false", "")).await?;

    let mut socket = connect(gateway.addr).await?;
    socket.write_all(b"binary\0relay").await?;
    socket.shutdown().await?;
    let mut response = Vec::new();
    timeout(DEADLINE, socket.read_to_end(&mut response)).await??;
    assert_eq!(response, b"binary\0relay");
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn keeps_existing_tcp_flow_alive_during_graceful_shutdown() -> Result<()> {
    use std::sync::Arc;
    let entered = Arc::new(tokio::sync::Notify::new());
    let echo = Origin::spawn({
        let entered = entered.clone();
        move |mut stream| {
            let entered = entered.clone();
            async move {
                let mut first = [0];
                stream.read_exact(&mut first).await?;
                entered.notify_one();
                let mut rest = Vec::new();
                stream.read_to_end(&mut rest).await?;
                stream.write_all(&first).await?;
                stream.write_all(&rest).await?;
                stream.shutdown().await?;
                Ok(())
            }
        }
    })
    .await?;
    let rule = forwarding("127.0.0.1:0", &[echo.addr], "max_connections = 1");
    let mut gateway = Gateway::spawn(&config(&rule, "http_enabled = false", "")).await?;
    let mut client = connect(gateway.addr).await?;
    client.write_all(b"a").await?;
    timeout(DEADLINE, entered.notified()).await?;
    gateway.signal("-TERM").await?;
    gateway.wait_log("gateway draining connections").await?;
    client.write_all(b"bc").await?;
    client.shutdown().await?;
    let mut data = Vec::new();
    timeout(DEADLINE, client.read_to_end(&mut data)).await??;
    assert_eq!(data, b"abc");
    gateway.wait_exit().await?;
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_tcp_targets_and_conflicting_listeners() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let addr = "127.0.0.1:9000".parse()?;
    let rule = forwarding("127.0.0.1:9050", &[addr], "");
    for routes in [
        String::new(),
        forwarding("127.0.0.1:9050", &[], ""),
        forwarding("127.0.0.1:9050", &[addr, addr], ""),
        forwarding("127.0.0.1:9000", &[addr], ""),
        rule.repeat(2),
    ] {
        assert!(!Gateway::check(dir.path(), &config(&routes, "http_enabled = false", "")).await?);
    }
    assert!(Gateway::check(dir.path(), &config(&rule, "http_enabled = false", "")).await?);
    Ok(())
}

#[tokio::test]
async fn sends_proxy_v1_and_v2_before_the_client_payload() -> Result<()> {
    let capture = Origin::spawn(|mut socket| async move {
        let mut received = Vec::new();
        socket.read_to_end(&mut received).await?;
        socket.write_all(&received).await?;
        socket.shutdown().await?;
        Ok(())
    })
    .await?;

    for (version, address) in [
        ("v1", "127.0.0.1:0"),
        ("v2", "127.0.0.1:0"),
        ("v2", "[::1]:0"),
    ] {
        let rule = forwarding(
            address,
            &[capture.addr],
            &format!("proxy_protocol = \"{version}\""),
        );
        let gateway = Gateway::spawn(&config(&rule, "http_enabled = false", "")).await?;
        let mut client = connect(gateway.addr).await?;
        let source = client.local_addr()?;
        client.write_all(b"application bytes").await?;
        client.shutdown().await?;
        let mut received = Vec::new();
        timeout(DEADLINE, client.read_to_end(&mut received)).await??;

        let header_len = if version == "v1" {
            let expected = format!(
                "PROXY TCP4 127.0.0.1 127.0.0.1 {} {}\r\n",
                source.port(),
                gateway.addr.port()
            );
            assert!(received.starts_with(expected.as_bytes()));
            expected.len()
        } else {
            assert_eq!(&received[..13], b"\r\n\r\n\0\r\nQUIT\n\x21");
            let ports_at = if source.is_ipv4() {
                assert_eq!(
                    &received[13..24],
                    &[0x11, 0, 12, 127, 0, 0, 1, 127, 0, 0, 1]
                );
                24
            } else {
                assert_eq!(&received[13..16], &[0x21, 0, 36]);
                assert_eq!(&received[16..32], &std::net::Ipv6Addr::LOCALHOST.octets());
                assert_eq!(&received[32..48], &std::net::Ipv6Addr::LOCALHOST.octets());
                48
            };
            assert_eq!(
                &received[ports_at..ports_at + 2],
                &source.port().to_be_bytes()
            );
            assert_eq!(
                &received[ports_at + 2..ports_at + 4],
                &gateway.addr.port().to_be_bytes()
            );
            ports_at + 4
        };
        assert_eq!(&received[header_len..], b"application bytes");
    }
    Ok(())
}
