use std::{cmp::Reverse, net::SocketAddr, time::Duration};

use anyhow::Result;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use super::common::*;

/// Legacy TOML emission used by `modules.rs` to embed a forwarding rule in
/// the manifest.
pub(super) fn forwarding(listen: &str, targets: &[SocketAddr], options: &str) -> String {
    let targets = targets
        .iter()
        .map(|target| format!("\"{target}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!("\n[[tcp_forward]]\nlisten = \"{listen}\"\ntargets = [{targets}]\n{options}\n")
}

/// Renders a portforward.json document with one TCP rule. A `:0` listen
/// resolves to a concrete reserved port (the JSON model rejects port 0).
fn forwarding_with(
    settings: Value,
    listen: &str,
    targets: &[SocketAddr],
    options: Value,
) -> Result<String> {
    Ok(forwarding_json(
        settings,
        &[tcp_rule(
            &reserve(listen)?,
            &targets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            options,
        )],
    ))
}

fn forwarding_rules(listen: &str, targets: &[SocketAddr], options: Value) -> Result<String> {
    forwarding_with(json!({}), listen, targets, options)
}

fn reserve(listen: &str) -> Result<String> {
    Ok(if let Some(host) = listen.strip_suffix(":0") {
        let port = if host == "[::1]" {
            free_tcp6_ports(1)?[0]
        } else {
            free_tcp_ports(1)?[0]
        };
        format!("{host}:{port}")
    } else {
        listen.to_owned()
    })
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
    let forwarding = forwarding_rules("127.0.0.1:0", &[dead_address, echo.addr], json!({}))?;
    let gateway =
        Gateway::spawn_forwarding(&config("", "http_enabled = false", ""), &forwarding).await?;

    let mut socket = connect(gateway.addr).await?;
    socket.write_all(b"binary\0relay").await?;
    socket.shutdown().await?;
    let mut response = Vec::new();
    timeout(DEADLINE, socket.read_to_end(&mut response)).await??;
    assert_eq!(response, b"binary\0relay");
    Ok(())
}

#[tokio::test]
async fn first_data_timeout_releases_an_idle_slot_after_sending_proxy_header() -> Result<()> {
    let origin = Origin::spawn(|socket| async move {
        use tokio::io::{AsyncBufReadExt, BufReader};

        let mut socket = BufReader::new(socket);
        let mut header = String::new();
        socket.read_line(&mut header).await?;
        assert!(header.starts_with("PROXY TCP4 "));
        let mut byte = [0];
        if socket.read(&mut byte).await? != 0 {
            socket.get_mut().write_all(&byte).await?;
        }
        Ok(())
    })
    .await?;
    // The JSON model carries the first-data timeout in whole seconds.
    let forwarding = forwarding_with(
        json!({"first_data_timeout": 1}),
        "127.0.0.1:0",
        &[origin.addr],
        json!({"proxy_protocol": "v1", "max_connections": 1}),
    )?;
    let gateway =
        Gateway::spawn_forwarding(&config("", "http_enabled = false", ""), &forwarding).await?;
    let mut idle = connect(gateway.addr).await?;
    let mut byte = [0];
    assert_eq!(timeout(DEADLINE, idle.read(&mut byte)).await??, 0);

    let mut active = connect(gateway.addr).await?;
    active.write_all(b"a").await?;
    assert_eq!(timeout(DEADLINE, active.read_u8()).await??, b'a');
    Ok(())
}

#[tokio::test]
async fn server_first_data_disarms_the_timeout_for_both_directions() -> Result<()> {
    let origin = Origin::spawn(|mut socket| async move {
        socket.write_all(b"a").await?;
        let byte = socket.read_u8().await?;
        socket.write_u8(byte).await?;
        Ok(())
    })
    .await?;
    let forwarding = forwarding_with(
        json!({"first_data_timeout": 1}),
        "127.0.0.1:0",
        &[origin.addr],
        json!({}),
    )?;
    let gateway =
        Gateway::spawn_forwarding(&config("", "http_enabled = false", ""), &forwarding).await?;
    let mut client = connect(gateway.addr).await?;
    assert_eq!(timeout(DEADLINE, client.read_u8()).await??, b'a');
    assert!(
        timeout(Duration::from_millis(600), client.read_u8())
            .await
            .is_err()
    );
    client.write_u8(b'b').await?;
    assert_eq!(timeout(DEADLINE, client.read_u8()).await??, b'b');
    Ok(())
}

#[tokio::test]
async fn empty_client_half_close_reaches_the_upstream() -> Result<()> {
    let origin = Origin::spawn(|mut socket| async move {
        let mut byte = [0];
        assert_eq!(socket.read(&mut byte).await?, 0);
        socket.write_all(b"eof").await?;
        Ok(())
    })
    .await?;
    let forwarding = forwarding_rules("127.0.0.1:0", &[origin.addr], json!({}))?;
    let gateway =
        Gateway::spawn_forwarding(&config("", "http_enabled = false", ""), &forwarding).await?;
    let mut client = connect(gateway.addr).await?;
    client.shutdown().await?;
    let mut buffer = [0; 3];
    timeout(DEADLINE, client.read_exact(&mut buffer)).await??;
    assert_eq!(&buffer, b"eof");
    Ok(())
}

#[tokio::test]
async fn forwards_each_tcp_port_to_the_matching_target_position() -> Result<()> {
    let first = Origin::spawn(|mut stream| async move {
        stream.write_u8(b'a').await?;
        Ok(())
    })
    .await?;
    let second = Origin::spawn(|mut stream| async move {
        stream.write_u8(b'b').await?;
        Ok(())
    })
    .await?;
    let start = (0..32)
        .find_map(|_| {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
            // Steer clear of the ephemeral ports allocated by parallel tests.
            let port = 12_000 + probe.local_addr().ok()?.port() % 20_000;
            let _first = std::net::TcpListener::bind(("127.0.0.1", port)).ok()?;
            let _second = std::net::TcpListener::bind(("127.0.0.1", port + 1)).ok()?;
            Some(port)
        })
        .ok_or_else(|| anyhow::anyhow!("no consecutive loopback TCP ports available"))?;
    let mut targets = [(first.addr.port(), b'a'), (second.addr.port(), b'b')];
    targets.sort_unstable_by_key(|&(port, _)| Reverse(port));
    let forwarding = forwarding_json(
        json!({}),
        &[tcp_rule(
            &format!("127.0.0.1:{start}-{}", start + 1),
            &["127.0.0.1".to_string()],
            json!({"target_ports": format!("{},{}", targets[0].0, targets[1].0)}),
        )],
    );
    let _gateway =
        Gateway::spawn_forwarding(&config("", "http_enabled = false", ""), &forwarding).await?;
    for (port, (_, expected)) in (start..=start + 1).zip(targets) {
        let mut client = connect(([127, 0, 0, 1], port).into()).await?;
        assert_eq!(timeout(DEADLINE, client.read_u8()).await??, expected);
    }
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
    let forwarding = forwarding_rules("127.0.0.1:0", &[echo.addr], json!({"max_connections": 1}))?;
    let mut gateway =
        Gateway::spawn_forwarding(&config("", "http_enabled = false", ""), &forwarding).await?;
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
    let addr: SocketAddr = "127.0.0.1:9000".parse()?;
    let base = forwarding_rules("127.0.0.1:9050", &[addr], json!({}))?;
    let duplicated = {
        let rule = tcp_rule("127.0.0.1:9050", &[addr.to_string()], json!({}));
        forwarding_json(json!({}), &[rule.clone(), rule])
    };
    let maxed = forwarding_json(
        json!({}),
        &[
            tcp_rule("127.0.0.1:9100-9163", &[addr.to_string()], json!({})),
            tcp_rule("127.0.0.1:9050", &[addr.to_string()], json!({})),
        ],
    );
    let overlapping = forwarding_json(
        json!({}),
        &[
            tcp_rule("127.0.0.1:9050-9051", &[addr.to_string()], json!({})),
            tcp_rule("127.0.0.1:9050", &[addr.to_string()], json!({})),
        ],
    );
    for forwarding in [
        forwarding_json(json!({}), &[]),
        forwarding_rules("127.0.0.1:9050", &[], json!({}))?,
        forwarding_rules("127.0.0.1:9050", &[addr, addr], json!({}))?,
        forwarding_rules("127.0.0.1:9000", &[addr], json!({}))?,
        // The 3600-second first-data ceiling rejects larger settings.
        forwarding_with(
            json!({"first_data_timeout": 4000}),
            "127.0.0.1:9050",
            &[addr],
            json!({}),
        )?,
        forwarding_rules("127.0.0.1:9050", &[addr], json!({"max_connections": 65536}))?,
        maxed,
        // Mapped targets may not collide with the rule's own listeners.
        forwarding_json(
            json!({}),
            &[tcp_rule(
                "127.0.0.1:9050-9051",
                &["127.0.0.1".to_string()],
                json!({"target_ports": "9051,9050"}),
            )],
        ),
        forwarding_json(
            json!({}),
            &[tcp_rule(
                "127.0.0.1:9050",
                &[addr.to_string()],
                json!({"target_addresses": ["127.0.0.1:9000-9001"]}),
            )],
        ),
        duplicated,
        overlapping,
    ] {
        assert!(
            !Gateway::check_forwarding(
                dir.path(),
                &config("", "http_enabled = false", ""),
                &forwarding
            )
            .await?
        );
    }
    assert!(
        Gateway::check_forwarding(dir.path(), &config("", "http_enabled = false", ""), &base)
            .await?
    );
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
        let forwarding =
            forwarding_rules(address, &[capture.addr], json!({"proxy_protocol": version}))?;
        let gateway =
            Gateway::spawn_forwarding(&config("", "http_enabled = false", ""), &forwarding).await?;
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

#[cfg(unix)]
#[tokio::test]
async fn reloads_tcp_source_rules_without_closing_existing_connections() -> Result<()> {
    use std::{sync::Arc, time::Duration};
    let dialed = Arc::new(tokio::sync::Notify::new());
    let origin = Origin::spawn({
        let dialed = dialed.clone();
        move |mut socket| {
            let dialed = dialed.clone();
            async move {
                dialed.notify_one();
                let mut buffer = [0; 64];
                loop {
                    let size = socket.read(&mut buffer).await?;
                    if size == 0 {
                        break;
                    }
                    socket.write_all(&buffer[..size]).await?;
                }
                Ok(())
            }
        }
    })
    .await?;
    let toml = config("", "http_enabled = false", "");
    let listen = format!("127.0.0.1:{}", free_tcp_ports(1)?[0]);
    let settings = |source: Value| -> Result<String> {
        Ok(forwarding_json(
            json!({}),
            &[tcp_rule(&listen, &[origin.addr.to_string()], source)],
        ))
    };
    let deny = json!({"allow": ["127.0.0.0/8"], "deny": ["127.0.0.1"]});
    let allow = json!({"allow": ["127.0.0.1"]});
    let mut gateway = Gateway::spawn_forwarding(&toml, &settings(deny.clone())?).await?;

    let mut denied = connect(gateway.addr).await?;
    assert!(timeout(DEADLINE, denied.read_u8()).await?.is_err());
    assert!(
        timeout(Duration::from_millis(100), dialed.notified())
            .await
            .is_err()
    );
    gateway.replace_forwarding(&settings(allow.clone())?)?;
    gateway.signal("-HUP").await?;
    gateway.wait_log("configuration reloaded").await?;

    let mut existing = connect(gateway.addr).await?;
    existing.write_all(b"a").await?;
    assert_eq!(timeout(DEADLINE, existing.read_u8()).await??, b'a');
    gateway.replace_forwarding(&settings(deny)?)?;
    gateway.signal("-HUP").await?;
    gateway.wait_log("configuration reloaded").await?;

    let mut denied = connect(gateway.addr).await?;
    assert!(timeout(DEADLINE, denied.read_u8()).await?.is_err());
    existing.write_all(b"b").await?;
    assert_eq!(timeout(DEADLINE, existing.read_u8()).await??, b'b');

    let invalid = settings(json!({"allow": ["192.0.2.1/33"]}))?;
    assert!(!Gateway::check_forwarding(gateway.dir.path(), &toml, &invalid).await?);
    Ok(())
}

#[tokio::test]
async fn tcp_source_quota_rejects_new_flows_and_releases_finished_slots() -> Result<()> {
    use std::time::Duration;
    let echo = Origin::spawn(|mut socket| async move {
        let mut data = [0; 64];
        loop {
            let size = socket.read(&mut data).await?;
            if size == 0 {
                return Ok(());
            }
            socket.write_all(&data[..size]).await?;
        }
    })
    .await?;
    let base = json!({"max_connections": 3, "max_conns_per_source": 1});
    let spawn = |forwarding: String| async move {
        Gateway::spawn_forwarding(&config("", "http_enabled = false", ""), &forwarding).await
    };

    let gateway = spawn(forwarding_rules("127.0.0.1:0", &[echo.addr], base.clone())?).await?;
    let mut first = connect(gateway.addr).await?;
    first.write_all(b"a").await?;
    assert_eq!(timeout(DEADLINE, first.read_u8()).await??, b'a');
    let mut denied = connect(gateway.addr).await?;
    assert!(timeout(DEADLINE, denied.read_u8()).await?.is_err());
    drop(first);

    timeout(DEADLINE, async {
        loop {
            let mut sender = connect(gateway.addr).await?;
            if sender.write_all(b"b").await.is_ok()
                && timeout(Duration::from_millis(200), sender.read_u8())
                    .await
                    .is_ok_and(|result| result.is_ok_and(|byte| byte == b'b'))
            {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;

    let exempt = spawn(forwarding_with(
        json!({"per_source_exempt": ["127.0.0.0/8"]}),
        "127.0.0.1:0",
        &[echo.addr],
        base,
    )?)
    .await?;
    let (mut a, mut b) = (connect(exempt.addr).await?, connect(exempt.addr).await?);
    a.write_all(b"c").await?;
    b.write_all(b"d").await?;
    assert_eq!(timeout(DEADLINE, a.read_u8()).await??, b'c');
    assert_eq!(timeout(DEADLINE, b.read_u8()).await??, b'd');
    assert!(
        !Gateway::check_forwarding(
            gateway.dir.path(),
            &config("", "http_enabled = false", ""),
            &forwarding_rules(
                "127.0.0.1:0",
                &[echo.addr],
                json!({"max_connections": 2, "max_conns_per_source": 3}),
            )?
        )
        .await?
    );
    Ok(())
}
