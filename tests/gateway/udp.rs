use std::{net::SocketAddr, time::Duration};

use anyhow::Result;
use serde_json::{Value, json};
use tokio::{net::UdpSocket, sync::mpsc, time::timeout};

use super::common::*;

async fn echo_target() -> Result<(SocketAddr, mpsc::UnboundedReceiver<SocketAddr>)> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let address = socket.local_addr()?;
    let (send, receive) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buffer = [0; 4096];
        while let Ok((size, peer)) = socket.recv_from(&mut buffer).await {
            if send.send(peer).is_err() || socket.send_to(&buffer[..size], peer).await.is_err() {
                break;
            }
        }
    });
    Ok((address, receive))
}

/// Renders a portforward.json document with one UDP rule on a concrete
/// reserved listen port (the JSON model rejects port 0).
fn forwarding_with(settings: Value, targets: &[SocketAddr], options: Value) -> Result<String> {
    Ok(forwarding_json(
        settings,
        &[udp_rule(
            &format!("127.0.0.1:{}", free_udp_ports(1)?[0]),
            &targets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            options,
        )],
    ))
}

fn rule(target: SocketAddr, options: Value) -> Result<String> {
    forwarding_with(json!({}), &[target], options)
}

fn multi_target_rule(targets: &[SocketAddr], options: Value) -> Result<String> {
    forwarding_with(json!({}), targets, options)
}

async fn client(address: SocketAddr) -> Result<UdpSocket> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(address).await?;
    Ok(socket)
}

#[tokio::test]
async fn forwards_datagrams_and_isolates_client_associations() -> Result<()> {
    let (target, mut peers) = echo_target().await?;
    let gateway = Gateway::spawn_forwarding(
        &config("", "http_enabled = false", ""),
        &rule(target, json!({}))?,
    )
    .await?;
    let first = client(gateway.addr).await?;
    let second = client(gateway.addr).await?;
    first.send(b"one\0").await?;
    second.send(b"two\0").await?;
    for (socket, expected) in [(&first, b"one\0"), (&second, b"two\0")] {
        let mut buffer = [0; 16];
        let received = timeout(DEADLINE, socket.recv(&mut buffer)).await??;
        assert_eq!(&buffer[..received], expected);
    }
    let a = timeout(DEADLINE, peers.recv()).await?.unwrap();
    let b = timeout(DEADLINE, peers.recv()).await?.unwrap();
    assert_ne!(a, b);
    Ok(())
}

#[tokio::test]
async fn forwards_empty_and_large_udp_replies_without_truncation() -> Result<()> {
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let gateway = Gateway::spawn_forwarding(
        &config("", "http_enabled = false", ""),
        &rule(target.local_addr()?, json!({}))?,
    )
    .await?;
    let sender = client(gateway.addr).await?;
    sender.send(b"start").await?;
    let mut request = [0; 16];
    let (size, peer) = timeout(DEADLINE, target.recv_from(&mut request)).await??;
    assert_eq!(&request[..size], b"start");

    let payload = vec![0x5a; 8192];
    let mut response = vec![0; payload.len() + 1];
    for expected in [payload.as_slice(), &[], payload.as_slice()] {
        target.send_to(expected, peer).await?;
        let size = timeout(DEADLINE, sender.recv(&mut response)).await??;
        assert_eq!(&response[..size], expected);
    }
    Ok(())
}

#[tokio::test]
async fn rotates_new_udp_sessions_and_keeps_existing_sessions_on_their_target() -> Result<()> {
    let (first_target, mut first_peers) = echo_target().await?;
    let (second_target, mut second_peers) = echo_target().await?;
    let settings = multi_target_rule(&[first_target, second_target], json!({}))?;
    let gateway =
        Gateway::spawn_forwarding(&config("", "http_enabled = false", ""), &settings).await?;
    let first = client(gateway.addr).await?;
    let second = client(gateway.addr).await?;
    let third = client(gateway.addr).await?;

    let mut original = None;
    for (sender, peers, payload) in [
        (&first, &mut first_peers, b"one"),
        (&second, &mut second_peers, b"two"),
    ] {
        sender.send(payload).await?;
        let mut response = [0; 16];
        let len = timeout(DEADLINE, sender.recv(&mut response)).await??;
        assert_eq!(&response[..len], payload);
        let peer = timeout(DEADLINE, peers.recv()).await?.unwrap();
        original.get_or_insert(peer);
    }

    let mut response = [0; 16];
    first.send(b"same session").await?;
    let len = timeout(DEADLINE, first.recv(&mut response)).await??;
    assert_eq!(&response[..len], b"same session");
    assert_eq!(timeout(DEADLINE, first_peers.recv()).await?, original);

    third.send(b"new session").await?;
    let len = timeout(DEADLINE, third.recv(&mut response)).await??;
    assert_eq!(&response[..len], b"new session");
    let peer = timeout(DEADLINE, first_peers.recv()).await?.unwrap();
    assert_ne!(Some(peer), original);
    Ok(())
}

#[tokio::test]
async fn tries_the_next_udp_target_when_connecting_fails() -> Result<()> {
    // A link-local destination with a nonexistent interface index cannot connect.
    let invalid = "[fe80::1%4294967295]:12345".parse()?;
    let (target, mut peers) = echo_target().await?;
    let settings = multi_target_rule(&[invalid, target], json!({}))?;
    let gateway =
        Gateway::spawn_forwarding(&config("", "http_enabled = false", ""), &settings).await?;
    let sender = client(gateway.addr).await?;
    sender.send(b"backup").await?;
    let mut response = [0; 16];
    let len = timeout(DEADLINE, sender.recv(&mut response)).await??;
    assert_eq!(&response[..len], b"backup");
    assert!(timeout(DEADLINE, peers.recv()).await?.is_some());
    Ok(())
}

#[tokio::test]
async fn does_not_replay_a_udp_datagram_when_the_selected_target_is_silent() -> Result<()> {
    let silent = UdpSocket::bind("127.0.0.1:0").await?;
    let backup = UdpSocket::bind("127.0.0.1:0").await?;
    // The JSON model carries the UDP session timeout in whole seconds.
    let settings = multi_target_rule(
        &[silent.local_addr()?, backup.local_addr()?],
        json!({"udp_session_timeout": 1}),
    )?;
    let gateway =
        Gateway::spawn_forwarding(&config("", "http_enabled = false", ""), &settings).await?;
    let sender = client(gateway.addr).await?;
    sender.send(b"once").await?;
    let mut buffer = [0; 16];
    let (len, _) = timeout(DEADLINE, silent.recv_from(&mut buffer)).await??;
    assert_eq!(&buffer[..len], b"once");
    assert!(
        timeout(Duration::from_millis(250), backup.recv_from(&mut buffer))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn forwards_each_udp_port_independently_to_a_shared_target() -> Result<()> {
    let (target, mut peers) = echo_target().await?;
    let first = UdpSocket::bind("127.0.0.1:0").await?;
    let second = UdpSocket::bind("127.0.0.1:0").await?;
    let first_addr = first.local_addr()?;
    let second_addr = second.local_addr()?;
    let settings = forwarding_json(
        json!({}),
        &[udp_rule(
            &format!("127.0.0.1:{},{}", first_addr.port(), second_addr.port()),
            &[target.to_string()],
            json!({"max_connections": 1}),
        )],
    );
    drop((first, second));
    let _gateway =
        Gateway::spawn_forwarding(&config("", "http_enabled = false", ""), &settings).await?;

    let sender = client(first_addr).await?;
    let mut upstream_peers = Vec::new();
    for (address, payload) in [(first_addr, b"one"), (second_addr, b"two")] {
        sender.connect(address).await?;
        sender.send(payload).await?;
        let mut buffer = [0; 16];
        let size = timeout(DEADLINE, sender.recv(&mut buffer)).await??;
        assert_eq!(&buffer[..size], payload);
        let peer = timeout(DEADLINE, peers.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("UDP target closed"))?;
        upstream_peers.push(peer);
    }
    assert_ne!(upstream_peers[0], upstream_peers[1]);
    Ok(())
}

#[tokio::test]
async fn bounds_udp_associations_and_releases_idle_slots() -> Result<()> {
    let (target, _peers) = echo_target().await?;
    let gateway = Gateway::spawn_forwarding(
        &config("", "http_enabled = false", ""),
        &rule(
            target,
            json!({"max_connections": 1, "udp_session_timeout": 1}),
        )?,
    )
    .await?;
    let admitted = client(gateway.addr).await?;
    let waiting = client(gateway.addr).await?;
    admitted.send(b"first").await?;
    let mut buffer = [0; 16];
    let len = timeout(DEADLINE, admitted.recv(&mut buffer)).await??;
    assert_eq!(&buffer[..len], b"first");
    waiting.send(b"second").await?;
    assert!(
        timeout(Duration::from_millis(60), waiting.recv(&mut buffer))
            .await
            .is_err()
    );
    let received = timeout(DEADLINE, async {
        loop {
            waiting.send(b"second").await?;
            if let Ok(result) = timeout(Duration::from_millis(70), waiting.recv(&mut buffer)).await
            {
                break result;
            }
        }
    })
    .await??;
    assert_eq!(&buffer[..received], b"second");
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_udp_targets_duplicate_binds_and_excessive_sessions() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let addr: SocketAddr = "127.0.0.1:9000".parse()?;
    let duplicated = {
        let entry = udp_rule("127.0.0.1:9001", &[addr.to_string()], json!({}));
        forwarding_json(json!({}), &[entry.clone(), entry])
    };
    let invalid_address = udp_rule(
        "127.0.0.1:0",
        &[addr.to_string()],
        json!({"target_addresses": ["127.0.0.1:9000-9001"]}),
    );
    for settings in [
        rule("255.255.255.255:9000".parse()?, json!({}))?,
        rule("127.0.0.1:0".parse()?, json!({}))?,
        duplicated,
        forwarding_json(
            json!({}),
            &[
                udp_rule(
                    "127.0.0.1:9001",
                    &[addr.to_string()],
                    json!({"max_connections": 4096}),
                ),
                udp_rule(
                    "127.0.0.1:9050",
                    &[addr.to_string()],
                    json!({"max_connections": 1}),
                ),
            ],
        ),
        forwarding_json(
            json!({}),
            &[udp_rule(
                "127.0.0.1:9050-9051",
                &[addr.to_string()],
                json!({"max_connections": 2049}),
            )],
        ),
        forwarding_json(
            json!({}),
            &[udp_rule(
                "127.0.0.1:9050-9051,9051",
                &[addr.to_string()],
                json!({}),
            )],
        ),
        multi_target_rule(&[], json!({}))?,
        multi_target_rule(&[addr; 9], json!({}))?,
        multi_target_rule(&[addr, addr], json!({}))?,
        // A rule must declare at least one protocol.
        forwarding_json(
            json!({}),
            &[forwarding_rule(
                "udp",
                "",
                "127.0.0.1:0",
                &[addr.to_string()],
                json!({}),
            )],
        ),
        forwarding_json(json!({}), &[invalid_address]),
    ] {
        assert!(
            !Gateway::check_forwarding(
                dir.path(),
                &config("", "http_enabled = false", ""),
                &settings
            )
            .await?
        );
    }
    for settings in [
        rule(addr, json!({}))?,
        multi_target_rule(&[addr], json!({}))?,
        forwarding_json(
            json!({}),
            &[udp_rule(
                "127.0.0.1:9050-9051",
                &["127.0.0.1".to_string(), "[::1]:9080".to_string()],
                json!({"target_ports": "9000-9001"}),
            )],
        ),
    ] {
        assert!(
            Gateway::check_forwarding(
                dir.path(),
                &config("", "http_enabled = false", ""),
                &settings
            )
            .await?
        );
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn udp_source_reload_blocks_pending_replies_and_new_datagrams() -> Result<()> {
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let address = target.local_addr()?;
    let toml = config("", "http_enabled = false", "");
    let listen = format!("127.0.0.1:{}", free_udp_ports(1)?[0]);
    let settings = |source: Value| -> Result<String> {
        Ok(forwarding_json(
            json!({}),
            &[udp_rule(&listen, &[address.to_string()], source)],
        ))
    };
    let allow = json!({"allow": ["127.0.0.0/8"]});
    let deny = json!({"allow": ["127.0.0.0/8"], "deny": ["127.0.0.1"]});
    let mut gateway = Gateway::spawn_forwarding(&toml, &settings(allow.clone())?).await?;
    let sender = client(gateway.addr).await?;

    sender.send(b"before").await?;
    let mut buffer = [0; 32];
    let (len, peer) = timeout(DEADLINE, target.recv_from(&mut buffer)).await??;
    assert_eq!(&buffer[..len], b"before");

    gateway.replace_forwarding(&settings(deny.clone())?)?;
    gateway.signal("-HUP").await?;
    gateway.wait_log("configuration reloaded").await?;
    target.send_to(b"stale reply", peer).await?;
    assert!(
        timeout(Duration::from_millis(100), sender.recv(&mut buffer))
            .await
            .is_err()
    );
    sender.send(b"blocked").await?;
    assert!(
        timeout(Duration::from_millis(100), target.recv_from(&mut buffer))
            .await
            .is_err()
    );

    gateway.replace_forwarding(&settings(allow)?)?;
    gateway.signal("-HUP").await?;
    gateway.wait_log("configuration reloaded").await?;
    sender.send(b"allowed").await?;
    let (len, peer) = timeout(DEADLINE, target.recv_from(&mut buffer)).await??;
    assert_eq!(&buffer[..len], b"allowed");
    target.send_to(b"new reply", peer).await?;
    let len = timeout(DEADLINE, sender.recv(&mut buffer)).await??;
    assert_eq!(&buffer[..len], b"new reply");
    Ok(())
}
