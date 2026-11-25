use std::{net::SocketAddr, time::Duration};

use anyhow::Result;
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

fn rule(target: SocketAddr, options: &str) -> String {
    format!("\n[[udp_forward]]\nlisten = \"127.0.0.1:0\"\ntarget = \"{target}\"\n{options}\n")
}

async fn client(address: SocketAddr) -> Result<UdpSocket> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(address).await?;
    Ok(socket)
}

#[tokio::test]
async fn forwards_datagrams_and_isolates_client_associations() -> Result<()> {
    let (target, mut peers) = echo_target().await?;
    let gateway = Gateway::spawn(&config(&rule(target, ""), "http_enabled = false", "")).await?;
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
async fn forwards_each_udp_port_independently_to_a_shared_target() -> Result<()> {
    let (target, mut peers) = echo_target().await?;
    let first = UdpSocket::bind("127.0.0.1:0").await?;
    let second = UdpSocket::bind("127.0.0.1:0").await?;
    let first_addr = first.local_addr()?;
    let second_addr = second.local_addr()?;
    let rules = rule(target, "max_sessions = 1").replace(
        "127.0.0.1:0",
        &format!("127.0.0.1:{},{}", first_addr.port(), second_addr.port()),
    );
    drop((first, second));
    let _gateway = Gateway::spawn(&config(&rules, "http_enabled = false", "")).await?;

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
    let gateway = Gateway::spawn(&config(
        &rule(target, "max_sessions = 1\nidle_timeout_ms = 500"),
        "http_enabled = false",
        "",
    ))
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
    let addr = "127.0.0.1:9000".parse()?;
    let repeated = rule(addr, "")
        .replace("127.0.0.1:0", "127.0.0.1:9001")
        .repeat(2);
    for rules in [
        rule("255.255.255.255:9000".parse()?, ""),
        rule("127.0.0.1:0".parse()?, ""),
        repeated,
        rule(addr, "max_sessions = 4096") + &rule(addr, "max_sessions = 1"),
        rule(addr, "max_sessions = 2049").replace("127.0.0.1:0", "127.0.0.1:9050-9051"),
        rule(addr, "").replace("127.0.0.1:0", "127.0.0.1:9050-9051,9051"),
    ] {
        assert!(!Gateway::check(dir.path(), &config(&rules, "http_enabled = false", "")).await?);
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn udp_source_reload_blocks_pending_replies_and_new_datagrams() -> Result<()> {
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let address = target.local_addr()?;
    let settings = |source: &str| config(&rule(address, source), "http_enabled = false", "");
    let allow = "[udp_forward.source]\nallow = [\"127.0.0.0/8\"]";
    let deny = "[udp_forward.source]\nallow = [\"127.0.0.0/8\"]\ndeny = [\"127.0.0.1\"]";
    let mut gateway = Gateway::spawn(&settings(allow)).await?;
    let sender = client(gateway.addr).await?;

    sender.send(b"before").await?;
    let mut buffer = [0; 32];
    let (len, peer) = timeout(DEADLINE, target.recv_from(&mut buffer)).await??;
    assert_eq!(&buffer[..len], b"before");

    gateway.replace(&settings(deny))?;
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

    gateway.replace(&settings(allow))?;
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
