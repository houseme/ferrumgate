//! Accept-time handling: when a denial is determinable from the TCP peer
//! alone (LAN-only, banned) with `Close`/`Drop` configured, the connection
//! never reaches the HTTP service. `Drop` holds the socket silently within
//! bounded resources; `Close` drops it immediately.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::{net::TcpStream, sync::Semaphore};

use super::{AccessConfig, Decision, DenyMode};
use fg_net::ClientAddr;

/// How long one held connection may sit silently.
pub const HOLD_TIMEOUT: Duration = Duration::from_secs(120);
/// Held connections allowed at once; extra connections are closed.
pub const MAX_HELD: usize = 256;
/// Held connections read and discard at most this much before release.
pub const MAX_DISCARD: usize = 64 * 1024;

/// What to do with a freshly accepted connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptAction {
    Serve,
    /// Drop immediately (`Close` mode).
    Close,
    /// Hold silently (`Drop` mode).
    Hold,
}

/// Decides at accept time. Only peer-address determinations happen here;
/// safe-entry needs the request path and is left to the HTTP layer.
pub fn accept_action(
    _peer: SocketAddr,
    addr: &ClientAddr,
    banned: bool,
    cfg: &AccessConfig,
) -> AcceptAction {
    if !matches!(cfg.deny_mode, DenyMode::Close | DenyMode::Drop) {
        return AcceptAction::Serve;
    }
    let banned_or_outside = banned || (cfg.lan_only && !fg_net::client_addr::is_internal(addr.ip));
    if !banned_or_outside {
        return AcceptAction::Serve;
    }
    match cfg.deny_mode {
        DenyMode::Close => AcceptAction::Close,
        _ => AcceptAction::Hold,
    }
}

/// Bounded slot pool for held connections.
pub struct HoldSlots(Arc<Semaphore>);

impl Default for HoldSlots {
    fn default() -> Self {
        Self(Arc::new(Semaphore::new(MAX_HELD)))
    }
}

impl HoldSlots {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Holds the stream until the client gives up, the timeout elapses, or
    /// 64 KiB has been read. Never spawns: one task per connection comes
    /// from the accept loop.
    pub async fn hold(self: &Arc<Self>, stream: TcpStream) -> bool {
        let Ok(permit) = self.0.clone().try_acquire_owned() else {
            // Pool exhausted: closing is safer than queueing.
            drop(stream);
            return false;
        };
        let _permit = permit;
        let held = tokio::time::timeout(HOLD_TIMEOUT, drain(stream)).await;
        matches!(held, Ok(true))
    }
}

/// Reads and discards until EOF, the byte cap, or the deadline — whichever
/// comes first. Returns true on EOF (the client gave up).
async fn drain(mut stream: TcpStream) -> bool {
    use tokio::io::AsyncReadExt;
    let mut buffer = [0u8; 4096];
    let mut total = 0usize;
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => return true,
            Ok(n) => {
                total += n;
                if total >= MAX_DISCARD {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
}

#[allow(dead_code)]
fn _unused(_: Decision) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn client_addr(ip: &str) -> ClientAddr {
        ClientAddr {
            ip: ip.parse().unwrap(),
            via: None,
            verified: false,
        }
    }

    fn config(mode: DenyMode, lan_only: bool) -> AccessConfig {
        AccessConfig {
            deny_mode: mode,
            lan_only,
            ..AccessConfig::default()
        }
    }

    /// One accept decision per row of the WP-14 matrix: only `Close`/`Drop`
    /// plus a peer-determinable denial (banned, outside a LAN-only entry)
    /// keep the connection from the HTTP service.
    #[test]
    fn accept_action_matrix() {
        let peer: SocketAddr = "203.0.113.5:4434".parse().unwrap();
        let public = client_addr("203.0.113.9");
        let lan = client_addr("192.168.1.10");

        // Close/Drop are the only modes with accept-time handling; every
        // other mode serves even a banned outsider.
        for mode in [
            DenyMode::Default,
            DenyMode::NotFound,
            DenyMode::Blank,
            DenyMode::Custom,
        ] {
            let cfg = config(mode, true);
            assert_eq!(
                accept_action(peer, &public, true, &cfg),
                AcceptAction::Serve,
                "{mode:?} must leave the denial to the HTTP layer"
            );
        }

        let rows: &[(&str, DenyMode, bool, bool, &ClientAddr, AcceptAction)] = &[
            (
                "close + lan_only closes a public client",
                DenyMode::Close,
                true,
                false,
                &public,
                AcceptAction::Close,
            ),
            (
                "drop + lan_only holds a public client",
                DenyMode::Drop,
                true,
                false,
                &public,
                AcceptAction::Hold,
            ),
            (
                "internal client is served despite lan_only",
                DenyMode::Close,
                true,
                false,
                &lan,
                AcceptAction::Serve,
            ),
            (
                "banned client is closed",
                DenyMode::Close,
                false,
                true,
                &public,
                AcceptAction::Close,
            ),
            (
                "without lan_only a public peer is served (close)",
                DenyMode::Close,
                false,
                false,
                &public,
                AcceptAction::Serve,
            ),
            (
                "without lan_only a public peer is served (drop)",
                DenyMode::Drop,
                false,
                false,
                &public,
                AcceptAction::Serve,
            ),
        ];
        for (name, mode, lan_only, banned, addr, expected) in rows {
            let cfg = config(*mode, *lan_only);
            assert_eq!(
                accept_action(peer, addr, *banned, &cfg),
                *expected,
                "{name}"
            );
        }
    }

    /// `Drop` must stay bounded: with all MAX_HELD slots taken the next
    /// hold is refused immediately, and giving-up clients free the slots.
    #[tokio::test]
    async fn drop_caps_concurrent_holds() {
        let slots = HoldSlots::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // MAX_HELD real connections whose clients stay connected. Connect
        // and accept in lockstep so the backlog never builds up.
        let mut clients = Vec::with_capacity(MAX_HELD);
        let mut held = Vec::with_capacity(MAX_HELD);
        for _ in 0..MAX_HELD {
            let client = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (server, _) = listener.accept().await.unwrap();
            clients.push(client);
            let slots = slots.clone();
            held.push(tokio::spawn(async move { slots.hold(server).await }));
        }

        // Let every spawned hold acquire its permit.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // One more connection: the pool is exhausted, so hold refuses
        // without waiting for the hold timeout.
        let extra_client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (extra_server, _) = listener.accept().await.unwrap();
        let started = Instant::now();
        let refused = tokio::time::timeout(Duration::from_secs(5), slots.hold(extra_server))
            .await
            .expect("the 257th hold must not wait for the hold timeout");
        assert!(!refused, "pool exhausted: the 257th hold must be refused");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "refusal must be immediate, took {:?}",
            started.elapsed()
        );
        drop(extra_client);

        // Clients giving up releases every slot: each drain sees EOF and
        // its hold reports success.
        drop(clients);
        for task in held {
            assert!(
                task.await.expect("hold task should not panic"),
                "held connection should end on client EOF"
            );
        }

        // The pool is usable again.
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        drop(client);
        let again = tokio::time::timeout(Duration::from_secs(5), slots.hold(server))
            .await
            .expect("a fresh hold must not wait for the hold timeout");
        assert!(again, "released slots must serve a new hold");
    }

    /// Drain stops at the 64 KiB cap: a client sending more than the cap
    /// and staying connected is released well before the hold timeout.
    #[tokio::test]
    async fn drain_stops_at_the_discard_cap() {
        let slots = HoldSlots::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        // 70 KiB is past the cap; the writer stays connected afterwards so
        // the hold must end on the cap, not on EOF.
        let payload = vec![0u8; 70 * 1024];
        let writer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut client = client;
            client.write_all(&payload).await.unwrap();
            std::future::pending::<()>().await;
        });

        let started = Instant::now();
        let held = tokio::time::timeout(Duration::from_secs(10), slots.hold(server))
            .await
            .expect("the cap must end the hold long before the timeout");
        let elapsed = started.elapsed();
        assert!(!held, "the 64 KiB cap must end the hold");
        assert!(
            elapsed < Duration::from_secs(10),
            "cap release took {elapsed:?}, well over the expected quick path"
        );

        // Now the client closes; nothing is left holding the stream.
        writer.abort();
        let _ = writer.await;
    }

    /// Drain reports a client that gave up (EOF) as success.
    #[tokio::test]
    async fn drain_reports_client_giveup_as_success() {
        let slots = HoldSlots::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        {
            use tokio::io::AsyncWriteExt;
            let mut client = client;
            client.write_all(b"x").await.unwrap();
        }
        // The client handle is dropped here: one byte written, then EOF.

        let started = Instant::now();
        let held = tokio::time::timeout(Duration::from_secs(10), slots.hold(server))
            .await
            .expect("client EOF must end the hold long before the timeout");
        assert!(held, "client EOF must end the hold with true");
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
