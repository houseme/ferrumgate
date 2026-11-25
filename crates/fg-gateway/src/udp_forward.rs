use std::{
    collections::{HashMap, hash_map::Entry},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use hyper::body::Bytes;
use serde::Deserialize;
use tokio::{
    net::UdpSocket,
    sync::{Semaphore, SemaphorePermit, mpsc, watch},
    task::{Id, JoinSet},
    time::{sleep, timeout},
};

const MAX_DATAGRAM: usize = 65_535;
static QUEUED_PACKETS: Semaphore = Semaphore::const_new(1024);

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct RawUdpForward {
    listen: Option<SocketAddr>,
    target: Option<SocketAddr>,
    max_sessions: usize,
    idle_timeout_ms: u64,
}

impl Default for RawUdpForward {
    fn default() -> Self {
        Self {
            listen: None,
            target: None,
            max_sessions: 128,
            idle_timeout_ms: 30_000,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct UdpForward {
    pub listen: SocketAddr,
    target: SocketAddr,
    pub max_sessions: usize,
    idle: Duration,
}

struct Packet {
    data: Bytes,
    _reservation: SemaphorePermit<'static>,
}

impl UdpForward {
    pub fn compile(raw: RawUdpForward) -> Result<Self> {
        let listen = raw.listen.context("udp_forward.listen is required")?;
        let target = raw.target.context("udp_forward.target is required")?;
        ensure!(
            target.port() != 0
                && !target.ip().is_unspecified()
                && !target.ip().is_multicast()
                && target.ip() != IpAddr::V4(Ipv4Addr::BROADCAST)
                && target != listen,
            "udp_forward target must be a unicast address with nonzero port, different from the listener"
        );
        ensure!(
            (1..=4096).contains(&raw.max_sessions),
            "udp_forward.max_sessions must be in 1..=4096"
        );
        ensure!(
            (100..=3_600_000).contains(&raw.idle_timeout_ms),
            "udp_forward.idle_timeout_ms must be in 100..=3600000"
        );
        Ok(Self {
            listen,
            target,
            max_sessions: raw.max_sessions,
            idle: Duration::from_millis(raw.idle_timeout_ms),
        })
    }

    pub async fn serve(self, socket: UdpSocket, mut drain: watch::Receiver<bool>) {
        let socket = Arc::new(socket);
        let mut tasks = JoinSet::new();
        let mut sessions = HashMap::<SocketAddr, (Id, mpsc::Sender<Packet>)>::new();
        let mut buffer = vec![0; MAX_DATAGRAM];
        loop {
            tokio::select! {
                biased;
                _ = drain.changed() => break,
                Some(result) = tasks.join_next_with_id(), if !tasks.is_empty() => {
                    match result {
                        Ok((_, peer)) => { sessions.remove(&peer); }
                        Err(error) => {
                            tracing::warn!(%error, "UDP relay task failed");
                            sessions.retain(|_, (id, _)| *id != error.id());
                        }
                    }
                }
                received = socket.recv_from(&mut buffer) => {
                    let (len, peer) = match received {
                        Ok(packet) => packet,
                        Err(error) => {
                            tracing::warn!(%error, "UDP forward receive failed");
                            sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    };
                    let Ok(reservation) = QUEUED_PACKETS.try_acquire() else { continue };
                    let can_start = sessions.len() < self.max_sessions;
                    let (_, queue) = match sessions.entry(peer) {
                        Entry::Occupied(entry) => entry.into_mut(),
                        Entry::Vacant(entry) if can_start => {
                            let (send, receive) = mpsc::channel(4);
                            let socket = socket.clone();
                            let task = tasks.spawn(async move {
                                if let Err(error) = relay(socket, peer, receive, self.target, self.idle).await {
                                    tracing::debug!(kind = ?error.kind(), "UDP relay ended");
                                }
                                peer
                            });
                            entry.insert((task.id(), send))
                        }
                        Entry::Vacant(_) => continue,
                    };
                    if let Ok(slot) = queue.try_reserve() {
                        slot.send(Packet { data: Bytes::copy_from_slice(&buffer[..len]), _reservation: reservation });
                    }
                }
            }
        }
        tasks.shutdown().await;
    }
}

async fn relay(
    listener: Arc<UdpSocket>,
    peer: SocketAddr,
    mut packets: mpsc::Receiver<Packet>,
    target: SocketAddr,
    idle: Duration,
) -> std::io::Result<()> {
    let upstream = UdpSocket::bind(if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    upstream.connect(target).await?;
    let mut buffer = vec![0; MAX_DATAGRAM];
    loop {
        let result = timeout(idle, async {
            tokio::select! {
                packet = packets.recv() => {
                    let Some(packet) = packet else { return Ok(false) };
                    upstream.send(&packet.data).await?;
                }
                response = upstream.recv(&mut buffer) => {
                    let len = response?;
                    listener.send_to(&buffer[..len], peer).await?;
                }
            }
            Ok::<_, std::io::Error>(true)
        })
        .await;
        match result {
            Ok(Ok(true)) => {}
            Ok(Err(error)) => return Err(error),
            Ok(Ok(false)) | Err(_) => return Ok(()),
        }
    }
}
