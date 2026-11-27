use std::{
    cell::Cell,
    collections::{HashMap, HashSet, hash_map::Entry},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, atomic::Ordering::Relaxed},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use hyper::body::Bytes;
use serde::Deserialize;
use tokio::{
    net::UdpSocket,
    sync::{Semaphore, SemaphorePermit, mpsc, watch},
    task::{Id, JoinSet},
    time::{sleep, timeout},
};

use crate::{
    forward_metrics::ForwardStats,
    forward_ports,
    source_policy::{RawSourcePolicy, SourcePolicy},
};

const MAX_DATAGRAM: usize = 65_535;
static QUEUED_PACKETS: Semaphore = Semaphore::const_new(1024);

thread_local! {
    static REPLY_BUFFER: Cell<Vec<u8>> = const { Cell::new(Vec::new()) };
}

#[derive(Deserialize)]
#[derive(serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawUdpForward {
    listen: Option<String>,
    target: Option<String>,
    targets: Option<Vec<String>>,
    max_sessions: usize,
    idle_timeout_ms: u64,
    source: RawSourcePolicy,
}

impl Default for RawUdpForward {
    fn default() -> Self {
        Self {
            listen: None,
            target: None,
            targets: None,
            max_sessions: 128,
            idle_timeout_ms: 30_000,
            source: RawSourcePolicy::default(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct UdpForward {
    pub listen: SocketAddr,
    pub(crate) targets: Arc<[SocketAddr]>,
    pub max_sessions: usize,
    pub(crate) idle: Duration,
    pub source: SourcePolicy,
}

struct Packet {
    data: Bytes,
    _reservation: SemaphorePermit<'static>,
}

struct ReplyBuffer(Vec<u8>);

impl Drop for ReplyBuffer {
    fn drop(&mut self) {
        // A reply may finish on a different worker. Keep one reusable buffer there.
        let _ = REPLY_BUFFER.try_with(|slot| slot.set(std::mem::take(&mut self.0)));
    }
}

impl UdpForward {
    pub fn compile(raw: RawUdpForward) -> Result<Vec<Self>> {
        let listens = forward_ports::parse(&raw.listen.context("udp_forward.listen is required")?)
            .context("invalid udp_forward.listen")?;
        let endpoints = match (raw.target, raw.targets) {
            (Some(target), None) => vec![target],
            (None, Some(targets)) => targets,
            _ => bail!("udp_forward requires exactly one of target or targets"),
        };
        ensure!(
            (1..=8).contains(&endpoints.len()),
            "udp_forward needs 1..=8 targets"
        );
        let targets = endpoints
            .iter()
            .map(|target| forward_ports::targets(target, listens.len()))
            .collect::<Result<Vec<_>>>()
            .context("invalid udp_forward targets")?;
        ensure!(
            (1..=4096).contains(&raw.max_sessions),
            "udp_forward.max_sessions must be in 1..=4096"
        );
        ensure!(
            (100..=3_600_000).contains(&raw.idle_timeout_ms),
            "udp_forward.idle_timeout_ms must be in 100..=3600000"
        );
        let source = SourcePolicy::compile(raw.source)?;
        listens
            .iter()
            .enumerate()
            .map(|(index, &listen)| {
                let targets: Arc<[_]> = targets.iter().map(|target| target[index]).collect();
                let mut unique = HashSet::new();
                ensure!(
                    targets.iter().all(|target| {
                        target.port() != 0
                            && !target.ip().is_unspecified()
                            && !target.ip().is_multicast()
                            && target.ip() != IpAddr::V4(Ipv4Addr::BROADCAST)
                            && !listens.contains(target)
                            && unique.insert(*target)
                    }),
                    "udp_forward targets must be distinct unicast addresses with nonzero ports, different from the rule's listeners"
                );
                Ok(Self {
                    listen,
                    targets,
                    max_sessions: raw.max_sessions,
                    idle: Duration::from_millis(raw.idle_timeout_ms),
                    source: source.clone(),
                })
            })
            .collect()
    }

    #[cfg(unix)]
    pub fn same_startup(&self, other: &Self) -> bool {
        self.listen == other.listen
            && self.targets == other.targets
            && self.max_sessions == other.max_sessions
            && self.idle == other.idle
    }

    pub async fn serve(
        self,
        socket: UdpSocket,
        mut drain: watch::Receiver<bool>,
        stats: Option<Arc<ForwardStats>>,
        permits: impl Fn(IpAddr) -> bool + Clone + Send + Sync + 'static,
    ) {
        let socket = Arc::new(socket);
        let rule = Arc::new(self);
        let mut tasks = JoinSet::new();
        let mut sessions = HashMap::<SocketAddr, (Id, mpsc::Sender<Packet>)>::new();
        let mut buffer = vec![0; MAX_DATAGRAM];
        let mut next_target = 0;
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
                    if !permits(peer.ip()) {
                        if let Some(stats) = &stats {
                            stats.denied.fetch_add(1, Relaxed);
                        }
                        continue;
                    }
                    let Ok(reservation) = QUEUED_PACKETS.try_acquire() else { continue };
                    let can_start = sessions.len() < rule.max_sessions;
                    let (_, queue) = match sessions.entry(peer) {
                        Entry::Occupied(entry) => entry.into_mut(),
                        Entry::Vacant(entry) if can_start => {
                            let (send, receive) = mpsc::channel(4);
                            let socket = socket.clone();
                            let permits = permits.clone();
                            let rule = rule.clone();
                            let stats = stats.clone();
                            let start = next_target;
                            next_target = (start + 1) % rule.targets.len();
                            let task = tasks.spawn(async move {
                                if let Err(error) = relay(socket, peer, receive, &rule, start, stats.as_deref(), permits).await {
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
    rule: &UdpForward,
    start: usize,
    stats: Option<&ForwardStats>,
    permits: impl Fn(IpAddr) -> bool + Send + Sync,
) -> io::Result<()> {
    let mut candidates = rule.targets[start..].iter().chain(&rule.targets[..start]);
    let mut connected = connect(*candidates.next().expect("validated UDP target list")).await;
    for &target in candidates {
        if connected.is_ok() {
            break;
        }
        connected = connect(target).await;
    }
    let upstream = connected?;
    let _active = stats.map(ForwardStats::open);
    loop {
        let result = timeout(rule.idle, async {
            tokio::select! {
                packet = packets.recv() => {
                    let Some(packet) = packet else { return Ok(false) };
                    if !permits(peer.ip()) { return Ok(false); }
                    let sent = upstream.send(&packet.data).await?;
                    if let Some(stats) = stats {
                        stats.bytes_in.fetch_add(sent as u64, Relaxed);
                    }
                }
                response = recv_reply(&upstream) => {
                    let (buffer, len) = response?;
                    if !permits(peer.ip()) { return Ok(false); }
                    let sent = listener.send_to(&buffer.0[..len], peer).await?;
                    if let Some(stats) = stats {
                        stats.bytes_out.fetch_add(sent as u64, Relaxed);
                    }
                }
            }
            Ok::<_, io::Error>(true)
        })
        .await;
        match result {
            Ok(Ok(true)) => {}
            Ok(Err(error)) => return Err(error),
            Ok(Ok(false)) | Err(_) => return Ok(()),
        }
    }
}

async fn recv_reply(upstream: &UdpSocket) -> io::Result<(ReplyBuffer, usize)> {
    loop {
        upstream.readable().await?;
        let mut buffer = ReplyBuffer(REPLY_BUFFER.take());
        buffer.0.resize(MAX_DATAGRAM, 0);
        match upstream.try_recv(&mut buffer.0) {
            Ok(len) => return Ok((buffer, len)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    }
}

async fn connect(target: SocketAddr) -> io::Result<UdpSocket> {
    let upstream = UdpSocket::bind(if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    upstream.connect(target).await?;
    Ok(upstream)
}
