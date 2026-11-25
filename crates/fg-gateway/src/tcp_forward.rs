use std::{
    collections::HashSet,
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinSet,
    time::{sleep, timeout},
};

use crate::source_policy::{RawSourcePolicy, SourcePolicy};

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct RawForward {
    listen: Option<SocketAddr>,
    targets: Vec<SocketAddr>,
    max_connections: usize,
    connect_timeout_ms: u64,
    connection_lifetime_ms: u64,
    proxy_protocol: Option<ProxyProtocol>,
    source: RawSourcePolicy,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ProxyProtocol {
    V1,
    V2,
}

impl Default for RawForward {
    fn default() -> Self {
        Self {
            listen: None,
            targets: Vec::new(),
            max_connections: 128,
            connect_timeout_ms: 2_000,
            connection_lifetime_ms: 300_000,
            proxy_protocol: None,
            source: RawSourcePolicy::default(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct TcpForward {
    pub listen: SocketAddr,
    targets: Vec<SocketAddr>,
    max_connections: usize,
    connect_timeout: Duration,
    connection_lifetime: Duration,
    proxy_protocol: Option<ProxyProtocol>,
    pub source: SourcePolicy,
}

impl TcpForward {
    pub fn compile(raw: RawForward) -> Result<Self> {
        let listen = raw.listen.context("tcp_forward.listen is required")?;
        ensure!(
            (1..=8).contains(&raw.targets.len()),
            "tcp_forward needs 1..=8 targets"
        );
        let mut targets = HashSet::new();
        ensure!(
            raw.targets.iter().all(|target| {
                target.port() != 0
                    && !target.ip().is_unspecified()
                    && !target.ip().is_multicast()
                    && *target != listen
                    && targets.insert(*target)
            }),
            "tcp_forward targets must be distinct unicast addresses with nonzero ports, different from the listener"
        );
        ensure!(
            (1..=65_535).contains(&raw.max_connections),
            "tcp_forward.max_connections must be in 1..=65535"
        );
        ensure!(
            (1..=300_000).contains(&raw.connect_timeout_ms),
            "tcp_forward.connect_timeout_ms must be in 1..=300000"
        );
        ensure!(
            (1..=86_400_000).contains(&raw.connection_lifetime_ms),
            "tcp_forward.connection_lifetime_ms must be in 1..=86400000"
        );
        Ok(Self {
            listen,
            targets: raw.targets,
            max_connections: raw.max_connections,
            connect_timeout: Duration::from_millis(raw.connect_timeout_ms),
            connection_lifetime: Duration::from_millis(raw.connection_lifetime_ms),
            proxy_protocol: raw.proxy_protocol,
            source: SourcePolicy::compile(raw.source)?,
        })
    }

    #[cfg(unix)]
    pub fn same_startup(&self, other: &Self) -> bool {
        self.listen == other.listen
            && self.targets == other.targets
            && self.max_connections == other.max_connections
            && self.connect_timeout == other.connect_timeout
            && self.connection_lifetime == other.connection_lifetime
            && self.proxy_protocol == other.proxy_protocol
    }

    pub async fn serve(
        self,
        listener: TcpListener,
        mut drain: watch::Receiver<bool>,
        permits: impl Fn(IpAddr) -> bool + Send,
    ) {
        let targets = std::sync::Arc::new(self.targets);
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = drain.changed() => break,
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "TCP relay task failed");
                    }
                }
                accepted = listener.accept(), if connections.len() < self.max_connections => {
                    let (stream, peer) = match accepted {
                        Ok(connection) => connection,
                        Err(error) => {
                            tracing::warn!(%error, "TCP forward accept failed");
                            sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    };
                    if !permits(peer.ip()) {
                        tracing::debug!(source = %peer.ip(), "TCP forward source denied");
                        continue;
                    }
                    let targets = targets.clone();
                    connections.spawn(async move {
                        let _ = timeout(self.connection_lifetime, relay(stream, peer, &targets, self.connect_timeout, self.proxy_protocol)).await;
                    });
                }
            }
        }
        drop(listener);
        while connections.join_next().await.is_some() {}
    }
}

async fn relay(
    mut client: TcpStream,
    source: SocketAddr,
    targets: &[SocketAddr],
    connect_timeout: Duration,
    proxy_protocol: Option<ProxyProtocol>,
) {
    let _ = client.set_nodelay(true);
    for &target in targets {
        if let Ok(Ok(mut upstream)) = timeout(connect_timeout, TcpStream::connect(target)).await {
            let _ = upstream.set_nodelay(true);
            if let Some(protocol) = proxy_protocol {
                let result = async {
                    protocol
                        .write(&mut upstream, source, client.local_addr()?)
                        .await
                }
                .await;
                if let Err(error) = result {
                    tracing::debug!(kind = ?error.kind(), "TCP PROXY header failed");
                    return;
                }
            }
            if let Err(error) = copy_bidirectional(&mut client, &mut upstream).await {
                tracing::debug!(kind = ?error.kind(), "TCP relay ended");
            }
            return;
        }
    }
    tracing::debug!("all TCP forward targets failed to connect");
}

impl ProxyProtocol {
    async fn write(
        self,
        upstream: &mut TcpStream,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<()> {
        let source_ip = source.ip().to_canonical();
        let destination_ip = destination.ip().to_canonical();
        if source_ip.is_ipv4() != destination_ip.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "inconsistent TCP address families",
            ));
        }
        match self {
            Self::V1 => {
                let family = if source_ip.is_ipv4() { "TCP4" } else { "TCP6" };
                let header = format!(
                    "PROXY {family} {source_ip} {destination_ip} {} {}\r\n",
                    source.port(),
                    destination.port()
                );
                upstream.write_all(header.as_bytes()).await
            }
            Self::V2 => {
                let mut header = [0u8; 52];
                header[..12].copy_from_slice(b"\r\n\r\n\0\r\nQUIT\n");
                header[12] = 0x21; // Version 2, PROXY command.
                let ports_at = match (source_ip, destination_ip) {
                    (IpAddr::V4(source), IpAddr::V4(destination)) => {
                        header[13] = 0x11;
                        header[15] = 12;
                        header[16..20].copy_from_slice(&source.octets());
                        header[20..24].copy_from_slice(&destination.octets());
                        24
                    }
                    (IpAddr::V6(source), IpAddr::V6(destination)) => {
                        header[13] = 0x21;
                        header[15] = 36;
                        header[16..32].copy_from_slice(&source.octets());
                        header[32..48].copy_from_slice(&destination.octets());
                        48
                    }
                    _ => unreachable!("verified matching address families"),
                };
                header[ports_at..ports_at + 2].copy_from_slice(&source.port().to_be_bytes());
                header[ports_at + 2..ports_at + 4]
                    .copy_from_slice(&destination.port().to_be_bytes());
                upstream.write_all(&header[..ports_at + 4]).await
            }
        }
    }
}
