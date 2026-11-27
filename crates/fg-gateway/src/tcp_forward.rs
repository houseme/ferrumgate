use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::Ordering::Relaxed},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use serde::Deserialize;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinSet,
    time::{sleep, timeout},
};

use crate::{
    forward_metrics::ForwardStats,
    forward_ports,
    l4::shared::{
        failover::dial_targets,
        pipe::{FirstData, PipeLimits, RelayResult},
        proxy_proto::{self, write_header},
    },
    source_policy::{RawSourcePolicy, SourcePolicy, compile_networks},
    source_quota::SourceQuota,
};

#[derive(Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawForward {
    listen: Option<String>,
    targets: Vec<String>,
    max_connections: usize,
    connect_timeout_ms: u64,
    first_data_timeout_ms: u64,
    connection_lifetime_ms: u64,
    proxy_protocol: Option<ProxyProtocol>,
    source: RawSourcePolicy,
    max_connections_per_source: Option<usize>,
    source_limit_exempt: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
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
            first_data_timeout_ms: 60_000,
            connection_lifetime_ms: 300_000,
            proxy_protocol: None,
            source: RawSourcePolicy::default(),
            max_connections_per_source: None,
            source_limit_exempt: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct TcpForward {
    pub listen: SocketAddr,
    pub(crate) targets: Vec<SocketAddr>,
    pub(crate) max_connections: usize,
    pub(crate) connect_timeout: Duration,
    pub(crate) first_data_timeout: Duration,
    connection_lifetime: Duration,
    pub(crate) proxy_protocol: Option<ProxyProtocol>,
    pub source: SourcePolicy,
    source_limit: Option<SourceLimit>,
}

#[derive(Clone, PartialEq, Eq)]
struct SourceLimit {
    max: usize,
    exempt: Vec<IpNet>,
}

impl TcpForward {
    pub fn compile(raw: RawForward) -> Result<Vec<Self>> {
        let listens = forward_ports::parse(&raw.listen.context("tcp_forward.listen is required")?)
            .context("invalid tcp_forward.listen")?;
        ensure!(
            (1..=8).contains(&raw.targets.len()),
            "tcp_forward needs 1..=8 targets"
        );
        let targets = raw
            .targets
            .iter()
            .map(|target| forward_ports::targets(target, listens.len()))
            .collect::<Result<Vec<_>>>()
            .context("invalid tcp_forward.targets")?;
        ensure!(
            (1..=65_535).contains(&raw.max_connections),
            "tcp_forward.max_connections must be in 1..=65535"
        );
        ensure!(
            (1..=300_000).contains(&raw.connect_timeout_ms),
            "tcp_forward.connect_timeout_ms must be in 1..=300000"
        );
        ensure!(
            (1..=3_600_000).contains(&raw.first_data_timeout_ms),
            "tcp_forward.first_data_timeout_ms must be in 1..=3600000"
        );
        ensure!(
            (1..=86_400_000).contains(&raw.connection_lifetime_ms),
            "tcp_forward.connection_lifetime_ms must be in 1..=86400000"
        );
        ensure!(
            raw.max_connections_per_source.is_some() || raw.source_limit_exempt.is_empty(),
            "source_limit_exempt requires max_connections_per_source"
        );
        let source_limit = if let Some(max) = raw.max_connections_per_source {
            ensure!(
                (1..=raw.max_connections).contains(&max),
                "max_connections_per_source must be positive and no greater than max_connections"
            );
            let exempt =
                compile_networks(raw.source_limit_exempt).context("invalid source_limit_exempt")?;
            Some(SourceLimit { max, exempt })
        } else {
            None
        };
        let source = SourcePolicy::compile(raw.source)?;
        listens
            .iter()
            .enumerate()
            .map(|(index, &listen)| {
                let targets: Vec<_> = targets.iter().map(|target| target[index]).collect();
                let mut unique = HashSet::new();
                ensure!(
                    targets.iter().all(|target| {
                        target.port() != 0
                            && !target.ip().is_unspecified()
                            && !target.ip().is_multicast()
                            && !listens.contains(target)
                            && unique.insert(*target)
                    }),
                    "tcp_forward targets must be distinct unicast addresses with nonzero ports, different from the rule's listeners"
                );
                Ok(Self {
                    listen,
                    targets,
                    max_connections: raw.max_connections,
                    connect_timeout: Duration::from_millis(raw.connect_timeout_ms),
                    first_data_timeout: Duration::from_millis(raw.first_data_timeout_ms),
                    connection_lifetime: Duration::from_millis(raw.connection_lifetime_ms),
                    proxy_protocol: raw.proxy_protocol,
                    source: source.clone(),
                    source_limit: source_limit.clone(),
                })
            })
            .collect()
    }

    #[cfg(unix)]
    pub fn same_startup(&self, other: &Self) -> bool {
        self.listen == other.listen
            && self.targets == other.targets
            && self.max_connections == other.max_connections
            && self.connect_timeout == other.connect_timeout
            && self.first_data_timeout == other.first_data_timeout
            && self.connection_lifetime == other.connection_lifetime
            && self.proxy_protocol == other.proxy_protocol
            && self.source_limit == other.source_limit
    }

    pub async fn serve(
        self,
        listener: TcpListener,
        mut drain: watch::Receiver<bool>,
        stats: Option<Arc<ForwardStats>>,
        permits: impl Fn(IpAddr) -> bool + Send,
    ) {
        let targets = Arc::new(self.targets);
        let quota = self
            .source_limit
            .map(|limit| (limit, Arc::new(SourceQuota::default())));
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
                        if let Some(stats) = &stats {
                            stats.denied.fetch_add(1, Relaxed);
                        }
                        tracing::debug!(source = %peer.ip(), "TCP forward source denied");
                        continue;
                    }
                    let lease = if let Some((limit, quota)) = &quota
                        && !limit.exempt.iter().any(|network| network.contains(&peer.ip().to_canonical()))
                    {
                        let Some(lease) = quota.acquire(peer.ip(), limit.max) else {
                            tracing::debug!(source = %peer.ip(), "TCP forward source quota exhausted");
                            continue;
                        };
                        Some(lease)
                    } else {
                        None
                    };
                    let targets = targets.clone();
                    let stats = stats.clone();
                    connections.spawn(async move {
                        let _lease = lease;
                        let _active = stats.as_deref().map(ForwardStats::open);
                        let _ = timeout(self.connection_lifetime, relay(stream, peer, &targets, self.connect_timeout, self.first_data_timeout, self.proxy_protocol, stats.as_deref())).await;
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
    first_data_timeout: Duration,
    proxy_protocol: Option<ProxyProtocol>,
    stats: Option<&ForwardStats>,
) {
    let _ = client.set_nodelay(true);
    let Ok(mut upstream) = dial_targets(targets, connect_timeout).await else {
        tracing::debug!("all TCP forward targets failed to connect");
        return;
    };
    if let Some(protocol) = proxy_protocol {
        let protocol = match protocol {
            ProxyProtocol::V1 => proxy_proto::ProxyProtocol::V1,
            ProxyProtocol::V2 => proxy_proto::ProxyProtocol::V2,
        };
        let result =
            async { write_header(protocol, &mut upstream, source, client.local_addr()?).await }
                .await;
        if let Err(error) = result {
            tracing::debug!(kind = ?error.kind(), "TCP PROXY header failed");
            return;
        }
    }
    let limits = PipeLimits {
        first_data_timeout,
        drain: Duration::ZERO,
    };
    // EOF is readable too. Relay it so the other peer can still respond.
    let result = match stats {
        Some(stats) => {
            crate::l4::shared::pipe::relay_counted(
                &mut client,
                &mut upstream,
                limits,
                FirstData::None,
                || false,
                &stats.bytes_out,
                &stats.bytes_in,
            )
            .await
        }
        None => {
            crate::l4::shared::pipe::relay(
                &mut client,
                &mut upstream,
                limits,
                FirstData::None,
                || false,
            )
            .await
        }
    };
    match result {
        RelayResult::FirstDataTimeout => tracing::debug!("TCP first data timed out"),
        RelayResult::Error(error) => tracing::debug!(kind = ?error.kind(), "TCP relay ended"),
        RelayResult::Closed | RelayResult::Killed => {}
    }
}
