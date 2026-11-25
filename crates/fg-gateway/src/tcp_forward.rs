use std::{collections::HashSet, net::SocketAddr, time::Duration};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinSet,
    time::{sleep, timeout},
};

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct RawForward {
    listen: Option<SocketAddr>,
    targets: Vec<SocketAddr>,
    max_connections: usize,
    connect_timeout_ms: u64,
    connection_lifetime_ms: u64,
}

impl Default for RawForward {
    fn default() -> Self {
        Self {
            listen: None,
            targets: Vec::new(),
            max_connections: 128,
            connect_timeout_ms: 2_000,
            connection_lifetime_ms: 300_000,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TcpForward {
    pub listen: SocketAddr,
    targets: Vec<SocketAddr>,
    max_connections: usize,
    connect_timeout: Duration,
    connection_lifetime: Duration,
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
        })
    }

    pub async fn serve(self, listener: TcpListener, mut drain: watch::Receiver<bool>) {
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
                    let (stream, _) = match accepted {
                        Ok(connection) => connection,
                        Err(error) => {
                            tracing::warn!(%error, "TCP forward accept failed");
                            sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    };
                    let targets = targets.clone();
                    connections.spawn(async move {
                        let _ = timeout(self.connection_lifetime, relay(stream, &targets, self.connect_timeout)).await;
                    });
                }
            }
        }
        drop(listener);
        while connections.join_next().await.is_some() {}
    }
}

async fn relay(mut client: TcpStream, targets: &[SocketAddr], connect_timeout: Duration) {
    let _ = client.set_nodelay(true);
    for &target in targets {
        if let Ok(Ok(mut upstream)) = timeout(connect_timeout, TcpStream::connect(target)).await {
            let _ = upstream.set_nodelay(true);
            if let Err(error) = copy_bidirectional(&mut client, &mut upstream).await {
                tracing::debug!(kind = ?error.kind(), "TCP relay ended");
            }
            return;
        }
    }
    tracing::debug!("all TCP forward targets failed to connect");
}
