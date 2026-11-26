use std::{io, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use fg_core::module::Module;
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::watch,
    task::JoinSet,
};

use crate::{
    forward_metrics::{self, ForwardStats, Series},
    server::Generation,
    tcp_forward::TcpForward,
    udp_forward::UdpForward,
};

pub(crate) struct L4 {
    tcp: Vec<(TcpForward, TcpListener)>,
    udp: Vec<(UdpForward, UdpSocket)>,
    metrics: Option<TcpListener>,
    state: Arc<ArcSwap<Generation>>,
}

impl L4 {
    pub async fn prepare(
        tcp: &[TcpForward],
        udp: &[UdpForward],
        metrics_listen: Option<SocketAddr>,
        state: Arc<ArcSwap<Generation>>,
    ) -> Result<Self> {
        let mut tcp_listeners = Vec::with_capacity(tcp.len());
        for (index, rule) in tcp.iter().enumerate() {
            let listener = TcpListener::bind(rule.listen)
                .await
                .with_context(|| format!("bind tcp_forward[{index}] listener"))?;
            tcp_listeners.push((rule.clone(), listener));
        }
        let mut udp_sockets = Vec::with_capacity(udp.len());
        for (index, rule) in udp.iter().enumerate() {
            let socket = UdpSocket::bind(rule.listen)
                .await
                .with_context(|| format!("bind udp_forward[{index}] listener"))?;
            udp_sockets.push((rule.clone(), socket));
        }
        let metrics = match metrics_listen {
            Some(listen) => Some(
                TcpListener::bind(listen)
                    .await
                    .context("bind metrics listener")?,
            ),
            None => None,
        };
        Ok(Self {
            tcp: tcp_listeners,
            udp: udp_sockets,
            metrics,
            state,
        })
    }

    pub fn first_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.tcp
            .first()
            .map(|(_, listener)| listener.local_addr())
            .or_else(|| self.udp.first().map(|(_, socket)| socket.local_addr()))
            .transpose()
    }

    pub fn metrics_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.metrics
            .as_ref()
            .map(TcpListener::local_addr)
            .transpose()
    }
}

impl Module for L4 {
    const ID: &'static str = "portforward";

    async fn run(self, mut drain: watch::Receiver<bool>) -> Result<()> {
        let mut forwarding = JoinSet::new();
        let mut series = Vec::new();
        let mut counters = |protocol, listen| {
            self.metrics.as_ref().map(|_| {
                let stats = Arc::new(ForwardStats::default());
                series.push(Series {
                    protocol,
                    listen,
                    stats: stats.clone(),
                });
                stats
            })
        };
        let tcp_count = self.tcp.len();
        for (index, (rule, socket)) in self.udp.into_iter().enumerate() {
            let slot = tcp_count + index;
            let state = self.state.clone();
            let listen = socket.local_addr()?;
            let stats = counters("udp", listen);
            tracing::info!(%listen, "UDP forward ready");
            forwarding.spawn(rule.serve(socket, drain.clone(), stats, move |ip| {
                state.load().forward_sources[slot].permits(ip)
            }));
        }
        for (index, (rule, listener)) in self.tcp.into_iter().enumerate() {
            let state = self.state.clone();
            let listen = listener.local_addr()?;
            let stats = counters("tcp", listen);
            tracing::info!(%listen, "TCP forward ready");
            forwarding.spawn(rule.serve(listener, drain.clone(), stats, move |ip| {
                state.load().forward_sources[index].permits(ip)
            }));
        }
        let metrics = self
            .metrics
            .map(|listener| forwarding.spawn(forward_metrics::serve(listener, series)));
        loop {
            tokio::select! {
                biased;
                _ = drain.changed() => break,
                Some(result) = forwarding.join_next(), if !forwarding.is_empty() => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "forwarding task failed");
                    }
                }
            }
        }
        if let Some(metrics) = metrics {
            metrics.abort();
        }
        while forwarding.join_next().await.is_some() {}
        Ok(())
    }
}
