//! The UDP knock listener and receive loop (WP-54 §3.3 steps 1–3, §3.3
//! "收包循环"): binds `settings.port` (0 disables UDP; TCP knocks arrive
//! through protocol routing via [`crate::engine::Engine::submit`]), drops
//! banned and oversized sources, applies the pre-authentication rate
//! limit, hands every packet to the engine and summarizes invalid packets
//! once per minute. TCP knock ingestion is exercised by the integration
//! tests through a loopback socket forwarding into `submit`, mirroring the
//! protocol-routing contract.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::engine::{Engine, Via};
use crate::spa::MAX_PACKET_LEN;

/// Runs the UDP listener until `token` fires. Periodically prunes expired
/// grants and logs the per-minute invalid summary.
pub async fn run_udp(
    engine: Arc<Engine>,
    port: u16,
    token: CancellationToken,
) -> anyhow::Result<()> {
    let socket = bind(port).await?;
    tracing::info!(target: "fg_knock", port, "敲门监听已启动");
    let mut summary = tokio::time::interval(Duration::from_secs(30));
    summary.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the immediate first tick.
    summary.tick().await;
    let mut buffer = vec![0u8; MAX_PACKET_LEN + 1];
    loop {
        tokio::select! {
            biased;
            _ = token.cancelled() => break,
            _ = summary.tick() => {
                let now = std::time::Instant::now();
                if let Some(invalid) = engine.take_invalid_summary(now) {
                    tracing::warn!(target: "fg_knock", sources = invalid.sources, count = invalid.count, "{}", invalid.message());
                }
                engine.grants().prune(engine.now());
            }
            received = socket.recv_from(&mut buffer) => {
                let Ok((length, peer)) = received else {
                    // Transient socket errors: keep serving.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                engine.handle(&buffer[..length], peer, Via::Udp).await;
            }
        }
    }
    tracing::info!(target: "fg_knock", port, "敲门监听已停止");
    Ok(())
}

/// Binds the knock port dual-stack when possible, IPv4 otherwise.
async fn bind(port: u16) -> anyhow::Result<UdpSocket> {
    match UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, port)).await {
        Ok(socket) => Ok(socket),
        Err(v6_error) => UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port))
            .await
            .map_err(|v4_error| {
                anyhow::anyhow!("bind knock udp port {port}: v6: {v6_error}; v4: {v4_error}")
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_falls_back_to_ipv4_when_v6_is_unavailable() {
        // Port 0 lets the OS pick a free port; on dual-stack systems the
        // v6 bind succeeds, otherwise the v4 fallback must.
        let bound = bind(0).await.expect("a wildcard socket binds");
        assert!(bound.local_addr().is_ok());
    }
}
