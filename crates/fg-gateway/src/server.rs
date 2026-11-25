use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use hyper::{
    server::conn::{http1, http2},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::watch,
    task::JoinSet,
    time::{Instant, sleep, timeout, timeout_at},
};

use crate::{
    config::{self, Config, milliseconds},
    proxy::Proxy,
};

struct Generation {
    proxy: Proxy,
    tls: Option<tokio_rustls::TlsAcceptor>,
}

impl Generation {
    fn new(config: Config) -> Self {
        Self {
            proxy: Proxy::new(config.routes, &config.settings, config.tls.client),
            tls: config.tls.server,
        }
    }
}

/// Run the configured data plane until a process shutdown signal arrives.
pub async fn serve(path: PathBuf) -> Result<()> {
    let config = config::load(&path).await?;
    let settings = config.settings.clone();
    let state = Arc::new(ArcSwap::from_pointee(Generation::new(config)));
    let (drain, _) = watch::channel(false);
    let mut connections = JoinSet::new();
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);

    #[cfg(unix)]
    let (mut terminate, mut hangup) = {
        use tokio::signal::unix::{SignalKind, signal};
        (
            signal(SignalKind::terminate())?,
            signal(SignalKind::hangup())?,
        )
    };
    let termination = async {
        #[cfg(unix)]
        {
            terminate.recv().await;
        }
        #[cfg(not(unix))]
        std::future::pending::<()>().await;
    };
    tokio::pin!(termination);
    let reload = async {
        #[cfg(unix)]
        while hangup.recv().await.is_some() {
            let candidate = async {
                let next = config::load(&path).await?;
                anyhow::ensure!(next.settings == settings, "server settings require restart");
                state.store(Arc::new(Generation::new(next)));
                Ok::<_, anyhow::Error>(())
            };
            match candidate.await {
                Ok(()) => tracing::info!("configuration reloaded"),
                Err(error) => tracing::warn!(%error, "configuration reload rejected"),
            }
        }
        std::future::pending::<()>().await;
    };
    tokio::pin!(reload);

    let listener = TcpListener::bind(settings.listen)
        .await
        .context("bind business listener")?;
    tracing::info!(listen = %listener.local_addr()?, tls = settings.tls, "gateway ready");
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new())
        .max_buf_size(32 * 1024)
        .header_read_timeout(milliseconds(settings.header_timeout_ms));

    let mut h2 = http2::Builder::new(TokioExecutor::new());
    h2.max_concurrent_streams(100)
        .max_header_list_size(32 * 1024)
        .initial_stream_window_size(65_535)
        .initial_connection_window_size(1024 * 1024)
        .max_send_buf_size(64 * 1024);

    let handshake_timeout = milliseconds(settings.tls_handshake_timeout_ms);
    let shutdown_result = loop {
        tokio::select! {
            biased;
            result = &mut interrupt => break result,
            _ = &mut termination => break Ok(()),
            _ = &mut reload => unreachable!(),
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(%error, "connection task failed");
                }
            }
            accepted = listener.accept(), if connections.len() < settings.max_connections => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        tracing::warn!(%error, "accept failed");
                        sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let deadline = Instant::now() + milliseconds(settings.connection_lifetime_ms);
                let _ = stream.set_nodelay(true);
                let tls = state.load().tls.clone();
                let state = state.clone();
                let mut drain = drain.subscribe();
                let http = http.clone();
                let h2 = h2.clone();
                connections.spawn(async move {
                    let _ = timeout_at(deadline, async {
                        if let Some(tls) = tls {
                            let negotiated = tokio::select! {
                                biased;
                                _ = drain.changed() => return,
                                result = timeout(handshake_timeout, tls.accept(stream)) => result,
                            };
                            match negotiated {
                                Ok(Ok(stream)) => {
                                    let session = stream.get_ref().1;
                                    let http2 = session.alpn_protocol() == Some(b"h2");
                                    let name = session.server_name().map(str::to_owned);
                                    if http2 {
                                        serve_h2(&h2, stream, &state, peer, name, drain).await;
                                    } else {
                                        serve_http(&http, stream, &state, peer, name.as_deref(), drain).await;
                                    }
                                }
                                _ => tracing::debug!("TLS handshake failed or timed out"),
                            }
                        } else {
                            serve_http(&http, stream, &state, peer, None, drain).await;
                        }
                    }).await;
                });
            }
        }
    };

    drop(listener);
    drain.send_replace(true);
    tracing::info!("gateway draining connections");
    if timeout(milliseconds(settings.shutdown_timeout_ms), async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tracing::warn!("drain deadline expired");
        connections.shutdown().await;
    }
    shutdown_result.context("wait for shutdown signal")
}

async fn serve_http(
    http: &http1::Builder,
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    state: &ArcSwap<Generation>,
    peer: SocketAddr,
    tls_name: Option<&str>,
    mut drain: watch::Receiver<bool>,
) {
    let tunnel = OnceLock::new();
    let result = {
        let service = service_fn(|request| async {
            let current = state.load_full();
            Ok::<_, std::convert::Infallible>(
                current
                    .proxy
                    .forward(request, peer, tls_name, Some(&tunnel))
                    .await,
            )
        });
        let connection = http
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades();
        tokio::pin!(connection);
        tokio::select! {
            biased;
            _ = drain.changed() => {
                connection.as_mut().graceful_shutdown();
                connection.await
            }
            result = &mut connection => result,
        }
    };
    if let Err(error) = result {
        tracing::debug!(%error, "HTTP connection closed");
        return;
    }
    if let Some(tunnel) = tunnel.into_inner() {
        // Keep the tunnel inside the accepted connection's task and deadline.
        tokio::select! {
            biased;
            _ = drain.wait_for(|draining| *draining) => {}
            _ = tunnel.relay() => {}
        }
    }
}

async fn serve_h2(
    http: &http2::Builder<TokioExecutor>,
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    state: &ArcSwap<Generation>,
    peer: SocketAddr,
    tls_name: Option<String>,
    mut drain: watch::Receiver<bool>,
) {
    let tls_name = tls_name.map(Arc::<str>::from);
    let service = service_fn(|request| {
        let current = state.load_full();
        let tls_name = tls_name.clone();
        async move {
            Ok::<_, std::convert::Infallible>(
                current
                    .proxy
                    .forward(request, peer, tls_name.as_deref(), None)
                    .await,
            )
        }
    });
    let connection = http.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    let result = tokio::select! {
        biased;
        _ = drain.changed() => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
        result = &mut connection => result,
    };
    if let Err(error) = result {
        tracing::debug!(%error, "HTTP/2 connection closed");
    }
}
