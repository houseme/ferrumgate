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
    net::{TcpListener, UdpSocket},
    sync::watch,
    task::JoinSet,
    time::{Instant, sleep, timeout, timeout_at},
};

use crate::{
    acme::{self, Managed},
    config::{self, Config, milliseconds},
    proxy::Proxy,
    tls::{ConnectionIdentity, ServerTls},
};

struct Generation {
    proxy: Proxy,
    tls: Option<ServerTls>,
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
    let managed = Arc::new(Managed::default());
    let mut config = config::load(&path, managed.clone()).await?;
    let acme_config = config.acme.take();
    let acme_boot = if let Some(acme) = &acme_config {
        let (lock, renew_at) = acme.restore(&managed).await?;
        let listener = match acme.challenge_listen {
            Some(listen) => Some(
                TcpListener::bind(listen)
                    .await
                    .context("bind ACME HTTP-01 listener")?,
            ),
            None => None,
        };
        Some((lock, renew_at, listener))
    } else {
        None
    };
    let tcp_rules = std::mem::take(&mut config.tcp_forward);
    let udp_rules = std::mem::take(&mut config.udp_forward);
    let settings = config.settings.clone();
    let state = Arc::new(ArcSwap::from_pointee(Generation::new(config)));
    let (drain, _) = watch::channel(false);
    let (publications, mut generations) = watch::channel(state.load_full());
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
                let next = config::load(&path, managed.clone()).await?;
                anyhow::ensure!(
                    next.settings == settings
                        && next.tcp_forward == tcp_rules
                        && next.udp_forward == udp_rules
                        && next.acme == acme_config,
                    "server, forwarding, and ACME settings require restart"
                );
                let next = Arc::new(Generation::new(next));
                state.store(next.clone());
                publications.send_replace(next);
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

    let listener = if settings.http_enabled {
        Some(
            TcpListener::bind(settings.listen)
                .await
                .context("bind business listener")?,
        )
    } else {
        None
    };
    let mut tcp_listeners = Vec::with_capacity(tcp_rules.len());
    for (index, rule) in tcp_rules.iter().enumerate() {
        let listener = TcpListener::bind(rule.listen)
            .await
            .with_context(|| format!("bind tcp_forward[{index}] listener"))?;
        tcp_listeners.push((rule.clone(), listener));
    }
    let mut udp_listeners = Vec::with_capacity(udp_rules.len());
    for (index, rule) in udp_rules.iter().enumerate() {
        let socket = UdpSocket::bind(rule.listen)
            .await
            .with_context(|| format!("bind udp_forward[{index}] listener"))?;
        udp_listeners.push((rule.clone(), socket));
    }
    let ready_addr = if let Some(listener) = &listener {
        listener.local_addr()?
    } else if let Some((_, listener)) = tcp_listeners.first() {
        listener.local_addr()?
    } else {
        udp_listeners[0].1.local_addr()?
    };
    let mut forwarding = JoinSet::new();
    for (rule, socket) in udp_listeners {
        tracing::info!(listen = %socket.local_addr()?, "UDP forward ready");
        forwarding.spawn(rule.serve(socket, drain.subscribe()));
    }
    for (rule, listener) in tcp_listeners {
        tracing::info!(listen = %listener.local_addr()?, "TCP forward ready");
        forwarding.spawn(rule.serve(listener, drain.subscribe()));
    }
    let mut acme_tasks = JoinSet::new();
    let _acme_lock = if let Some((lock, renew_at, listener)) = acme_boot {
        if let Some(listener) = listener {
            tracing::info!(listen = %listener.local_addr()?, "ACME HTTP-01 listener ready");
            acme_tasks.spawn(acme::serve_challenges(listener, managed.clone()));
        }
        let acme = acme_config.clone().expect("ACME startup config");
        let lock = Arc::new(lock);
        acme_tasks.spawn(acme.run(managed.clone(), lock.clone(), renew_at));
        Some(lock)
    } else {
        None
    };
    let mut health = JoinSet::new();
    health.spawn(async move {
        loop {
            let current = generations.borrow_and_update().clone();
            tokio::select! {
                _ = current.proxy.monitor_health() => {
                    if generations.changed().await.is_err() { break; }
                }
                next = generations.changed() => {
                    if next.is_err() { break; }
                }
            }
        }
    });
    tracing::info!(listen = %ready_addr, http = settings.http_enabled, tls = settings.tls, "gateway ready");
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
            accepted = async { listener.as_ref().expect("enabled HTTP listener").accept().await }, if listener.is_some() && connections.len() < settings.max_connections => {
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
                                Ok(Ok((stream, identity))) => {
                                    let http2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
                                    if http2 {
                                        serve_h2(&h2, stream, &state, peer, identity, drain).await;
                                    } else {
                                        serve_http(&http, stream, &state, peer, Some(&identity), drain).await;
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
    tokio::join!(health.shutdown(), acme_tasks.shutdown());
    tracing::info!("gateway draining connections");
    if timeout(milliseconds(settings.shutdown_timeout_ms), async {
        tokio::join!(
            async { while connections.join_next().await.is_some() {} },
            async { while forwarding.join_next().await.is_some() {} },
        );
    })
    .await
    .is_err()
    {
        tracing::warn!("drain deadline expired");
        tokio::join!(connections.shutdown(), forwarding.shutdown());
    }
    shutdown_result.context("wait for shutdown signal")
}

async fn serve_http(
    http: &http1::Builder,
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    state: &ArcSwap<Generation>,
    peer: SocketAddr,
    tls_identity: Option<&ConnectionIdentity>,
    mut drain: watch::Receiver<bool>,
) {
    let tunnel = OnceLock::new();
    let result = {
        let service = service_fn(|request| async {
            let current = state.load_full();
            Ok::<_, std::convert::Infallible>(
                current
                    .proxy
                    .forward(request, peer, tls_identity, Some(&tunnel))
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
    tls_identity: ConnectionIdentity,
    mut drain: watch::Receiver<bool>,
) {
    let service = service_fn(|request| {
        let current = state.load_full();
        let tls_identity = tls_identity.clone();
        async move {
            Ok::<_, std::convert::Infallible>(
                current
                    .proxy
                    .forward(request, peer, Some(&tls_identity), None)
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
