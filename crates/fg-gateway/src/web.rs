use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::Result;
use arc_swap::ArcSwap;
use fg_core::{events::EventBus, module::Module};
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
    config::{Settings, milliseconds},
    server::Generation,
    tls::ConnectionIdentity,
};

pub(crate) struct Web {
    pub listener: TcpListener,
    pub settings: Settings,
    pub state: Arc<ArcSwap<Generation>>,
    pub generations: watch::Receiver<Arc<Generation>>,
    pub events: EventBus,
}

impl Module for Web {
    const ID: &'static str = "webservice";

    async fn run(self, mut drain: watch::Receiver<bool>) -> Result<()> {
        let Self {
            listener,
            settings,
            state,
            mut generations,
            events,
        } = self;
        let mut connections = JoinSet::new();
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
        {
            let health = async {
                loop {
                    let current = generations.borrow_and_update().clone();
                    tokio::select! {
                        _ = current.proxy.monitor_health(&events) => {
                            if generations.changed().await.is_err() {
                                break;
                            }
                        }
                        next = generations.changed() => {
                            if next.is_err() {
                                break;
                            }
                        }
                    }
                }
            };
            tokio::pin!(health);

            loop {
                tokio::select! {
                    biased;
                    _ = drain.changed() => break,
                    _ = &mut health => break,
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
                        let mut drain = drain.clone();
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
            }
        }
        drop(listener);
        while connections.join_next().await.is_some() {}
        Ok(())
    }
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
