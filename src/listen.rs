//! Custom TCP accept loop for the management listener: hostile peers are
//! refused at accept time (`Close` drops the socket, `Drop` holds it
//! silently within bounded slots) before any HTTP parsing happens, and
//! every served connection gets its peer address as the
//! `ConnectInfo<SocketAddr>` extension the routes expect.

use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Request},
    http::Request as HttpRequest,
    middleware::{self, Next},
    response::Response,
};
use fg_admin::access::{
    AccessConfig, DenyMode,
    listener::{AcceptAction, HoldSlots, accept_action},
};
use fg_net::ClientAddr;
use hyper::{body::Incoming, service::Service as HyperService};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use tokio::{net::TcpListener, sync::watch, task::JoinHandle};

/// How long in-flight connections may finish after the drain signal
/// before they are aborted (the caller bounds the whole drain again).
const DRAIN_WINDOW: Duration = Duration::from_secs(3);

/// Accept-time posture resolved from the startup settings snapshot.
pub struct ServeOptions {
    pub lan_only: bool,
    pub deny_mode: DenyMode,
}

/// Serves `router` on `listener` until the listener fails or `drain`
/// fires. On drain: stop accepting, let in-flight connections finish
/// within [`DRAIN_WINDOW`], then abort whatever is left (held sockets go
/// immediately — they are hostile peers being tarpitted, not work to
/// finish).
pub async fn serve_tcp(
    listener: TcpListener,
    router: Router,
    options: ServeOptions,
    mut drain: watch::Receiver<bool>,
) -> Result<()> {
    let slots = HoldSlots::new();
    let mut builder = Builder::new(TokioExecutor::new());
    // CONNECT protocol, so HTTP/2 WebSockets keep working (parity with
    // `axum::serve`).
    builder.http2().enable_connect_protocol();
    let config = AccessConfig {
        lan_only: options.lan_only,
        deny_mode: options.deny_mode,
        ..AccessConfig::default()
    };
    let mut connections: Vec<JoinHandle<()>> = Vec::new();
    let mut holds: Vec<JoinHandle<()>> = Vec::new();
    loop {
        tokio::select! {
            biased;
            _ = drain.wait_for(|&draining| draining) => break,
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("accept management connection")?;
                // Reap finished tasks so the vectors stay bounded.
                connections.retain(|handle| !handle.is_finished());
                holds.retain(|handle| !handle.is_finished());
                match accept_action(
                    peer,
                    &ClientAddr {
                        ip: peer.ip(),
                        via: None,
                        verified: false,
                    },
                    // The ban list lands with WP-26/WP-50.
                    false,
                    &config,
                ) {
                    AcceptAction::Close => drop(stream),
                    AcceptAction::Hold => {
                        let slots = Arc::clone(&slots);
                        holds.push(tokio::spawn(async move {
                            slots.hold(stream).await;
                        }));
                    }
                    AcceptAction::Serve => {
                        let service = RouterService::new(with_peer(&router, peer));
                        let builder = builder.clone();
                        connections.push(tokio::spawn(async move {
                            // Upgrades: management pages speak WebSocket.
                            let _ = builder
                                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                                .await;
                        }));
                    }
                }
            }
        }
    }
    for handle in holds.drain(..) {
        handle.abort();
    }
    // Give in-flight connections the bounded window, then abort the rest.
    let deadline = tokio::time::Instant::now() + DRAIN_WINDOW;
    for mut handle in connections.drain(..) {
        if tokio::time::timeout_at(deadline, &mut handle)
            .await
            .is_err()
        {
            handle.abort();
        }
    }
    Ok(())
}

/// Clones the router and wraps it with a per-connection layer that
/// publishes the accepted peer as `ConnectInfo<SocketAddr>` on every
/// request (axum injects that extension through the make service, which a
/// raw connection loop bypasses). Router clones are cheap; layering per
/// connection keeps the shared router untouched.
fn with_peer(router: &Router, peer: SocketAddr) -> Router {
    router.clone().layer(middleware::from_fn(
        move |mut request: Request, next: Next| async move {
            request.extensions_mut().insert(ConnectInfo(peer));
            next.run(request).await
        },
    ))
}

/// Serves an axum `Router` through hyper's connection machinery: hyper
/// hands over `Request<Incoming>`, the router wants
/// `Request<axum::body::Body>`. `TowerToHyperService` does the trait
/// bridging; this wrapper only maps the body type (axum's own serve loop
/// wraps the same way with `tower`'s `map_request`, which is not a direct
/// dependency here).
#[derive(Clone)]
struct RouterService(TowerToHyperService<Router>);

impl RouterService {
    fn new(router: Router) -> Self {
        Self(TowerToHyperService::new(router))
    }
}

impl HyperService<HttpRequest<Incoming>> for RouterService {
    type Response = Response;
    type Error = Infallible;
    type Future = <TowerToHyperService<Router> as HyperService<HttpRequest<Body>>>::Future;

    fn call(&self, request: HttpRequest<Incoming>) -> Self::Future {
        self.0.call(request.map(Body::new))
    }
}
