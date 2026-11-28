//! WebDAV listener runtime: `ArcSwap` hot-reloading, graceful drain via
//! `CancellationToken`, optional SNI TLS, `OpenPorts` registration, and
//! keep-alive idle connection tracking.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Context as _, Result, anyhow};
use arc_swap::ArcSwap;
use fg_files::FileUsersStore;
use fg_net::{
    client_addr::ProxyTrust,
    openports::{OpenPort, OpenPorts, Proto},
};
use hyper::{
    Response,
    body::{Body, Frame},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::server::ResolvesServerCert;
use serde::Serialize;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    sync::Mutex as AsyncMutex,
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::{
    handler::{DavBody, WebDavHandler},
    model::{RuntimeTimeouts, Settings, limits},
    validate,
};

/// Immutable snapshot read lock-free once per incoming request.
#[derive(Clone, Debug)]
pub struct RuntimeSnapshot {
    pub settings: Settings,
    pub proxy_trust: ProxyTrust,
}

impl RuntimeSnapshot {
    pub fn from_settings(settings: Settings) -> Self {
        let proxy_trust = validate::build_proxy_trust(&settings.trusted_proxies);
        Self {
            settings,
            proxy_trust,
        }
    }
}

/// Public runtime status returned by management status endpoints.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStatus {
    pub running: bool,
    pub listen: Option<String>,
    pub tls: bool,
    pub active_connections: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

struct ActiveListener {
    addr: SocketAddr,
    bind_key: BindKey,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BindKey {
    listen_ip: Option<IpAddr>,
    port: u16,
    tls: bool,
}

/// Manages the live WebDAV TCP/TLS listener and hot-reloadable configuration.
pub struct WebDavRuntime {
    snapshot: Arc<ArcSwap<RuntimeSnapshot>>,
    handler: Arc<WebDavHandler>,
    timeouts: RuntimeTimeouts,
    certs: Option<Arc<dyn ResolvesServerCert>>,
    open_ports: Option<Arc<OpenPorts>>,
    active_conns: Arc<AtomicUsize>,
    listener: AsyncMutex<Option<ActiveListener>>,
    last_error: Mutex<Option<String>>,
    bound_addr: Mutex<Option<SocketAddr>>,
    running: AtomicBool,
}

impl WebDavRuntime {
    pub fn new(
        initial: Settings,
        shared_users: Arc<FileUsersStore>,
        certs: Option<Arc<dyn ResolvesServerCert>>,
        open_ports: Option<Arc<OpenPorts>>,
        timeouts: RuntimeTimeouts,
    ) -> Arc<Self> {
        let snapshot = Arc::new(ArcSwap::from_pointee(RuntimeSnapshot::from_settings(
            initial,
        )));
        let handler = Arc::new(WebDavHandler::new(
            Arc::clone(&snapshot),
            shared_users,
            timeouts,
        ));
        Arc::new(Self {
            snapshot,
            handler,
            timeouts,
            certs,
            open_ports,
            active_conns: Arc::new(AtomicUsize::new(0)),
            listener: AsyncMutex::new(None),
            last_error: Mutex::new(None),
            bound_addr: Mutex::new(None),
            running: AtomicBool::new(false),
        })
    }

    /// Returns the currently bound socket address if listening.
    pub fn bound_addr(&self) -> Option<SocketAddr> {
        *self.bound_addr.lock().expect("bound addr lock poisoned")
    }

    /// Returns the latest published immutable runtime snapshot (lock-free).
    pub fn snapshot(&self) -> Arc<RuntimeSnapshot> {
        self.snapshot.load_full()
    }

    /// Returns current runtime status.
    pub fn status(&self) -> RuntimeStatus {
        let snap = self.snapshot.load();
        RuntimeStatus {
            running: self.running.load(Ordering::Acquire),
            listen: self.bound_addr().map(|a| a.to_string()),
            tls: snap.settings.tls,
            active_connections: self.active_conns.load(Ordering::Relaxed),
            last_error: self
                .last_error
                .lock()
                .expect("last_error lock poisoned")
                .clone(),
        }
    }

    /// Hot-applies updated settings: publishes snapshot immediately, and starts,
    /// stops, or restarts the listener only if `enable`/`listen_ip`/`port`/`tls`
    /// changed.
    pub async fn apply(&self, settings: Settings) -> Result<()> {
        let next_key = BindKey {
            listen_ip: settings.listen_ip,
            port: settings.port,
            tls: settings.tls,
        };
        let enable = settings.enable;
        self.snapshot
            .store(Arc::new(RuntimeSnapshot::from_settings(settings)));

        let mut guard = self.listener.lock().await;
        if !enable {
            self.stop_locked(&mut guard).await;
            return Ok(());
        }
        if let Some(active) = guard.as_ref()
            && active.bind_key == next_key
        {
            return Ok(());
        }
        self.stop_locked(&mut guard).await;
        self.start_locked(&mut guard, next_key).await
    }

    /// Forces a listener restart if WebDAV is currently enabled.
    pub async fn restart(&self) -> Result<()> {
        let settings = self.snapshot.load().settings.clone();
        let mut guard = self.listener.lock().await;
        self.stop_locked(&mut guard).await;
        if settings.enable {
            let key = BindKey {
                listen_ip: settings.listen_ip,
                port: settings.port,
                tls: settings.tls,
            };
            self.start_locked(&mut guard, key).await?;
        }
        Ok(())
    }

    /// Stops the listener and gracefully drains connections.
    pub async fn stop(&self) {
        let mut guard = self.listener.lock().await;
        self.stop_locked(&mut guard).await;
    }

    async fn start_locked(&self, guard: &mut Option<ActiveListener>, key: BindKey) -> Result<()> {
        let tls_acceptor = if key.tls {
            match build_tls_acceptor(self.certs.clone()) {
                Ok(acc) => Some(acc),
                Err(err) => {
                    *self.last_error.lock().expect("last_error lock poisoned") =
                        Some(err.to_string());
                    return Err(err);
                }
            }
        } else {
            None
        };

        let bind_ip = key.listen_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let bind_addr = SocketAddr::new(bind_ip, key.port);
        let tcp = match TcpListener::bind(bind_addr).await {
            Ok(l) => l,
            Err(err) => {
                let msg = format!("bind WebDAV listener on {bind_addr}: {err}");
                *self.last_error.lock().expect("last_error lock poisoned") = Some(msg.clone());
                return Err(anyhow!(msg));
            }
        };
        let local_addr = tcp.local_addr().context("query WebDAV bound address")?;

        if let Some(ports) = &self.open_ports {
            ports.set(
                "webdav",
                &[OpenPort {
                    proto: Proto::Tcp,
                    port: local_addr.port(),
                }],
            );
        }

        let cancel = CancellationToken::new();
        let loop_cancel = cancel.clone();
        let handler = Arc::clone(&self.handler);
        let timeouts = self.timeouts;
        let active_conns = Arc::clone(&self.active_conns);

        let task = tokio::spawn(async move {
            accept_loop(
                tcp,
                tls_acceptor,
                handler,
                timeouts,
                active_conns,
                loop_cancel,
            )
            .await;
        });

        *self.last_error.lock().expect("last_error lock poisoned") = None;
        *self.bound_addr.lock().expect("bound addr lock poisoned") = Some(local_addr);
        self.running.store(true, Ordering::Release);

        *guard = Some(ActiveListener {
            addr: local_addr,
            bind_key: key,
            cancel,
            task,
        });
        tracing::info!(listen = %local_addr, tls = key.tls, "WebDAV listener started");
        Ok(())
    }

    async fn stop_locked(&self, guard: &mut Option<ActiveListener>) {
        if let Some(active) = guard.take() {
            active.cancel.cancel();
            let _ = tokio::time::timeout(limits::SHUTDOWN_DEADLINE, active.task).await;
            tracing::info!(listen = %active.addr, "WebDAV listener stopped");
        }
        self.running.store(false, Ordering::Release);
        *self.bound_addr.lock().expect("bound addr lock poisoned") = None;
        if let Some(ports) = &self.open_ports {
            ports.set("webdav", &[]);
        }
    }
}

fn build_tls_acceptor(certs: Option<Arc<dyn ResolvesServerCert>>) -> Result<TlsAcceptor> {
    let resolver =
        certs.ok_or_else(|| anyhow!("TLS enabled but no certificate provider configured"))?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("configure rustls protocol versions")?
    .with_no_client_auth()
    .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

async fn accept_loop(
    listener: TcpListener,
    tls_acceptor: Option<TlsAcceptor>,
    handler: Arc<WebDavHandler>,
    timeouts: RuntimeTimeouts,
    active_conns: Arc<AtomicUsize>,
    cancel: CancellationToken,
) {
    let mut conn_tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let _ = stream.set_nodelay(true);
                        let handler = Arc::clone(&handler);
                        let tls = tls_acceptor.clone();
                        let active = Arc::clone(&active_conns);
                        let conn_cancel = cancel.child_token();
                        conn_tasks.spawn(async move {
                            active.fetch_add(1, Ordering::Relaxed);
                            if let Some(acceptor) = tls {
                                match tokio::time::timeout(timeouts.header_read, acceptor.accept(stream)).await {
                                    Ok(Ok(tls_stream)) => {
                                        serve_connection(tls_stream, peer, handler, timeouts, conn_cancel).await;
                                    }
                                    Ok(Err(err)) => {
                                        tracing::debug!(%peer, error = %err, "WebDAV TLS handshake failed");
                                    }
                                    Err(_) => {
                                        tracing::debug!(%peer, "WebDAV TLS handshake timed out");
                                    }
                                }
                            } else {
                                serve_connection(stream, peer, handler, timeouts, conn_cancel).await;
                            }
                            active.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "WebDAV accept error");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            Some(_) = conn_tasks.join_next(), if !conn_tasks.is_empty() => {}
        }
    }

    // Drain active connections until shutdown deadline.
    let _ = tokio::time::timeout(limits::SHUTDOWN_DEADLINE, async {
        while conn_tasks.join_next().await.is_some() {}
    })
    .await;
    conn_tasks.abort_all();
}

async fn serve_connection<S>(
    stream: S,
    peer: SocketAddr,
    handler: Arc<WebDavHandler>,
    timeouts: RuntimeTimeouts,
    cancel: CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let in_flight = Arc::new(AtomicUsize::new(0));
    let deadline_dirty = Arc::new(AtomicBool::new(true));
    let io = TokioIo::new(IdleTrackedIo::new(
        stream,
        timeouts.idle_keepalive,
        Arc::clone(&in_flight),
        Arc::clone(&deadline_dirty),
    ));

    let svc = service_fn(move |req| {
        let handler = Arc::clone(&handler);
        let guard = InFlightGuard::enter(Arc::clone(&in_flight), Arc::clone(&deadline_dirty));
        async move {
            let resp = handler.handle(req, peer).await;
            let (parts, body) = resp.into_parts();
            let tracked = TrackedBody {
                inner: body,
                _guard: guard,
            };
            Ok::<_, std::convert::Infallible>(Response::from_parts(parts, tracked))
        }
    });

    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(timeouts.header_read)
        .keep_alive(true);

    let conn = builder.serve_connection(io, svc);
    tokio::pin!(conn);
    tokio::select! {
        res = conn.as_mut() => {
            if let Err(err) = res {
                tracing::debug!(%peer, error = %err, "WebDAV connection closed");
            }
        }
        _ = cancel.cancelled() => {
            conn.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(Duration::from_secs(2), conn).await;
        }
    }
}

/// Keeps `in_flight` incremented for the full lifetime of a request + response
/// body so idle keep-alive timeouts only apply *between* requests.
struct InFlightGuard {
    in_flight: Arc<AtomicUsize>,
    deadline_dirty: Arc<AtomicBool>,
}

impl InFlightGuard {
    fn enter(in_flight: Arc<AtomicUsize>, deadline_dirty: Arc<AtomicBool>) -> Self {
        in_flight.fetch_add(1, Ordering::AcqRel);
        Self {
            in_flight,
            deadline_dirty,
        }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.deadline_dirty.store(true, Ordering::Release);
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

struct TrackedBody {
    inner: DavBody,
    _guard: InFlightGuard,
}

impl Body for TrackedBody {
    type Data = <DavBody as Body>::Data;
    type Error = <DavBody as Body>::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Wraps a stream to close idle keep-alive connections cleanly after
/// `idle_timeout` when no request is in flight (`in_flight == 0`).
struct IdleTrackedIo<S> {
    inner: S,
    idle_timeout: Duration,
    in_flight: Arc<AtomicUsize>,
    deadline_dirty: Arc<AtomicBool>,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl<S> IdleTrackedIo<S> {
    fn new(
        inner: S,
        idle_timeout: Duration,
        in_flight: Arc<AtomicUsize>,
        deadline_dirty: Arc<AtomicBool>,
    ) -> Self {
        let sleep = Box::pin(tokio::time::sleep(idle_timeout));
        Self {
            inner,
            idle_timeout,
            in_flight,
            deadline_dirty,
            sleep,
        }
    }

    fn reset_timer(&mut self) {
        self.sleep
            .as_mut()
            .reset(tokio::time::Instant::now() + self.idle_timeout);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for IdleTrackedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let idle = self.in_flight.load(Ordering::Acquire) == 0;
        if idle && self.deadline_dirty.swap(false, Ordering::AcqRel) {
            self.reset_timer();
        }
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    self.reset_timer();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => {
                if idle && self.sleep.as_mut().poll(cx).is_ready() {
                    // Clean EOF causes hyper to close the idle keep-alive connection.
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for IdleTrackedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
