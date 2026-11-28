//! Active health checks (WP-23 step 4): parameter compilation aligned to
//! the upstream ranges, one-shot probes, and the per-generation monitor
//! whose results — not the passive counter — decide recovery.
#![allow(dead_code)]

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use fg_core::events::{Event, EventBus, Kind};
use futures_util::{StreamExt, stream::FuturesUnordered};
use http_body_util::Empty;
use hyper::{Request, Uri, body::Bytes, header::HOST};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use rustls::{ClientConfig, RootCertStore};
use tokio::{
    net::TcpStream,
    sync::Semaphore,
    time::{sleep, timeout},
};

use super::pool::Pool;
use super::target::{Target, display_url};
use super::{ActiveCheck, CheckMode};
use crate::web::model::Site;

/// Probes in flight at once per generation (mirrors the legacy monitor).
const MAX_CONCURRENT_PROBES: usize = 32;
/// Monitor cadence when no check compiled (probes then change nothing).
const FALLBACK_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckError {
    BadRange(&'static str),
    BadPath(String),
}

impl std::fmt::Display for CheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRange(field) => write!(f, "{field} 超出范围"),
            Self::BadPath(path) => write!(f, "health.path 必须是 / 开头的路径：{path}"),
        }
    }
}

impl std::error::Error for CheckError {}

impl ActiveCheck {
    /// Compiles the check from a site's `health*` fields; `None` when the
    /// site has no check (`health_mode` empty). HTTP checks are demoted to
    /// TCP when the backend receives PROXY protocol (`force_tcp`).
    pub fn compile(site: &Site, force_tcp: bool) -> Result<Option<Self>, CheckError> {
        if site.health_mode.is_empty() {
            return Ok(None);
        }
        let mode = match site.health_mode.as_str() {
            "http" => CheckMode::Http,
            "tcp" => CheckMode::Tcp,
            _ => return Err(CheckError::BadRange("health_mode 必须是 http 或 tcp")),
        };
        let mode = if force_tcp { CheckMode::Tcp } else { mode };
        for (value, field, range) in [
            (site.health_interval_secs, "health.interval_secs", 1..=3600),
            (site.health_timeout_secs, "health.timeout_secs", 1..=60),
            (site.health_fails, "health.fails", 1..=20),
            (site.health_passes, "health.passes", 1..=20),
        ] {
            if !range.contains(&value) {
                return Err(CheckError::BadRange(field));
            }
        }
        if mode == CheckMode::Tcp && !site.health_path.is_empty() {
            return Err(CheckError::BadPath(site.health_path.clone()));
        }
        let path = match mode {
            CheckMode::Tcp => String::new(),
            CheckMode::Http if site.health_path.is_empty() => "/".to_string(),
            CheckMode::Http => {
                let path = site.health_path.clone();
                if !path.starts_with('/') || path.contains('#') {
                    return Err(CheckError::BadPath(path));
                }
                path
            }
        };
        Ok(Some(Self {
            mode,
            path,
            interval: Duration::from_secs(u64::from(site.health_interval_secs)),
            timeout: Duration::from_secs(u64::from(site.health_timeout_secs)),
            fails: site.health_fails,
            passes: site.health_passes,
        }))
    }
}

/// Shared probe client — same stack as the proxy (hyper-util legacy over
/// an HTTPS-capable rustls connector with webpki roots). Reused across
/// probes so connections pool instead of piling up.
type ProbeClient = Client<HttpsConnector<HttpConnector>, Empty<Bytes>>;

fn probe_client() -> &'static ProbeClient {
    static CLIENT: OnceLock<ProbeClient> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("AWS-LC supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(connector);
        Client::builder(TokioExecutor::new()).build(https)
    })
}

/// One HTTP probe: `GET scheme://host:port path`, healthy on status < 400.
/// The probe address carries no credentials (same rule as `display_url`).
async fn probe_http(scheme: &str, host: &str, port: u16, path: &str) -> bool {
    let host_port = format!("{host}:{port}");
    let uri = Uri::builder()
        .scheme(scheme)
        .authority(host_port.as_str())
        .path_and_query(path)
        .build();
    let Ok(uri) = uri else {
        return false;
    };
    let request = Request::builder()
        .header(HOST, host_port.as_str())
        .uri(uri)
        .body(Empty::<Bytes>::new());
    let Ok(request) = request else {
        return false;
    };
    probe_client()
        .request(request)
        .await
        .is_ok_and(|response| response.status().as_u16() < 400)
}

/// One probe against a backend: HTTP `GET path` healthy on status < 400,
/// TCP just a connect. Never panics; transport errors mean unhealthy.
pub async fn probe_once(target: &Target, check: &ActiveCheck) -> bool {
    let uri = &target.uri;
    let Some(authority) = uri.authority() else {
        return false;
    };
    let scheme = uri.scheme_str().unwrap_or("http");
    let host = authority.host();
    let port = authority
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    timeout(check.timeout, async {
        match check.mode {
            CheckMode::Tcp => TcpStream::connect((host.trim_matches(['[', ']']), port))
                .await
                .is_ok(),
            CheckMode::Http => probe_http(scheme, host, port, &check.path).await,
        }
    })
    .await
    .unwrap_or(false)
}

/// Probes every backend in the pool once, at most
/// [`MAX_CONCURRENT_PROBES`] in flight, and feeds [`Pool::mark_probe`].
/// A returned transition is logged and published as `upstream.down` /
/// `upstream.up`, carrying the site key and the backend display address.
pub async fn run_probes_once(pool: &Arc<Pool>, events: &EventBus, site: &str) {
    let Some(check) = pool.check.as_ref() else {
        return; // no active check: mark_probe never transitions, skip the round
    };
    let slots = Semaphore::new(MAX_CONCURRENT_PROBES);
    let mut jobs: FuturesUnordered<_> = pool
        .iter()
        .map(|backend| async {
            let permit = slots.acquire().await.expect("health semaphore stays open");
            let healthy = probe_once(&backend.target, check).await;
            drop(permit);
            let Some(transition) = pool.mark_probe(backend, healthy) else {
                return;
            };
            let url = display_url(&backend.target);
            if transition {
                tracing::info!(site, upstream = %url, "upstream recovered");
                events.publish_with(|| {
                    let mut event = Event::new(Kind::UpstreamUp, "webservice");
                    event.args = vec![("site", site.to_owned()), ("upstream", url)];
                    event
                });
            } else {
                tracing::warn!(site, upstream = %url, "upstream unavailable");
                events.publish_with(|| {
                    let mut event = Event::new(Kind::UpstreamDown, "webservice");
                    event.args = vec![("site", site.to_owned()), ("upstream", url)];
                    event
                });
            }
        })
        .collect();
    while jobs.next().await.is_some() {}
}

/// Per-generation monitor: probes every backend on `interval`, keeps
/// fail/pass streaks (inside [`Pool::mark_probe`]), and logs/publishes the
/// transitions via [`run_probes_once`]. Wired into the serving loop in a
/// later increment; until then it runs as a detached task that only ever
/// stops by being aborted. Every await point is a cancellation point and a
/// probe result is applied atomically after the probe finished, so an
/// abort never leaves a half-applied transition behind.
pub async fn monitor_pool(pool: Arc<Pool>, events: EventBus) {
    let interval = pool
        .check
        .as_ref()
        .map(|check| check.interval)
        .unwrap_or(FALLBACK_INTERVAL);
    loop {
        // The site key arrives with the wiring increment; the placeholder
        // rounds publish an empty site until then.
        run_probes_once(&pool, &events, "").await;
        tokio::select! {
            () = sleep(interval) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::{net::TcpListener, sync::mpsc};

    use super::*;
    use crate::web::upstream::{Policy, parse_target};

    fn site(
        mode: &str,
        path: &str,
        interval: u32,
        timeout_secs: u32,
        fails: u32,
        passes: u32,
    ) -> Site {
        Site {
            health_mode: mode.to_owned(),
            health_path: path.to_owned(),
            health_interval_secs: interval,
            health_timeout_secs: timeout_secs,
            health_fails: fails,
            health_passes: passes,
            ..Site::default()
        }
    }

    fn tcp_check(timeout: Duration) -> ActiveCheck {
        ActiveCheck {
            mode: CheckMode::Tcp,
            path: String::new(),
            interval: Duration::from_secs(1),
            timeout,
            fails: 1,
            passes: 1,
        }
    }

    fn http_check(path: &str, timeout: Duration) -> ActiveCheck {
        ActiveCheck {
            mode: CheckMode::Http,
            path: path.to_owned(),
            interval: Duration::from_secs(1),
            timeout,
            fails: 1,
            passes: 1,
        }
    }

    fn target(addr: SocketAddr) -> Target {
        parse_target(&format!("http://{addr}")).expect("valid target")
    }

    /// An ephemeral port whose listener has been dropped: connecting there
    /// is refused for the rest of the test.
    async fn closed_port() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        addr
    }

    #[test]
    fn compile_ranges() {
        // An empty mode disables the check entirely.
        assert!(matches!(
            ActiveCheck::compile(&site("", "", 10, 3, 3, 2), false),
            Ok(None)
        ));
        // Anything but http/tcp is rejected.
        assert!(ActiveCheck::compile(&site("grpc", "", 10, 3, 3, 2), false).is_err());

        // Boundary values pass.
        let compiled = ActiveCheck::compile(&site("http", "/healthz", 1, 60, 1, 20), false)
            .expect("boundary values compile")
            .expect("check present");
        assert_eq!(compiled.mode, CheckMode::Http);
        assert_eq!(compiled.path, "/healthz");
        assert_eq!(compiled.interval, Duration::from_secs(1));
        assert_eq!(compiled.timeout, Duration::from_secs(60));
        assert_eq!(compiled.fails, 1);
        assert_eq!(compiled.passes, 20);

        for bad in [
            (0, 3, 3, 2),
            (3601, 3, 3, 2),
            (10, 0, 3, 2),
            (10, 61, 3, 2),
            (10, 3, 0, 2),
            (10, 3, 21, 2),
            (10, 3, 3, 0),
            (10, 3, 3, 21),
        ] {
            let (interval, timeout_secs, fails, passes) = bad;
            assert!(
                matches!(
                    ActiveCheck::compile(
                        &site("http", "/", interval, timeout_secs, fails, passes),
                        false
                    ),
                    Err(CheckError::BadRange(_))
                ),
                "out-of-range {bad:?} must be rejected"
            );
        }

        // HTTP defaults the path to "/" and demands origin-form paths.
        let default_path = ActiveCheck::compile(&site("http", "", 10, 3, 3, 2), false)
            .expect("empty path compiles")
            .expect("check present")
            .path;
        assert_eq!(default_path, "/");
        for path in ["healthz", "/a#b"] {
            assert!(
                matches!(
                    ActiveCheck::compile(&site("http", path, 10, 3, 3, 2), false),
                    Err(CheckError::BadPath(_))
                ),
                "path {path:?} must be rejected"
            );
        }

        // TCP rejects a path; PROXY protocol demotes HTTP checks to TCP.
        assert!(matches!(
            ActiveCheck::compile(&site("tcp", "/healthz", 10, 3, 3, 2), false),
            Err(CheckError::BadPath(_))
        ));
        let demoted = ActiveCheck::compile(&site("http", "", 10, 3, 3, 2), true)
            .expect("http + force_tcp compiles")
            .expect("check present");
        assert_eq!(demoted.mode, CheckMode::Tcp);
        assert_eq!(demoted.path, "");
    }

    #[tokio::test]
    async fn probe_tcp() {
        let open = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = open.local_addr().expect("addr");
        let check = tcp_check(Duration::from_secs(1));
        assert!(probe_once(&target(addr), &check).await);

        let closed = closed_port().await;
        assert!(!probe_once(&target(closed), &check).await);
    }

    #[tokio::test]
    async fn probe_http() {
        let app = axum::Router::new()
            .route(
                "/",
                axum::routing::get(|| async { axum::http::StatusCode::OK }),
            )
            .route(
                "/fail",
                axum::routing::get(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }),
            )
            .route(
                "/slow",
                axum::routing::get(|| async {
                    sleep(Duration::from_millis(300)).await;
                    axum::http::StatusCode::OK
                }),
            );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        assert!(
            probe_once(&target(addr), &http_check("/", Duration::from_secs(2))).await,
            "200 is healthy"
        );
        assert!(
            !probe_once(&target(addr), &http_check("/fail", Duration::from_secs(2))).await,
            "500 is unhealthy"
        );
        assert!(
            !probe_once(
                &target(addr),
                &http_check("/slow", Duration::from_millis(50))
            )
            .await,
            "a response slower than the timeout is unhealthy"
        );
    }

    #[tokio::test]
    async fn run_probes_once_publishes() {
        let closed = closed_port().await;
        // Held open for the whole test: connects succeed without accepting.
        let open = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let up = open.local_addr().expect("addr");

        let pool = Arc::new(
            Pool::compile(
                vec![target(closed), target(up)],
                Policy::default(),
                Some(tcp_check(Duration::from_secs(1))),
            )
            .expect("valid pool"),
        );
        let events = EventBus::default();
        let (send, mut receive) = mpsc::unbounded_channel();
        let _subscription = events
            .subscribe(move |event| {
                send.send(event).expect("receiver alive");
                std::future::ready(())
            })
            .expect("subscribe");

        run_probes_once(&pool, &events, "app.test").await;

        let down = receive.recv().await.expect("down event");
        assert_eq!(down.kind, Kind::UpstreamDown);
        assert_eq!(down.module, "webservice");
        assert_eq!(
            down.args,
            [
                ("site", "app.test".to_owned()),
                ("upstream", format!("http://{closed}"))
            ]
        );
        assert!(
            receive.try_recv().is_err(),
            "the healthy backend must not publish a transition"
        );

        // The closed port reopens: the next round recovers the backend.
        let revived = TcpListener::bind(closed).await.expect("rebind");
        run_probes_once(&pool, &events, "app.test").await;
        let up_event = receive.recv().await.expect("up event");
        assert_eq!(up_event.kind, Kind::UpstreamUp);
        assert_eq!(
            up_event.args,
            [
                ("site", "app.test".to_owned()),
                ("upstream", format!("http://{closed}"))
            ]
        );
        drop(open);
        drop(revived);
    }
}
