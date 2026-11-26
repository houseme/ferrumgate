use std::time::Duration;

use anyhow::{Result, ensure};
use fg_core::events::{Event, EventBus, Kind};
use futures_util::{StreamExt, stream::FuturesUnordered};
use hyper::{Request, Uri, Version, body::Bytes, header::HOST, http::uri::PathAndQuery};
use serde::Deserialize;
use tokio::{
    net::TcpStream,
    sync::Semaphore,
    time::{sleep, timeout},
};

use crate::{
    backend::Backend,
    config::{ProxyRoute, RouteAction, Routes},
    proxy::Proxy,
};

const MAX_CONCURRENT_PROBES: usize = 32;

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
    #[default]
    Http,
    Tcp,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct RawHealthCheck {
    mode: Mode,
    path: Option<String>,
    interval_secs: u64,
    timeout_secs: u64,
    fails: u8,
    passes: u8,
}

impl Default for RawHealthCheck {
    fn default() -> Self {
        Self {
            mode: Mode::Http,
            path: None,
            interval_secs: 10,
            timeout_secs: 3,
            fails: 3,
            passes: 2,
        }
    }
}

pub(crate) struct HealthCheck {
    path: Option<PathAndQuery>,
    interval: Duration,
    timeout: Duration,
    fails: i8,
    passes: i8,
}

impl HealthCheck {
    pub fn compile(config: RawHealthCheck) -> Result<Self> {
        ensure!(
            (1..=3600).contains(&config.interval_secs),
            "health.interval_secs must be in 1..=3600"
        );
        ensure!(
            (1..=60).contains(&config.timeout_secs),
            "health.timeout_secs must be in 1..=60"
        );
        ensure!(
            (1..=20).contains(&config.fails) && (1..=20).contains(&config.passes),
            "health.fails and health.passes must be in 1..=20"
        );
        let path = match config.mode {
            Mode::Tcp => {
                ensure!(config.path.is_none(), "health.path is only for HTTP");
                None
            }
            Mode::Http => {
                let path = config.path.as_deref().unwrap_or("/");
                ensure!(
                    path.starts_with('/') && !path.contains('#'),
                    "health.path must be an origin-form path"
                );
                Some(
                    path.parse::<PathAndQuery>()
                        .map_err(|_| anyhow::anyhow!("invalid health.path"))?,
                )
            }
        };
        Ok(Self {
            path,
            interval: Duration::from_secs(config.interval_secs),
            timeout: Duration::from_secs(config.timeout_secs),
            fails: config.fails as i8,
            passes: config.passes as i8,
        })
    }
}

pub(crate) async fn monitor(proxy: &Proxy, routes: &Routes, events: &EventBus) {
    let slots = Semaphore::new(MAX_CONCURRENT_PROBES);
    let mut jobs = FuturesUnordered::new();
    for (host, route) in routes.iter() {
        if let RouteAction::Proxy(route) = &route.action
            && let Some(check) = &route.health
        {
            for backend in route.backends.iter() {
                jobs.push(run_check(
                    proxy, host, route, backend, check, &slots, events,
                ));
            }
        }
    }
    while jobs.next().await.is_some() {}
}

async fn run_check(
    proxy: &Proxy,
    host: &str,
    route: &ProxyRoute,
    backend: &Backend,
    check: &HealthCheck,
    slots: &Semaphore,
    events: &EventBus,
) {
    let mut streak = 0i8;
    loop {
        let slot = slots.acquire().await.expect("health semaphore stays open");
        let healthy = timeout(check.timeout, async {
            if let Some(path) = &check.path {
                let uri = Uri::builder()
                    .scheme(backend.scheme.clone())
                    .authority(backend.authority.clone())
                    .path_and_query(path.clone())
                    .build()
                    .expect("validated probe URI");
                let request = Request::builder()
                    .uri(uri)
                    .version(if route.upstream_h2c {
                        Version::HTTP_2
                    } else {
                        Version::HTTP_11
                    })
                    .header(HOST, backend.host.clone())
                    .body(http_body_util::Either::Right(
                        http_body_util::Empty::<Bytes>::new(),
                    ))
                    .expect("validated probe request");
                proxy.probe_http(request, route.upstream_h2c).await
            } else {
                let address = backend.authority.host().trim_matches(['[', ']']);
                let port = backend.authority.port_u16().unwrap_or(
                    if backend.scheme == hyper::http::uri::Scheme::HTTPS {
                        443
                    } else {
                        80
                    },
                );
                TcpStream::connect((address, port)).await.is_ok()
            }
        })
        .await
        .unwrap_or(false);
        drop(slot);

        let changed = if healthy {
            streak = (streak.max(0) + 1).min(check.passes);
            streak == check.passes && backend.mark_active(true)
        } else {
            streak = (streak.min(0) - 1).max(-check.fails);
            streak == -check.fails && backend.mark_active(false)
        };
        if changed {
            let kind = if healthy {
                tracing::info!(site = host, backend = %backend.authority, "upstream recovered");
                Kind::UpstreamUp
            } else {
                tracing::warn!(site = host, backend = %backend.authority, "upstream unavailable");
                Kind::UpstreamDown
            };
            events.publish_with(|| {
                let mut event = Event::new(kind, "webservice");
                event.args = vec![
                    ("site", host.to_owned()),
                    ("upstream", backend.authority.to_string()),
                ];
                event
            });
        }
        sleep(check.interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use tokio::{net::TcpListener, sync::mpsc};

    #[tokio::test]
    async fn active_health_transitions_publish_loopback_events() -> Result<()> {
        let reserved = TcpListener::bind("127.0.0.1:0").await?;
        let upstream = reserved.local_addr()?;
        drop(reserved);
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("health.toml");
        std::fs::write(
            &path,
            format!(
                r#"
schema_version = 1
[[routes]]
host = "app.test"
upstream = "http://{upstream}"
[routes.health]
mode = "tcp"
interval_secs = 1
fails = 1
passes = 1
"#
            ),
        )?;
        let config = config::load(&path, std::sync::Arc::default()).await?;
        let proxy = Proxy::new(config.routes, &config.settings, config.tls.client);
        let events = EventBus::default();
        let (send, mut receive) = mpsc::unbounded_channel();
        let _subscription = events.subscribe(move |event| {
            send.send(event).unwrap();
            std::future::ready(())
        })?;
        let transitions = async {
            let down = receive.recv().await.expect("down event");
            assert_eq!(down.kind, Kind::UpstreamDown);
            assert_eq!(down.module, "webservice");
            assert_eq!(
                down.args,
                [
                    ("site", "app.test".into()),
                    ("upstream", upstream.to_string())
                ]
            );
            let _origin = TcpListener::bind(upstream).await?;
            let up = receive.recv().await.expect("up event");
            assert_eq!(up.kind, Kind::UpstreamUp);
            assert_eq!(up.args, down.args);
            Ok(())
        };
        timeout(Duration::from_secs(4), async {
            tokio::select! {
                () = proxy.monitor_health(&events) => anyhow::bail!("health monitor stopped"),
                result = transitions => result,
            }
        })
        .await?
    }
}
