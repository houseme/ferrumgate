use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use fg_core::{events::EventBus, module::Module, registry::Registry};
use tokio::{net::TcpListener, sync::watch, task::JoinSet, time::timeout};

use crate::{
    acme::Managed,
    certs::Certificates,
    config::{self, Config, milliseconds},
    l4::L4,
    proxy::Proxy,
    source_policy::SourcePolicy,
    tls::ServerTls,
    web::Web,
};

pub(crate) const REGISTRY: Registry = Registry::new(&[L4::ID, Certificates::ID, Web::ID]);

pub(crate) struct Generation {
    pub proxy: Proxy,
    pub tls: Option<ServerTls>,
    pub forward_sources: Vec<SourcePolicy>,
}

impl Generation {
    fn new(config: Config) -> Self {
        Self {
            proxy: Proxy::new(config.routes, &config.settings, config.tls.client),
            tls: config.tls.server,
            forward_sources: config
                .tcp_forward
                .into_iter()
                .map(|rule| rule.source)
                .chain(config.udp_forward.into_iter().map(|rule| rule.source))
                .collect(),
        }
    }
}

/// Run the configured data plane until a process shutdown signal arrives.
pub async fn serve(path: PathBuf) -> Result<()> {
    let managed = Arc::new(Managed::default());
    let config = config::load(&path, managed.clone()).await?;
    let enabled = REGISTRY.resolve_enabled(&config.disabled_modules, false);
    for module in &enabled.restored {
        tracing::warn!(module = module.id, required_by = ?module.by, "required module kept enabled");
    }
    let settings = config.settings.clone();
    let acme_config = config.acme.clone();
    let certificates = match &acme_config {
        Some(acme) if enabled.contains(Certificates::ID) => Some(
            Certificates::prepare(acme.clone(), managed.clone())
                .await
                .context("prepare ssl")?,
        ),
        _ => None,
    };

    #[cfg(unix)]
    let (mut interrupt, mut terminate, mut hangup) = {
        use tokio::signal::unix::{SignalKind, signal};

        (
            signal(SignalKind::interrupt())?,
            signal(SignalKind::terminate())?,
            signal(SignalKind::hangup())?,
        )
    };
    let interrupt = async {
        #[cfg(unix)]
        {
            interrupt.recv().await;
            Ok(())
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c().await
    };
    tokio::pin!(interrupt);
    let termination = async {
        #[cfg(unix)]
        terminate.recv().await;
        #[cfg(not(unix))]
        std::future::pending::<()>().await;
    };
    tokio::pin!(termination);

    // Bind every enabled listener before starting any task.
    let http = if enabled.contains(Web::ID) && settings.http_enabled {
        Some(
            TcpListener::bind(settings.listen)
                .await
                .context("bind business listener")?,
        )
    } else {
        None
    };
    let http_addr = http.as_ref().map(TcpListener::local_addr).transpose()?;
    let tcp_rules = config.tcp_forward.clone();
    let udp_rules = config.udp_forward.clone();
    #[cfg(unix)]
    let disabled_modules = config.disabled_modules.clone();

    let state = Arc::new(ArcSwap::from_pointee(Generation::new(config)));
    let (publications, generations) = watch::channel(state.load_full());
    let l4 = if enabled.contains(L4::ID) {
        Some(
            L4::prepare(
                &tcp_rules,
                &udp_rules,
                settings.metrics_listen,
                state.clone(),
            )
            .await
            .context("prepare portforward")?,
        )
    } else {
        None
    };
    let ready_addr = if let Some(addr) = http_addr {
        Some(addr)
    } else if let Some(l4) = &l4 {
        l4.first_addr()?
    } else {
        None
    };
    let metrics_addr = l4.as_ref().map(L4::metrics_addr).transpose()?.flatten();

    let (drain, drain_rx) = watch::channel(false);
    let mut modules = JoinSet::new();
    if let Some(certificates) = certificates {
        start(certificates, drain_rx.clone(), &mut modules);
    }
    if let Some(listener) = http {
        let web = Web {
            listener,
            settings: settings.clone(),
            state: state.clone(),
            generations,
            events: EventBus::default(),
        };
        start(web, drain_rx.clone(), &mut modules);
    }
    if let Some(l4) = l4 {
        start(l4, drain_rx, &mut modules);
    }
    tracing::info!(
        listen = ready_addr.map(tracing::field::display),
        http = http_addr.is_some(),
        tls = http_addr.is_some() && settings.tls,
        metrics_listen = metrics_addr.map(tracing::field::display),
        "gateway ready"
    );

    let reload = async {
        #[cfg(unix)]
        while hangup.recv().await.is_some() {
            let candidate = async {
                let next = config::load(&path, managed.clone()).await?;
                anyhow::ensure!(
                    next.settings == settings
                        && next.disabled_modules == disabled_modules
                        && next.tcp_forward.len() == tcp_rules.len()
                        && next
                            .tcp_forward
                            .iter()
                            .zip(&tcp_rules)
                            .all(|(next, current)| next.same_startup(current))
                        && next.udp_forward.len() == udp_rules.len()
                        && next
                            .udp_forward
                            .iter()
                            .zip(&udp_rules)
                            .all(|(next, current)| next.same_startup(current))
                        && next.acme == acme_config,
                    "server, forwarding, ACME, and module settings require restart"
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

        // Hold the sender for the module lifetime on platforms without SIGHUP.
        let _publications = &publications;
        std::future::pending::<()>().await;
    };

    let shutdown_result: std::io::Result<()> = {
        tokio::pin!(reload);
        loop {
            tokio::select! {
                biased;
                result = &mut interrupt => break result,
                _ = &mut termination => break Ok(()),
                _ = &mut reload => unreachable!(),
                Some(result) = modules.join_next(), if !modules.is_empty() => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "module task failed");
                    }
                }
            }
        }
    };

    drain.send_replace(true);
    tracing::info!("gateway draining connections");
    if timeout(milliseconds(settings.shutdown_timeout_ms), async {
        while modules.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tracing::warn!("drain deadline expired");
        modules.shutdown().await;
    }
    shutdown_result.context("wait for shutdown signal")
}

fn start<M: Module>(module: M, drain: watch::Receiver<bool>, tasks: &mut JoinSet<()>) {
    tasks.spawn(async move {
        if let Err(error) = module.run(drain).await {
            tracing::warn!(module = M::ID, %error, "module failed");
        }
    });
}
