#![forbid(unsafe_code)]

//! Protocol routing module (`protoroute`, WP-35): multiplexes multiple TCP
//! application protocols (TLS by SNI/ALPN, HTTP by Host, Minecraft by server
//! address, SSH, RDP, SOCKS, OpenVPN, SPA port-knock packets, timeout
//! server-speaks-first protocols, and more) onto a shared public port with
//! zero-loss transparent passthrough.

pub mod model;
pub mod router;
pub mod routes;
pub mod runtime;
pub mod sniff;
pub mod validate;

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::Router;
use fg_config::{ConfigStore, Loaded};
use fg_core::metrics::Sample;
use fg_net::fwopen;
use fg_net::openports::OpenPorts;
use fg_net::source_rule::BanCheck;
use tokio::sync::watch;

use crate::model::FileConfig;
use crate::routes::{CONFIG_NAME, Summary};
use crate::runtime::Manager;

/// External capability supplied by the optional port-knock module (WP-54).
pub trait KnockProvider: Send + Sync {
    /// Returns whether `peer` currently holds a live knock grant for `rule_key`.
    fn is_open(&self, rule_key: &str, peer: IpAddr) -> bool;

    /// Hands a captured SPA knock packet received over TCP to the knock module.
    fn handle_spa(&self, peer: IpAddr, listen_port: u16, packet: &[u8]);
}

/// External capabilities injected by the host binary (conventions §3.4).
#[derive(Clone, Default)]
pub struct Deps {
    /// Optional port-knock provider (absent when the knock module is not compiled in).
    pub knock: Option<Arc<dyn KnockProvider>>,
    /// Shared live ban table checked before source allow/deny lists.
    pub ban: Option<Arc<dyn BanCheck>>,
    /// Automatic firewall opener group (`protoroute`).
    pub fw_open: Option<Arc<fwopen::Group>>,
    /// Shared open-port registry (`protoroute` owner).
    pub open_ports: Option<Arc<OpenPorts>>,
    /// Optional log handle from the host logging pipeline.
    pub logs: Option<fg_logging::LogHandle>,
}

/// The prepared `protoroute` module implementing [`fg_core::module::Module`].
pub struct Module {
    store: Arc<ConfigStore>,
    manager: Arc<Manager>,
}

impl Module {
    /// Loads `protoroute.json` (or defaults when absent), normalizes it, and
    /// prepares the runtime manager without starting listeners yet.
    pub fn new(store: Arc<ConfigStore>, deps: Deps) -> Result<Self> {
        let config = match store.load::<FileConfig>(CONFIG_NAME)? {
            Loaded::Found(cfg) => cfg,
            Loaded::Missing => FileConfig::default(),
        };
        let manager = Arc::new(Manager::new(config, deps));
        Ok(Self { store, manager })
    }

    /// Handle to the runtime manager for status, hot-reloads, and tests.
    pub fn manager(&self) -> Arc<Manager> {
        Arc::clone(&self.manager)
    }

    /// Management API router mounting `/api/protoroute/*`.
    pub fn router(&self) -> Router {
        routes::router(Arc::clone(&self.store), Arc::clone(&self.manager))
    }

    /// Overview summary of rules, listeners, and counters.
    pub async fn summary(&self) -> Summary {
        routes::summary(&self.manager).await
    }

    /// Prometheus samples (`ferrumgate_protoroute_*`) for `/api/metrics`.
    pub async fn metrics(&self) -> Vec<Sample> {
        routes::metrics(&self.manager).await
    }

    /// TCP ports currently carrying an enabled `spa` route.
    pub async fn spa_ports(&self) -> Vec<u16> {
        self.manager.spa_ports().await
    }
}

impl fg_core::module::Module for Module {
    const ID: &'static str = "protoroute";

    async fn run(self, mut drain: watch::Receiver<bool>) -> Result<()> {
        self.manager.start().await?;
        if !*drain.borrow() {
            let _ = drain.wait_for(|&draining| draining).await;
        }
        self.manager.shutdown().await;
        Ok(())
    }
}
