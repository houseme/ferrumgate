//! WP-44 frp (optional module, Cargo feature `frp`): managed frpc / frps
//! instances — config rendering (Gately model → frp 0.52+ TOML), process
//! hosting via WP-43 fg-proc, proxy ownership and visitor access
//! addresses, the frps port whitelist / subdomain / dashboard / KCP+QUIC
//! ports, the login-source access control gate, and import of legacy INI
//! and current TOML configs. Layout and layering follow
//! `docs/plan/00-conventions.md` §2; behavior details in
//! `docs/plan/WP-44-frp.md`.
//!
//! Assembly (root package wiring; this crate does not join REGISTRY /
//! bootstrap itself):
//!
//! ```ignore
//! let proc = fg_proc::Proc::open(&store, fetch)?;             // WP-43
//! let fw = fg_net::fwopen::Group::new("frp");                 // WP-37 wiring
//! let module = fg_frp::Module::new(store.clone(), fg_frp::Deps {
//!     proc, fetch, fw_open: Some(fw), open_ports, ip_sets, bus: None,
//! })?;
//! let router = module.mount(router);                          // /api/frp/…
//! checks.register("frp", module.self_check(local_ports));     // WP-17
//! registry.spawn(module, drain);                              // Module::run
//! ```
//!
//! `Module::run` owns the instance reconcile loop: one pass at start,
//! reload-triggered passes on every persisted change (only instances with
//! changed rendered configs restart), and a bounded stop of every instance
//! when the drain fires. The loopback login gate (`login_check`) starts on
//! the first reconcile pass.

#![forbid(unsafe_code)]

pub mod access_addr;
pub mod import;
pub mod login_check;
pub mod model;
pub mod routes;
pub mod runtime;
pub mod selfcheck;
pub mod validate;

use std::sync::Arc;

use anyhow::{Context as _, Result};
use fg_config::{ConfigStore, Loaded};
use tokio::sync::{RwLock, watch};

pub use access_addr::{ProxyUrl, UrlKind, proxy_urls};
pub use import::{
    ImportMode, ImportPreview, ImportTarget, apply as apply_import, parse as parse_import,
};
pub use login_check::{Decision, GateHook, LoginGate, SetLookup};
pub use model::{
    Client, ClientAccess, FileConfig, InstallConfig, Protocol, Proxy, ProxyType, QuicTuning,
    Server, Settings, limits,
};
pub use routes::{PersistFn, RoutesState, SettingsView, mount};
pub use runtime::{ExitView, InstanceStatus, Runtime, Summary, firewall_ports};
pub use selfcheck::{FrpCheck, findings};
pub use validate::{
    PluginEndpoint, Problem, normalize, render_client_toml, render_server_toml, validate,
};

/// The module's configuration file (`frp.json`).
pub const CONFIG_NAME: &str = "frp";

/// External capabilities the module needs, injected by the assembler
/// (conventions §3.4). Everything but the `Proc` handle is optional.
pub struct Deps {
    /// Managed-program infrastructure (WP-43).
    pub proc: Arc<fg_proc::Proc>,
    /// Download channel for `install/check` (the same one the assembler
    /// gave `Proc::open`); the installers themselves take theirs from the
    /// `Proc` handle.
    pub fetch: Option<fg_proc::install::HttpGetter>,
    /// WP-37 firewall group (`fwopen::Group::new("frp")`); absent → port
    /// opening is not wired for this build.
    pub fw_open: Option<Arc<fg_net::fwopen::Group>>,
    /// The open-port registry published to the intrusion protection.
    pub open_ports: Option<Arc<fg_net::openports::OpenPorts>>,
    /// Resolves subscribed IP-set keys for the login gate.
    pub ip_sets: Option<SetLookup>,
    /// Event bus for the program-update events (WP-43 auto check).
    pub bus: Option<fg_core::events::EventBus>,
}

/// The frp module: loads `frp.json`, prepares the runtime and the route
/// state. The assembler calls [`Module::mount`] before running it.
pub struct Module {
    runtime: Arc<Runtime>,
    state: Arc<RoutesState>,
    bus: Option<fg_core::events::EventBus>,
}

impl Module {
    /// Loads `frp.json`, normalizes it (problems are logged, not fatal)
    /// and prepares the runtime plus the route state. Does not start any
    /// process — that happens on the first reconcile pass inside
    /// [`Module::run`] (which provides the tokio runtime context the
    /// loopback login gate needs).
    pub fn new(store: Arc<ConfigStore>, deps: Deps) -> Result<Self> {
        let config = match store.load::<FileConfig>(CONFIG_NAME)? {
            Loaded::Found(config) => normalize(config),
            Loaded::Missing => FileConfig::default(),
        };
        let problems = validate(&config);
        for problem in &problems {
            tracing::warn!(
                field = %problem.field,
                reason = %problem.reason,
                "frp.json has a problem; fix it in the management UI"
            );
        }
        let config = Arc::new(RwLock::new(config));
        let runtime = Runtime::open(
            Arc::clone(&config),
            runtime::Deps {
                proc: Arc::clone(&deps.proc),
                fw_open: deps.fw_open.clone(),
                open_ports: deps.open_ports.clone(),
                ip_sets: deps.ip_sets.clone(),
            },
            &store,
        )?;
        let persist_store = Arc::clone(&store);
        let persist: PersistFn = Arc::new(move |config: &FileConfig| {
            persist_store
                .save(CONFIG_NAME, config)
                .map(|_| ())
                .with_context(|| format!("save {CONFIG_NAME}.json"))
        });
        let state = Arc::new(RoutesState {
            config,
            persist,
            runtime: Arc::clone(&runtime),
            proc: Arc::clone(&deps.proc),
            fetch: deps.fetch.clone(),
        });
        Ok(Self {
            runtime,
            state,
            bus: deps.bus,
        })
    }

    /// Adds the management routes (`/api/frp/…`) to the assembler's
    /// router. Authentication is applied by the surrounding management
    /// router (permission domain `frp`).
    pub fn mount(&self, router: axum::Router) -> axum::Router {
        routes::mount(router, Arc::clone(&self.state))
    }

    /// The runtime handle (status readback, tests).
    pub fn runtime(&self) -> Arc<Runtime> {
        Arc::clone(&self.runtime)
    }

    /// The route state handle (tests, custom mounts).
    pub fn routes_state(&self) -> Arc<RoutesState> {
        Arc::clone(&self.state)
    }

    /// The self-check (`frp.ok` / `frp.conflict` / `frp.duplicate`).
    /// `local_ports` is the list of ports Gately itself listens on, wired
    /// by the assembler (WP-17 / WP-11).
    pub fn self_check(&self, local_ports: Vec<u16>) -> FrpCheck {
        FrpCheck {
            runtime: Arc::clone(&self.runtime),
            local_ports,
        }
    }
}

impl fg_core::module::Module for Module {
    const ID: &'static str = "frp";

    async fn run(self, drain: watch::Receiver<bool>) -> Result<()> {
        // The update auto-checker follows install.autoCheck and stops with
        // the same drain as the reconcile loop.
        if let Some(checker) = self.runtime.auto_checker(self.bus.clone()).await {
            tokio::spawn(Arc::new(checker).run(drain.clone()));
        }
        self.runtime.run(drain).await
    }
}
