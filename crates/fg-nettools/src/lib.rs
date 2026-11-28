//! WP-71 网络诊断（可选模块，feature `nettools`）：Ping、路由追踪、TCP
//! 端口探测、DNS 查询（含 DoH）、下载测速与局域网扫描，全部以后台任务
//! 形式运行（[`jobs::JobRegistry`]），界面轮询输出。行为细节见
//! `docs/plan/WP-71-nettools.md`；ICMP 只使用无特权套接字（决策 D13）。
//!
//! 装配方式（根包统一接线，本包不进 REGISTRY/bootstrap）：
//!
//! ```ignore
//! let module = fg_nettools::Module::new(store, fg_nettools::Deps::default())?;
//! let router = module.mount(router);            // 挂到管理路由（/api/nettools/…）
//! registry.spawn(module, drain);                 // Module::run 等待排空
//! ```
//!
//! [`Deps::dns_servers`] 是 WP-07 全局自定义 DNS 的注入点：DNS 查询的
//! 「服务器留空」与局域网扫描的反解都经它取服务器列表；未注入时在 Unix
//! 上读 `/etc/resolv.conf`，否则要求显式填写。网络诊断不受出站请求限制
//! 约束（其目的就是探测内网），代价是所有写操作需要 `nettools:write`
//! 权限并记审计（WP-71 §3.3）。

#![forbid(unsafe_code)]

pub mod dns_lookup;
pub mod jobs;
pub mod lan_scan;
pub mod model;
pub mod ping;
pub mod port_probe;
pub mod routes;
pub mod speed_test;
pub mod traceroute;
pub mod validate;

use std::sync::Arc;

use anyhow::{Context, Result};
use fg_config::{ConfigStore, Loaded};
use tokio::sync::{RwLock, watch};

pub use jobs::{Caps, JobError, JobRegistry, JobStatus, JobView};
pub use model::{
    DnsParams, FileConfig, LanScanParams, PingParams, PortProbeParams, RecordKind, Settings,
    SpeedParams, Tool, TracerouteParams,
};
pub use routes::{PersistFn, RoutesState, mount};
pub use validate::{Problem, normalize, validate};

/// The module's configuration file (`nettools.json`).
pub const CONFIG_NAME: &str = "nettools";

/// The management-API User-Agent for outbound HTTP (DoH, speed test).
pub const USER_AGENT: &str = concat!(
    "FerrumGate/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/houseme/ferrumgate)"
);

/// External capabilities the module needs, injected by the assembler
/// (conventions §3.4). All providers are optional.
#[derive(Clone, Default)]
pub struct Deps {
    /// Injectable clock for job timestamps (tests); `None` uses system UTC.
    pub clock: Option<jobs::NowFn>,
    /// Global custom DNS servers (WP-07): provider of the resolver list for
    /// the "empty server" DNS case and LAN-scan reverse lookups. `None`
    /// reads `/etc/resolv.conf` on Unix.
    pub dns_servers: Option<dns_lookup::DnsProvider>,
}

/// The nettools module: owns the loaded config, the job registry and the
/// routes. The assembler calls [`Module::mount`] before running it.
pub struct Module {
    registry: Arc<JobRegistry>,
    state: Arc<RoutesState>,
}

impl Module {
    /// Loads `nettools.json`, normalizes it (problems are logged, not
    /// fatal) and prepares the registry plus route state.
    pub fn new(store: Arc<ConfigStore>, deps: Deps) -> Result<Self> {
        let config = match store.load::<FileConfig>(CONFIG_NAME)? {
            Loaded::Found(config) => normalize(config),
            Loaded::Missing => FileConfig::default(),
        };
        for problem in validate(&config) {
            tracing::warn!(
                field = %problem.field,
                reason = %problem.reason,
                "nettools.json has a problem; fix it in the management UI"
            );
        }
        let caps = Caps::from_settings(&config.settings);
        let registry = match deps.clock.clone() {
            Some(clock) => Arc::new(JobRegistry::with_clock(
                caps,
                clock,
                jobs::default_sleeper(),
            )),
            None => Arc::new(JobRegistry::new(caps)),
        };
        let config = Arc::new(RwLock::new(config));
        let persist_store = Arc::clone(&store);
        let persist: PersistFn = Arc::new(move |config: &FileConfig| {
            persist_store
                .save(CONFIG_NAME, config)
                .map(|_| ())
                .with_context(|| format!("save {CONFIG_NAME}.json"))
        });
        let state = Arc::new(RoutesState {
            config,
            registry: Arc::clone(&registry),
            persist,
            dns_servers: deps.dns_servers,
        });
        Ok(Self { registry, state })
    }

    /// Adds the management routes (`/api/nettools/…`) to the assembler's
    /// router. Authentication is applied by the surrounding management
    /// router (permission domain `nettools`).
    pub fn mount(&self, router: axum::Router) -> axum::Router {
        routes::mount(router, Arc::clone(&self.state))
    }

    /// The registry handle (run-now from other tooling, tests).
    pub fn registry(&self) -> Arc<JobRegistry> {
        Arc::clone(&self.registry)
    }
}

impl fg_core::module::Module for Module {
    const ID: &'static str = "nettools";

    /// Nettools keeps no listeners; the run loop only waits for the drain
    /// signal, then cancels the running jobs.
    async fn run(self, mut drain: watch::Receiver<bool>) -> Result<()> {
        loop {
            match drain.changed().await {
                Ok(()) if *drain.borrow() => break,
                Ok(()) => continue,
                Err(_) => break,
            }
        }
        self.registry.cancel_all();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_id_and_config_name_are_stable() {
        assert_eq!(<Module as fg_core::module::Module>::ID, "nettools");
        assert_eq!(CONFIG_NAME, "nettools");
    }

    #[test]
    fn module_loads_missing_config_with_defaults() {
        let store = fg_config::ConfigStore::open(
            &std::env::temp_dir().join(format!("fg-nettools-module-test-{}", std::process::id())),
        )
        .expect("store");
        let module = Module::new(store, Deps::default()).expect("module");
        let caps = module.registry().caps();
        assert_eq!(caps.max_running, 4);
        assert_eq!(caps.max_tasks, 50);
        assert_eq!(caps.task_timeout, std::time::Duration::from_secs(300));
    }

    #[tokio::test]
    async fn module_run_cancels_jobs_on_drain() {
        let store = fg_config::ConfigStore::open(
            &std::env::temp_dir().join(format!("fg-nettools-module-drain-{}", std::process::id())),
        )
        .expect("store");
        let module = Module::new(store, Deps::default()).expect("module");
        let registry = module.registry();
        let id = registry
            .spawn("ping", "drain", move |handle| {
                Box::pin(async move {
                    handle.token().cancelled().await;
                    Ok(())
                }) as jobs::JobFut
            })
            .expect("spawn");
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            use fg_core::module::Module as _;
            module.run(rx).await.expect("run");
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _ = tx.send(true);
        handle.await.expect("task");
        let view = registry.get(&id).expect("job view");
        assert_eq!(view.status, JobStatus::Cancelled);
    }
}
