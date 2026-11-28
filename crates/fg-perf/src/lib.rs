//! WP-69 性能监控（可选模块，feature `perf`）：把主机、FerrumGate 进程、
//! 托管进程与各站点的性能数据汇总展示，并在指标持续超过阈值时经事件总线
//! 发布 `perf.alert` / `perf.recovered` 通知。
//!
//! 布局与分层遵循 `docs/plan/00-conventions.md` §2，行为细节见
//! `docs/plan/WP-69-perf.md`。
//!
//! 装配方式（根包统一接线）：
//!
//! ```ignore
//! let module = fg_perf::Module::new(store, events, fg_perf::Deps { .. })?;
//! let router = module.mount(router);       // 挂到管理路由（/api/perf/…）
//! let service = module.service();          // 供指标导出与站点改名回调
//! registry.spawn(module, drain);           // Module::run 每 5 秒采样并评估
//! ```

#![forbid(unsafe_code)]

pub mod alerts;
pub mod history;
pub mod model;
pub mod procs;
pub mod routes;
pub mod runtime;
pub mod series;
pub mod validate;

use std::{sync::Arc, time::SystemTime};

use anyhow::{Context as _, Result};
use fg_config::{ConfigStore, Loaded};
use fg_core::events::EventBus;
use tokio::sync::{RwLock, watch};

pub use alerts::{
    ActiveAlert, AlertEvent, AlertState, Evaluator, Readings, RecoverReason, RuleChange,
    SiteReading,
};
pub use history::{ExtraMetric, History, ProcPoint, ProcValues, Sample, SiteValues, Values};
pub use model::{AlertRule, CmpOp, FileConfig, Level, Metric, Window, limits, presets};
pub use procs::{ProcHandle, ProcTracker, ProcView, RawProc, RawReader, sys_reader};
pub use routes::{RoutesState, mount};
pub use runtime::{
    ActiveAlertView, AlertsSummary, BackendSnapshot, Clock, Deps, ManagedProcsReader, OverviewView,
    PerfService, PersistFn, ProcessRowView, ProcessesView, SiteSnapshot, SiteStatsReader, SiteView,
};
pub use series::{Point, Series};
pub use validate::{
    Problem, normalize, normalize_rule, random_key, semantic_eq, valid_key, validate,
};

/// Module identifier registered in `fg_core::module::Module::ID`.
pub const MODULE_ID: &str = "perf";

/// Configuration file stem (`perf.json`).
pub const CONFIG_NAME: &str = model::FILE_NAME;

/// Default 5-second sampling and evaluation interval (WP-69 §3.2).
pub const SAMPLE_INTERVAL: std::time::Duration = limits::SAMPLE_INTERVAL;

/// Number of samples in the 60-second short ring (`60s / 5s = 12`).
pub const SHORT_SLOTS: usize = limits::SHORT_SLOTS;

/// Formats a [`SystemTime`] as UTC RFC 3339 (conventions §3.5).
pub fn rfc3339(time: SystemTime) -> String {
    time::OffsetDateTime::from(time)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

/// The performance monitoring module: owns the loaded `perf.json`,
/// [`PerfService`] and route state.
pub struct Module {
    service: Arc<PerfService>,
    state: Arc<RoutesState>,
}

impl Module {
    /// Loads `perf.json` (missing file → empty rule list), normalizes it,
    /// logs any validation problems so the UI can repair them, and prepares
    /// [`PerfService`] and the management routes.
    pub fn new(store: Arc<ConfigStore>, events: EventBus, mut deps: Deps) -> Result<Self> {
        let config = match store.load::<FileConfig>(CONFIG_NAME)? {
            Loaded::Found(config) => normalize(config),
            Loaded::Missing => FileConfig::default(),
        };
        for problem in validate(&config) {
            tracing::warn!(
                field = %problem.field,
                reason = %problem.reason,
                "perf.json has a problem; fix it in the management UI"
            );
        }
        if deps.config_mount.is_none() {
            deps.config_mount = Some(store.dir().to_path_buf());
        }
        let initial_rules = config.rules.clone();
        let config = Arc::new(RwLock::new(config));
        let persist_store = Arc::clone(&store);
        let persist: PersistFn = Arc::new(move |config: &FileConfig| {
            persist_store
                .save(CONFIG_NAME, config)
                .map(|_| ())
                .with_context(|| format!("save {CONFIG_NAME}.json"))
        });
        let service = PerfService::new(config, &initial_rules, persist, events, deps);
        let state = Arc::new(RoutesState {
            service: Arc::clone(&service),
        });
        Ok(Self { service, state })
    }

    /// Mounts the management routes (`/api/perf/…`) onto `router`.
    pub fn mount(&self, router: axum::Router) -> axum::Router {
        routes::mount(router, Arc::clone(&self.state))
    }

    /// Handle to the underlying [`PerfService`] (for Prometheus scrapes,
    /// site-rename hooks, `site_removed`, or tests).
    pub fn service(&self) -> Arc<PerfService> {
        Arc::clone(&self.service)
    }

    /// Live desired `perf.json` configuration.
    pub fn config(&self) -> Arc<RwLock<FileConfig>> {
        self.service.config()
    }
}

impl fg_core::module::Module for Module {
    const ID: &'static str = MODULE_ID;

    async fn run(self, drain: watch::Receiver<bool>) -> Result<()> {
        tracing::info!(module = MODULE_ID, "starting perf sampling loop");
        self.service.run_loop(drain).await;
        tracing::info!(module = MODULE_ID, "stopped perf sampling loop");
        Ok(())
    }
}
