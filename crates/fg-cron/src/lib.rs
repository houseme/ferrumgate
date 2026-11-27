//! WP-62 计划任务（可选模块，feature `cron`）：按 cron 表达式定时执行命令
//! 或发起 HTTP 请求。模块布局与分层遵循 `docs/plan/00-conventions.md` §2，
//! 行为细节见 `docs/plan/WP-62-cron.md`。
//!
//! 装配方式（根包统一接线，本包不进 REGISTRY/bootstrap）：
//!
//! ```ignore
//! let module = fg_cron::Module::new(store, fg_cron::Deps::default())?;
//! let router = module.mount(router);            // 挂到管理路由（/api/cron/…）
//! registry.spawn(module, drain);                 // Module::run 跑调度循环
//! ```
//!
//! HTTP 任务的出站请求默认由内置 reqwest 执行；WP-14/WP-40 的
//! `fg-net::http::OutboundHttp` 就绪后，经 [`Deps::http`] 注入以获得自定义
//! DNS 与出站请求限制。时区暂为 UTC（WP-07 全局设置的时区句柄就绪后接入
//! [`Scheduler`](runtime::Scheduler) 的时钟）。

#![forbid(unsafe_code)]

pub mod exec;
pub mod history;
pub mod model;
pub mod routes;
pub mod runtime;
pub mod schedule;
pub mod validate;

use std::sync::Arc;

use anyhow::{Context, Result};
use fg_config::{ConfigStore, Loaded};
use tokio::sync::{RwLock, watch};

pub use exec::http::HttpExecutor;
pub use history::{History, RunRecord};
pub use model::{FileConfig, HttpTask, Task, TaskKind};
pub use routes::{PersistFn, RecordView, RoutesState, TaskView, mount};
pub use runtime::{NowFn, RunNow, Scheduler};
pub use schedule::{Schedule, ScheduleError, describe, parse};
pub use validate::{Problem, normalize, validate};

/// The module's configuration file (`cron.json`).
pub const CONFIG_NAME: &str = "cron";

/// External capabilities the module needs, injected by the assembler
/// (conventions §3.4). Absent providers fall back to the built-ins.
#[derive(Clone, Default)]
pub struct Deps {
    /// Outbound HTTP runner for `http` tasks (custom DNS, egress
    /// restrictions). `None` uses the built-in reqwest executor.
    pub http: Option<HttpExecutor>,
    /// Injectable clock; `None` uses UTC system time.
    pub clock: Option<runtime::NowFn>,
}

/// The cron module: owns the loaded config, the scheduler and the routes.
/// The assembler calls [`Module::mount`] before running it.
pub struct Module {
    scheduler: Arc<Scheduler>,
    state: Arc<RoutesState>,
}

impl Module {
    /// Loads `cron.json`, normalizes it (problems are logged, not fatal)
    /// and prepares the scheduler plus route state.
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
                "cron.json has a problem; fix it in the management UI"
            );
        }
        let config = Arc::new(RwLock::new(config));
        let scheduler = match deps.clock {
            Some(clock) => Scheduler::with_clock(config.clone(), deps.http, clock),
            None => Scheduler::new(config.clone(), deps.http),
        };
        let scheduler = Arc::new(scheduler);
        let persist_store = Arc::clone(&store);
        let persist: PersistFn = Arc::new(move |config: &FileConfig| {
            persist_store
                .save(CONFIG_NAME, config)
                .map(|_| ())
                .with_context(|| format!("save {CONFIG_NAME}.json"))
        });
        let on_change = scheduler.on_change_handle();
        let state = Arc::new(RoutesState {
            config,
            on_change,
            persist,
            scheduler: Arc::clone(&scheduler),
        });
        Ok(Self { scheduler, state })
    }

    /// Adds the management routes (`/api/cron/…`) to the assembler's
    /// router. Authentication is applied by the surrounding management
    /// router (permission domain `cron`).
    pub fn mount(&self, router: axum::Router) -> axum::Router {
        routes::mount(router, Arc::clone(&self.state))
    }

    /// The scheduler handle (run-now from other tooling, tests).
    pub fn scheduler(&self) -> Arc<Scheduler> {
        Arc::clone(&self.scheduler)
    }
}

impl fg_core::module::Module for Module {
    const ID: &'static str = "cron";

    async fn run(self, drain: watch::Receiver<bool>) -> Result<()> {
        self.scheduler.run(drain).await
    }
}
