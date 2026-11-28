//! WP-40 动态域名（可选模块，feature `ddns`）：家庭宽带的公网 IP 变化后
//! 自动更新 DNS 解析。`ddns.json` 的模型与校验、三种 IP 获取方式（URL /
//! 网卡 / 命令）、任务调度与失败退避、记录值变量（`{ipv4Addr}`、
//! `{ipv6Addr}`、`{STUN_…}`）、Webhook、批量添加记录、自检与管理接口，
//! 经 `fg-dns` 适配项（[`fg_dns::DnsProvider::upsert`]）更新解析记录。
//! 模块布局与分层遵循 `docs/plan/00-conventions.md` §2，行为细节见
//! `docs/plan/WP-40-ddns.md`。
//!
//! 装配方式（根包统一接线，本包不进 REGISTRY/bootstrap）：
//!
//! ```ignore
//! let module = fg_ddns::Module::new(store, fg_ddns::Deps::default())?;
//! let router = module.mount(router);           // 挂到管理路由（/api/ddns/…）
//! let checks = module.check(resolve);          // 注册 SelfCheck
//! registry.spawn(module, drain);               // Module::run 跑调度循环
//! ```
//!
//! `Deps` 里可注入的能力（约定 §3.4）：STUN 变量查询、事件总线
//! （`ddns.changed` / `ddns.failed` 与 `stun.changed` 订阅）、远端删除
//! 钩子（`fg_dns::delete` 的 `Deleter` trait 无法从装箱的
//! `DnsProvider` 取出，由装配层提供闭包）与测试用时钟。DNS 提供商
//! feature（`dns-*`）未启用时注册表为空，`GET /api/ddns/providers` 会把
//! 这些适配项标记为 `available: false`。

#![forbid(unsafe_code)]

pub mod batch_add;
pub mod ip_source;
pub mod model;
pub mod remote;
pub mod routes;
pub mod runtime;
pub mod selfcheck;
pub mod validate;
pub mod vars;
pub mod webhook;

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use fg_config::{ConfigStore, Loaded};
use tokio::sync::{RwLock, watch};

pub use model::{
    Credentials, FileConfig, IpSource, IpSourceKind, Record, RecordType, Settings, Task,
    WebhookConfig,
};
pub use remote::{build_record, effective_ttl, remark_for};
pub use routes::{PersistFn, RoutesState, TaskView, mount};
pub use runtime::{
    DeleteRemoteFn, Deps, NowFn, ProviderNew, RecordOutcome, RecordState, RoundOutcome, Scheduler,
    StunLookup, SyncNow, TaskState, TaskStatus, next_check_delay, perform_round,
};
pub use selfcheck::{DdnsCheck, ResolveFn};
pub use validate::{Problem, merge_credentials, normalize, validate};
pub use vars::{StunPart, StunValue, ValueCtx, VarError, expand_value};

/// The module's configuration file (`ddns.json`).
pub const CONFIG_NAME: &str = model::FILE_NAME;

/// The DDNS module: owns the loaded config, the scheduler and the routes.
/// The assembler creates it after the config store (and event bus) exist,
/// mounts [`Module::mount`] under the management router, registers
/// [`Module::check`] and hands the module to the registry.
pub struct Module {
    scheduler: Arc<Scheduler>,
    state: Arc<RoutesState>,
}

impl Module {
    /// Loads `ddns.json` (missing file → defaults), normalizes it and
    /// prepares the scheduler plus route state. Tasks whose validation
    /// fails at load time are listed in their status (`loadErr`) and
    /// never started; the problems clear on the next save through the
    /// management API.
    pub fn new(store: Arc<ConfigStore>, deps: Deps) -> Result<Self> {
        let config = match store.load::<FileConfig>(CONFIG_NAME)? {
            Loaded::Found(config) => normalize(config),
            Loaded::Missing => FileConfig::default(),
        };
        let problems = validate(&config);
        let mut load_errors: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for problem in &problems {
            tracing::warn!(
                field = %problem.field,
                reason = %problem.reason,
                "ddns.json has a problem; fix it in the management UI"
            );
            // Field paths look like `tasks.<key>…` / `tasks.<name>…`.
            let task_key = problem
                .field
                .strip_prefix("tasks.")
                .and_then(|rest| rest.split(['.', ' ']).next())
                .unwrap_or_default()
                .to_owned();
            if !task_key.is_empty() {
                load_errors
                    .entry(task_key)
                    .or_default()
                    .push(format!("{}：{}", problem.field, problem.reason));
            }
        }
        let config = Arc::new(RwLock::new(config));
        let scheduler = Arc::new(Scheduler::with_load_errors(
            config.clone(),
            deps.clone(),
            load_errors,
        ));
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
            scheduler: Arc::clone(&scheduler),
            persist,
            on_change,
            delete_remote: deps.delete_remote.clone(),
        });
        Ok(Self { scheduler, state })
    }

    /// Adds the management routes (`/api/ddns/…`) to the assembler's
    /// router. Authentication is applied by the surrounding management
    /// router (permission domain `ddns`).
    pub fn mount(&self, router: axum::Router) -> axum::Router {
        routes::mount(router, Arc::clone(&self.state))
    }

    /// The scheduler handle (run-now from other tooling, tests).
    pub fn scheduler(&self) -> Arc<Scheduler> {
        Arc::clone(&self.scheduler)
    }

    /// The live desired config snapshot (already normalized once loaded).
    pub fn config(&self) -> Arc<RwLock<FileConfig>> {
        Arc::clone(&self.state.config)
    }

    /// The self-check: compares each A/AAAA record's current DNS
    /// resolution with its last synced value (`ddns.match` /
    /// `ddns.mismatch` / `ddns.unresolved`). The resolver is injected by
    /// the assembler; without one every record reports unresolved.
    pub fn check(&self, resolve: Option<ResolveFn>) -> DdnsCheck {
        DdnsCheck {
            scheduler: Arc::clone(&self.scheduler),
            resolve,
        }
    }
}

impl fg_core::module::Module for Module {
    const ID: &'static str = "ddns";

    /// Runs the scheduler until the drain signal: a loop per enabled task
    /// (first round after the startup delay), restarted on config changes,
    /// with the shutdown deadline applied to in-flight rounds.
    async fn run(self, drain: watch::Receiver<bool>) -> Result<()> {
        self.scheduler.run(drain).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fg_core::module::Module as _;

    #[tokio::test]
    async fn module_loads_missing_config_and_runs_drain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ConfigStore::open(dir.path()).expect("store");
        let module = Module::new(Arc::clone(&store), Deps::default()).expect("module");
        assert_eq!(<Module as fg_core::module::Module>::ID, "ddns");
        let (drain_tx, drain_rx) = watch::channel(false);
        let handle = tokio::spawn(module.run(drain_rx));
        // The module runs until the drain fires; no task exists, so it
        // simply waits.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drain_tx.send(true).expect("drain");
        handle.await.expect("run").expect("ok");
    }

    #[test]
    fn module_marks_load_errors_and_keeps_tasks_listed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ConfigStore::open(dir.path()).expect("store");
        let config = FileConfig {
            settings: Settings {
                enable: true,
                ..Settings::default()
            },
            tasks: vec![Task {
                key: "task00000001".into(),
                name: "broken".into(),
                enable: true,
                provider: "cloudflare".into(),
                credentials: Credentials::default(),
                ..Task::default()
            }],
        };
        store.save(CONFIG_NAME, &config).expect("save");
        let module = Module::new(Arc::clone(&store), Deps::default()).expect("module");
        let errors = module.scheduler().load_errors("task00000001");
        assert!(
            errors
                .iter()
                .any(|error| error.contains("credentials.secret")),
            "{errors:?}"
        );
    }
}
