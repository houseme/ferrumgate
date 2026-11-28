//! WP-66 File Browser（可选模块，feature `filebrowser`）：托管 FileBrowser
//! Quantum（`gtsteffaniak/filebrowser`；原版已归档）。模块布局与分层遵循
//! `docs/plan/00-conventions.md` §2，行为细节见 `docs/plan/WP-66-filebrowser.md`。
//!
//! 装配方式（根包统一接线，本包不进 REGISTRY/bootstrap）：
//!
//! ```ignore
//! let module = fg_filebrowser::Module::new(store, deps)?;
//! let router = module.mount(router);            // /api/filebrowser/…
//! registry.spawn(module, drain);
//! ```
//!
//! 每个实例一个独立的 Quantum 进程（fg-proc 监督）：配置文件写入实例
//! 数据目录（0600），管理员密码经 `FILEBROWSER_ADMIN_PASSWORD` 环境变量
//! 传入（配置文件中只有 `${VAR}` 引用），每次启动同步为 Gately 中的设置。
//! 共享目录与 Gately 配置目录重叠会被直接拒绝——File Browser 无法隐藏
//! 其中的子树。

#![forbid(unsafe_code)]

pub mod install;
pub mod instance;
pub mod model;
pub mod render;
pub mod routes;
pub mod validate;

use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use fg_config::{ConfigStore, Loaded};
use tokio::sync::{RwLock, watch};

pub use instance::{InstanceRuntime, InstanceStatus};
pub use model::{AuthMethod, FileConfig, InstallConfig, Instance, Settings, Source};
pub use routes::{PersistFn, RoutesState, mount};
pub use validate::{Problem, Warning};

/// The module's configuration file (`filebrowser.json`).
pub const CONFIG_NAME: &str = "filebrowser";

/// External capabilities injected by the assembler (conventions §3.4).
#[derive(Clone)]
pub struct Deps {
    /// The managed-process handle (WP-43): binary resolution, supervision
    /// and the online installer.
    pub proc: Arc<fg_proc::Proc>,
    /// Download channel for the installer; `None` reports
    /// 「下载通道未配置」 until fg-net's outbound HTTP is wired in.
    pub fetch: Option<fg_proc::install::HttpGetter>,
}

/// The filebrowser module: owns the loaded config, the instance runtime
/// and the routes.
pub struct Module {
    runtime: Arc<InstanceRuntime>,
    state: Arc<RoutesState>,
}

impl Module {
    /// Loads `filebrowser.json`, normalizes it (problems are logged, not
    /// fatal) and prepares the runtime plus route state.
    pub fn new(store: Arc<ConfigStore>, deps: Deps) -> Result<Self> {
        let config = match store.load::<FileConfig>(CONFIG_NAME)? {
            Loaded::Found(config) => config,
            Loaded::Missing => FileConfig::default(),
        };
        let config_dir: PathBuf = store.dir().to_path_buf();
        let mut config = config;
        // Overlaps cannot be fixed automatically — refuse the file loudly
        // so the operator moves the share, instead of serving the config.
        let overlaps = validate::validate_overlaps(&config, &config_dir);
        for problem in &overlaps {
            tracing::warn!(
                field = %problem.field,
                reason = %problem.reason,
                "filebrowser.json shares overlap the config dir; refusing to start instances"
            );
        }
        let _ = validate::normalize(&mut config);
        for warning in validate::warnings(&config) {
            tracing::warn!(
                field = %warning.field,
                reason = %warning.reason,
                "filebrowser.json warning"
            );
        }
        let config = Arc::new(RwLock::new(config));
        let runtime = Arc::new(InstanceRuntime::new(
            config_dir.clone(),
            Arc::clone(&deps.proc),
        ));
        runtime.set_program_path(None);
        let installer = Arc::clone(&deps.proc).installer(&install::SPEC);
        let installer = Some((installer, deps.fetch));
        let persist_store = Arc::clone(&store);
        let persist: PersistFn = Arc::new(move |config: &FileConfig| {
            persist_store
                .save(CONFIG_NAME, config)
                .map(|_| ())
                .with_context(|| format!("save {CONFIG_NAME}.json"))
        });
        let state = Arc::new(RoutesState {
            config_dir,
            config,
            runtime: Arc::clone(&runtime),
            installer,
            persist,
        });
        Ok(Self { runtime, state })
    }

    /// Adds the management routes (`/api/filebrowser/…`) to the
    /// assembler's router (permission domain `filebrowser`).
    pub fn mount(&self, router: axum::Router) -> axum::Router {
        routes::mount(router, Arc::clone(&self.state))
    }

    /// The instance runtime handle (status probes, tests).
    pub fn runtime(&self) -> Arc<InstanceRuntime> {
        Arc::clone(&self.runtime)
    }

    /// Starts every enabled instance whose sources exist; missing sources
    /// surface in the card's `failed`. Called by `run` on startup.
    async fn reconcile(&self) {
        let enabled: Vec<Instance> = {
            let config = self.state.config.read().await;
            config
                .instances
                .iter()
                .filter(|instance| instance.enable)
                .cloned()
                .collect()
        };
        for instance in enabled {
            if let Err(reason) = self.runtime.start(&instance).await {
                tracing::warn!(
                    key = %instance.key,
                    reason,
                    "filebrowser instance did not start"
                );
            }
        }
    }
}

impl fg_core::module::Module for Module {
    const ID: &'static str = "filebrowser";

    async fn run(self, mut drain: watch::Receiver<bool>) -> Result<()> {
        self.reconcile().await;
        tokio::select! {
            // Nothing else to poll: fg-proc supervises the processes and
            // route handlers reconcile on change.
            () = std::future::pending::<()>() => {}
            _ = drain.changed() => {
                // Bounded drain: stop everything within the deadline; a
                // hung stop cannot hold the shutdown hostage.
                let _ = tokio::time::timeout(
                    model::limits::SHUTDOWN_DEADLINE,
                    self.runtime.stop_all(),
                )
                .await;
            }
        }
        Ok(())
    }
}
