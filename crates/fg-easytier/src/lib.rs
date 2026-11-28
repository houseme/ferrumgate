//! WP-45 EasyTier 组网模块（可选模块，feature `easytier`）：托管
//! `easytier-core`，P2P 打洞优先，自托管或指定中继节点，用户态网络下的
//! 端口转发。布局与分层遵循 `docs/plan/00-conventions.md` §2，行为细节见
//! `docs/plan/WP-45-mesh-tunnels.md`。
//!
//! 装配方式（根包统一接线，本包不进 REGISTRY/bootstrap）：
//!
//! ```ignore
//! let runtime = fg_easytier::Runtime::new(
//!     Arc::clone(&store),
//!     fg_easytier::runtime::Deps { proc, fetch, logs: None },
//!     config,
//! );
//! let module = fg_easytier::Module::new(runtime, persist)?;
//! let router = module.mount(router);   // /api/easytier/…
//! registry.spawn(module, drain);       // Module::run 应用配置并托管实例
//! ```
//!
//! 安全口径（WP-45 §8）：网络密钥只经 `ET_NETWORK_SECRET` 环境变量传给
//! `easytier-core`，绝不出现在命令行、日志、状态输出或只读接口里
//! （`easytier-cli node` 的输出按字段白名单解析）；管理端口只监听
//! `127.0.0.1` 的随机端口并以 `--rpc-portal-whitelist` 限定回环来源。

#![forbid(unsafe_code)]

pub mod args;
pub mod model;
pub mod routes;
pub mod runtime;
pub mod status;
pub mod validate;

use std::sync::Arc;

use anyhow::Result;
use fg_config::{ConfigStore, Loaded};
use tokio::sync::{RwLock, watch};

pub use model::{ExitNodeRole, ExtraEnv, FileConfig, Instance, ProgramSettings, VipMode};
pub use routes::{PersistFn, RoutesState, mount};
pub use runtime::{Deps, InstanceSnapshot, Runtime};
pub use status::{InstanceStatus, NodeInfo, PeerInfo};
pub use validate::{Conflict, Problem};

/// The module's configuration file (`easytier.json`).
pub const CONFIG_NAME: &str = "easytier";
/// The module ID (fg-core registry and permission domain).
pub const MODULE_ID: &str = "easytier";

/// The EasyTier module: owns the loaded config, the instance runtime and
/// the routes. The assembler creates it after the config store and the
/// [`crate::runtime::Deps`] handles exist, mounts [`routes::mount`] under
/// the management router and hands it to the registry together with a
/// drain receiver.
pub struct Module {
    runtime: Arc<Runtime>,
    state: Arc<RoutesState>,
}

impl Module {
    /// Loads `easytier.json` (missing file → defaults), normalizes it
    /// (problems are logged, not fatal) and prepares the runtime plus
    /// route state.
    pub fn new(store: Arc<ConfigStore>, deps: Deps) -> Result<Self> {
        let config = match store.load::<FileConfig>(CONFIG_NAME)? {
            Loaded::Found(config) => validate::normalize(config),
            Loaded::Missing => FileConfig::default(),
        };
        for problem in validate::validate(&config) {
            tracing::warn!(
                field = %problem.field,
                reason = %problem.reason,
                "easytier.json 有问题；请在管理界面修正"
            );
        }
        let config = Arc::new(RwLock::new(config));
        let runtime = Arc::new(Runtime::new(Arc::clone(&store), deps, Arc::clone(&config)));
        let persist_store = Arc::clone(&store);
        let persist: PersistFn = Arc::new(move |config: &FileConfig| {
            persist_store.save(CONFIG_NAME, config).map(|_| ())
        });
        let state = Arc::new(RoutesState {
            config: Arc::clone(&config),
            on_change: runtime.on_change(),
            persist,
            runtime: Arc::clone(&runtime),
        });
        Ok(Self { runtime, state })
    }

    /// Adds the management routes (`/api/easytier/…`) to the assembler's
    /// router. Authentication is applied by the surrounding management
    /// router (permission domain `easytier`).
    pub fn mount(&self, router: axum::Router) -> axum::Router {
        routes::mount(router, Arc::clone(&self.state))
    }

    /// The runtime handle: read-only snapshots for other modules and the
    /// restart hook used after online installs.
    pub fn runtime(&self) -> Arc<Runtime> {
        Arc::clone(&self.runtime)
    }
}

impl fg_core::module::Module for Module {
    const ID: &'static str = MODULE_ID;

    /// Applies the desired state and supervises the instances until the
    /// drain signal; every instance stops within the module shutdown
    /// deadline.
    async fn run(self, drain: watch::Receiver<bool>) -> Result<()> {
        self.runtime.run(drain).await
    }
}
