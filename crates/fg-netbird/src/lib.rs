//! WP-45 NetBird 组网模块（可选模块，feature `netbird`）：加入 NetBird
//! 云或自建管理服务的网络——托管 `netbird` 守护进程（用户态网络）或接入
//! 系统服务。布局与分层遵循 `docs/plan/00-conventions.md` §2，行为细节
//! 见 `docs/plan/WP-45-mesh-tunnels.md`。
//!
//! 装配方式（根包统一接线，本包不进 REGISTRY/bootstrap）：
//!
//! ```ignore
//! let module = fg_netbird::Module::new(
//!     Arc::clone(&store),
//!     fg_netbird::Deps { proc, fetch, logs: None },
//! )?;
//! let router = module.mount(router);   // /api/netbird/…
//! registry.spawn(module, drain);       // Module::run 应用配置并托管实例
//! ```
//!
//! 安全口径（WP-45 §8）：设置密钥只经 `NB_SETUP_KEY` 环境变量传递，绝不
//! 出现在命令行、日志、状态输出或只读接口里；登录链接的一次性令牌在日
//! 志中打码、只在状态接口中出现；SOCKS5 代理没有认证，绑定到非回环地址
//! 时校验阶段给出警告；内核模式实例同时最多启用一个，启动前检查系统上
//! 是否已有外部内核模式 NetBird。

#![forbid(unsafe_code)]

pub mod args;
pub mod external;
pub mod model;
pub mod routes;
pub mod runtime;
pub mod status;
pub mod validate;

use std::sync::Arc;

use anyhow::Result;
use fg_config::{ConfigStore, Loaded};
use tokio::sync::{RwLock, watch};

pub use model::{ExtraEnv, FileConfig, Instance, ProgramSettings};
pub use routes::{PersistFn, RoutesState, mount};
pub use runtime::{Deps, InstanceSnapshot, LoginState, Runtime};
pub use status::{PeerInfo, StatusInfo};
pub use validate::{Conflict, Problem};

/// The module's configuration file (`netbird.json`).
pub const CONFIG_NAME: &str = "netbird";
/// The module ID (fg-core registry and permission domain).
pub const MODULE_ID: &str = "netbird";

/// The NetBird module: owns the loaded config, the instance runtime and
/// the routes.
pub struct Module {
    runtime: Arc<Runtime>,
    state: Arc<RoutesState>,
}

impl Module {
    /// Loads `netbird.json` (missing file → defaults), normalizes it
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
                "netbird.json 有问题；请在管理界面修正"
            );
        }
        for warning in validate::warnings(&config) {
            tracing::warn!(
                field = %warning.field,
                reason = %warning.reason,
                "netbird.json 配置警告"
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

    /// Adds the management routes (`/api/netbird/…`) to the assembler's
    /// router. Authentication is applied by the surrounding management
    /// router (permission domain `netbird`).
    pub fn mount(&self, router: axum::Router) -> axum::Router {
        routes::mount(router, Arc::clone(&self.state))
    }

    /// The runtime handle: read-only snapshots for other modules.
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
