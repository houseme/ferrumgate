//! WP-42 STUN 穿透（可选模块，feature `stun`）：`stun.json` 的模型与校验、
//! RFC 5389 最小子集的 STUN 客户端、映射保持运行时与管理接口。模块布局与
//! 分层遵循 `docs/plan/00-conventions.md` §2，行为细节见
//! `docs/plan/WP-42-stun.md`。
//!
//! 装配方式（根包统一接线，本包不进 REGISTRY/bootstrap）：
//!
//! ```ignore
//! let module = fg_stun::Module::new(store, fg_stun::Deps {
//!     events: Some(event_bus),                    // stun.changed 事件
//!     fw_open: Some(fg_net::fwopen::Group::new("stun")), // 自动放行（可选）
//! })?;
//! let router = module.mount(router);              // 挂到管理路由（/api/stun/…）
//! registry.spawn(module, drain);                  // Module::run 跑映射保持循环
//! ```
//!
//! 发现的公网地址经 [`Runtime::snapshot`] 以只读快照发布，供 L4 /
//! protoroute（WP-36/WP-35）消费；UPnP / NAT-PMP 端口映射、内置转发与
//! Webhook / 脚本通知按 WP-42 实施步骤在后续步骤接入。

#![forbid(unsafe_code)]

pub mod channel;
pub mod model;
pub mod routes;
pub mod runtime;
pub mod stun;
pub mod validate;

use std::sync::Arc;

use anyhow::{Context, Result};
use fg_config::{ConfigStore, Loaded};
use fg_core::events::EventBus;
use tokio::sync::{RwLock as AsyncRwLock, watch};

pub use channel::{Action, Channel, ChannelState, Timings, Transition};
pub use model::{Bind, BindMode, FileConfig, Proto, Rule, Settings, WebhookConfig};
pub use routes::{PersistFn, RoutesState, RuleView, StatusView, mount};
pub use runtime::{EntryStatus, Runtime, RuntimeSnapshot};
pub use validate::{Problem, normalize, validate};

/// The module's configuration file (`stun.json`).
pub const CONFIG_NAME: &str = "stun";

/// External capabilities the module needs, injected by the assembler
/// (conventions §3.4). Absent providers degrade gracefully: without the
/// event bus no `stun.changed` is published, without the firewall group
/// auto-firewall registrations are skipped.
#[derive(Clone, Default)]
pub struct Deps {
    /// Event bus for `stun.changed` publications (consumed by DDNS,
    /// WP-40).
    pub events: Option<EventBus>,
    /// Firewall opening group (WP-37); the runtime registers the channel
    /// port of rules with `autoFirewall` through it.
    pub fw_open: Option<Arc<fg_net::fwopen::Group>>,
}

/// The STUN module: owns the loaded config, the mapping runtime and the
/// routes. The assembler calls [`Module::mount`] before running it.
pub struct Module {
    runtime: Arc<Runtime>,
    state: Arc<RoutesState>,
}

impl Module {
    /// Loads `stun.json`, normalizes it (problems are logged, not fatal)
    /// and prepares the runtime plus route state.
    pub fn new(store: Arc<ConfigStore>, deps: Deps) -> Result<Self> {
        let config = match store.load::<FileConfig>(CONFIG_NAME)? {
            Loaded::Found(config) => normalize(config),
            Loaded::Missing => FileConfig::default(),
        };
        for problem in validate(&config) {
            tracing::warn!(
                module = "stun",
                field = %problem.field,
                reason = %problem.reason,
                "stun.json has a problem; fix it in the management UI"
            );
        }
        let config = Arc::new(AsyncRwLock::new(config));
        let runtime = Arc::new(Runtime::new(config.clone(), deps.events, deps.fw_open));
        let persist_store = Arc::clone(&store);
        let persist: PersistFn = Arc::new(move |config: &FileConfig| {
            persist_store
                .save(CONFIG_NAME, config)
                .map(|_| ())
                .with_context(|| format!("save {CONFIG_NAME}.json"))
        });
        let on_change = runtime.on_change_handle();
        let state = Arc::new(RoutesState {
            config,
            on_change,
            persist,
            runtime: Arc::clone(&runtime),
        });
        Ok(Self { runtime, state })
    }

    /// Adds the management routes (`/api/stun/…`) to the assembler's
    /// router. Authentication is applied by the surrounding management
    /// router (permission domain `stun`).
    pub fn mount(&self, router: axum::Router) -> axum::Router {
        routes::mount(router, Arc::clone(&self.state))
    }

    /// The runtime handle (snapshot / metrics / restart from other
    /// tooling, tests).
    pub fn runtime(&self) -> Arc<Runtime> {
        Arc::clone(&self.runtime)
    }
}

impl fg_core::module::Module for Module {
    const ID: &'static str = "stun";

    async fn run(self, drain: watch::Receiver<bool>) -> Result<()> {
        self.runtime.run(drain).await
    }
}
