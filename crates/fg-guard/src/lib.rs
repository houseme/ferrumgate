//! WP-50 统一封禁表与入侵防护模块：`fg_net::banlist` 承载共享数据结构，
//! 本 crate 提供 `guard.json` 模块设置、自动/手动封禁接口、`guard.banned`
//! 事件发布、管理路由与自检；防火墙同步（[`firewall`]，WP-51）与日志规则
//! jails（[`jail`]，WP-52：文件 / journal / 命令 / Docker / 事件来源与
//! Web / TLS 探测，见 [`webprobe`]）在本包之上实现，它们调用
//! [`bans::GuardService::ban_auto`] 写入同一张表。诱饵端口与扫描检测
//! （WP-53）也走同一入口。

#![forbid(unsafe_code)]

pub mod bans;
pub mod firewall;
pub mod jail;
pub mod model;
pub mod presets;
pub mod routes;
pub mod selfcheck;
pub mod validate;
pub mod webprobe;

use std::sync::Arc;

use anyhow::{Context, Result};
use fg_config::{ConfigStore, Loaded};
use fg_core::events::EventBus;
use tokio::sync::{RwLock, watch};

use crate::bans::GuardService;
use crate::model::FileConfig;

/// The guard module: owns the shared ban table service, the normalized
/// `guard.json` snapshot, the jail engine (WP-52) and, when
/// `settings.firewall` is on, the WP-51 firewall sync
/// ([`bans::GuardService::firewall`]). The assembly layer creates it
/// after the config store and event bus exist, mounts [`routes::mount`]
/// under the management router, registers [`selfcheck::GuardCheck`] and
/// hands [`GuardService::table`] to the modules that need `is_banned`.
pub struct Module {
    pub config: Arc<RwLock<FileConfig>>,
    pub service: Arc<GuardService>,
    /// The WP-52 jail engine: compiled rules snapshot, source tasks,
    /// event subscription. The assembly layer calls
    /// [`jail::JailEngine::reconcile_sources`] and
    /// [`jail::event_source::attach`] once the runtime is up.
    pub engine: Arc<jail::JailEngine>,
}

impl Module {
    /// Loads `guard.json` (missing file → defaults), normalizes it and
    /// opens the bans file under the config store.
    pub fn open(store: &Arc<ConfigStore>, events: EventBus) -> Result<Self> {
        let loaded = store.load::<FileConfig>(model::FILE_NAME)?;
        let mut config = match loaded {
            Loaded::Found(config) => config,
            Loaded::Missing => FileConfig::default(),
        };
        config = validate::normalize(config);
        if let Some(problem) = validate::validate(&config).first() {
            anyhow::bail!(
                "invalid guard configuration: {} {}",
                problem.field,
                problem.reason
            );
        }
        let service = GuardService::open(store, &config.settings, events.clone())
            .context("opening the guard module")?;
        let engine = Arc::new(jail::JailEngine::new(
            Arc::clone(&service),
            fg_net::banlist::system_clock(),
        ));
        engine
            .reload(&config)
            .context("compiling the guard jails")?;
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            service,
            engine,
        })
    }
}

impl fg_core::module::Module for Module {
    const ID: &'static str = "guard";

    /// The firewall sync removes its table before the thread exits
    /// (bounded wait); the jail source tasks are aborted first; the
    /// delayed saver owns persistence while running and the bans file is
    /// flushed on the way out.
    async fn run(self, mut drain: watch::Receiver<bool>) -> Result<()> {
        while drain
            .changed()
            .await
            .is_ok_and(|_| !*drain.borrow_and_update())
        {}
        self.engine.stop_sources();
        if let Some(sync) = self.service.firewall() {
            tracing::info!(module = "guard", "removing the firewall table on shutdown");
            sync.stop();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            while !sync.cleared() && std::time::Instant::now() < deadline {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
        tracing::info!(module = "guard", "flushing the ban table on shutdown");
        self.service.flush()
    }
}
