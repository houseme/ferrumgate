//! WP-50 统一封禁表与入侵防护模块地基：`fg_net::banlist` 承载共享数据结构，
//! 本 crate 提供 `guard.json` 模块设置、自动/手动封禁接口、`guard.banned`
//! 事件发布、管理路由与自检。防火墙同步（[`firewall`]，WP-51）与各 jail、
//! 诱饵端口、扫描检测（WP-52、WP-53）在本包之上实现，它们调用
//! [`bans::GuardService::ban_auto`] 写入同一张表。

#![forbid(unsafe_code)]

pub mod bans;
pub mod firewall;
pub mod model;
pub mod routes;
pub mod selfcheck;
pub mod validate;

use std::sync::Arc;

use anyhow::{Context, Result};
use fg_config::{ConfigStore, Loaded};
use fg_core::events::EventBus;
use tokio::sync::{RwLock, watch};

use crate::bans::GuardService;
use crate::model::FileConfig;

/// The guard module: owns the shared ban table service, the normalized
/// `guard.json` snapshot and, when `settings.firewall` is on, the WP-51
/// firewall sync ([`bans::GuardService::firewall`]). The assembly layer
/// creates it after the config store and event bus exist, mounts
/// [`routes::mount`] under the management router, registers
/// [`selfcheck::GuardCheck`] and hands [`GuardService::table`] to the
/// modules that need `is_banned`.
pub struct Module {
    pub config: Arc<RwLock<FileConfig>>,
    pub service: Arc<GuardService>,
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
        let service = GuardService::open(store, &config.settings, events)
            .context("opening the guard module")?;
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            service,
        })
    }
}

impl fg_core::module::Module for Module {
    const ID: &'static str = "guard";

    /// The firewall sync removes its table before the thread exits
    /// (bounded wait); the delayed saver owns persistence while running
    /// and the bans file is flushed on the way out.
    async fn run(self, mut drain: watch::Receiver<bool>) -> Result<()> {
        while drain
            .changed()
            .await
            .is_ok_and(|_| !*drain.borrow_and_update())
        {}
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
