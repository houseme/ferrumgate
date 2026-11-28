//! WP-54 单包授权与放行（可选模块，feature `knock`）：与 fwknop 客户端
//! 兼容的 SPA 报文（解析、HMAC 校验、解密、字段校验与生成）、敲门规则、
//! 验证流程（限速 → HMAC → 解密 → 时间窗 → 重放 → 规则匹配 → 登记）、
//! 进程内授权登记表、UDP 监听与经协议分流的 TCP 提交、客户端命令生成、
//! 管理接口。模块布局与分层遵循 `docs/plan/00-conventions.md` §2，行为
//! 细节见 `docs/plan/WP-54-port-knock.md`。
//!
//! 装配方式（根包统一接线，本包不进 REGISTRY/bootstrap）：
//!
//! ```ignore
//! let module = fg_knock::Module::new(store, fg_knock::Deps { ..Default::default() })?;
//! let router = module.mount(router);          // /api/knock/…
//! registry.spawn(module, drain);              // UDP 监听 + 关窗定时器
//! ```
//!
//! 防火墙与入侵防护的接线点（约定 §3.4，由装配层注入
//! [`Deps`]，本包不直接依赖 `fwopen`）：
//!
//! - `Deps.open_window` / `Deps.close_window`：命中后开窗、到期或撤销后
//!   关窗。主会话可包一层 `fg_net::fwopen::Group::want(owner, ports)`
//!   （owner 形如 `knock:<rule key>`，空端口列表即关窗），或转发给
//!   WP-51 的 `inet gately_knock` 放行集合。
//! - `Deps.bans`：共享封禁表（`fg_net::banlist::BanTable`）。被封禁来源
//!   的敲门直接丢弃；验证通过后对来源调用 `trust_login`，避免陷阱端口
//!   误封刚放行的地址。
//! - `Deps.events`：事件总线（`knock.opened` / `knock.failed`）。
//! - `Deps.references` / `Deps.spa_ports` / `Deps.firewall_rules`：端口
//!   转发、协议分流与 STUN 的规则引用查询（删除保护）、`spa` 路由占用
//!   端口（保存冲突检查）与防火墙窗口只读视图（状态页）。
//!
//! 授权登记表目前是本 crate 内的 [`grants::Grants`]；WP-01 把
//! `knockgate` 提升到 `fg-core` 后，装配层把 [`Module::grants`] 的数据
//! 迁移过去并让端口转发 / 协议分流 / STUN / Web 站点查询共享表（接线
//! 点见 `grants` 模块文档）。

#![forbid(unsafe_code)]

pub mod client;
pub mod engine;
pub mod grants;
pub mod limit;
pub mod listen;
pub mod model;
pub mod replay;
pub mod routes;
pub mod selfcheck;
pub mod spa;
pub mod validate;

use std::sync::Arc;

use anyhow::{Context, Result};
use fg_config::{ConfigStore, Loaded};
use fg_core::check::BoxFut;
use tokio::sync::{RwLock, watch};
use tokio_util::sync::CancellationToken;

pub use client::{ClientKeys, ClientTarget};
pub use engine::{
    Clock, Compiled, CompiledRule, Engine, Hooks, InvalidSummary, Opened, Outcome, Reject, Revoke,
    Stats, Via, WindowRequest, check_message, effective_timeout, revokes_on_edit, system_clock,
};
pub use grants::{Grant, GrantSource, GrantView, Grants};
pub use limit::RateLimiter;
pub use model::{Access, CONFIG_NAME, FileConfig, HmacType, Identity, Proto, Rule, Settings};
pub use replay::{ReplayCache, ReplayKey};
pub use routes::{FirewallRuleView, OnChangeFn, PersistFn, RoutesState, mount};
pub use validate::{Problem, normalize, validate, validate_with};

/// Async external capability injected by the assembler (conventions §3.4).
pub type SharedFn<A, R> = Arc<dyn Fn(A) -> BoxFut<'static, Result<R>> + Send + Sync>;

/// External capabilities the knock module needs. Absent providers degrade
/// the corresponding behavior (no ban drop, no events, no firewall window).
#[derive(Clone, Default)]
pub struct Deps {
    /// Shared ban table (`fg_net::banlist::BanTable`): banned sources are
    /// dropped before decoding; successful knocks shield their address
    /// against trap and scan sources (`trust_login`).
    pub bans: Option<Arc<fg_net::banlist::BanTable>>,
    /// Event bus (`knock.opened`, `knock.failed` — the latter only for
    /// TCP-channel rejections).
    pub events: Option<fg_core::events::EventBus>,
    /// Open the firewall window after a hit (fwopen::Group or WP-51's
    /// `inet gately_knock` admit set).
    pub open_window: Option<SharedFn<WindowRequest, ()>>,
    /// Close the window on expiry, revoke or shutdown (payload: rule key).
    pub close_window: Option<SharedFn<String, ()>>,
    /// Rule references from other modules (port forwarding, protocol
    /// routing, STUN, web sites) for the delete protection.
    pub references: Option<SharedFn<String, Vec<String>>>,
    /// Ports occupied by protocol-routing `spa` routes (save-time
    /// conflict check with firewall-blocked rules).
    pub spa_ports: Option<SharedFn<(), Vec<Access>>>,
    /// Read-only firewall window view for the status page.
    pub firewall_rules: Option<SharedFn<(), Vec<routes::FirewallRuleView>>>,
    /// Injectable wall clock (tests); `None` uses UTC system time.
    pub clock: Option<Clock>,
}

/// The knock module: owns the loaded config, the engine (verification,
/// grants, close-window timers) and the routes. The assembler calls
/// [`Module::mount`] before running it.
pub struct Module {
    engine: Arc<Engine>,
    state: Arc<RoutesState>,
    check: Arc<selfcheck::KnockCheck>,
    /// Bumped on every config change; the run loop restarts the UDP
    /// listener when the port changed or the key set appeared or
    /// disappeared.
    reload_tx: watch::Sender<u64>,
}

impl Module {
    /// Loads `knock.json`, normalizes it (problems are logged, not fatal)
    /// and prepares the engine plus route state.
    pub fn new(store: Arc<ConfigStore>, deps: Deps) -> Result<Self> {
        let mut config = match store.load::<FileConfig>(CONFIG_NAME)? {
            Loaded::Found(config) => normalize(config),
            Loaded::Missing => FileConfig::default(),
        };
        config = normalize(config);
        for problem in validate(&config) {
            tracing::warn!(
                field = %problem.field,
                reason = %problem.reason,
                "knock.json has a problem; fix it in the management UI"
            );
        }
        let clock = deps.clock.clone().unwrap_or_else(engine::system_clock);
        let started = (clock)();
        let hooks = Hooks {
            open_window: deps.open_window,
            close_window: deps.close_window,
            events: deps.events,
            bans: deps.bans,
        };
        let grants = Arc::new(Grants::new());
        let engine = Engine::new(
            Arc::clone(&grants),
            ReplayCache::new(started),
            RateLimiter::new(),
            hooks,
            clock,
        );
        engine.apply_config(None, &config);
        let persist_store = Arc::clone(&store);
        let persist: PersistFn = Arc::new(move |config: &FileConfig| {
            persist_store
                .save(CONFIG_NAME, config)
                .map(|_| ())
                .with_context(|| format!("save {CONFIG_NAME}.json"))
        });
        let (reload_tx, _) = watch::channel(0);
        let reload_for_hook = Arc::new(reload_tx.clone());
        let engine_for_hook = Arc::clone(&engine);
        let on_change: OnChangeFn = Arc::new(move |old: &FileConfig, new: &FileConfig| {
            engine_for_hook.apply_config(Some(old), new);
            reload_for_hook.send_modify(|generation| *generation += 1);
        });
        let state = Arc::new(RoutesState {
            config: Arc::new(RwLock::new(config)),
            persist,
            on_change,
            engine: Arc::clone(&engine),
            references: deps.references,
            spa_ports: deps.spa_ports,
            firewall_rules: deps.firewall_rules,
        });
        let check = Arc::new(selfcheck::KnockCheck {
            engine: Arc::clone(&engine),
            config: Arc::clone(&state.config),
        });
        Ok(Self {
            engine,
            state,
            check,
            reload_tx,
        })
    }

    /// Adds the management routes (`/api/knock/…`) to the assembler's
    /// router. Authentication is applied by the surrounding management
    /// router (permission domain `knock`).
    pub fn mount(&self, router: axum::Router) -> axum::Router {
        routes::mount(router, Arc::clone(&self.state))
    }

    /// The verification engine (submit entry for protocol routing, stats,
    /// close-window timers).
    pub fn engine(&self) -> Arc<Engine> {
        Arc::clone(&self.engine)
    }

    /// The grant registry (the local slice of `knockgate`; wiring point
    /// for the WP-01 shared table in fg-core).
    pub fn grants(&self) -> Arc<Grants> {
        Arc::clone(self.engine.grants())
    }

    /// The self-check handle for the system checks run.
    pub fn check(&self) -> Arc<selfcheck::KnockCheck> {
        Arc::clone(&self.check)
    }
}

impl fg_core::module::Module for Module {
    const ID: &'static str = "knock";

    async fn run(self, drain: watch::Receiver<bool>) -> Result<()> {
        let config = self.state.config.read().await;
        let mut port = config.settings.port;
        drop(config);
        let mut listener: Option<(tokio::task::JoinHandle<()>, CancellationToken)> = None;
        if port != 0 && !self.engine.snapshot().keys.is_empty() {
            let token = CancellationToken::new();
            let engine = Arc::clone(&self.engine);
            let listener_token = token.clone();
            let handle = tokio::spawn(async move {
                let _ = listen::run_udp(engine, port, listener_token).await;
            });
            listener = Some((handle, token));
        } else if port != 0 {
            tracing::info!(
                target: "fg_knock",
                "没有启用的敲门密钥，UDP 监听未启动；规则保存后将自动启动"
            );
        }
        let mut reload_rx = self.reload_tx.subscribe();
        let mut generation = *reload_rx.borrow_and_update();
        let mut drain = drain;
        loop {
            tokio::select! {
                biased;
                _ = drain.changed() => break,
                changed = reload_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    let current = *reload_rx.borrow_and_update();
                    if current == generation {
                        continue;
                    }
                    generation = current;
                    // Restart the listener when the port changed or the
                    // key set appeared / disappeared.
                    let want_port = self.state.config.read().await.settings.port;
                    let want = want_port != 0 && !self.engine.snapshot().keys.is_empty();
                    let running = listener.is_some();
                    if want && (!running || want_port != port) {
                        if let Some((handle, token)) = listener.take() {
                            token.cancel();
                            let _ = handle.await;
                        }
                        port = want_port;
                        let token = CancellationToken::new();
                        let engine = Arc::clone(&self.engine);
                        let listener_token = token.clone();
                        let handle = tokio::spawn(
                            async move { let _ = listen::run_udp(engine, port, listener_token).await; },
                        );
                        listener = Some((handle, token));
                    } else if !want
                        && running
                        && let Some((handle, token)) = listener.take()
                    {
                        token.cancel();
                        let _ = handle.await;
                    }
                }
            }
        }
        // Draining: close every open window and stop the listener.
        self.engine.shutdown().await;
        if let Some((handle, token)) = listener.take() {
            token.cancel();
            let _ = handle.await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_id_matches_config_name() {
        assert_eq!(<Module as fg_core::module::Module>::ID, "knock");
        assert_eq!(CONFIG_NAME, "knock");
    }
}
