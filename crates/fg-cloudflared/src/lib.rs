//! WP-46 Cloudflare Tunnel（可选模块，feature `cloudflared`）：托管官方的
//! `cloudflared`——令牌隧道与 trycloudflare 临时隧道、多隧道、自动重启、
//! 公网地址展示，以及通过 Cloudflare API 编辑令牌隧道的路由规则（ingress）
//! 并创建 DNS 记录。模块布局与分层遵循 `docs/plan/00-conventions.md` §2，
//! 行为细节见 `docs/plan/WP-46-cloudflared.md`。
//!
//! 进程托管与在线安装全部走 `fg-proc`：安装器（CLOUDFLARED 静态规格）、
//! 二进制查找（设置路径 → 配置目录 bin/ → PATH）、监督重启与日志清理打码。
//! 令牌经环境变量 `TUNNEL_TOKEN` 传入，不出现在进程参数、日志与只读接口。
//!
//! 装配方式（根包统一接线，本包不进 REGISTRY/bootstrap）：
//!
//! ```ignore
//! let module = fg_cloudflared::Module::new(store, deps)?;
//! let router = module.mount(router);            // /api/cloudflared/…
//! registry.spawn(module, drain);                 // Module::run 启停隧道
//! ```
//!
//! `Deps.fetch` 注入下载通道（在线安装与更新检查，生产包装
//! `fg_net::http::OutboundHttp`），`Deps.cf_http` 注入 Cloudflare API 的
//! 出站通道；两者缺省时安装与 API 调用返回错误，模块本身照常运行。

#![forbid(unsafe_code)]

pub mod cf_api;
pub mod ingress;
pub mod model;
pub mod routes;
pub mod token;
pub mod tunnel;
pub mod validate;

use std::sync::{Arc, atomic::AtomicBool};

use anyhow::{Context, Result};
use fg_config::{ConfigStore, Loaded};
use tokio::sync::{Mutex, RwLock, watch};

pub use cf_api::{CfClient, CfError, DnsRecord, DnsResult, DnsStatus, FetchFn, RemoteConfig};
pub use ingress::{
    IngressUpdate, IngressView, Rule, Service, build_ingress, default_catch_all, normalize_rules,
    split_ingress, validate_service,
};
pub use model::{FileConfig, InstallConfig, Settings, Tunnel, TunnelKind};
pub use routes::{LatestInfo, PersistFn, RoutesState};
pub use token::{TokenError, TokenInfo, parse_token};
pub use tunnel::{TunnelRuntime, parse_quick_url, tunnel_args, tunnel_env, tunnel_view};
pub use validate::{Problem, normalize, normalize_tunnel, validate};

/// The module's configuration file (`cloudflared.json`) and permission
/// domain / module ID.
pub const MODULE_ID: &str = "cloudflared";
pub const CONFIG_NAME: &str = "cloudflared";

/// External capabilities the module needs, injected by the assembler
/// (conventions §3.4). Absent providers degrade gracefully.
#[derive(Clone, Default)]
pub struct Deps {
    /// Download channel for the online install and update checks
    /// (production wraps `fg_net::http::OutboundHttp`). `None` disables
    /// installs and checks.
    pub fetch: Option<fg_proc::install::HttpGetter>,
    /// Outbound channel for the Cloudflare API (ingress editing, DNS
    /// sync). Calls fail with a network error until injected.
    pub cf_http: Option<cf_api::FetchFn>,
    /// Event bus for the automatic update check (`program.update`).
    pub bus: Option<fg_core::events::EventBus>,
    /// Cloudflare API endpoint override; `None` uses
    /// [`model::limits::CF_ENDPOINT`] (tests point it at a fake server).
    pub cf_endpoint: Option<String>,
}

/// The cloudflared module: owns the loaded config, the process runtime,
/// the installer and the routes.
pub struct Module {
    proc: Arc<fg_proc::Proc>,
    config: Arc<RwLock<FileConfig>>,
    runtime: Arc<TunnelRuntime>,
    installer: Arc<fg_proc::Installer>,
    bus: Option<fg_core::events::EventBus>,
    state: Arc<routes::RoutesState>,
}

impl Module {
    /// Loads `cloudflared.json`, normalizes it (problems are logged, not
    /// fatal) and prepares the process runtime, the installer and the
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
                "cloudflared.json has a problem; fix it in the management UI"
            );
        }
        let config = Arc::new(RwLock::new(config));
        let proc = fg_proc::Proc::open(&store, deps.fetch.clone())
            .context("open the managed program bin directory")?;
        let installer = proc.installer(&fg_proc::install::spec::CLOUDFLARED);
        let runtime = Arc::new(TunnelRuntime::new(Arc::clone(&proc)));
        let persist_store = Arc::clone(&store);
        let persist: PersistFn = Arc::new(move |config: &FileConfig| {
            persist_store
                .save(CONFIG_NAME, config)
                .map(|_| ())
                .with_context(|| format!("save {CONFIG_NAME}.json"))
        });
        let state = Arc::new(routes::RoutesState {
            config: Arc::clone(&config),
            persist,
            runtime: Arc::clone(&runtime),
            installer: Arc::clone(&installer),
            fetch: deps.fetch.clone(),
            cf_http: deps
                .cf_http
                .clone()
                .unwrap_or_else(cf_api::unconfigured_fetch),
            cf_endpoint: deps
                .cf_endpoint
                .unwrap_or_else(|| model::limits::CF_ENDPOINT.to_owned()),
            ingress_lock: Arc::new(Mutex::new(())),
            latest: Arc::new(Mutex::new(None)),
            checking: Arc::new(AtomicBool::new(false)),
            version_cache: Arc::new(std::sync::Mutex::new(None)),
        });
        Ok(Self {
            proc,
            config,
            runtime,
            installer,
            bus: deps.bus,
            state,
        })
    }

    /// Adds the management routes (`/api/cloudflared/…`) to the assembler's
    /// router. Authentication is applied by the surrounding management
    /// router (permission domain `cloudflared`).
    pub fn mount(&self, router: axum::Router) -> axum::Router {
        routes::mount(router, Arc::clone(&self.state))
    }

    /// The tunnel runtime handle (tooling / tests).
    pub fn runtime(&self) -> Arc<TunnelRuntime> {
        Arc::clone(&self.runtime)
    }

    /// The cloudflared installer handle (assembler / tests).
    pub fn installer(&self) -> Arc<fg_proc::Installer> {
        Arc::clone(&self.installer)
    }

    /// The route state handle (tooling / tests).
    pub fn routes_state(&self) -> Arc<routes::RoutesState> {
        Arc::clone(&self.state)
    }

    /// Starts the enabled tunnels, runs the automatic update check every
    /// 12 hours, and on drain stops every tunnel within the shutdown
    /// deadline.
    async fn serve(self, mut drain: watch::Receiver<bool>) -> Result<()> {
        {
            let config = self.config.read().await.clone();
            for tunnel in config.tunnels.iter().filter(|tunnel| tunnel.enable) {
                self.runtime.apply(tunnel, &config.settings).await;
            }
        }
        let auto_checker = self.proc.auto_checker(
            MODULE_ID,
            &[&fg_proc::install::spec::CLOUDFLARED],
            self.bus.clone(),
        );
        let checker_drain = drain.clone();
        let checker = tokio::spawn(async move {
            Arc::new(auto_checker).run(checker_drain).await;
        });
        // Drain：停止接入，等待有界停止（每进程 5 秒优雅宽限，总时限
        // limits::SHUTDOWN_DEADLINE）。
        let _ = drain.changed().await;
        self.runtime.stop_all().await;
        checker.abort();
        Ok(())
    }
}

impl fg_core::module::Module for Module {
    const ID: &'static str = MODULE_ID;

    async fn run(self, drain: watch::Receiver<bool>) -> Result<()> {
        self.serve(drain).await
    }
}
