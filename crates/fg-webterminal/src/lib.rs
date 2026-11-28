//! WP-61 Web Terminal (`fg-webterminal`):
//! Browser-based SSH, Telnet, and local shell terminal with persistent
//! server-side sessions, TOFU host key verification before authentication,
//! credential presets, SOCKS5/HTTP proxies, SFTP & local file management with
//! pure-Rust archive support, user agreement & TOTP 2FA security controls,
//! and reusable `ssh_push` / `ssh_exec` / `ssh_targets` providers.

#![forbid(unsafe_code)]

pub mod local_shell;
pub mod model;
pub mod routes;
pub mod security;
pub mod session;
pub mod sftp;
pub mod ssh;
pub mod telnet;
pub mod validate;
pub mod ws;

use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use fg_config::{ConfigStore, Loaded};
use serde::Serialize;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::model::{ConnKind, FileConfig, HostKey};
use crate::routes::ApiError;
use crate::security::TwoFaTracker;
use crate::session::{Caps, SessionTable};
use crate::sftp::SftpPool;
use crate::ssh::{PushFile, SshTarget};
use crate::validate::normalize;

/// Config name in `fg-config` (`webterminal.json`).
pub const CONFIG_NAME: &str = "webterminal";

/// Summary of an SSH target exposed to other modules (WP-33 / WP-72).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshTargetSummary {
    pub key: String,
    pub name: String,
    pub host: String,
    /// `true` only when a host key fingerprint has already been recorded via TOFU.
    pub trusted: bool,
}

/// Request payload for [`WebTerminalHandle::ssh_push`] (WP-33 certificate deploy).
#[derive(Clone, Debug)]
pub struct SshPushRequest {
    pub conn_key: String,
    pub dir: String,
    pub files: Vec<PushFile>,
    pub command: String,
}

/// Shared runtime handle for the Web Terminal module: holds the persisted
/// configuration, active session table, pooled SFTP connections, and 2FA state.
pub struct WebTerminalHandle {
    store: Arc<ConfigStore>,
    config: RwLock<FileConfig>,
    pub sessions: Arc<SessionTable>,
    pub sftp_pool: Arc<SftpPool>,
    pub two_fa: Arc<TwoFaTracker>,
}

impl WebTerminalHandle {
    /// Loads `webterminal.json` from `store` (falling back to normalized defaults)
    /// and initializes the runtime handle.
    pub fn open(store: Arc<ConfigStore>) -> Result<Arc<Self>> {
        let loaded = match store.load::<FileConfig>(CONFIG_NAME)? {
            Loaded::Found(cfg) => normalize(cfg),
            Loaded::Missing => normalize(FileConfig::default()),
        };
        let caps = Caps::from_settings(&loaded.settings);
        Ok(Arc::new(Self {
            store,
            config: RwLock::new(loaded),
            sessions: Arc::new(SessionTable::new(caps)),
            sftp_pool: Arc::new(SftpPool::new()),
            two_fa: Arc::new(TwoFaTracker::new()),
        }))
    }

    /// Returns a cloned snapshot of the current configuration.
    pub fn config_snapshot(&self) -> FileConfig {
        self.config.read().expect("config read lock").clone()
    }

    /// Mutates the configuration atomically and persists it to `webterminal.json`.
    pub(crate) fn update_config<T, F>(&self, f: F) -> std::result::Result<T, ApiError>
    where
        F: FnOnce(&mut FileConfig) -> std::result::Result<T, ApiError>,
    {
        let mut guard = self.config.write().expect("config write lock");
        let mut candidate = guard.clone();
        let out = f(&mut candidate)?;
        self.store
            .save(CONFIG_NAME, &candidate)
            .map_err(|e| ApiError::internal(format!("保存配置失败：{e}")))?;
        *guard = candidate;
        Ok(out)
    }

    /// Persists a newly observed or backfilled TOFU host key for `conn_key`.
    pub fn record_host_key(&self, conn_key: &str, host_key: HostKey) {
        let mut guard = self.config.write().expect("config write lock");
        if let Some(conn) = guard.connections.iter_mut().find(|c| c.key == conn_key) {
            conn.host_key = Some(host_key);
            if let Err(err) = self.store.save(CONFIG_NAME, &*guard) {
                tracing::warn!(conn = %conn_key, %err, "failed to persist TOFU host key");
            }
        }
    }

    /// Builds the Axum router serving `/api/webterminal/*`.
    pub fn router(self: &Arc<Self>) -> axum::Router {
        routes::router(Arc::clone(self))
    }

    // --- Cross-module providers (WP-61 §3.3 Deps) ------------------------

    /// Lists configured SSH connections and whether each has a recorded host key.
    pub fn ssh_targets(&self) -> Vec<SshTargetSummary> {
        let cfg = self.config_snapshot();
        cfg.connections
            .into_iter()
            .filter(|c| c.kind == ConnKind::Ssh && c.enable)
            .map(|c| SshTargetSummary {
                key: c.key,
                name: c.name,
                host: c.host,
                trusted: c.host_key.is_some(),
            })
            .collect()
    }

    /// Executes a single command over a fresh SSH connection (WP-72 remote shutdown).
    /// Strictly refuses untrusted hosts without a recorded host key!
    pub async fn ssh_exec(&self, conn_key: &str, command: &str) -> Result<String> {
        let target = self.resolve_trusted_ssh_target(conn_key)?;
        ssh::ssh_exec_target(&target, command).await
    }

    /// Uploads files into `dir` over SFTP and runs `command` (WP-33 certificate deploy).
    /// Strictly refuses untrusted hosts without a recorded host key!
    pub async fn ssh_push(&self, req: SshPushRequest) -> Result<String> {
        let target = self.resolve_trusted_ssh_target(&req.conn_key)?;
        ssh::ssh_push_target(&target, &req.dir, &req.files, &req.command).await
    }

    fn resolve_trusted_ssh_target(&self, conn_key: &str) -> Result<SshTarget> {
        let cfg = self.config_snapshot();
        let conn = cfg
            .connections
            .iter()
            .find(|c| c.key == conn_key)
            .ok_or_else(|| anyhow!("SSH 连接 {conn_key} 不存在"))?;
        if conn.kind != ConnKind::Ssh {
            bail!("连接 {conn_key} 不是 SSH 类型");
        }
        if !conn.enable {
            bail!("SSH 连接 {conn_key} 已禁用");
        }
        if conn.host_key.is_none() {
            bail!("主机 {conn_key} 尚未信任（未记录主机指纹），拒绝无人值守连接");
        }
        SshTarget::resolve(conn, &cfg.credentials).map_err(|e| anyhow!("{e}"))
    }
}

/// Web Terminal module implementing [`fg_core::module::Module`].
pub struct WebTerminalModule {
    handle: Arc<WebTerminalHandle>,
}

impl WebTerminalModule {
    /// Creates a new module instance from an initialized [`WebTerminalHandle`].
    pub fn new(handle: Arc<WebTerminalHandle>) -> Self {
        Self { handle }
    }

    /// Returns a clone of the shared handle for mounting routes and Deps.
    pub fn handle(&self) -> Arc<WebTerminalHandle> {
        Arc::clone(&self.handle)
    }
}

impl fg_core::module::Module for WebTerminalModule {
    const ID: &'static str = "webterminal";

    async fn run(self, mut drain: watch::Receiver<bool>) -> Result<()> {
        let token = CancellationToken::new();
        let session_janitor = self
            .handle
            .sessions
            .spawn_janitor(token.clone(), Duration::from_secs(15));
        let sftp_janitor = self
            .handle
            .sftp_pool
            .spawn_janitor(token.clone(), Duration::from_secs(30));

        // Wait until drain becomes true or sender drops.
        loop {
            if *drain.borrow() {
                break;
            }
            if drain.changed().await.is_err() {
                break;
            }
        }

        token.cancel();
        let _ = session_janitor.await;
        let _ = sftp_janitor.await;
        self.handle.sftp_pool.close_all();
        // Terminate all active sessions cleanly on shutdown.
        for view in self.handle.sessions.list() {
            self.handle.sessions.close(&view.id);
        }
        Ok(())
    }
}
