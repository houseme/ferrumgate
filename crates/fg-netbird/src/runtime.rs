//! Instance runtime (WP-45 §3.3): one supervised `netbird service run`
//! daemon per enabled managed instance with its own state dir and control
//! address, then a one-shot `netbird up` login (setup key via
//! `NB_SETUP_KEY`, login link surfaced when keyless). Unmanaged instances
//! attach to the system service through its control address instead.
//!
//! Before a managed kernel-mode instance starts, the host is probed for
//! an external kernel-mode NetBird ([`crate::external`]); finding one
//! blocks the instance with a reason. Conflicting instances leave the
//! later one stopped. Draining is bounded by
//! [`crate::model::limits::SHUTDOWN_DEADLINE`].

use std::{
    collections::{BTreeMap, HashSet},
    ffi::OsString,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Result, anyhow, bail};
use fg_config::ConfigStore;
use fg_proc::{LogHandle, Owner, Proc, Spec, Supervisor, install::NETBIRD};
use serde_json::{Value, json};
use tokio::{
    sync::{Notify, RwLock},
    time::timeout,
};

use crate::{
    args, external,
    model::{FileConfig, Instance, ProgramSettings, limits},
    status,
    validate::{self, Conflict},
};

/// The managed program (daemon via `service run`, CLI via subcommands).
pub const PROGRAM: &str = "netbird";
/// Per-instance state directories live under this config-store data dir.
pub const MODULE_DATA_DIR: &str = "netbird";

/// External capabilities (conventions §3.4), injected by the assembler.
#[derive(Clone)]
pub struct Deps {
    pub proc: Arc<Proc>,
    pub fetch: Option<fg_proc::install::HttpGetter>,
    pub logs: Option<LogHandle>,
}

/// Login link tracking with refresh (WP-45 §3.3: 链接过期后自动更新).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoginState {
    pub link: Option<String>,
    pub issued_at: Option<Instant>,
}

impl LoginState {
    /// The stored link is stale and the instance is still not connected:
    /// re-run `up` to fetch a fresh one.
    pub fn needs_refresh(&self, now: Instant) -> bool {
        self.link.is_some()
            && self
                .issued_at
                .is_some_and(|at| now.duration_since(at) >= limits::LOGIN_REFRESH_AFTER)
    }

    pub fn record(&mut self, link: Option<String>, now: Instant) {
        self.issued_at = link.as_ref().map(|_| now);
        self.link = link;
    }
}

/// Per-instance runtime extras kept outside the supervisor.
#[derive(Default)]
struct ExtraState {
    login: LoginState,
    /// `netbird version` probe result.
    version: Option<(u32, u32, u32)>,
    /// Version below 0.75 with a userspace SOCKS5 configured (WP-45
    /// §3.3): the proxy listens on all interfaces regardless.
    old_socks5_warning: bool,
}

/// One tracked instance.
pub struct Handle {
    name: String,
    supervisor: Option<Arc<Supervisor>>,
    state_dir: PathBuf,
    managed: bool,
    fingerprint: String,
    epoch: u64,
    blocked: Option<String>,
    extras: Mutex<ExtraState>,
}

/// Read-only per-instance summary for other modules.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceSnapshot {
    pub key: String,
    pub name: String,
    pub group: String,
    pub enable: bool,
    pub managed: bool,
    pub running: bool,
    pub blocked: Option<String>,
}

pub struct Runtime {
    store: Arc<ConfigStore>,
    proc: Arc<Proc>,
    fetch: Option<fg_proc::install::HttpGetter>,
    logs: LogHandle,
    config: Arc<RwLock<FileConfig>>,
    handles: tokio::sync::Mutex<BTreeMap<String, Handle>>,
    epoch: Arc<AtomicU64>,
    wake: Arc<Notify>,
}

impl Runtime {
    pub fn new(store: Arc<ConfigStore>, deps: Deps, config: Arc<RwLock<FileConfig>>) -> Self {
        Self {
            store,
            proc: deps.proc,
            fetch: deps.fetch,
            logs: deps.logs.unwrap_or_else(LogHandle::tracing),
            config,
            handles: tokio::sync::Mutex::new(BTreeMap::new()),
            epoch: Arc::new(AtomicU64::new(1)),
            wake: Arc::new(Notify::new()),
        }
    }

    pub fn proc(&self) -> &Arc<Proc> {
        &self.proc
    }

    pub fn fetch(&self) -> Option<&fg_proc::install::HttpGetter> {
        self.fetch.as_ref()
    }

    pub fn installer(&self) -> Arc<fg_proc::install::Installer> {
        self.proc.installer(&NETBIRD)
    }

    pub fn config(&self) -> Arc<RwLock<FileConfig>> {
        Arc::clone(&self.config)
    }

    pub fn on_change(&self) -> Arc<dyn Fn() + Send + Sync> {
        let wake = Arc::clone(&self.wake);
        Arc::new(move || wake.notify_one())
    }

    pub fn on_installed(&self) -> Arc<dyn Fn() + Send + Sync> {
        let wake = Arc::clone(&self.wake);
        let epoch = Arc::clone(&self.epoch);
        epoch.fetch_add(1, Ordering::SeqCst);
        Arc::new(move || {
            epoch.fetch_add(1, Ordering::SeqCst);
            wake.notify_one();
        })
    }

    /// The default state directory: `<config>/netbird/<key>`.
    pub fn state_dir(&self, key: &str) -> Result<PathBuf> {
        let base = self.store.data_dir(MODULE_DATA_DIR)?;
        Ok(base.join(sanitize_key(key)))
    }

    pub(crate) fn effective_state_dir(&self, instance: &Instance) -> PathBuf {
        crate::validate::resolved_state_dir(
            instance,
            &self
                .state_dir(&instance.key)
                .unwrap_or_else(|_| std::env::temp_dir().join(format!("netbird-{}", instance.key))),
        )
        .into_owned()
    }

    async fn resolve_cli(&self) -> Option<PathBuf> {
        let config = self.config.read().await;
        self.proc
            .resolve(configured_path(&config.settings), PROGRAM)
            .map(|(_, exe)| exe)
    }

    async fn start_instance(
        &self,
        instance: &Instance,
        daemon_exe: &Path,
    ) -> (Arc<Supervisor>, ExtraState) {
        let dir = self.effective_state_dir(instance);
        let _ = fg_core::fsperm::mkdir_all(&dir, 0o700);
        let mut spec = Spec::new(
            Owner::new(crate::MODULE_ID, instance.name.clone()),
            daemon_exe.to_path_buf(),
        );
        spec.args = args::daemon_args(instance, &dir);
        spec.env = args::daemon_env(instance, &dir);
        spec.cwd = Some(dir.clone());
        let supervisor = Supervisor::new(spec, self.logs.clone());
        let mut extras = ExtraState::default();
        if let Err(error) = supervisor.start().await {
            tracing::warn!(instance = %instance.name, error = %error, "netbird 守护进程启动失败");
            return (supervisor, extras);
        }
        // Version probe once per start: pre-0.75 versions run the
        // userspace SOCKS5 proxy on all interfaces (WP-45 §3.3).
        if instance.userspace
            && !instance.socks5.is_empty()
            && let Some(cli) = self.resolve_cli().await
            && let Ok(lines) = run_cli(
                &cli,
                &args::version_args(instance, &dir),
                &[],
                limits::CLI_TIMEOUT,
            )
            .await
        {
            let version = status::parse_version(&lines.join(" "));
            let old = status::old_version_warns_public_socks(version);
            if old {
                tracing::warn!(
                    instance = %instance.name,
                    "NetBird 版本低于 0.75：用户态 SOCKS5 代理将监听全部地址且无认证"
                );
            }
            extras.version = version;
            extras.old_socks5_warning = old;
        }
        // Login: `netbird up` joins with the setup key (env) or surfaces
        // a login link for the device-code flow. The link lands in the
        // extras the caller stores with the handle.
        let link = self.up_once(instance).await;
        extras.login.record(link, Instant::now());
        (supervisor, extras)
    }

    /// Runs `netbird up` once and returns the login link (if any) from
    /// the raw output. Errors are logged, not fatal — the daemon keeps
    /// running and the status endpoint surfaces the link.
    async fn up_once(&self, instance: &Instance) -> Option<String> {
        let Some(cli) = self.resolve_cli().await else {
            self.logs
                .write(fg_logging::Level::Warn, "找不到程序 netbird，无法执行登录");
            return None;
        };
        let dir = self.effective_state_dir(instance);
        let outcome = run_cli(
            &cli,
            &args::up_args(instance, &dir),
            &args::up_env(instance),
            limits::LOGIN_TIMEOUT,
        )
        .await;
        match outcome {
            Ok(lines) => {
                // Log masked lines; keep the raw link for the UI.
                let link = status::parse_login_link(&lines);
                for raw in &lines {
                    let (level, masked) = fg_proc::supervise::output::process_line(raw);
                    self.logs.write(level, &masked);
                }
                link
            }
            Err(error) => {
                tracing::warn!(
                    instance = %instance.name,
                    error = %error,
                    "netbird up 未完成；等待登录或检查配置"
                );
                None
            }
        }
    }

    /// Blocks (reasons) for the desired config: resource conflicts plus
    /// the external kernel-mode NetBird check for managed kernel
    /// instances (WP-45 §3.3 外部实例检查).
    async fn blocked_reasons(&self, config: &FileConfig) -> BTreeMap<String, String> {
        let dir_of = |instance: &Instance| self.effective_state_dir(instance);
        let mut blocked: BTreeMap<String, String> = BTreeMap::new();
        for conflict in validate::conflicts(config.instances.as_slice(), &|instance: &Instance| {
            dir_of(instance)
        }) {
            let Some(later) = conflict.keys.last() else {
                continue;
            };
            let entry = blocked.entry(later.clone()).or_default();
            if !entry.is_empty() {
                entry.push('；');
            }
            entry.push_str(&describe_conflict(&conflict));
        }
        // External kernel NetBird: one probe round per apply.
        let needs_probe = config
            .instances
            .iter()
            .any(|instance| instance.enable && instance.is_kernel_mode());
        if needs_probe {
            let probe = external::probe_system().await;
            if probe.any()
                && let (Some(cli), Some(instance)) = (
                    self.resolve_cli().await,
                    config
                        .instances
                        .iter()
                        .find(|instance| instance.enable && instance.is_kernel_mode()),
                )
            {
                let connected = self
                    .system_daemon_connected(&cli, instance)
                    .await
                    .unwrap_or(false);
                if let Some(reason) = external::kernel_block_reason(&probe, connected) {
                    for instance in config
                        .instances
                        .iter()
                        .filter(|instance| instance.enable && instance.is_kernel_mode())
                    {
                        let entry = blocked.entry(instance.key.clone()).or_default();
                        if !entry.is_empty() {
                            entry.push('；');
                        }
                        entry.push_str(reason);
                    }
                }
            }
        }
        blocked
    }

    /// `netbird status` against the *system* control address: `Some(true)`
    /// when a daemon answers and is connected to the management plane.
    async fn system_daemon_connected(
        &self,
        cli: &Path,
        kernel_instance: &Instance,
    ) -> Option<bool> {
        let mut external_probe = kernel_instance.clone();
        external_probe.managed = false;
        external_probe.control_addr = external::SYSTEM_SOCKET.to_owned();
        let lines = run_cli(
            cli,
            &args::status_args(&external_probe, Path::new("/")),
            &[],
            limits::CLI_TIMEOUT,
        )
        .await
        .ok()?;
        let body = lines
            .first()
            .and_then(|line| serde_json::from_str::<Value>(line).ok())?;
        Some(status::parse_status(&body).connected())
    }

    /// Synchronizes the running set with the desired config.
    pub async fn apply(&self) {
        let config = self.config.read().await.clone();
        let blocked = self.blocked_reasons(&config).await;
        let resolved = self
            .proc
            .resolve(configured_path(&config.settings), PROGRAM);
        let epoch = self.epoch.load(Ordering::SeqCst);
        let mut handles = self.handles.lock().await;
        let mut live: HashSet<&str> = HashSet::new();
        for instance in &config.instances {
            live.insert(instance.key.as_str());
            if !instance.enable {
                if let Some(handle) = handles.remove(instance.key.as_str()) {
                    stop_handle(handle).await;
                }
                continue;
            }
            let dir = self.effective_state_dir(instance);
            let fingerprint = format!(
                "{}\u{1}{}",
                instance.fingerprint(),
                resolved
                    .as_ref()
                    .map(|(_, exe)| exe.display().to_string())
                    .unwrap_or_default(),
            );
            let keep = matches!(handles.get(instance.key.as_str()), Some(handle)
                if handle.blocked.is_none()
                    && handle.fingerprint == fingerprint
                    && handle.epoch == epoch
                    && (handle.supervisor.is_some() == instance.managed));
            if keep {
                continue;
            }
            if let Some(old) = handles.remove(instance.key.as_str()) {
                stop_handle(old).await;
            }
            let handle = if let Some(reason) = blocked.get(instance.key.as_str()) {
                Handle {
                    name: instance.name.clone(),
                    supervisor: None,
                    state_dir: dir,
                    managed: instance.managed,
                    fingerprint,
                    epoch,
                    blocked: Some(reason.clone()),
                    extras: Mutex::new(ExtraState::default()),
                }
            } else if instance.managed {
                match &resolved {
                    Some((_, daemon_exe)) => {
                        let (supervisor, extras) = self.start_instance(instance, daemon_exe).await;
                        Handle {
                            name: instance.name.clone(),
                            supervisor: Some(supervisor),
                            state_dir: dir,
                            managed: true,
                            fingerprint,
                            epoch,
                            blocked: None,
                            extras: Mutex::new(extras),
                        }
                    }
                    None => Handle {
                        name: instance.name.clone(),
                        supervisor: None,
                        state_dir: dir,
                        managed: true,
                        fingerprint,
                        epoch,
                        blocked: Some(
                            "找不到程序 netbird：请在程序设置中填写路径或在线安装".into(),
                        ),
                        extras: Mutex::new(ExtraState::default()),
                    },
                }
            } else {
                // Unmanaged: nothing to spawn; the CLI talks to the
                // system service.
                Handle {
                    name: instance.name.clone(),
                    supervisor: None,
                    state_dir: dir,
                    managed: false,
                    fingerprint,
                    epoch,
                    blocked: if resolved.is_none() {
                        Some("找不到程序 netbird，无法接入系统服务".into())
                    } else {
                        None
                    },
                    extras: Mutex::new(ExtraState::default()),
                }
            };
            handles.insert(instance.key.clone(), handle);
        }
        let gone: Vec<String> = handles
            .keys()
            .filter(|key| !live.contains(key.as_str()))
            .cloned()
            .collect();
        for key in gone {
            if let Some(handle) = handles.remove(&key) {
                stop_handle(handle).await;
            }
        }
    }

    /// Module loop.
    pub async fn run(self: Arc<Self>, mut drain: tokio::sync::watch::Receiver<bool>) -> Result<()> {
        self.apply().await;
        loop {
            tokio::select! {
                changed = drain.changed() => {
                    if changed.is_err() || *drain.borrow_and_update() {
                        break;
                    }
                }
                _ = self.wake.notified() => self.apply().await,
            }
        }
        self.stop_all().await;
        Ok(())
    }

    /// Restarts exactly one instance.
    pub async fn restart(&self, key: &str) -> Result<()> {
        let instance = self
            .config
            .read()
            .await
            .instances
            .iter()
            .find(|instance| instance.key == key)
            .cloned()
            .ok_or_else(|| anyhow!("实例不存在"))?;
        if !instance.enable {
            bail!("实例未启用");
        }
        if let Some(handle) = self.handles.lock().await.remove(key) {
            stop_handle(handle).await;
        }
        self.apply().await;
        Ok(())
    }

    /// `netbird logout` for one instance (deregisters from management).
    pub async fn logout(&self, key: &str) -> Result<()> {
        let instance = self
            .config
            .read()
            .await
            .instances
            .iter()
            .find(|instance| instance.key == key)
            .cloned()
            .ok_or_else(|| anyhow!("实例不存在"))?;
        self.logout_instance(&instance).await
    }

    async fn logout_instance(&self, instance: &Instance) -> Result<()> {
        let cli = self
            .resolve_cli()
            .await
            .ok_or_else(|| anyhow!("找不到程序 netbird"))?;
        let dir = self.effective_state_dir(instance);
        run_cli(
            &cli,
            &args::logout_args(instance, &dir),
            &[],
            limits::CLI_TIMEOUT,
        )
        .await
        .map(|_| ())
    }

    /// Stops one instance; deletion cleanup keeps custom state dirs.
    pub async fn delete_cleanup(&self, instance: &Instance) {
        let default_dir = self.state_dir(&instance.key).ok();
        let uses_default = if instance.state_dir.is_empty() {
            true
        } else {
            default_dir
                .as_ref()
                .map(|default| self.effective_state_dir(instance) == *default)
                .unwrap_or(false)
        };
        if let Some(handle) = self.handles.lock().await.remove(instance.key.as_str()) {
            stop_handle(handle).await;
        }
        if instance.managed
            && uses_default
            && let Err(error) = self.logout_instance(instance).await
        {
            tracing::debug!(
                instance = %instance.name,
                %error,
                "删除实例前退出登录失败（继续删除目录）"
            );
        }
        if uses_default
            && let Some(dir) = default_dir
            && let Err(error) = std::fs::remove_dir_all(&dir)
        {
            tracing::debug!(dir = %dir.display(), %error, "删除实例状态目录失败");
        }
    }

    /// Full status of one instance.
    pub async fn status(&self, key: &str) -> Result<Value> {
        let (handle_name, supervisor, managed, blocked, dir, instance) = {
            let handles = self.handles.lock().await;
            let handle = handles
                .get(key)
                .ok_or_else(|| anyhow!("实例未启用或不存在"))?;
            (
                handle.name.clone(),
                handle.supervisor.clone(),
                handle.managed,
                handle.blocked.clone(),
                handle.state_dir.clone(),
                self.config
                    .read()
                    .await
                    .instances
                    .iter()
                    .find(|instance| instance.key == key)
                    .cloned(),
            )
        };
        let state = supervisor
            .as_ref()
            .map(|supervisor| supervisor.state())
            .unwrap_or_default();
        let extras: Option<ExtraState> = {
            let handles = self.handles.lock().await;
            handles.get(key).and_then(|handle| {
                handle.extras.lock().ok().map(|extras| ExtraState {
                    login: extras.login.clone(),
                    version: extras.version,
                    old_socks5_warning: extras.old_socks5_warning,
                })
            })
        };
        let mut result = json!({
            "key": key,
            "name": handle_name,
            "managed": managed,
            "running": state.running,
            "pid": state.pid,
            "since": rfc3339(state.since),
            "uptimeSecs": state.uptime().map(|uptime| uptime.as_secs()),
            "restarts": state.restarts,
            "failed": state.failed,
            "blocked": blocked,
            "loginUrl": extras.as_ref().and_then(|e| e.login.link.clone()),
            "oldVersionSocks5Warning": extras.as_ref().map(|e| e.old_socks5_warning).unwrap_or(false),
        });
        if let Some(instance) = &instance {
            result["userspace"] = json!(instance.userspace);
            result["socks5"] = json!(instance.socks5);
        }
        let cli = self.resolve_cli().await;
        let should_query =
            cli.is_some() && ((managed && state.running) || (!managed && blocked.is_none()));
        if let (true, Some(cli), Some(instance)) = (should_query, cli, &instance) {
            match run_cli(
                &cli,
                &args::status_args(instance, &dir),
                &[],
                limits::CLI_TIMEOUT,
            )
            .await
            {
                Ok(lines) => {
                    let parsed = lines
                        .first()
                        .and_then(|line| serde_json::from_str::<Value>(line).ok())
                        .map(|body| status::parse_status(&body))
                        .unwrap_or_default();
                    result["managementUrl"] = json!(parsed.management_url);
                    result["managementConnected"] = json!(parsed.management_connected);
                    result["connected"] = json!(parsed.connected());
                    result["localIp"] = json!(parsed.local_ip);
                    result["peers"] =
                        serde_json::to_value(&parsed.peers).unwrap_or(Value::Array(vec![]));
                    if !managed {
                        result["running"] = json!(true);
                    }
                    // Stale login link: fetch a fresh one (WP-45 §3.3).
                    if managed && !parsed.connected() {
                        let stale =
                            {
                                let handles = self.handles.lock().await;
                                handles
                                    .get(key)
                                    .and_then(|handle| {
                                        handle.extras.lock().ok().map(|extras| {
                                            extras.login.needs_refresh(Instant::now())
                                        })
                                    })
                                    .unwrap_or(false)
                            };
                        if stale && let Some(link) = self.up_once(instance).await {
                            self.record_login(key, Some(link)).await;
                        }
                    }
                }
                Err(error) => {
                    result["error"] = json!(error.to_string());
                    if !managed {
                        result["running"] = json!(false);
                    }
                }
            }
        }
        Ok(result)
    }

    /// Read-only snapshots for other modules and the module status page.
    pub async fn snapshot(&self) -> Vec<InstanceSnapshot> {
        let config = self.config.read().await.clone();
        let handles = self.handles.lock().await;
        snapshot_of(&config, &handles)
    }

    /// Non-blocking variant for diagnostics and tests that poll.
    pub fn try_snapshot(&self) -> Option<Vec<InstanceSnapshot>> {
        let config = self.config.try_read().ok()?.clone();
        let handles = self.handles.try_lock().ok()?;
        Some(snapshot_of(&config, &handles))
    }

    /// Bounded stop of every instance.
    pub async fn stop_all(&self) {
        let taken = std::mem::take(&mut *self.handles.lock().await);
        if taken.is_empty() {
            return;
        }
        let tasks: Vec<_> = taken
            .into_values()
            .map(|handle| tokio::spawn(async move { stop_handle(handle).await }))
            .collect();
        let _ = timeout(limits::SHUTDOWN_DEADLINE, futures_all(tasks)).await;
    }

    /// Reset to factory defaults (WP-45 §3.3): stop everything, log out
    /// managed instances on default dirs, restore defaults, remove the
    /// generated per-instance state directories.
    pub async fn reset(&self) -> Result<()> {
        let instances = self.config.read().await.instances.clone();
        self.stop_all().await;
        for instance in &instances {
            if instance.managed
                && instance.state_dir.is_empty()
                && let Err(error) = self.logout_instance(instance).await
            {
                tracing::debug!(instance = %instance.name, %error, "恢复默认时退出登录失败");
            }
        }
        self.store
            .save(crate::CONFIG_NAME, &FileConfig::default())
            .map_err(|error| anyhow!("保存重置后的配置失败：{error}"))?;
        for instance in &instances {
            if instance.state_dir.is_empty()
                && let Ok(dir) = self.state_dir(&instance.key)
                && let Err(error) = std::fs::remove_dir_all(&dir)
            {
                tracing::debug!(dir = %dir.display(), %error, "清理实例状态目录失败");
            }
        }
        *self.config.write().await = FileConfig::default();
        tracing::info!(module = crate::MODULE_ID, "已恢复默认配置并清理状态目录");
        Ok(())
    }
}

impl Runtime {
    /// Stores a refreshed login link in the handle's login state.
    async fn record_login(&self, key: &str, link: Option<String>) {
        let handles = self.handles.lock().await;
        if let Some(handle) = handles.get(key)
            && let Ok(mut extras) = handle.extras.lock()
        {
            extras.login.record(link, Instant::now());
        }
    }
}

fn snapshot_of(config: &FileConfig, handles: &BTreeMap<String, Handle>) -> Vec<InstanceSnapshot> {
    config
        .instances
        .iter()
        .map(|instance| {
            let running = handles
                .get(instance.key.as_str())
                .and_then(|handle| handle.supervisor.as_ref())
                .map(|supervisor| supervisor.state().running)
                .unwrap_or(false);
            InstanceSnapshot {
                key: instance.key.clone(),
                name: instance.name.clone(),
                group: instance.group.clone(),
                enable: instance.enable,
                managed: instance.managed,
                running,
                blocked: handles
                    .get(instance.key.as_str())
                    .and_then(|handle| handle.blocked.clone()),
            }
        })
        .collect()
}

async fn futures_all(tasks: Vec<tokio::task::JoinHandle<()>>) {
    for task in tasks {
        let _ = task.await;
    }
}

fn configured_path(settings: &ProgramSettings) -> Option<&Path> {
    let path = settings.program_path.trim();
    if path.is_empty() {
        None
    } else {
        Some(Path::new(path))
    }
}

pub(crate) fn describe_conflict(conflict: &Conflict) -> String {
    let params = conflict
        .params
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("{}（{params}）", conflict.message_key)
}

async fn stop_handle(handle: Handle) {
    let Handle { supervisor, .. } = handle;
    if let Some(supervisor) = supervisor
        && let Err(error) = supervisor.stop().await
    {
        tracing::warn!(error = %error, "停止 netbird 守护进程失败");
    }
}

/// Runs a one-shot CLI command; returns the RAW output lines. Callers
/// must run each line through the fg-proc masking before logging (login
/// links carry one-time tokens).
async fn run_cli(
    exe: &Path,
    args: &[OsString],
    env: &[(OsString, OsString)],
    limit: Duration,
) -> Result<Vec<String>> {
    let mut command = tokio::process::Command::new(exe);
    command
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = timeout(limit, command.output())
        .await
        .map_err(|_| anyhow!("netbird 命令超时"))?
        .map_err(|error| anyhow!("运行 netbird 失败：{error}"))?;
    let lines: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .chain(String::from_utf8_lossy(&output.stderr).lines())
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect();
    if !output.status.success() {
        let reason = lines
            .last()
            .cloned()
            .unwrap_or_else(|| format!("退出码 {}", output.status.code().unwrap_or(-1)));
        bail!("{reason}");
    }
    Ok(lines)
}

pub(crate) fn rfc3339(at: Option<SystemTime>) -> Option<String> {
    at.map(|at| {
        let at: time::OffsetDateTime = at.into();
        at.format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default()
    })
}

fn sanitize_key(key: &str) -> String {
    let clean: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if clean.is_empty() {
        "unknown".to_owned()
    } else {
        clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netbird_rfc3339_and_sanitize_key_helpers() {
        let stamp = rfc3339(Some(SystemTime::UNIX_EPOCH)).expect("stamp");
        assert!(stamp.starts_with("1970-01-01T00:00:00Z"), "{stamp}");
        assert_eq!(rfc3339(None), None);
        assert_eq!(sanitize_key("k_1"), "k_1");
        assert_eq!(sanitize_key("../x"), "x");
        assert_eq!(sanitize_key(""), "unknown");
    }

    #[test]
    fn netbird_conflict_description_lists_params() {
        let conflict = Conflict {
            keys: vec!["a".into(), "b".into()],
            message_key: crate::validate::messages::WG_PORT,
            params: vec![("port".into(), "51820".into())],
        };
        let text = describe_conflict(&conflict);
        assert!(text.contains(crate::validate::messages::WG_PORT));
        assert!(text.contains("port=51820"));
    }

    #[test]
    fn netbird_login_link_refresh() {
        let now = Instant::now();
        let mut login = LoginState::default();
        assert!(!login.needs_refresh(now), "没有链接时不刷新");
        login.record(Some("https://login.example/one".into()), now);
        assert_eq!(login.link.as_deref(), Some("https://login.example/one"));
        assert!(
            !login.needs_refresh(now + limits::LOGIN_REFRESH_AFTER - Duration::from_secs(1)),
            "链接还新鲜"
        );
        assert!(
            login.needs_refresh(now + limits::LOGIN_REFRESH_AFTER),
            "过期后需要刷新"
        );
        // Recording again resets the clock.
        login.record(
            Some("https://login.example/two".into()),
            now + Duration::from_secs(60),
        );
        assert_eq!(login.link.as_deref(), Some("https://login.example/two"));
        assert!(!login.needs_refresh(
            now + Duration::from_secs(60) + limits::LOGIN_REFRESH_AFTER - Duration::from_secs(1)
        ));
        // Clearing the link (login completed) stops refreshes.
        login.record(None, now);
        assert!(!login.needs_refresh(now + Duration::from_secs(3600)));
    }
}
