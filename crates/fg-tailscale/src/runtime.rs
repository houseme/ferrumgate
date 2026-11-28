//! Instance runtime (WP-45 §3.3): one supervised `tailscaled` per enabled
//! managed instance with its own state directory and control socket, then
//! a one-shot `tailscale up` login. Unmanaged instances attach to the
//! system daemon through the control socket instead of spawning anything.
//!
//! Change application follows the upstream rule: editing or toggling an
//! instance restarts only that instance; a group or remark edit does not
//! restart anything. Conflicting instances (two kernel modes, shared
//! sockets / state dirs / fixed ports) leave the later one stopped with
//! the reason attached. Draining is bounded by
//! [`crate::model::limits::SHUTDOWN_DEADLINE`].

use std::{
    collections::{BTreeMap, HashSet},
    ffi::OsString,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};

use anyhow::{Result, anyhow, bail};
use fg_config::ConfigStore;
use fg_proc::{LogHandle, Owner, Proc, Spec, Supervisor, install::TAILSCALE};
use serde_json::{Value, json};
use tokio::{
    sync::{Notify, RwLock},
    time::timeout,
};

use crate::{
    args,
    model::{FileConfig, Instance, ProgramSettings, limits},
    status,
    validate::{self, Conflict},
};

/// The managed daemon program.
pub const DAEMON_PROGRAM: &str = "tailscaled";
/// The CLI program (login, status, logout).
pub const CLI_PROGRAM: &str = "tailscale";
/// Per-instance state directories live under this config-store data dir.
pub const MODULE_DATA_DIR: &str = "tailscale";

/// External capabilities (conventions §3.4), injected by the assembler.
#[derive(Clone)]
pub struct Deps {
    pub proc: Arc<Proc>,
    pub fetch: Option<fg_proc::install::HttpGetter>,
    pub logs: Option<LogHandle>,
}

/// One tracked instance.
pub struct Handle {
    name: String,
    /// The supervised `tailscaled`; `None` for unmanaged instances (the
    /// system daemon is not ours to own).
    supervisor: Option<Arc<Supervisor>>,
    state_dir: PathBuf,
    /// `false` for unmanaged instances.
    managed: bool,
    fingerprint: String,
    epoch: u64,
    /// Conflict / missing-program reason: the instance is not running.
    blocked: Option<String>,
}

/// Read-only per-instance summary for other modules (WP-45 状态输出面).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceSnapshot {
    pub key: String,
    pub name: String,
    pub group: String,
    pub enable: bool,
    pub managed: bool,
    /// Managed: the supervised daemon runs. Unmanaged: unknown here —
    /// query the status endpoint.
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
        self.proc.installer(&TAILSCALE)
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

    /// The default state directory for one instance:
    /// `<config>/tailscale/<key>` (WP-45 §3.4).
    pub fn state_dir(&self, key: &str) -> Result<PathBuf> {
        let base = self.store.data_dir(MODULE_DATA_DIR)?;
        Ok(base.join(sanitize_key(key)))
    }

    /// The effective state directory: the custom one when set.
    pub(crate) fn effective_state_dir(&self, instance: &Instance) -> PathBuf {
        if instance.state_dir.is_empty() {
            self.state_dir(&instance.key).unwrap_or_else(|_| {
                std::env::temp_dir().join(format!("tailscale-{}", instance.key))
            })
        } else {
            PathBuf::from(&instance.state_dir)
        }
    }

    fn socket_of(&self, instance: &Instance) -> String {
        args::control_socket(instance, &self.effective_state_dir(instance))
    }

    async fn start_instance(
        &self,
        instance: &Instance,
        daemon_exe: &Path,
    ) -> (Arc<Supervisor>, bool) {
        let dir = self.effective_state_dir(instance);
        let _ = fg_core::fsperm::mkdir_all(&dir, 0o700);
        // Kernel mode may need the nf_tables backend (Linux hosts); the
        // detection is best effort.
        let nftables = detect_nftables().await;
        let mut spec = Spec::new(
            Owner::new(crate::MODULE_ID, instance.name.clone()),
            daemon_exe.to_path_buf(),
        );
        spec.args = args::daemon_args(instance, &dir);
        spec.env = args::daemon_env(instance, nftables);
        spec.cwd = Some(dir.clone());
        let supervisor = Supervisor::new(spec, self.logs.clone());
        if let Err(error) = supervisor.start().await {
            tracing::warn!(instance = %instance.name, error = %error, "tailscaled 启动失败");
            return (supervisor, false);
        }
        // Login: `tailscale up` is one-shot and bounded; without an auth
        // key it may wait for the browser login — the daemon keeps
        // running and the status endpoint surfaces the login link.
        let cli_exe = self.proc.resolve(
            configured_path(&self.config.read().await.settings),
            CLI_PROGRAM,
        );
        match cli_exe {
            Some((_, cli_exe)) => {
                let outcome = run_cli(
                    &cli_exe,
                    &args::up_args(instance, &dir),
                    &args::up_env(instance),
                    limits::LOGIN_TIMEOUT,
                )
                .await;
                match outcome {
                    Ok(lines) => {
                        for line in lines {
                            self.logs.write(fg_logging::Level::Info, &line);
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            instance = %instance.name,
                            error = %error,
                            "tailscale up 未完成；等待登录或检查配置"
                        );
                        self.logs.write(fg_logging::Level::Warn, &error.to_string());
                    }
                }
            }
            None => {
                self.logs.write(
                    fg_logging::Level::Warn,
                    "找不到程序 tailscale，无法执行登录",
                );
            }
        }
        (supervisor, true)
    }

    /// Synchronizes the running set with the desired config.
    pub async fn apply(&self) {
        let config = self.config.read().await.clone();
        let blocked = self.blocked_reasons(&config).await;
        let daemon = self
            .proc
            .resolve(configured_path(&config.settings), DAEMON_PROGRAM);
        let cli = self
            .proc
            .resolve(configured_path(&config.settings), CLI_PROGRAM);
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
                "{}\u{1}{}\u{1}{}",
                instance.fingerprint(),
                daemon
                    .as_ref()
                    .map(|(_, exe)| exe.display().to_string())
                    .unwrap_or_default(),
                cli.as_ref()
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
                }
            } else if instance.managed {
                match &daemon {
                    Some((_, daemon_exe)) => {
                        let (supervisor, _) = self.start_instance(instance, daemon_exe).await;
                        Handle {
                            name: instance.name.clone(),
                            supervisor: Some(supervisor),
                            state_dir: dir,
                            managed: true,
                            fingerprint,
                            epoch,
                            blocked: None,
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
                            "找不到程序 tailscaled：请在程序设置中填写路径或在线安装（仅 Linux）"
                                .into(),
                        ),
                    },
                }
            } else if cli.is_none() {
                Handle {
                    name: instance.name.clone(),
                    supervisor: None,
                    state_dir: dir,
                    managed: false,
                    fingerprint,
                    epoch,
                    blocked: Some("找不到程序 tailscale，无法接入系统守护进程".into()),
                }
            } else {
                Handle {
                    name: instance.name.clone(),
                    supervisor: None,
                    state_dir: dir,
                    managed: false,
                    fingerprint,
                    epoch,
                    blocked: None,
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

    async fn blocked_reasons(&self, config: &FileConfig) -> BTreeMap<String, String> {
        let socket_of = |instance: &Instance| self.socket_of(instance);
        let dir_of = |instance: &Instance| self.effective_state_dir(instance).display().to_string();
        let mut blocked: BTreeMap<String, String> = BTreeMap::new();
        for conflict in validate::conflicts(config.instances.as_slice(), &socket_of, &dir_of) {
            let Some(later) = conflict.keys.last() else {
                continue;
            };
            let entry = blocked.entry(later.clone()).or_default();
            if !entry.is_empty() {
                entry.push('；');
            }
            entry.push_str(&describe_conflict(&conflict));
        }
        blocked
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

    /// `tailscale logout` against the instance's socket (WP-45 §3.3:
    /// 退出登录从管理端注销本机).
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

    /// Logout for an instance value that the caller already holds — the
    /// config may have dropped it already (deletion, reset).
    async fn logout_instance(&self, instance: &Instance) -> Result<()> {
        let cli_exe = self
            .proc
            .resolve(
                configured_path(&self.config.read().await.settings),
                CLI_PROGRAM,
            )
            .map(|(_, exe)| exe)
            .ok_or_else(|| anyhow!("找不到程序 tailscale"))?;
        let dir = self.effective_state_dir(instance);
        run_cli(
            &cli_exe,
            &args::logout_args(instance, &dir),
            &[],
            limits::CLI_TIMEOUT,
        )
        .await
        .map(|_| ())
    }

    /// Stops one instance and performs the deletion cleanup (WP-45 §3.3):
    /// managed instances on the default state dir log out first and the
    /// directory is removed; custom state directories are kept.
    pub async fn delete_cleanup(&self, instance: &Instance) {
        let default_dir = self.state_dir(&instance.key).ok();
        let uses_default = match (&default_dir, instance.state_dir.is_empty()) {
            (_, true) => true,
            (Some(default), false) => self.effective_state_dir(instance) == *default,
            (None, false) => false,
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
        });
        if let Some(instance) = &instance {
            result["userspace"] = json!(instance.userspace);
            result["socks5"] = json!(instance.socks5);
        }
        // Query the daemon through the CLI: managed instances while
        // running, unmanaged instances always (a successful query proves
        // the system daemon is alive).
        let cli_exe = self
            .proc
            .resolve(
                configured_path(&self.config.read().await.settings),
                CLI_PROGRAM,
            )
            .map(|(_, exe)| exe);
        let should_query =
            cli_exe.is_some() && ((managed && state.running) || (!managed && blocked.is_none()));
        if should_query {
            let cli_exe = cli_exe.expect("checked");
            match run_cli(
                &cli_exe,
                &args::status_args(instance.as_ref().expect("enabled instance"), &dir),
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
                    result["backendState"] = json!(parsed.backend_state);
                    result["connected"] = json!(parsed.connected());
                    result["loginUrl"] = json!(parsed.login_url);
                    result["version"] = json!(parsed.version);
                    result["selfHostname"] = json!(parsed.self_hostname);
                    result["selfIps"] = json!(parsed.self_ips);
                    result["tailnetName"] = json!(parsed.tailnet_name);
                    result["peers"] =
                        serde_json::to_value(&parsed.peers).unwrap_or(Value::Array(vec![]));
                    if !managed {
                        result["running"] = json!(true);
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
    /// the managed instances that use our default state dirs, restore the
    /// default settings and instance list, and delete the generated files.
    /// Installed programs and custom state directories are kept.
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
        // Remove the generated per-instance state directories; unknown
        // content in the module data dir survives.
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
        tracing::warn!(error = %error, "停止 tailscaled 失败");
    }
}

/// Runs a one-shot CLI command; returns the cleaned, masked output lines.
/// Raw output never reaches the log or the API (WP-45 §8).
async fn run_cli(
    exe: &Path,
    args: &[OsString],
    env: &[(OsString, OsString)],
    limit: std::time::Duration,
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
        .map_err(|_| anyhow!("tailscale 命令超时"))?
        .map_err(|error| anyhow!("运行 tailscale 失败：{error}"))?;
    let mut lines: Vec<String> = Vec::new();
    for raw in String::from_utf8_lossy(&output.stdout)
        .lines()
        .chain(String::from_utf8_lossy(&output.stderr).lines())
    {
        let (level, line) = fg_proc::supervise::output::process_line(raw);
        if line.trim().is_empty() {
            continue;
        }
        lines.push(line);
        let _ = level;
    }
    if !output.status.success() {
        let reason = lines
            .last()
            .cloned()
            .unwrap_or_else(|| format!("退出码 {}", output.status.code().unwrap_or(-1)));
        bail!("{reason}");
    }
    Ok(lines)
}

/// Best-effort detection of the nf_tables iptables backend (Linux only).
pub async fn detect_nftables() -> bool {
    #[cfg(target_os = "linux")]
    {
        for program in ["iptables", "/usr/sbin/iptables"] {
            let output = tokio::process::Command::new(program)
                .arg("--version")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .output()
                .await;
            if let Ok(output) = output
                && String::from_utf8_lossy(&output.stdout).contains("nf_tables")
            {
                return true;
            }
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

pub(crate) fn rfc3339(at: Option<SystemTime>) -> Option<String> {
    at.map(|at| {
        let at: time::OffsetDateTime = at.into();
        at.format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default()
    })
}

/// Instance keys are validated at the API boundary; this guard keeps path
/// building safe even for keys read back from an edited file.
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
    fn runtime_rfc3339_and_sanitize_key_helpers() {
        let stamp = rfc3339(Some(SystemTime::UNIX_EPOCH)).expect("stamp");
        assert!(stamp.starts_with("1970-01-01T00:00:00Z"), "{stamp}");
        assert_eq!(rfc3339(None), None);
        assert_eq!(sanitize_key("k-1"), "k-1");
        assert_eq!(sanitize_key("../x"), "x");
        assert_eq!(sanitize_key(""), "unknown");
    }

    #[test]
    fn runtime_conflict_description_lists_params() {
        let conflict = Conflict {
            keys: vec!["a".into(), "b".into()],
            message_key: crate::validate::messages::PORT,
            params: vec![("port".into(), "41841".into())],
        };
        let text = describe_conflict(&conflict);
        assert!(text.contains(crate::validate::messages::PORT));
        assert!(text.contains("port=41841"));
    }
}
