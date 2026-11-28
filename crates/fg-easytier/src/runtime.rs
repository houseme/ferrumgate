//! Instance runtime (WP-45 §3.3): one supervised `easytier-core` process
//! per enabled instance, each with its own state directory under the
//! config store and its own randomly allocated loopback management portal.
//!
//! Change application follows the upstream rule: editing or toggling an
//! instance restarts only that instance's process; a group or remark edit
//! does not restart anything (the fingerprint in [`crate::model`] covers
//! the behavior-affecting fields only). Conflicting instances are left
//! stopped with the reason attached — the later one in saved order yields.
//!
//! Draining is bounded: every supervisor gets its own graceful stop (5 s
//! grace inside fg-proc) and the whole shutdown finishes within
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
use fg_proc::{LogHandle, Owner, Proc, Spec, Supervisor, install::EASYTIER};
use serde_json::{Value, json};
use tokio::{
    net::TcpListener,
    sync::{Notify, RwLock},
    time::timeout,
};

use crate::{
    args,
    model::{FileConfig, Instance, ProgramSettings, limits},
    status,
    validate::{self, Conflict},
};

/// The managed daemon program (`files[0]` of the [`EASYTIER`] spec).
pub const CORE_PROGRAM: &str = "easytier-core";
/// The status query program.
pub const CLI_PROGRAM: &str = "easytier-cli";
/// Per-instance state directories live under this config-store data dir.
pub const MODULE_DATA_DIR: &str = "easytier";

/// External capabilities (conventions §3.4), injected by the assembler.
#[derive(Clone)]
pub struct Deps {
    /// Process infrastructure: binary resolution, supervision, installer.
    pub proc: Arc<Proc>,
    /// Outbound HTTP for online install / update checks. `None` disables
    /// them (the endpoints answer with a download error).
    pub fetch: Option<fg_proc::install::HttpGetter>,
    /// Where supervised process output goes. Defaults to the tracing
    /// bridge; the assembler swaps in the fg-logging handle when the
    /// module log source exists.
    pub logs: Option<LogHandle>,
}

/// One tracked instance: its supervisor (when running or attempted), the
/// allocated portal and the fingerprint of the configuration it was
/// started with.
pub struct Handle {
    name: String,
    supervisor: Option<Arc<Supervisor>>,
    portal: u16,
    fingerprint: String,
    epoch: u64,
    /// Conflict reason: the process is intentionally not started.
    blocked: Option<String>,
}

/// Read-only per-instance summary for other modules and the module
/// status endpoint (WP-45: 状态输出面按文档，供其他模块消费的只读快照).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceSnapshot {
    pub key: String,
    pub name: String,
    pub group: String,
    pub enable: bool,
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
    /// Bumped when the installed program changed: running instances are
    /// restarted on the next apply.
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

    /// The installer shared for the module program (WP-43 semantics: one
    /// instance per spec, so the busy flag and progress channel are unique).
    pub fn installer(&self) -> Arc<fg_proc::install::Installer> {
        self.proc.installer(&EASYTIER)
    }

    pub fn config(&self) -> Arc<RwLock<FileConfig>> {
        Arc::clone(&self.config)
    }

    /// The change hook for the routes: apply the new desired state.
    pub fn on_change(&self) -> Arc<dyn Fn() + Send + Sync> {
        let wake = Arc::clone(&self.wake);
        Arc::new(move || wake.notify_one())
    }

    /// The online-install completion hook: bump the epoch so running
    /// instances restart onto the new binary, then apply.
    pub fn on_installed(&self) -> Arc<dyn Fn() + Send + Sync> {
        let wake = Arc::clone(&self.wake);
        let epoch = Arc::clone(&self.epoch);
        epoch.fetch_add(1, Ordering::SeqCst);
        Arc::new(move || {
            epoch.fetch_add(1, Ordering::SeqCst);
            wake.notify_one();
        })
    }

    /// The per-instance state directory: always the default
    /// `<config>/easytier/<key>` for this module (the model has no custom
    /// state dir field, WP-45 §3.2).
    pub fn state_dir(&self, key: &str) -> Result<PathBuf> {
        let base = self.store.data_dir(MODULE_DATA_DIR)?;
        Ok(base.join(sanitize_key(key)))
    }

    async fn alloc_portal(&self) -> Result<u16> {
        let listener = TcpListener::bind(args::portal_address(0)).await?;
        let port = listener.local_addr()?.port();
        drop(listener);
        Ok(port)
    }

    async fn start_instance(&self, instance: &Instance, exe: &Path) -> (Arc<Supervisor>, u16) {
        let state_dir = self
            .state_dir(&instance.key)
            .unwrap_or_else(|_| std::env::temp_dir().join(format!("easytier-{}", instance.key)));
        let _ = fg_core::fsperm::mkdir_all(&state_dir, 0o700);
        let portal = match self.alloc_portal().await {
            Ok(portal) => portal,
            Err(error) => {
                tracing::warn!(instance = %instance.name, error = %error, "分配管理端口失败");
                return (idle_supervisor(instance, exe, &state_dir, &self.logs), 0);
            }
        };
        let mut spec = Spec::new(
            Owner::new(crate::MODULE_ID, instance.name.clone()),
            exe.to_path_buf(),
        );
        spec.args = args::core_args(instance, portal);
        spec.env = args::core_env(instance);
        spec.cwd = Some(state_dir.clone());
        let supervisor = Supervisor::new(spec, self.logs.clone());
        if let Err(error) = supervisor.start().await {
            // fg-proc keeps the failure reason in its state; do not retry
            // until the config changes or the user restarts.
            tracing::warn!(instance = %instance.name, error = %error, "EasyTier 实例启动失败");
        }
        (supervisor, portal)
    }

    /// Synchronizes the running set with the desired config. Called at
    /// module start, on every config change and after installs.
    pub async fn apply(&self) {
        let config = self.config.read().await.clone();
        let blocked = blocked_reasons(&config);
        let resolved = self
            .proc
            .resolve(configured_path(&config.settings), CORE_PROGRAM);
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
            let fingerprint = instance_fingerprint(instance, resolved.as_ref());
            let keep = matches!(handles.get(instance.key.as_str()), Some(handle)
                if handle.blocked.is_none()
                    && handle.fingerprint == fingerprint
                    && handle.epoch == epoch
                    && handle.supervisor.is_some());
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
                    portal: 0,
                    fingerprint,
                    epoch,
                    blocked: Some(reason.clone()),
                }
            } else if let Some((_, exe)) = &resolved {
                let (supervisor, portal) = self.start_instance(instance, exe).await;
                Handle {
                    name: instance.name.clone(),
                    supervisor: Some(supervisor),
                    portal,
                    fingerprint,
                    epoch,
                    blocked: None,
                }
            } else {
                Handle {
                    name: instance.name.clone(),
                    supervisor: None,
                    portal: 0,
                    fingerprint,
                    epoch,
                    blocked: Some(
                        "找不到程序 easytier-core：请在程序设置中填写路径或在线安装".into(),
                    ),
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

    /// Module loop: apply once, re-apply on change/install signals, and
    /// stop everything (bounded) on drain.
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

    /// Restarts exactly one instance: drops its handle and re-applies, so
    /// every other process keeps running (WP-45 test
    /// `restart_only_own_instance`).
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

    /// Stops one instance and performs the deletion cleanup: this module
    /// has only default state directories, so the directory is removed.
    pub async fn delete_cleanup(&self, instance: &Instance) {
        if let Some(handle) = self.handles.lock().await.remove(instance.key.as_str()) {
            stop_handle(handle).await;
        }
        match self.state_dir(&instance.key) {
            Ok(dir) => {
                if let Err(error) = std::fs::remove_dir_all(&dir) {
                    tracing::debug!(dir = %dir.display(), %error, "删除实例状态目录失败");
                }
            }
            Err(error) => tracing::debug!(%error, "解析实例状态目录失败"),
        }
    }

    /// Full status of one instance: supervisor state plus the network
    /// status queried from the management portal.
    pub async fn status(&self, key: &str) -> Result<Value> {
        let (handle_name, supervisor, portal, blocked) = {
            let handles = self.handles.lock().await;
            let handle = handles
                .get(key)
                .ok_or_else(|| anyhow!("实例未启用或不存在"))?;
            (
                handle.name.clone(),
                handle.supervisor.clone(),
                handle.portal,
                handle.blocked.clone(),
            )
        };
        let state = supervisor
            .as_ref()
            .map(|supervisor| supervisor.state())
            .unwrap_or_default();
        let mut result = json!({
            "key": key,
            "name": handle_name,
            "running": state.running,
            "pid": state.pid,
            "since": rfc3339(state.since),
            "uptimeSecs": state.uptime().map(|uptime| uptime.as_secs()),
            "restarts": state.restarts,
            "failed": state.failed,
            "lastExit": last_exit_json(state.last_exit.as_ref()),
            "blocked": blocked,
            "portal": if state.running { portal } else { 0 },
            "node": Value::Null,
            "peers": [],
        });
        if supervisor.is_some() && state.running {
            let config = self.config.read().await.clone();
            match self
                .proc
                .resolve(configured_path(&config.settings), CLI_PROGRAM)
            {
                Some((_, cli_exe)) => {
                    let node = run_cli(&cli_exe, &args::cli_args(portal, "node")).await;
                    let peers = run_cli(&cli_exe, &args::cli_args(portal, "peer")).await;
                    match (node, peers) {
                        (Ok(node), Ok(peers)) => {
                            let parsed = status::InstanceStatus {
                                node: Some(status::parse_node(&node)),
                                peers: status::parse_peers(&peers),
                                error: None,
                            };
                            result["node"] =
                                serde_json::to_value(&parsed.node).unwrap_or(Value::Null);
                            result["peers"] =
                                serde_json::to_value(&parsed.peers).unwrap_or(Value::Array(vec![]));
                        }
                        (Err(error), _) | (_, Err(error)) => {
                            result["error"] = json!(error.to_string());
                        }
                    }
                }
                None => {
                    result["error"] = json!("找不到程序 easytier-cli");
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

    /// Non-blocking variant: `None` when a lock is currently held. Used by
    /// diagnostics and tests that poll.
    pub fn try_snapshot(&self) -> Option<Vec<InstanceSnapshot>> {
        let config = self.config.try_read().ok()?.clone();
        let handles = self.handles.try_lock().ok()?;
        Some(snapshot_of(&config, &handles))
    }

    /// Bounded stop of every instance: all supervisors stop concurrently,
    /// the whole shutdown finishes within [`limits::SHUTDOWN_DEADLINE`].
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

    /// Reset to factory defaults (WP-45 §3.3): stop every process,
    /// restore the default settings and instance list (the old config
    /// stays in the config history), and delete the generated per-instance
    /// state directories. Installed programs are kept.
    pub async fn reset(&self) -> Result<()> {
        let instances = self.config.read().await.instances.clone();
        self.stop_all().await;
        self.store
            .save(crate::CONFIG_NAME, &FileConfig::default())
            .map_err(|error| anyhow!("保存重置后的配置失败：{error}"))?;
        // Remove the generated per-instance state directories; unknown
        // content in the module data dir survives.
        for instance in &instances {
            if let Ok(dir) = self.state_dir(&instance.key)
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

/// Joins all stop tasks; spawned because the map lock must not be held
/// across the (slow) stops.
async fn futures_all(tasks: Vec<tokio::task::JoinHandle<()>>) {
    for task in tasks {
        let _ = task.await;
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
                running,
                blocked: handles
                    .get(instance.key.as_str())
                    .and_then(|handle| handle.blocked.clone()),
            }
        })
        .collect()
}

fn configured_path(settings: &ProgramSettings) -> Option<&Path> {
    let path = settings.program_path.trim();
    if path.is_empty() {
        None
    } else {
        Some(Path::new(path))
    }
}

fn instance_fingerprint(
    instance: &Instance,
    resolved: Option<&(fg_proc::ResolvedFrom, PathBuf)>,
) -> String {
    let exe = resolved
        .map(|(_, exe)| exe.display().to_string())
        .unwrap_or_default();
    format!("{}\u{1}\u{2}{}", instance.fingerprint(), exe)
}

fn blocked_reasons(config: &FileConfig) -> BTreeMap<String, String> {
    let mut blocked: BTreeMap<String, String> = BTreeMap::new();
    for conflict in validate::conflicts(&config.instances) {
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

pub(crate) fn describe_conflict(conflict: &Conflict) -> String {
    let params = conflict
        .params
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("{}（{params}）", conflict.message_key)
}

fn idle_supervisor(
    instance: &Instance,
    exe: &Path,
    state_dir: &Path,
    logs: &LogHandle,
) -> Arc<Supervisor> {
    let mut spec = Spec::new(
        Owner::new(crate::MODULE_ID, instance.name.clone()),
        exe.to_path_buf(),
    );
    spec.cwd = Some(state_dir.to_path_buf());
    Supervisor::new(spec, logs.clone())
}

async fn stop_handle(handle: Handle) {
    let Handle { supervisor, .. } = handle;
    if let Some(supervisor) = supervisor
        && let Err(error) = supervisor.stop().await
    {
        tracing::warn!(error = %error, "停止实例进程失败");
    }
}

async fn run_cli(exe: &Path, args: &[OsString]) -> Result<Value> {
    let mut command = tokio::process::Command::new(exe);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let output = timeout(limits::CLI_TIMEOUT, command.output())
        .await
        .map_err(|_| anyhow!("easytier-cli 查询超时"))?
        .map_err(|error| anyhow!("运行 easytier-cli 失败：{error}"))?;
    if !output.status.success() {
        // The raw output may contain configuration fields (network
        // secret); report only the exit status (WP-45 §8).
        bail!(
            "easytier-cli 查询失败（退出码 {}）",
            output.status.code().unwrap_or(-1)
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_json_output(&text).ok_or_else(|| anyhow!("easytier-cli 输出不是 JSON"))
}

/// Finds the first JSON value in mixed program output.
fn parse_json_output(text: &str) -> Option<Value> {
    let trimmed = text.trim();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        return Some(value);
    }
    for anchor in ['{', '['] {
        if let Some(index) = trimmed.find(anchor)
            && let Ok(value) = serde_json::from_str::<Value>(&trimmed[index..])
        {
            return Some(value);
        }
    }
    None
}

pub(crate) fn rfc3339(at: Option<SystemTime>) -> Option<String> {
    at.map(|at| {
        let at: time::OffsetDateTime = at.into();
        at.format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default()
    })
}

fn last_exit_json(exit: Option<&fg_proc::ExitInfo>) -> Value {
    let Some(exit) = exit else {
        return Value::Null;
    };
    json!({
        "at": rfc3339(Some(exit.at)),
        "code": exit.code,
        "signal": exit.signal,
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
    fn runtime_json_helpers_format_rfc3339_and_exit() {
        let stamp = rfc3339(Some(SystemTime::UNIX_EPOCH)).expect("stamp");
        assert!(stamp.starts_with("1970-01-01T00:00:00Z"), "{stamp}");
        assert_eq!(rfc3339(None), None);
        let exit = last_exit_json(Some(&fg_proc::ExitInfo {
            at: SystemTime::UNIX_EPOCH,
            code: Some(1),
            signal: None,
            output_tail: String::new(),
        }));
        assert_eq!(exit["code"], 1);
        assert_eq!(last_exit_json(None), Value::Null);
    }

    #[test]
    fn runtime_parse_json_output_finds_value_in_noise() {
        assert_eq!(
            parse_json_output("warning: something\n{\"Version\": \"1\"}\n").unwrap()["Version"],
            "1"
        );
        assert_eq!(parse_json_output("[]").unwrap(), Value::Array(vec![]));
        assert!(parse_json_output("no json here").is_none());
    }

    #[test]
    fn runtime_sanitize_key_strips_path_characters() {
        assert_eq!(sanitize_key("abc-123"), "abc-123");
        assert_eq!(sanitize_key("../evil"), "evil");
        assert_eq!(sanitize_key(""), "unknown");
    }

    #[test]
    fn runtime_conflict_description_carries_key_and_params() {
        let conflict = Conflict {
            keys: vec!["a".into(), "b".into()],
            message_key: crate::validate::messages::LISTENER_PORT,
            params: vec![
                ("protocol".into(), "tcp".into()),
                ("port".into(), "11010".into()),
            ],
        };
        let text = describe_conflict(&conflict);
        assert!(text.contains(crate::validate::messages::LISTENER_PORT));
        assert!(text.contains("port=11010"));
    }
}
