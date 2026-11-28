//! Instance runtime (WP-44 steps 5–8, §3.3): every enabled frpc / frps
//! instance runs as its own supervised process via fg-proc — resolved
//! through the module settings (`frpcPath` / `frpsPath`, else the config
//! directory `bin/`, else `PATH`), started with `-c <rendered file>` only,
//! restarted on backoff after abnormal exits and stopped with the WP-43
//! grace when disabled.
//!
//! Lifecycle contract:
//! - the rendered TOML for each instance lives in `<config>/frp/` with mode
//!   0600 (the token is in the file, never on the command line);
//! - a config change re-renders every instance; only instances whose
//!   rendered file changed are restarted (editing a proxy restarts its own
//!   frpc, editing the visitor `access` block restarts nothing);
//! - each frps instance registers its ports with the WP-37 firewall group
//!   (connection TCP, KCP / QUIC UDP, vhost TCP; loopback listeners are
//!   never opened) and revokes them on stop;
//! - the login gate (`login_check`) sees every frpc Login / NewProxy: a
//!   valid token registers the source as trusted for 10 minutes and learns
//!   the requested remote TCP ports (capped, cleared on stop);
//! - process output is redacted against the current secrets before it
//!   reaches the logs;
//! - draining stops every instance within the bounded stop deadline.

use std::{
    collections::{BTreeSet, HashMap},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::SystemTime,
};

use anyhow::{Context, Result, bail};
use fg_core::fsperm;
use fg_logging::Level;
use fg_net::{
    fwopen::{self, Family, Port as FwPort},
    openports::{OpenPort, OpenPorts, Proto},
    trust_src::{self, TrustedSource},
};
use fg_proc::{LogHandle, Owner, Proc, Spec, Supervisor};
use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use tokio::sync::{RwLock, watch};

use crate::{
    login_check::{GateHook, LoginGate, SetLookup},
    model::{Client, FileConfig, Server, limits},
    validate,
};

/// External capabilities the runtime needs, injected by the assembler
/// (conventions §3.4). Everything but the `Proc` handle is optional; the
/// absent pieces degrade silently (no firewall opening / no port registry /
/// no subscribed IP sets) instead of failing the module.
pub struct Deps {
    /// Managed-program infrastructure (WP-43): binary lookup and installers.
    pub proc: Arc<Proc>,
    /// The WP-37 firewall group for this module; the assembler creates
    /// `fg_net::fwopen::Group::new("frp")` once per process.
    pub fw_open: Option<Arc<fwopen::Group>>,
    /// The open-port registry published to the intrusion protection.
    pub open_ports: Option<Arc<OpenPorts>>,
    /// Resolves subscribed IP-set keys for the login gate.
    pub ip_sets: Option<SetLookup>,
}

/// One observed process, as the status endpoints render it.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceStatus {
    /// `frpc` or `frps`.
    pub kind: &'static str,
    pub key: String,
    pub name: String,
    pub enable: bool,
    pub running: bool,
    pub pid: Option<u32>,
    /// UTC RFC 3339.
    pub since: Option<String>,
    pub uptime_secs: Option<u64>,
    /// Automatic restarts after abnormal exits (fg-proc supervisor).
    pub restarts: u32,
    /// How often the runtime started this instance (manual restarts too).
    pub starts: u64,
    pub failed: Option<String>,
    pub last_exit: Option<ExitView>,
}

impl InstanceStatus {
    /// The not-yet-started status of a configured instance (route views
    /// before the first reconcile saw it).
    pub fn zero(kind: &'static str, key: &str) -> Self {
        Self {
            kind,
            key: key.to_owned(),
            name: key.to_owned(),
            enable: false,
            running: false,
            pid: None,
            since: None,
            uptime_secs: None,
            restarts: 0,
            starts: 0,
            failed: None,
            last_exit: None,
        }
    }
}

/// The last exit of an instance (output already redacted).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExitView {
    pub at: String,
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub output_tail: String,
}

/// Summary for the overview page (WP-44 §3.3): running / abnormal counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub running_clients: usize,
    pub running_servers: usize,
    /// Enabled instances currently not running (start failure or crash
    /// inside the backoff window).
    pub abnormal: usize,
}

/// The current secret values, for redacting process output before logging.
struct Secrets(Mutex<Vec<String>>);

impl Secrets {
    fn redact(&self, line: &str) -> String {
        let secrets = self.0.lock().expect("secrets lock");
        let mut line = line.to_owned();
        for secret in &*secrets {
            if secret.len() >= 4 {
                line = line.replace(secret.as_str(), "******");
            }
        }
        line
    }
}

/// A pending start decided by a reconcile pass (file already rendered).
struct PendingStart {
    key: String,
    exe: PathBuf,
    conf: PathBuf,
    text: String,
}

/// The frp instance runtime. Share it (`Arc`) between the module loop, the
/// routes and the install callbacks.
pub struct Runtime {
    config: Arc<RwLock<FileConfig>>,
    proc: Arc<Proc>,
    fw_open: Option<Arc<fwopen::Group>>,
    open_ports: Option<Arc<OpenPorts>>,
    conf_dir: PathBuf,
    clients: Mutex<HashMap<String, Arc<Supervisor>>>,
    servers: Mutex<HashMap<String, Arc<Supervisor>>>,
    starts: Mutex<HashMap<String, u64>>,
    rendered: Mutex<HashMap<String, String>>,
    secrets: Arc<Secrets>,
    gate: Mutex<Option<Arc<LoginGate>>>,
    gate_servers: Arc<RwLock<HashMap<String, Server>>>,
    ip_sets: SetLookup,
    /// serverKey -> address -> expiry of the trusted-source window.
    trust: Mutex<HashMap<String, HashMap<IpAddr, SystemTime>>>,
    /// serverKey -> learned remote TCP ports.
    ports: Mutex<HashMap<String, BTreeSet<u16>>>,
    reload_tx: watch::Sender<u64>,
}

impl Runtime {
    /// Opens the runtime over the shared desired config. The rendered
    /// configs live in the store's `frp/` data directory (0700).
    pub fn open(
        config: Arc<RwLock<FileConfig>>,
        deps: Deps,
        store: &fg_config::ConfigStore,
    ) -> Result<Arc<Self>> {
        let conf_dir = store.data_dir(limits::CONFIG_DIR)?;
        fsperm::mkdir_all(&conf_dir, 0o700)?;
        let ip_sets = deps.ip_sets.unwrap_or_else(crate::login_check::no_sets);
        let (reload_tx, _) = watch::channel(0);
        Ok(Arc::new(Self {
            config,
            proc: deps.proc,
            fw_open: deps.fw_open,
            open_ports: deps.open_ports,
            conf_dir,
            clients: Mutex::new(HashMap::new()),
            servers: Mutex::new(HashMap::new()),
            starts: Mutex::new(HashMap::new()),
            rendered: Mutex::new(HashMap::new()),
            secrets: Arc::new(Secrets(Mutex::new(Vec::new()))),
            gate: Mutex::new(None),
            gate_servers: Arc::new(RwLock::new(HashMap::new())),
            ip_sets,
            trust: Mutex::new(HashMap::new()),
            ports: Mutex::new(HashMap::new()),
            reload_tx,
        }))
    }

    /// The shared config snapshot (routes mutate this same handle).
    pub fn config(&self) -> Arc<RwLock<FileConfig>> {
        Arc::clone(&self.config)
    }

    /// Asks for a reconcile pass (routes call this after every persisted
    /// mutation; the actual pass runs on the module loop).
    pub fn notify_change(&self) {
        self.reload_tx.send_modify(|generation| *generation += 1);
    }

    /// The reload counter receiver the module loop selects on.
    pub fn reload_rx(&self) -> watch::Receiver<u64> {
        self.reload_tx.subscribe()
    }

    /// The loopback login gate, started on demand (first reconcile, which
    /// always runs with a tokio runtime context). The listener binds
    /// before the lock is taken, so no std guard is ever held across an
    /// await; a racing starter that loses publishes the winner and aborts
    /// its own listener.
    async fn ensure_gate(self: &Arc<Self>) -> Result<Arc<LoginGate>> {
        if let Some(existing) = self
            .gate
            .lock()
            .expect("gate lock")
            .as_ref()
            .map(Arc::clone)
        {
            return Ok(existing);
        }
        let runtime = Arc::downgrade(self);
        let on_allow: crate::login_check::OnAllow = Arc::new(move |key, addr, hook| {
            if let Some(runtime) = runtime.upgrade() {
                runtime.observe_gate_allow(key, addr, hook);
            }
        });
        let gate = Arc::new(
            LoginGate::start(
                Arc::clone(&self.gate_servers),
                Arc::clone(&self.ip_sets),
                on_allow,
            )
            .await?,
        );
        let winner = {
            let mut guard = self.gate.lock().expect("gate lock");
            match guard.as_ref() {
                // Another starter won the publish race: use theirs.
                Some(existing) => Some(Arc::clone(existing)),
                None => {
                    *guard = Some(Arc::clone(&gate));
                    None
                }
            }
        };
        match winner {
            Some(existing) => {
                // Stop our duplicate listener and use the winner's.
                gate.stop();
                Ok(existing)
            }
            None => Ok(gate),
        }
    }

    /// The module loop: one reconcile, then reload-triggered passes until
    /// the drain; draining stops every instance within the deadline.
    pub async fn run(self: Arc<Self>, mut drain: watch::Receiver<bool>) -> Result<()> {
        let mut reload = self.reload_rx();
        Runtime::reconcile(&self).await;
        loop {
            tokio::select! {
                _ = drain.changed() => break,
                _ = reload.changed() => Runtime::reconcile(&self).await,
            }
        }
        let _ = tokio::time::timeout(limits::DRAIN_STOP, self.stop_all()).await;
        Ok(())
    }

    /// The update auto-checker (WP-43 `AutoChecker`) when
    /// `install.autoCheck` is on; found updates notify a reconcile so the
    /// affected instances restart on the new binary.
    pub async fn auto_checker(
        self: &Arc<Self>,
        bus: Option<fg_core::events::EventBus>,
    ) -> Option<fg_proc::AutoChecker> {
        if !self.config.read().await.install.auto_check {
            return None;
        }
        let runtime = Arc::downgrade(self);
        Some(
            self.proc
                .auto_checker(
                    "frp",
                    &[&fg_proc::install::FRPC, &fg_proc::install::FRPS],
                    bus,
                )
                .with_notify(Arc::new(move |_spec, _version| {
                    if let Some(runtime) = runtime.upgrade() {
                        runtime.notify_change();
                    }
                })),
        )
    }

    /// Reconciles the running instance set with the desired config: start,
    /// restart-on-change, stop-on-removal, gate rules, firewall ports,
    /// trusted sources and stale config files.
    pub async fn reconcile(self: &Arc<Self>) {
        let snapshot = self.config.read().await.clone();
        *self.secrets.0.lock().expect("secrets lock") = secrets_of(&snapshot);
        let gate = match self.ensure_gate().await {
            Ok(gate) => Some(gate),
            Err(error) => {
                tracing::warn!(%error, "登录检查端点启动失败，frps 将不接入来源控制");
                None
            }
        };
        // Desired entries: enabled instances with a resolvable binary and a
        // renderable config.
        let mut desired_clients: HashMap<String, (PathBuf, String)> = HashMap::new();
        for client in snapshot.clients.iter().filter(|client| client.enable) {
            let Some(exe) = self.resolve_frpc(&snapshot.settings) else {
                tracing::warn!(client = %client.name, "找不到 frpc 程序（设置路径、bin/ 或 PATH）");
                continue;
            };
            match validate::render_client_toml(client, &snapshot.proxies) {
                Ok(rendered) => {
                    desired_clients.insert(client.key.clone(), (exe, rendered));
                }
                Err(error) => tracing::warn!(client = %client.name, %error, "frpc 配置生成失败"),
            }
        }
        let mut desired_servers: HashMap<String, (PathBuf, String)> = HashMap::new();
        let mut gate_rules: HashMap<String, Server> = HashMap::new();
        for server in snapshot.servers.iter().filter(|server| server.enable) {
            let Some(exe) = self.resolve_frps(&snapshot.settings) else {
                tracing::warn!(server = %server.name, "找不到 frps 程序（设置路径、bin/ 或 PATH）");
                continue;
            };
            let endpoint = gate.as_ref().map(|gate| gate.endpoint(server.key.as_str()));
            match validate::render_server_toml(server, endpoint.as_ref()) {
                Ok(rendered) => {
                    desired_servers.insert(server.key.clone(), (exe, rendered));
                    gate_rules.insert(server.key.clone(), server.clone());
                }
                Err(error) => tracing::warn!(server = %server.name, %error, "frps 配置生成失败"),
            }
        }
        *self.gate_servers.write().await = gate_rules;
        self.apply_set("frpc", &desired_clients, &snapshot).await;
        self.apply_set("frps", &desired_servers, &snapshot).await;
        self.sync_firewall(&desired_servers);
        self.clean_stale_configs(
            desired_clients
                .keys()
                .chain(desired_servers.keys())
                .map(String::as_str),
        );
        self.publish_open_ports();
    }

    /// Starts new instances, restarts ones whose rendered config changed,
    /// and stops removed / disabled ones. Only changed instances restart —
    /// editing a proxy restarts its owning frpc, nothing else; editing the
    /// visitor access block restarts nothing.
    async fn apply_set(
        &self,
        kind: &'static str,
        desired: &HashMap<String, (PathBuf, String)>,
        snapshot: &FileConfig,
    ) {
        // 1. Decide stops: everything running that is no longer desired or
        //    whose rendered config changed. Locks are released before the
        //    first await.
        let to_stop: Vec<(String, Arc<Supervisor>)> = {
            let mut running = match kind {
                "frpc" => &self.clients,
                _ => &self.servers,
            }
            .lock()
            .expect("supervisors lock");
            let mut rendered = self.rendered.lock().expect("rendered lock");
            let mut stop = Vec::new();
            for (key, supervisor) in running.iter() {
                let changed = desired
                    .get(key)
                    .is_none_or(|(_, text)| rendered.get(key) != Some(text));
                if changed {
                    stop.push((key.clone(), Arc::clone(supervisor)));
                }
            }
            for (key, _) in &stop {
                running.remove(key);
                rendered.remove(key);
            }
            stop
        };
        for (key, supervisor) in to_stop {
            let _ = supervisor.stop().await;
            if kind == "frps" {
                // A stopped server keeps no trust or learned ports.
                self.forget_server_state(&key);
            }
        }
        // 2. Decide starts: desired instances with no supervisor or a
        //    changed config (file rendered before the start).
        let to_start: Vec<PendingStart> = {
            let running = match kind {
                "frpc" => &self.clients,
                _ => &self.servers,
            }
            .lock()
            .expect("supervisors lock");
            let rendered = self.rendered.lock().expect("rendered lock");
            let mut pending = Vec::new();
            for (key, (exe, text)) in desired {
                if running.contains_key(key) && rendered.get(key) == Some(text) {
                    continue;
                }
                match self.write_conf(kind, key, text) {
                    Ok(conf) => pending.push(PendingStart {
                        key: key.clone(),
                        exe: exe.clone(),
                        conf,
                        text: text.clone(),
                    }),
                    Err(error) => {
                        tracing::warn!(instance = %key, %error, "{kind} 配置写入失败");
                    }
                }
            }
            pending
        };
        for pending in to_start {
            let logs = self.log_for(kind, &pending.key, snapshot);
            let mut spec = Spec::new(
                Owner::new("frp", format!("{kind}:{}", pending.key)),
                &pending.exe,
            );
            spec.args = vec!["-c".into(), pending.conf.clone().into_os_string()];
            let supervisor = self.proc.supervisor(spec, logs);
            match supervisor.start().await {
                Ok(()) => {
                    *self
                        .starts
                        .lock()
                        .expect("starts lock")
                        .entry(format!("{kind}:{}", pending.key))
                        .or_insert(0) += 1;
                    self.rendered
                        .lock()
                        .expect("rendered lock")
                        .insert(pending.key.clone(), pending.text.clone());
                    match kind {
                        "frpc" => self
                            .clients
                            .lock()
                            .expect("supervisors lock")
                            .insert(pending.key.clone(), Arc::clone(&supervisor)),
                        _ => self
                            .servers
                            .lock()
                            .expect("supervisors lock")
                            .insert(pending.key.clone(), Arc::clone(&supervisor)),
                    };
                    if kind == "frps" {
                        // A restarted server starts with a clean slate.
                        self.forget_server_state(&pending.key);
                    }
                }
                Err(error) => {
                    tracing::warn!(instance = %pending.key, error = %error.to_string(), "{kind} 启动失败");
                }
            }
        }
    }

    /// Removes a server's learned state (trust + ports) on stop / restart.
    fn forget_server_state(&self, key: &str) {
        self.trust_clear(key);
        self.port_clear(key);
    }

    /// Stops every running instance concurrently (module drain).
    pub async fn stop_all(&self) {
        let mut supervisors: Vec<Arc<Supervisor>> = Vec::new();
        supervisors.extend(
            self.clients
                .lock()
                .expect("supervisors lock")
                .values()
                .cloned(),
        );
        supervisors.extend(
            self.servers
                .lock()
                .expect("supervisors lock")
                .values()
                .cloned(),
        );
        let mut set = tokio::task::JoinSet::new();
        for supervisor in supervisors {
            set.spawn(async move {
                let _ = supervisor.stop().await;
            });
        }
        while set.join_next().await.is_some() {}
        self.clients.lock().expect("supervisors lock").clear();
        self.servers.lock().expect("supervisors lock").clear();
        self.rendered.lock().expect("rendered lock").clear();
        let trust_keys: Vec<String> = self
            .trust
            .lock()
            .expect("trust lock")
            .keys()
            .cloned()
            .collect();
        for key in trust_keys {
            self.trust_clear(&key);
        }
        let port_keys: Vec<String> = self
            .ports
            .lock()
            .expect("ports lock")
            .keys()
            .cloned()
            .collect();
        for key in port_keys {
            self.port_clear(&key);
        }
        *self.gate_servers.write().await = HashMap::new();
        if let Some(fw) = &self.fw_open {
            fw.clear_all();
        }
    }

    /// Restarts one instance (routes restart endpoints). An enabled
    /// instance is started again after the stop; a disabled one just
    /// stops. Fails when an enabled instance cannot start.
    pub async fn restart(self: &Arc<Self>, kind: &'static str, key: &str) -> Result<()> {
        let supervisor = match kind {
            "frpc" => &self.clients,
            _ => &self.servers,
        }
        .lock()
        .expect("supervisors lock")
        .get(key)
        .map(Arc::clone);
        if let Some(supervisor) = supervisor {
            supervisor.stop().await.context("停止实例失败")?;
        }
        Runtime::reconcile(self).await;
        let running = match kind {
            "frpc" => &self.clients,
            _ => &self.servers,
        }
        .lock()
        .expect("supervisors lock")
        .contains_key(key);
        if !running {
            let snapshot = self.config.read().await;
            let enabled = match kind {
                "frpc" => snapshot
                    .clients
                    .iter()
                    .any(|client| client.key == key && client.enable),
                _ => snapshot
                    .servers
                    .iter()
                    .any(|server| server.key == key && server.enable),
            };
            if enabled {
                bail!("实例已启用但无法启动（程序或配置不可用）");
            }
        }
        Ok(())
    }

    /// The status of every instance (running or configured).
    pub async fn status(&self) -> Vec<InstanceStatus> {
        let snapshot = self.config.read().await;
        let clients = self.clients.lock().expect("supervisors lock");
        let servers = self.servers.lock().expect("supervisors lock");
        let starts = self.starts.lock().expect("starts lock");
        let mut all = Vec::new();
        for client in &snapshot.clients {
            all.push(status_of(
                "frpc",
                client,
                clients.get(client.key.as_str()),
                starts
                    .get(&format!("frpc:{}", client.key))
                    .copied()
                    .unwrap_or(0),
            ));
        }
        for server in &snapshot.servers {
            all.push(status_of(
                "frps",
                server,
                servers.get(server.key.as_str()),
                starts
                    .get(&format!("frps:{}", server.key))
                    .copied()
                    .unwrap_or(0),
            ));
        }
        all
    }

    /// One instance's status (routes status / restart endpoints).
    pub async fn status_of_one(&self, kind: &'static str, key: &str) -> Option<InstanceStatus> {
        self.status()
            .await
            .into_iter()
            .find(|status| status.kind == kind && status.key == key)
    }

    /// The overview summary: running / abnormal instance counts.
    pub fn summary(&self) -> Summary {
        let snapshot = self.config.clone();
        let Ok(snapshot) = snapshot.try_read() else {
            return Summary::default();
        };
        let clients = self.clients.lock().expect("supervisors lock");
        let servers = self.servers.lock().expect("supervisors lock");
        let running_clients = clients.values().filter(|s| s.state().running).count();
        let running_servers = servers.values().filter(|s| s.state().running).count();
        let mut abnormal = 0;
        for client in snapshot.clients.iter().filter(|client| client.enable) {
            let running = clients
                .get(client.key.as_str())
                .is_some_and(|supervisor| supervisor.state().running);
            if !running {
                abnormal += 1;
            }
        }
        for server in snapshot.servers.iter().filter(|server| server.enable) {
            let running = servers
                .get(server.key.as_str())
                .is_some_and(|supervisor| supervisor.state().running);
            if !running {
                abnormal += 1;
            }
        }
        Summary {
            running_clients,
            running_servers,
            abnormal,
        }
    }

    // -- binaries -----------------------------------------------------------

    fn resolve_frpc(&self, settings: &crate::model::Settings) -> Option<PathBuf> {
        let configured =
            (!settings.frpc_path.is_empty()).then(|| PathBuf::from(settings.frpc_path.as_str()));
        self.proc
            .resolve(configured.as_deref(), "frpc")
            .map(|(_, path)| path)
    }

    fn resolve_frps(&self, settings: &crate::model::Settings) -> Option<PathBuf> {
        let configured =
            (!settings.frps_path.is_empty()).then(|| PathBuf::from(settings.frps_path.as_str()));
        self.proc
            .resolve(configured.as_deref(), "frps")
            .map(|(_, path)| path)
    }

    // -- config files -------------------------------------------------------

    fn conf_file(&self, kind: &str, key: &str) -> PathBuf {
        self.conf_dir.join(format!("{kind}-{key}.toml"))
    }

    /// Writes one rendered config (mode 0600; the token is inside).
    fn write_conf(&self, kind: &str, key: &str, text: &str) -> Result<PathBuf> {
        let path = self.conf_file(kind, key);
        write_private(&path, text.as_bytes())
            .with_context(|| format!("写入 {} 失败", path.display()))?;
        Ok(path)
    }

    /// Removes rendered configs whose instance no longer exists (start
    /// cleans stale files, upstream `TestStartCleansStaleConfigFiles`).
    fn clean_stale_configs<'a>(&self, keep: impl Iterator<Item = &'a str>) {
        let keep: BTreeSet<String> = keep
            .flat_map(|key| ["frpc", "frps"].map(|kind| format!("{kind}-{key}.toml")))
            .collect();
        let Ok(entries) = std::fs::read_dir(&self.conf_dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".toml") && !keep.contains(&name) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// The rendered config path of one instance (tests).
    pub fn conf_file_of(&self, kind: &str, key: &str) -> PathBuf {
        self.conf_file(kind, key)
    }

    // -- logging ------------------------------------------------------------

    /// A per-instance log handle: lines are tagged with the instance and
    /// redacted against the current secrets.
    fn log_for(&self, kind: &str, key: &str, snapshot: &FileConfig) -> LogHandle {
        let name = match kind {
            "frpc" => snapshot
                .clients
                .iter()
                .find(|client| client.key == key)
                .map(|client| client.name.clone()),
            _ => snapshot
                .servers
                .iter()
                .find(|server| server.key == key)
                .map(|server| server.name.clone()),
        }
        .unwrap_or_else(|| key.to_owned());
        let source = format!("{kind}:{name}");
        let secrets = Arc::clone(&self.secrets);
        LogHandle::new(move |level, line| {
            let line = secrets.redact(line);
            match level {
                Level::Debug => tracing::debug!(target: "fg_frp", source = %source, "{line}"),
                Level::Info => tracing::info!(target: "fg_frp", source = %source, "{line}"),
                Level::Warn => tracing::warn!(target: "fg_frp", source = %source, "{line}"),
                Level::Error => tracing::error!(target: "fg_frp", source = %source, "{line}"),
            }
        })
    }

    // -- firewall -----------------------------------------------------------

    /// Registers / revokes the firewall ports of the configured servers
    /// (WP-37): connection port TCP, KCP / QUIC ports UDP, vhost HTTP /
    /// HTTPS TCP. Loopback listeners are never opened; a stopped or
    /// disabled instance's key is revoked.
    fn sync_firewall(&self, desired: &HashMap<String, (PathBuf, String)>) {
        let Some(fw) = &self.fw_open else {
            return;
        };
        let servers = futures_now(&self.config).servers.clone();
        for server in &servers {
            match desired.get(&server.key) {
                Some(_) if server.auto_firewall => {
                    fw.want(&server.key, firewall_ports(server));
                }
                _ => {
                    fw.want(&server.key, Vec::new());
                }
            }
        }
    }

    // -- trusted sources and learned ports -----------------------------------

    /// Handles an allowed gate operation: `Login` registers the trusted
    /// source, `NewProxy` learns the remote port; both refresh the trust
    /// window (the connection is alive). Public for tests and callers that
    /// observe the gate outside the HTTP path.
    pub fn observe_gate_allow(&self, key: &str, addr: Option<IpAddr>, hook: GateHook) {
        let Some(addr) = addr else {
            return;
        };
        match hook {
            GateHook::Login => self.trust_login(key, addr, SystemTime::now()),
            GateHook::NewProxy(port) => {
                self.trust_login(key, addr, SystemTime::now());
                self.port_learn(key, port);
            }
        }
    }

    /// Records `addr` as trusted for [`limits::TRUST_TTL`], refreshing any
    /// existing window; at most [`limits::TRUSTED_ADDR_CAP`] addresses per
    /// instance (the earliest expiry is evicted).
    fn trust_login(&self, key: &str, addr: IpAddr, now: SystemTime) {
        {
            let mut trust = self.trust.lock().expect("trust lock");
            let entries = trust.entry(key.to_owned()).or_default();
            entries.insert(addr, now + limits::TRUST_TTL);
            while entries.len() > limits::TRUSTED_ADDR_CAP {
                let earliest = entries
                    .iter()
                    .min_by_key(|(_, expiry)| *expiry)
                    .map(|(addr, _)| *addr)
                    .expect("non-empty");
                entries.remove(&earliest);
            }
        }
        self.trust_publish(key);
    }

    /// Clears one instance's trusted sources (stop, token or port change).
    pub fn trust_clear(&self, key: &str) {
        let removed = self.trust.lock().expect("trust lock").remove(key).is_some();
        if removed {
            trust_src::clear(&format!("frp:{key}"));
        }
    }

    fn trust_publish(&self, key: &str) {
        let list: Vec<TrustedSource> = {
            let trust = self.trust.lock().expect("trust lock");
            let Some(entries) = trust.get(key) else {
                return;
            };
            let now = SystemTime::now();
            entries
                .iter()
                .filter(|(_, expiry)| **expiry > now)
                .map(|(addr, expiry)| TrustedSource {
                    owner: format!("frp:{key}"),
                    addr: *addr,
                    until: Some(*expiry),
                    note: "frpc login".to_owned(),
                })
                .collect()
        };
        trust_src::set(&format!("frp:{key}"), list);
    }

    /// The trusted sources of one instance with their expiries (tests and
    /// status views).
    pub fn trust_entries(&self, key: &str) -> Vec<(IpAddr, SystemTime)> {
        self.trust
            .lock()
            .expect("trust lock")
            .get(key)
            .map(|entries| {
                let mut list: Vec<_> = entries
                    .iter()
                    .map(|(addr, expiry)| (*addr, *expiry))
                    .collect();
                list.sort_by_key(|(_, expiry)| *expiry);
                list
            })
            .unwrap_or_default()
    }

    /// Learns a remote TCP port a logged-in frpc registered: respects the
    /// allow-ports whitelist, capped at [`limits::OPEN_PORTS_CAP`], cleared
    /// when the instance stops.
    fn port_learn(&self, key: &str, port: u16) {
        if port == 0 {
            return;
        }
        let allow_ports = self.config.try_read().ok().and_then(|config| {
            config
                .servers
                .iter()
                .find(|server| server.key == key)
                .map(|server| server.allow_ports.clone())
        });
        if let Some(allow_ports) = allow_ports
            && !allow_ports.is_empty()
            && let Ok(list) = fg_net::ports::parse_ports(&allow_ports)
            && !list.ports.contains(&port)
        {
            return;
        }
        {
            let mut ports = self.ports.lock().expect("ports lock");
            let set = ports.entry(key.to_owned()).or_default();
            set.insert(port);
            while set.len() > limits::OPEN_PORTS_CAP {
                let smallest = *set.iter().next().expect("non-empty");
                set.remove(&smallest);
            }
        }
        self.publish_open_ports();
    }

    /// Clears one instance's learned ports.
    pub fn port_clear(&self, key: &str) {
        let removed = self.ports.lock().expect("ports lock").remove(key).is_some();
        if removed && let Some(open_ports) = &self.open_ports {
            open_ports.set(&format!("frp:{key}"), &[]);
        }
    }

    /// Publishes the learned ports of every instance into the open-port
    /// registry (intrusion protection reads them).
    fn publish_open_ports(&self) {
        let Some(open_ports) = &self.open_ports else {
            return;
        };
        let ports = self.ports.lock().expect("ports lock");
        for (key, set) in ports.iter() {
            let owned: Vec<OpenPort> = set
                .iter()
                .map(|port| OpenPort {
                    proto: Proto::Tcp,
                    port: *port,
                })
                .collect();
            open_ports.set(&format!("frp:{key}"), &owned);
        }
    }

    /// The learned ports of one instance (tests).
    pub fn learned_ports(&self, key: &str) -> Vec<u16> {
        self.ports
            .lock()
            .expect("ports lock")
            .get(key)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Reads the shared config when no writer holds it (best effort; the
/// callers tolerate the empty snapshot by doing nothing).
fn futures_now(config: &RwLock<FileConfig>) -> FileConfig {
    config
        .try_read()
        .map(|guard| guard.clone())
        .unwrap_or_default()
}

/// Writes a file with mode 0600 (unix); other platforms use the default.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(limits::CONFIG_FILE_MODE);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(limits::CONFIG_FILE_MODE),
        );
    }
    Ok(())
}

fn secrets_of(config: &FileConfig) -> Vec<String> {
    let mut secrets: Vec<String> = Vec::new();
    for client in &config.clients {
        if !client.token.is_empty() {
            secrets.push(client.token.clone());
        }
    }
    for server in &config.servers {
        if !server.token.is_empty() {
            secrets.push(server.token.clone());
        }
        if !server.dashboard_pwd.is_empty() {
            secrets.push(server.dashboard_pwd.clone());
        }
    }
    for proxy in &config.proxies {
        if !proxy.secret_key.is_empty() {
            secrets.push(proxy.secret_key.clone());
        }
    }
    secrets
}

fn status_of(
    kind: &'static str,
    entry: &impl NamedEnabled,
    supervisor: Option<&Arc<Supervisor>>,
    starts: u64,
) -> InstanceStatus {
    let state = supervisor.map(|supervisor| supervisor.state());
    InstanceStatus {
        kind,
        key: entry.key().to_owned(),
        name: entry.name().to_owned(),
        enable: entry.enabled(),
        running: state.as_ref().is_some_and(|state| state.running),
        pid: state.as_ref().and_then(|state| state.pid),
        since: state.as_ref().and_then(|state| state.since).map(|since| {
            let at: time::OffsetDateTime = since.into();
            at.format(&Rfc3339).unwrap_or_default()
        }),
        uptime_secs: state
            .as_ref()
            .and_then(|state| state.uptime())
            .map(|uptime| uptime.as_secs()),
        restarts: state.as_ref().map_or(0, |state| state.restarts),
        starts,
        failed: state.as_ref().and_then(|state| state.failed.clone()),
        last_exit: state
            .as_ref()
            .and_then(|state| state.last_exit.clone())
            .map(|exit| ExitView {
                at: {
                    let at: time::OffsetDateTime = exit.at.into();
                    at.format(&Rfc3339).unwrap_or_default()
                },
                code: exit.code,
                signal: exit.signal,
                output_tail: exit.output_tail,
            }),
    }
}

trait NamedEnabled {
    fn key(&self) -> &str;
    fn name(&self) -> &str;
    fn enabled(&self) -> bool;
}

impl NamedEnabled for Client {
    fn key(&self) -> &str {
        &self.key
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn enabled(&self) -> bool {
        self.enable
    }
}

impl NamedEnabled for Server {
    fn key(&self) -> &str {
        &self.key
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn enabled(&self) -> bool {
        self.enable
    }
}

/// The firewall ports a running frps instance needs (WP-44 §3.3):
/// connection port TCP, KCP / QUIC ports UDP, vhost HTTP / HTTPS TCP.
/// A loopback listener is never opened; a concrete bind address restricts
/// the rule to that address, `0.0.0.0` / `::` restrict the family.
pub fn firewall_ports(server: &Server) -> Vec<FwPort> {
    let bind = parse_bind(&server.bind_addr);
    // frp's own default: proxyBindAddr falls back to bindAddr.
    let proxy_text = if server.proxy_bind_addr.trim().is_empty() {
        server.bind_addr.as_str()
    } else {
        server.proxy_bind_addr.as_str()
    };
    let proxy_bind = parse_bind(proxy_text);
    let mut ports = Vec::new();
    if !bind.loopback && server.bind_port != 0 {
        ports.push(bind.port(Proto::Tcp, server.bind_port));
    }
    for (port, proto) in [
        (server.kcp_bind_port, Proto::Udp),
        (server.quic_bind_port, Proto::Udp),
    ] {
        if !bind.loopback && port != 0 {
            ports.push(bind.port(proto, port));
        }
    }
    for port in [server.vhost_http_port, server.vhost_https_port] {
        if !proxy_bind.loopback && port != 0 {
            ports.push(proxy_bind.port(Proto::Tcp, port));
        }
    }
    ports
}

/// The firewall view of one bind address: loopback flag, address / family
/// restriction. Empty means every address.
struct BindRule {
    loopback: bool,
    addr: Option<IpAddr>,
    family: Family,
}

impl BindRule {
    fn port(&self, proto: Proto, port: u16) -> FwPort {
        let mut fw = FwPort::single(proto, self.family, port);
        if let Some(addr) = self.addr {
            fw = fw.to_addr(addr);
        }
        fw
    }
}

fn parse_bind(text: &str) -> BindRule {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return BindRule {
            loopback: false,
            addr: None,
            family: Family::Both,
        };
    }
    match trimmed.parse::<IpAddr>() {
        Ok(addr) => BindRule {
            loopback: addr.is_loopback(),
            family: if addr.is_ipv4() {
                Family::V4
            } else {
                Family::V6
            },
            addr: Some(addr),
        },
        // Not an IP (hostname): treat as every address.
        Err(_) => BindRule {
            loopback: false,
            addr: None,
            family: Family::Both,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Proxy, QuicTuning, Server};
    use std::time::Duration;

    #[test]
    fn server_firewall_ports() {
        let server = Server {
            key: "s1".into(),
            name: "main".into(),
            bind_addr: String::new(),
            bind_port: 7000,
            kcp_bind_port: 7001,
            quic_bind_port: 7002,
            vhost_http_port: 8080,
            vhost_https_port: 8443,
            ..Server::default()
        };
        let ports = firewall_ports(&server);
        assert_eq!(ports.len(), 5, "{ports:?}");
        let first_of = |proto: Proto, first: u16| {
            ports
                .iter()
                .any(|port| port.proto == proto && port.first == first)
        };
        assert!(first_of(Proto::Tcp, 7000));
        assert!(first_of(Proto::Udp, 7001), "KCP 端口");
        assert!(first_of(Proto::Udp, 7002), "QUIC 端口");
        assert!(first_of(Proto::Tcp, 8080), "HTTP 端口");
        assert!(first_of(Proto::Tcp, 8443), "HTTPS 端口");
        // Empty bind addresses open both families without an address pin.
        assert!(
            ports
                .iter()
                .all(|port| port.addr.is_none() && port.family == Family::Both)
        );

        // A concrete bind address restricts its rules to it.
        let mut bound = server.clone();
        bound.bind_addr = "192.0.2.10".into();
        let ports = firewall_ports(&bound);
        assert!(
            ports
                .iter()
                .all(|port| port.addr == Some("192.0.2.10".parse().unwrap())),
            "{ports:?}"
        );
        assert!(ports.iter().all(|port| port.family == Family::V4));

        // Loopback proxy listeners are never opened (回环不放行).
        let mut local_vhost = server.clone();
        local_vhost.proxy_bind_addr = "127.0.0.1".into();
        let ports = firewall_ports(&local_vhost);
        assert_eq!(ports.len(), 3, "{ports:?}");
        assert!(
            ports
                .iter()
                .all(|port| port.first != 8080 && port.first != 8443)
        );

        // Everything on loopback: nothing at all.
        let mut all_local = server.clone();
        all_local.bind_addr = "127.0.0.1".into();
        all_local.proxy_bind_addr = "127.0.0.1".into();
        assert!(firewall_ports(&all_local).is_empty());

        // Disabled ports (0) produce nothing.
        let mut minimal = server.clone();
        minimal.kcp_bind_port = 0;
        minimal.quic_bind_port = 0;
        minimal.vhost_http_port = 0;
        minimal.vhost_https_port = 0;
        assert_eq!(firewall_ports(&minimal).len(), 1);
    }

    #[test]
    fn secrets_cover_every_secret_field_and_redact() {
        let config = FileConfig {
            clients: vec![Client {
                key: "c".into(),
                token: "client-token".into(),
                ..Client::default()
            }],
            servers: vec![Server {
                key: "s".into(),
                token: "server-token".into(),
                dashboard_pwd: "dash-pwd".into(),
                ..Server::default()
            }],
            proxies: vec![Proxy {
                key: "p".into(),
                secret_key: "proxy-secret".into(),
                ..Proxy::default()
            }],
            ..FileConfig::default()
        };
        assert_eq!(
            secrets_of(&config),
            ["client-token", "server-token", "dash-pwd", "proxy-secret"]
        );
        let secrets = Secrets(Mutex::new(secrets_of(&config)));
        let line = "login with token server-token failed for dash-pwd";
        let redacted = secrets.redact(line);
        assert_eq!(redacted, "login with token ****** failed for ******");
        // Short secrets are not replaced (too collision-prone).
        let secrets = Secrets(Mutex::new(vec!["ab".into()]));
        assert_eq!(secrets.redact("ab ab"), "ab ab");
    }

    #[test]
    fn status_view_carries_name_and_starts() {
        let server = Server {
            key: "s1".into(),
            name: "main".into(),
            enable: true,
            ..Server::default()
        };
        let status = status_of("frps", &server, None, 2);
        assert_eq!(status.kind, "frps");
        assert_eq!(status.key, "s1");
        assert_eq!(status.name, "main");
        assert!(status.enable);
        assert!(!status.running);
        assert_eq!(status.starts, 2);
        assert_eq!(status.restarts, 0);
        assert!(status.since.is_none());
        assert!(status.last_exit.is_none());
    }

    #[test]
    fn quic_defaults_and_caps_exist() {
        // The frp defaults the 0 values stand for (WP-44 §3.4).
        assert_eq!(limits::QUIC_KEEPALIVE_DEFAULT_SECS, 10);
        assert_eq!(limits::QUIC_IDLE_DEFAULT_SECS, 30);
        assert_eq!(limits::QUIC_STREAMS_DEFAULT, 100_000);
        assert_eq!(limits::QUIC_STREAMS_CAP, 1_000_000);
        assert_eq!(limits::TRUST_TTL, Duration::from_secs(600));
        assert_eq!(limits::TRUSTED_ADDR_CAP, 32);
        assert_eq!(limits::OPEN_PORTS_CAP, 4096);
        assert_eq!(QuicTuning::default().quic_keepalive_period, 0);
    }
}
