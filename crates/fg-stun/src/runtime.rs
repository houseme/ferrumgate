//! Mapping-keep runtime (WP-42 §3.3): one loop per enabled rule drives the
//! pure [`Channel`] state machine — periodic binding heartbeats keep the
//! NAT mapping alive, every response updates the mapping, changes are
//! published as `stun.changed` events, and the reachability check confirms
//! the mapped port forwards from the outside. Each rule owns a
//! [`CancellationToken`]; draining cancels in-flight operations and waits
//! out [`limits::SHUTDOWN_DEADLINE`] before returning.
//!
//! The discovered public endpoints are published as a read-only
//! [`Arc<RuntimeSnapshot>`] (conventions §2: hot-path consumers read one
//! snapshot) for the L4 / protocol-routing modules; the metrics surface
//! exposes `ferrumgate_stun_up{rule}` and
//! `ferrumgate_stun_connections_total{rule}`. The optional firewall group
//! (WP-37) receives the channel port via `want` when a rule enables
//! auto-firewall; the assembler injects it through [`crate::Deps`].

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;
use fg_core::events::{Event, EventBus, Kind};
use fg_core::metrics::Sample;
use fg_net::fwopen::{Family, Group, Port};
use fg_net::openports::Proto as FwProto;
use regex::Regex;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{RwLock as AsyncRwLock, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::channel::{Action, Channel, Timings, Transition};
use crate::model::{BindMode, FileConfig, Proto, Rule, Settings, WebhookConfig, limits};
use crate::notify::{self, Notification};
use crate::stun::client::{self, ClientError, ConsistencyReport, ConsistencyVerdict, QueryOutcome};
use crate::upnp::{self, MappingResult, MappingTarget};
use crate::validate::{effective_keep_alive, effective_servers};

/// Module-level settings a rule loop captures when it starts; config
/// changes restart the loops, so these stay consistent for the loop's
/// lifetime.
#[derive(Clone, Debug)]
struct EntrySettings {
    addr_check: u32,
    global_servers: Vec<String>,
    global_keep_alive: Vec<String>,
    global_webhook: WebhookConfig,
}

impl EntrySettings {
    fn capture(config: &FileConfig) -> Self {
        Self {
            addr_check: config.settings.addr_check_interval,
            global_servers: config.settings.stun_servers.clone(),
            global_keep_alive: config.settings.keep_alive_servers.clone(),
            global_webhook: config.settings.webhook.clone(),
        }
    }
}

/// Notification configuration of one loop incarnation, resolved at spawn
/// time (config changes restart the loops). `last_notified` suppresses
/// duplicate webhook / script runs for the same endpoint (a `Ready`
/// confirmation after `Mapped` must not re-fire).
#[derive(Debug)]
struct EntryNotify {
    webhook: WebhookConfig,
    webhook_only_on_change: bool,
    script_enable: bool,
    script: String,
    last_notified: Mutex<Option<SocketAddr>>,
}

impl EntryNotify {
    /// Resolves the effective webhook (global when the rule opts in).
    fn from_rule(rule: &Rule, settings: &EntrySettings) -> Self {
        Self {
            webhook: if rule.use_global_webhook {
                settings.global_webhook.clone()
            } else {
                rule.webhook.clone()
            },
            webhook_only_on_change: rule.webhook_only_on_change,
            script_enable: rule.script_enable,
            script: rule.script.clone(),
            last_notified: Mutex::new(None),
        }
    }
}

/// Read-only view of one rule channel for the management UI and the L4
/// consumers.
#[derive(Clone, Debug, PartialEq)]
pub struct EntryStatus {
    pub key: String,
    pub name: String,
    pub protocol: Proto,
    /// `binding` / `mapped` / `checking` / `ready` / `lost`.
    pub state: &'static str,
    pub local_addr: Option<SocketAddr>,
    /// The mapping discovered via STUN.
    pub public_addr: Option<SocketAddr>,
    /// When the current mapping was learned.
    pub since: Option<SystemTime>,
    pub last_error: Option<String>,
    /// Whether several STUN servers agreed on the mapping (`None` when the
    /// probe could not compare at least two endpoints).
    pub nat_consistent: Option<bool>,
    /// Firewall-opening status text (WP-37), empty when not registered.
    pub firewall: String,
}

/// The published snapshot: all active rule channels.
#[derive(Clone, Debug, PartialEq)]
pub struct RuntimeSnapshot {
    pub generated_at: SystemTime,
    pub entries: Vec<EntryStatus>,
}

/// Mutable per-rule status shared between the loop and the publisher.
#[derive(Debug)]
struct EntryView {
    state: &'static str,
    local_addr: Option<SocketAddr>,
    public_addr: Option<SocketAddr>,
    since: Option<SystemTime>,
    last_error: Option<String>,
    nat_consistent: Option<bool>,
}

impl EntryView {
    fn binding() -> Self {
        Self {
            state: "binding",
            local_addr: None,
            public_addr: None,
            since: None,
            last_error: None,
            nat_consistent: None,
        }
    }
}

#[derive(Debug)]
struct EntryHandle {
    key: String,
    name: String,
    protocol: Proto,
    loop_id: u64,
    view: Mutex<EntryView>,
    notify: Arc<EntryNotify>,
}

/// The STUN mapping runtime. Share it (`Arc`) between the module loop
/// ([`Runtime::run`]), the management routes ([`Runtime::restart`]) and the
/// L4 / protoroute consumers ([`Runtime::snapshot`]).
pub struct Runtime {
    config: Arc<AsyncRwLock<FileConfig>>,
    snapshot: Arc<ArcSwap<RuntimeSnapshot>>,
    events: Option<EventBus>,
    fw_open: Option<Arc<Group>>,
    exec_root: CancellationToken,
    tasks: Arc<tokio::sync::Mutex<JoinSet<()>>>,
    /// Live task count; wakes the module loop so a manual restart's new
    /// loop is joined promptly.
    task_count_tx: watch::Sender<usize>,
    task_count_rx: watch::Receiver<usize>,
    loops: Mutex<BTreeMap<String, (u64, CancellationToken)>>,
    handles: Mutex<BTreeMap<String, Arc<EntryHandle>>>,
    connections: Mutex<BTreeMap<String, u64>>,
    reload_tx: watch::Sender<u64>,
    reload_rx: watch::Receiver<u64>,
    next_loop_id: AtomicU64,
    inflight_ops: AtomicUsize,
}

impl Runtime {
    /// Creates a runtime over the shared desired config. The event bus and
    /// the firewall group are optional (injected by the assembler when
    /// present).
    pub fn new(
        config: Arc<AsyncRwLock<FileConfig>>,
        events: Option<EventBus>,
        fw_open: Option<Arc<Group>>,
    ) -> Self {
        let (reload_tx, reload_rx) = watch::channel(0);
        let (task_count_tx, task_count_rx) = watch::channel(0);
        Self {
            config,
            snapshot: Arc::new(ArcSwap::from_pointee(RuntimeSnapshot {
                generated_at: SystemTime::now(),
                entries: Vec::new(),
            })),
            events,
            fw_open,
            exec_root: CancellationToken::new(),
            tasks: Arc::new(tokio::sync::Mutex::new(JoinSet::new())),
            task_count_tx,
            task_count_rx,
            loops: Mutex::new(BTreeMap::new()),
            handles: Mutex::new(BTreeMap::new()),
            connections: Mutex::new(BTreeMap::new()),
            reload_tx,
            reload_rx,
            next_loop_id: AtomicU64::new(1),
            inflight_ops: AtomicUsize::new(0),
        }
    }

    /// The change hook for the routes: bumps the generation so the module
    /// loop restarts every rule loop.
    pub fn on_change_handle(self: &Arc<Self>) -> Arc<dyn Fn() + Send + Sync> {
        let runtime = Arc::clone(self);
        Arc::new(move || {
            runtime.reload_tx.send_modify(|generation| *generation += 1);
        })
    }

    /// The latest read-only snapshot for L4 / protoroute consumers and the
    /// management UI.
    pub fn snapshot(&self) -> Arc<RuntimeSnapshot> {
        Arc::clone(&*self.snapshot.load())
    }

    /// Prometheus samples for the global metrics endpoint.
    pub fn metrics(&self) -> Vec<Sample> {
        let snapshot = self.snapshot.load_full();
        let connections = self.connections.lock().expect("connections lock");
        snapshot
            .entries
            .iter()
            .flat_map(|entry| {
                let forwarded = connections.get(&entry.key).copied().unwrap_or(0);
                [
                    Sample::gauge(
                        "ferrumgate_stun_up",
                        "STUN rule has a confirmed public mapping",
                        u8::from(entry.state == "ready") as f64,
                    )
                    .label("rule", entry.key.clone()),
                    Sample::counter(
                        "ferrumgate_stun_connections_total",
                        "Connections forwarded through STUN channels",
                        forwarded as f64,
                    )
                    .label("rule", entry.key.clone()),
                ]
            })
            .collect()
    }

    /// Counts one forwarded connection (the built-in forward calls this
    /// once a session starts; WP-42 step 9).
    pub fn record_connection(&self, key: &str) {
        *self
            .connections
            .lock()
            .expect("connections lock")
            .entry(key.to_owned())
            .or_insert(0) += 1;
    }

    /// Firewall-opening status text for one rule (WP-37 integration).
    pub fn firewall_status(&self, key: &str) -> String {
        self.fw_open
            .as_ref()
            .map(|group| group.status(key))
            .unwrap_or_default()
    }

    /// Whether the module switch is on (self-check surface).
    pub async fn module_enabled(&self) -> bool {
        self.config.read().await.settings.enable
    }

    /// Operations currently in flight (binding rounds / checks).
    pub fn inflight(&self) -> usize {
        self.inflight_ops.load(Ordering::SeqCst)
    }

    /// Manually restarts one rule's loop. Returns `false` when the rule is
    /// missing or disabled.
    pub async fn restart(self: &Arc<Self>, key: &str) -> bool {
        let (rule, settings, module_enabled) = {
            let config = self.config.read().await;
            (
                config.rules.iter().find(|rule| rule.key == key).cloned(),
                EntrySettings::capture(&config),
                config.settings.enable,
            )
        };
        let Some(rule) = rule else {
            return false;
        };
        if !module_enabled || !rule.enable {
            return false;
        }
        if let Some((_, token)) = self.loops.lock().expect("loops lock").get(key) {
            token.cancel();
        }
        self.spawn_rule(rule, settings).await;
        self.publish();
        true
    }

    /// Runs the module: spawns a loop per enabled rule and restarts them on
    /// config changes until `drain` fires. Draining cancels the in-flight
    /// operations and waits out the shutdown deadline before the firewall
    /// registrations are revoked.
    pub async fn run(self: Arc<Self>, mut drain: watch::Receiver<bool>) -> anyhow::Result<()> {
        let mut reload_rx = self.reload_rx.clone();
        let mut task_count_rx = self.task_count_rx.clone();
        let mut generation = *reload_rx.borrow_and_update();
        self.spawn_enabled().await;
        loop {
            let tasks_pending = *task_count_rx.borrow_and_update() > 0;
            tokio::select! {
                biased;
                _ = drain.changed() => break,
                changed = reload_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    let current = *reload_rx.borrow_and_update();
                    if current != generation {
                        generation = current;
                        self.restart_all_loops().await;
                    }
                }
                changed = task_count_rx.changed() => {
                    // A loop was spawned or finished: re-evaluate the join
                    // arm below on the next iteration.
                    if changed.is_err() {
                        break;
                    }
                }
                Some(result) = async {
                    let mut tasks = self.tasks.lock().await;
                    tasks.join_next().await
                }, if tasks_pending => {
                    self.task_count_tx.send_modify(|count| *count = count.saturating_sub(1));
                    if let Err(error) = result {
                        tracing::warn!(module = "stun", %error, "stun rule loop failed");
                    }
                }
            }
        }
        self.drain().await;
        Ok(())
    }

    async fn drain(&self) {
        self.exec_root.cancel();
        self.stop_loops();
        let deadline = Instant::now() + limits::SHUTDOWN_DEADLINE;
        while self.inflight() > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        if self.inflight() > 0 {
            tracing::warn!(
                module = "stun",
                remaining = self.inflight(),
                "stun shutdown deadline reached with operations still active"
            );
        }
        if let Some(group) = &self.fw_open {
            group.clear_all();
        }
        let mut tasks = self.tasks.lock().await;
        while tasks.join_next().await.is_some() {}
    }

    async fn spawn_enabled(self: &Arc<Self>) {
        if !self.config.read().await.settings.enable {
            return;
        }
        let (settings, rules) = {
            let config = self.config.read().await;
            (EntrySettings::capture(&config), config.rules.clone())
        };
        for rule in rules.iter().filter(|rule| rule.enable).cloned() {
            self.spawn_rule(rule, settings.clone()).await;
        }
        self.publish();
    }

    /// Config change: stop every loop cooperatively (their exit paths clean
    /// up), drop the status entries and start fresh ones.
    async fn restart_all_loops(self: &Arc<Self>) {
        self.stop_loops();
        let removed: Vec<String> = {
            let mut handles = self.handles.lock().expect("handles lock");
            let keys: Vec<String> = handles.keys().cloned().collect();
            handles.clear();
            keys
        };
        let still_enabled: HashSet<String> = {
            let config = self.config.read().await;
            config
                .rules
                .iter()
                .filter(|rule| rule.enable)
                .map(|rule| rule.key.clone())
                .collect()
        };
        for key in &removed {
            if !still_enabled.contains(key) {
                self.revoke_firewall(key);
            }
        }
        self.spawn_enabled().await;
    }

    fn stop_loops(&self) {
        let loops = std::mem::take(&mut *self.loops.lock().expect("loops lock"));
        for (_, (_, token)) in loops {
            token.cancel();
        }
    }

    async fn spawn_rule(self: &Arc<Self>, rule: Rule, settings: EntrySettings) {
        let loop_id = self.next_loop_id.fetch_add(1, Ordering::SeqCst);
        let token = self.exec_root.child_token();
        self.loops
            .lock()
            .expect("loops lock")
            .insert(rule.key.clone(), (loop_id, token.clone()));
        let notify = Arc::new(EntryNotify::from_rule(&rule, &settings));
        let handle = Arc::new(EntryHandle {
            key: rule.key.clone(),
            name: rule.name.clone(),
            protocol: rule.protocol,
            loop_id,
            view: Mutex::new(EntryView::binding()),
            notify,
        });
        self.handles
            .lock()
            .expect("handles lock")
            .insert(rule.key.clone(), Arc::clone(&handle));
        let runtime = Arc::clone(self);
        self.tasks.lock().await.spawn(async move {
            entry_loop(runtime, rule, settings, token, handle).await;
        });
        // The count tracks unjoined tasks; the module loop's join arm
        // decrements it as reaped results come back.
        self.task_count_tx.send_modify(|count| *count += 1);
    }

    // -- status helpers used by the entry loops --------------------------

    fn handle(&self, key: &str) -> Option<Arc<EntryHandle>> {
        self.handles.lock().expect("handles lock").get(key).cloned()
    }

    fn update_view(&self, key: &str, apply: impl FnOnce(&mut EntryView)) {
        if let Some(handle) = self.handle(key)
            && let Ok(mut view) = handle.view.lock()
        {
            apply(&mut view);
        }
    }

    fn sync_state(&self, key: &str, channel: &Channel) {
        let state = channel.state();
        self.update_view(key, |view| {
            view.state = state.as_str();
            view.public_addr = state.mapped();
            view.since = state.since();
        });
    }

    fn set_local_addr(&self, key: &str, addr: SocketAddr) {
        self.update_view(key, |view| view.local_addr = Some(addr));
    }

    fn set_last_error(&self, key: &str, error: Option<String>) {
        self.update_view(key, |view| view.last_error = error);
    }

    fn set_consistent(&self, key: &str, consistent: Option<bool>) {
        self.update_view(key, |view| view.nat_consistent = consistent);
    }

    fn open_firewall(&self, rule: &Rule, bind: SocketAddr) {
        if !rule.auto_firewall {
            return;
        }
        let Some(group) = &self.fw_open else {
            return;
        };
        let port = if bind.port() == 0 {
            rule.local_port
        } else {
            bind.port()
        };
        if port == 0 {
            return;
        }
        let family = match bind.ip() {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        };
        let fw_proto = match rule.protocol {
            Proto::Tcp => FwProto::Tcp,
            Proto::Udp => FwProto::Udp,
        };
        group.want(&rule.key, vec![Port::single(fw_proto, family, port)]);
    }

    fn revoke_firewall(&self, key: &str) {
        if let Some(group) = &self.fw_open {
            group.want(key, Vec::new());
        }
    }

    /// Applies a transition: logs and publishes `stun.changed` on mapping
    /// changes (the webhook / script notifications are dispatched by the
    /// loops through [`Runtime::notify_round`]).
    fn apply_transition(&self, handle: &EntryHandle, transition: &Transition) {
        match transition {
            Transition::None => {}
            Transition::Mapped { .. } | Transition::Ready { .. } => {
                tracing::info!(
                    module = "stun",
                    rule = %handle.name,
                    addr = ?handle
                        .view
                        .lock()
                        .ok()
                        .and_then(|view| view.public_addr),
                    "STUN mapping established"
                );
            }
            Transition::Changed { old, new } => {
                tracing::info!(
                    module = "stun",
                    rule = %handle.name,
                    old = %old,
                    new = %new,
                    "STUN mapping changed"
                );
                if let Some(bus) = &self.events {
                    bus.publish_with(|| {
                        let mut event = Event::new(Kind::StunChanged, "stun");
                        event.args = vec![
                            ("rule", handle.name.clone()),
                            ("ip", new.ip().to_string()),
                            ("port", new.port().to_string()),
                        ];
                        event.fields = vec![
                            ("rule", handle.name.clone()),
                            ("ip", new.ip().to_string()),
                            ("port", new.port().to_string()),
                            ("old", old.to_string()),
                            ("new", new.to_string()),
                        ];
                        event.dedup = Some(format!("{}:{new}", handle.key));
                        event
                    });
                }
            }
            Transition::Lost { reason } => {
                tracing::warn!(
                    module = "stun",
                    rule = %handle.name,
                    reason,
                    "STUN mapping lost"
                );
            }
        }
    }

    /// Notification dispatch for one successful binding round (WP-42 §3.3
    /// "地址变化的通知"): the script runs on the first endpoint and on real
    /// changes; the webhook fires on every success unless
    /// `webhookOnlyOnChange` limits it to changes. Deliveries run in
    /// detached tasks so the channel loop never waits on them.
    fn notify_round(
        self: &Arc<Self>,
        handle: &Arc<EntryHandle>,
        endpoint: SocketAddr,
        changed: bool,
        token: &CancellationToken,
    ) {
        let is_change = {
            let mut last = handle.notify.last_notified.lock().expect("notify lock");
            let previous = *last;
            let is_change = changed || previous.is_none();
            if previous != Some(endpoint) {
                *last = Some(endpoint);
            }
            is_change
        };
        let notif = Notification::new(&handle.name, endpoint, is_change, SystemTime::now());
        let notify = &handle.notify;
        // Webhook: every successful round unless onlyOnChange restricts it
        // to real changes.
        if (!notify.webhook_only_on_change || is_change) && !notify.webhook.url.trim().is_empty() {
            let webhook = notify.webhook.clone();
            let notif = notif.clone();
            let cancel = token.child_token();
            tokio::spawn(async move {
                match notify::deliver_webhook(&webhook, &notif, &cancel).await {
                    Ok(()) => tracing::info!(
                        module = "stun",
                        rule = %notif.rule_name,
                        "Webhook 通知已发送"
                    ),
                    Err(error) if error.contains("已停止") => {}
                    Err(error) => tracing::warn!(
                        module = "stun",
                        rule = %notif.rule_name,
                        %error,
                        "Webhook 通知失败"
                    ),
                }
            });
        }
        // Script: on the first endpoint and on changes only.
        if is_change && notify.script_enable && !notify.script.trim().is_empty() {
            let script = notify.script.clone();
            let cancel = token.child_token();
            tokio::spawn(async move {
                let outcome = notify::run_script(&script, &notif, &cancel).await;
                tracing::info!(
                    module = "stun",
                    rule = %notif.rule_name,
                    success = outcome.success,
                    output = %outcome.output,
                    "通知脚本执行结束"
                );
            });
        }
    }

    fn publish(&self) {
        let now = SystemTime::now();
        let handles = self.handles.lock().expect("handles lock");
        let mut entries: Vec<EntryStatus> = handles
            .values()
            .map(|handle| {
                let view = handle.view.lock().expect("view lock");
                EntryStatus {
                    key: handle.key.clone(),
                    name: handle.name.clone(),
                    protocol: handle.protocol,
                    state: view.state,
                    local_addr: view.local_addr,
                    public_addr: view.public_addr,
                    since: view.since,
                    last_error: view.last_error.clone(),
                    nat_consistent: view.nat_consistent,
                    firewall: self.firewall_status(&handle.key),
                }
            })
            .collect();
        drop(handles);
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        self.snapshot.store(Arc::new(RuntimeSnapshot {
            generated_at: now,
            entries,
        }));
    }
}

/// Resolves the rule's local bind address (auto / ip / interface / regex).
pub fn resolve_bind(rule: &Rule) -> Result<SocketAddr, String> {
    let port = rule.local_port;
    match rule.bind.mode {
        BindMode::Ip => {
            let ip: IpAddr = rule
                .bind
                .ip
                .parse()
                .map_err(|error| format!("无法解析绑定 IP {}: {error}", rule.bind.ip))?;
            Ok(SocketAddr::new(ip, port))
        }
        BindMode::Interface => named_interface(&rule.bind.interface, port)
            .ok_or_else(|| format!("未找到网卡 {}", rule.bind.interface)),
        BindMode::Regex => {
            let pattern = Regex::new(&rule.bind.regex)
                .map_err(|error| format!("网卡匹配正则无效: {error}"))?;
            let interfaces =
                if_addrs::get_if_addrs().map_err(|error| format!("枚举网卡失败: {error}"))?;
            interfaces
                .iter()
                .find(|iface| pattern.is_match(&iface.name))
                .map(|iface| SocketAddr::new(iface.ip(), port))
                .ok_or_else(|| format!("没有网卡匹配 {}", rule.bind.regex))
        }
        BindMode::Auto => {
            let interfaces =
                if_addrs::get_if_addrs().map_err(|error| format!("枚举网卡失败: {error}"))?;
            let pick = interfaces
                .iter()
                .map(|iface| iface.ip())
                .filter(|ip| !ip.is_loopback())
                .find(|ip| ip.is_ipv4())
                .or_else(|| {
                    interfaces
                        .iter()
                        .map(|iface| iface.ip())
                        .find(|ip| !ip.is_loopback())
                });
            Ok(SocketAddr::new(
                pick.unwrap_or(IpAddr::from([0, 0, 0, 0])),
                port,
            ))
        }
    }
}

fn named_interface(name: &str, port: u16) -> Option<SocketAddr> {
    let interfaces = if_addrs::get_if_addrs().ok()?;
    interfaces
        .iter()
        .find(|iface| iface.name == name)
        .map(|iface| SocketAddr::new(iface.ip(), port))
}

/// Spawns the gateway mapping task (UPnP / NAT-PMP) for a rule loop: it
/// maps the channel port once the STUN endpoint is known, follows mapping
/// changes, refreshes leases and deletes the mapping when the loop stops.
fn spawn_port_mapping(
    runtime: &Arc<Runtime>,
    rule: &Rule,
    local: SocketAddr,
    token: &CancellationToken,
) {
    if !rule.upnp && !rule.natpmp {
        return;
    }
    tokio::spawn(port_mapping_loop(
        Arc::clone(runtime),
        rule.clone(),
        local,
        token.child_token(),
    ));
}

/// Builds the mapping target from the rule plus the bound channel socket.
fn mapping_target(rule: &Rule, local: SocketAddr) -> MappingTarget {
    MappingTarget {
        upnp_gateway: rule
            .upnp_gateway
            .trim()
            .parse::<IpAddr>()
            .ok()
            .filter(|_| !rule.upnp_gateway.trim().is_empty()),
        upnp_control_url: (!rule.upnp_control_url.trim().is_empty())
            .then(|| rule.upnp_control_url.trim().to_owned()),
        natpmp_gateway: parse_natpmp_gateway(&rule.natpmp_gateway),
        protocol: rule.protocol,
        internal_ip: local.ip(),
        internal_host: (!rule.upnp_local_host.trim().is_empty())
            .then(|| rule.upnp_local_host.trim().to_owned()),
        channel_port: local.port(),
        upnp_internal_port: rule.upnp_internal_port,
        description: rule.name.clone(),
    }
}

/// Parses the NAT-PMP gateway setting: an IP literal (default port 5351)
/// or `IP:port`.
fn parse_natpmp_gateway(raw: &str) -> Option<SocketAddr> {
    let (host, port) =
        crate::validate::parse_host_port(raw.trim(), crate::upnp::natpmp::DEFAULT_PORT)?;
    let ip = host.parse::<IpAddr>().ok()?;
    Some(SocketAddr::new(ip, port))
}

/// The rule's STUN endpoint from the published snapshot.
fn current_public(runtime: &Runtime, key: &str) -> Option<SocketAddr> {
    runtime
        .snapshot()
        .entries
        .iter()
        .find(|entry| entry.key == key)
        .and_then(|entry| entry.public_addr)
}

/// Keeps the gateway port mapping aligned with the channel's public
/// endpoint: (re)maps on endpoint changes, refreshes at half lease and
/// deletes the mapping on exit (WP-42 §3.3 "停止规则时 DeletePortMapping").
async fn port_mapping_loop(
    runtime: Arc<Runtime>,
    rule: Rule,
    local: SocketAddr,
    token: CancellationToken,
) {
    let target = mapping_target(&rule, local);
    let use_upnp = rule.upnp;
    let mut applied: Option<MappingResult> = None;
    let mut built_for: Option<SocketAddr> = None;
    let mut refresh_at: Option<SystemTime> = None;
    let poll = Duration::from_secs(1);
    loop {
        if token.is_cancelled() {
            break;
        }
        let now = SystemTime::now();
        let public = current_public(&runtime, &rule.key);
        let endpoint_changed = public.is_some() && built_for != public;
        let refresh_due = applied.is_some()
            && !matches!(applied.as_ref().map(|m| m.permanent), Some(true))
            && refresh_at.is_some_and(|at| now >= at);
        if endpoint_changed || refresh_due {
            // A changed endpoint invalidates the old mapping (its external
            // port moved); a refresh re-asserts the same mapping.
            if let Some(old) = applied.take() {
                let cleanup = cleanup_token();
                upnp::teardown_mapping(&target, &old, upnp::control_timeout(), &cleanup).await;
            }
            refresh_at = None;
        }
        if applied.is_none() && public.is_some() {
            runtime.inflight_ops.fetch_add(1, Ordering::SeqCst);
            let result =
                upnp::setup_mapping(&target, public, use_upnp, upnp::control_timeout(), &token)
                    .await;
            runtime.inflight_ops.fetch_sub(1, Ordering::SeqCst);
            match result {
                Ok(result) => {
                    built_for = public;
                    refresh_at = (!result.permanent && result.lease_secs > 0).then(|| {
                        SystemTime::now() + Duration::from_secs(u64::from(result.lease_secs) / 2)
                    });
                    applied = Some(result);
                }
                Err(upnp::UpnpError::Cancelled) => break,
                Err(error) => {
                    tracing::warn!(
                        module = "stun",
                        rule = %rule.name,
                        %error,
                        "端口映射失败，稍后重试"
                    );
                    refresh_at = Some(SystemTime::now() + Duration::from_secs(30));
                }
            }
        }
        // Sleep until the next poll tick or the scheduled refresh; a
        // cancellation breaks out for the deletion.
        let wait = refresh_at
            .map(|at| {
                at.duration_since(SystemTime::now())
                    .unwrap_or(Duration::ZERO)
                    .min(poll)
            })
            .unwrap_or(poll);
        tokio::select! {
            biased;
            _ = token.cancelled() => break,
            _ = tokio::time::sleep(wait) => {}
        }
    }
    // Loop stopped: delete the mapping with a fresh grace token so the
    // removal survives the loop's own cancellation.
    if let Some(applied) = applied {
        let cleanup = cleanup_token();
        upnp::teardown_mapping(&target, &applied, upnp::control_timeout(), &cleanup).await;
    }
}

/// A short-lived token that cancels itself after the cleanup grace so a
/// shutdown cannot hang on the mapping deletion.
fn cleanup_token() -> CancellationToken {
    let token = CancellationToken::new();
    let grace = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        grace.cancel();
    });
    token
}

/// One rule channel loop: owns the local socket, drives the state machine
/// and cleans up on exit. `handle` identifies this incarnation; a newer
/// incarnation (manual restart) owns the shared registrations afterwards.
async fn entry_loop(
    runtime: Arc<Runtime>,
    rule: Rule,
    settings: EntrySettings,
    token: CancellationToken,
    handle: Arc<EntryHandle>,
) {
    let key = rule.key.clone();
    let timing = Timings::from_rule(&rule, settings.addr_check);

    let Some(bind) = retry(&token, 3, || resolve_bind(&rule)).await else {
        runtime.set_last_error(
            &key,
            Some("绑定地址解析失败，请检查规则的绑定设置".to_owned()),
        );
        runtime.publish();
        finish_entry(&runtime, &handle, &key).await;
        return;
    };
    let live_settings = live_settings(&runtime, &settings).await;
    let server_list = effective_servers(&rule, &live_settings);
    let servers = client::resolve_servers(&server_list).await;
    if servers.len() < server_list.len() {
        tracing::warn!(
            module = "stun",
            rule = %rule.name,
            "部分 STUN 服务器无法解析，已跳过"
        );
    }
    if servers.is_empty() {
        runtime.set_last_error(&key, Some("没有可用的 STUN 服务器".to_owned()));
        runtime.publish();
        finish_entry(&runtime, &handle, &key).await;
        return;
    }
    match rule.protocol {
        Proto::Udp => {
            let Some(socket) = retry_opt(&token, 3, || UdpSocket::bind(bind)).await else {
                runtime.set_last_error(&key, Some("绑定本地端口失败".to_owned()));
                runtime.publish();
                finish_entry(&runtime, &handle, &key).await;
                return;
            };
            let local = socket.local_addr().ok().unwrap_or(bind);
            runtime.set_local_addr(&key, local);
            runtime.open_firewall(&rule, local);
            spawn_port_mapping(&runtime, &rule, local, &token);
            udp_channel(&runtime, servers, &socket, &token, &handle, &timing).await;
        }
        Proto::Tcp => {
            let Some(listener) = retry_opt(&token, 3, || TcpListener::bind(bind)).await else {
                runtime.set_last_error(&key, Some("绑定本地端口失败".to_owned()));
                runtime.publish();
                finish_entry(&runtime, &handle, &key).await;
                return;
            };
            let local = listener.local_addr().ok().unwrap_or(bind);
            runtime.set_local_addr(&key, local);
            runtime.open_firewall(&rule, local);
            spawn_port_mapping(&runtime, &rule, local, &token);
            // TCP rules hold plain long connections to the keep-alive
            // targets so the NAT mapping survives between heartbeats.
            let keep_alive = client::resolve_servers(&effective_keep_alive(&rule, &live_settings))
                .await
                .into_iter()
                .take(limits::KEEP_ALIVE_CONNECTIONS_MAX)
                .collect::<Vec<_>>();
            if !keep_alive.is_empty() {
                tokio::spawn(keep_alive_loop(
                    rule.name.clone(),
                    keep_alive,
                    token.child_token(),
                ));
            }
            tcp_channel(&runtime, servers, listener, &token, &handle, &timing).await;
        }
    }
    finish_entry(&runtime, &handle, &key).await;
}

/// Cleanup shared by every exit path: revoke the firewall registration and
/// drop the status entry when this incarnation is still the current one.
async fn finish_entry(runtime: &Arc<Runtime>, handle: &Arc<EntryHandle>, key: &str) {
    let superseded = {
        let loops = runtime.loops.lock().expect("loops lock");
        loops
            .get(key)
            .is_some_and(|(loop_id, _)| *loop_id != handle.loop_id)
    };
    if !superseded {
        runtime.revoke_firewall(key);
        runtime.handles.lock().expect("handles lock").remove(key);
    }
    runtime.publish();
}

/// The module settings as they are right now, with the values captured at
/// loop start as fallback.
async fn live_settings(runtime: &Runtime, captured: &EntrySettings) -> Settings {
    let config = runtime.config.read().await;
    Settings {
        stun_servers: if config.settings.stun_servers.is_empty() {
            captured.global_servers.clone()
        } else {
            config.settings.stun_servers.clone()
        },
        keep_alive_servers: if config.settings.keep_alive_servers.is_empty() {
            captured.global_keep_alive.clone()
        } else {
            config.settings.keep_alive_servers.clone()
        },
        ..config.settings.clone()
    }
}

/// Retries a fallible operation up to `attempts` times with a short pause,
/// stopping early when the token fires.
async fn retry<T, F: FnMut() -> Result<T, E>, E>(
    token: &CancellationToken,
    attempts: u32,
    mut operation: F,
) -> Option<T> {
    for attempt in 0..attempts {
        if token.is_cancelled() {
            return None;
        }
        match operation() {
            Ok(value) => return Some(value),
            Err(_) if attempt + 1 < attempts => {}
            Err(_) => return None,
        }
        tokio::select! {
            biased;
            _ = token.cancelled() => return None,
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
    }
    None
}

/// Same retry shape for async fallible operations.
async fn retry_opt<T, E, Fut, F>(
    token: &CancellationToken,
    attempts: u32,
    mut operation: F,
) -> Option<T>
where
    Fut: std::future::Future<Output = Result<T, E>>,
    F: FnMut() -> Fut,
{
    for attempt in 0..attempts {
        if token.is_cancelled() {
            return None;
        }
        match operation().await {
            Ok(value) => return Some(value),
            Err(_) if attempt + 1 < attempts => {}
            Err(_) => return None,
        }
        tokio::select! {
            biased;
            _ = token.cancelled() => return None,
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
    }
    None
}

/// The UDP channel: binding heartbeats over the channel socket (the same
/// socket future inbound traffic uses), reachability probes from it too.
async fn udp_channel(
    runtime: &Arc<Runtime>,
    servers: Vec<SocketAddr>,
    socket: &UdpSocket,
    token: &CancellationToken,
    handle: &Arc<EntryHandle>,
    timing: &Timings,
) {
    let key = handle.key.as_str();
    let mut channel = Channel::new(SystemTime::now());
    runtime.sync_state(key, &channel);
    runtime.publish();
    loop {
        if token.is_cancelled() {
            return;
        }
        for action in channel.tick(SystemTime::now(), timing) {
            match action {
                Action::SendBinding => {
                    channel.mark_attempt(SystemTime::now());
                    runtime.inflight_ops.fetch_add(1, Ordering::SeqCst);
                    let result =
                        client::query_servers_udp_on(socket, &servers, timing.stun_timeout, token)
                            .await;
                    runtime.inflight_ops.fetch_sub(1, Ordering::SeqCst);
                    if token.is_cancelled() {
                        return;
                    }
                    match result {
                        Ok(QueryOutcome { mapped, .. }) => {
                            runtime.set_last_error(key, None);
                            let transition = channel.on_mapped(mapped, SystemTime::now(), timing);
                            runtime.sync_state(key, &channel);
                            runtime.apply_transition(handle, &transition);
                            runtime.notify_round(
                                handle,
                                mapped,
                                matches!(transition, Transition::Changed { .. }),
                                token,
                            );
                            probe_consistency(
                                runtime,
                                handle,
                                &servers,
                                socket,
                                timing,
                                token,
                                &transition,
                            )
                            .await;
                        }
                        Err(errors) => {
                            if cancelled(&errors) {
                                return;
                            }
                            runtime.set_last_error(key, Some(binding_error(&errors)));
                            let transition = channel.on_timeout(SystemTime::now(), timing);
                            runtime.sync_state(key, &channel);
                            runtime.apply_transition(handle, &transition);
                        }
                    }
                    runtime.publish();
                }
                Action::Check => {
                    let Some(public) = channel.state().mapped() else {
                        continue;
                    };
                    channel.mark_check(SystemTime::now());
                    runtime.sync_state(key, &channel);
                    runtime.publish();
                    runtime.inflight_ops.fetch_add(1, Ordering::SeqCst);
                    let ok = client::probe_udp(socket, public, timing.stun_timeout, token)
                        .await
                        .is_ok();
                    runtime.inflight_ops.fetch_sub(1, Ordering::SeqCst);
                    if token.is_cancelled() {
                        return;
                    }
                    let transition = channel.on_check(ok, SystemTime::now(), timing);
                    runtime.sync_state(key, &channel);
                    runtime.apply_transition(handle, &transition);
                    runtime.publish();
                }
            }
        }
        wait_for(&channel, timing, token).await;
    }
}

/// The TCP channel: binding rounds on a persistent control connection to
/// the STUN server; the local listener stays bound for the future inbound
/// pipe, and the reachability probe dials the channel's own public
/// endpoint.
async fn tcp_channel(
    runtime: &Arc<Runtime>,
    servers: Vec<SocketAddr>,
    // Held (dropped on exit) so the channel port stays bound for the
    // future inbound pipe.
    _listener: TcpListener,
    token: &CancellationToken,
    handle: &Arc<EntryHandle>,
    timing: &Timings,
) {
    let key = handle.key.as_str();
    let mut channel = Channel::new(SystemTime::now());
    let mut control: Option<(SocketAddr, TcpStream)> = None;
    runtime.sync_state(key, &channel);
    runtime.publish();
    loop {
        if token.is_cancelled() {
            return;
        }
        for action in channel.tick(SystemTime::now(), timing) {
            match action {
                Action::SendBinding => {
                    channel.mark_attempt(SystemTime::now());
                    runtime.inflight_ops.fetch_add(1, Ordering::SeqCst);
                    let result =
                        tcp_binding_round(&mut control, &servers, timing.stun_timeout, token).await;
                    runtime.inflight_ops.fetch_sub(1, Ordering::SeqCst);
                    if token.is_cancelled() {
                        return;
                    }
                    match result {
                        Ok(QueryOutcome { mapped, .. }) => {
                            runtime.set_last_error(key, None);
                            let transition = channel.on_mapped(mapped, SystemTime::now(), timing);
                            runtime.sync_state(key, &channel);
                            runtime.apply_transition(handle, &transition);
                            runtime.notify_round(
                                handle,
                                mapped,
                                matches!(transition, Transition::Changed { .. }),
                                token,
                            );
                        }
                        Err(errors) => {
                            if cancelled(&errors) {
                                return;
                            }
                            runtime.set_last_error(key, Some(binding_error(&errors)));
                            let transition = channel.on_timeout(SystemTime::now(), timing);
                            runtime.sync_state(key, &channel);
                            runtime.apply_transition(handle, &transition);
                        }
                    }
                    runtime.publish();
                }
                Action::Check => {
                    let Some(public) = channel.state().mapped() else {
                        continue;
                    };
                    channel.mark_check(SystemTime::now());
                    runtime.sync_state(key, &channel);
                    runtime.publish();
                    runtime.inflight_ops.fetch_add(1, Ordering::SeqCst);
                    let probe = client::connect_tcp(public, timing.stun_timeout, token).await;
                    runtime.inflight_ops.fetch_sub(1, Ordering::SeqCst);
                    if token.is_cancelled() {
                        return;
                    }
                    let ok = probe.is_ok();
                    let transition = channel.on_check(ok, SystemTime::now(), timing);
                    runtime.sync_state(key, &channel);
                    runtime.apply_transition(handle, &transition);
                    runtime.publish();
                }
            }
        }
        wait_for(&channel, timing, token).await;
    }
}

/// Sleeps until the channel's next deadline (or a cancellation).
async fn wait_for(channel: &Channel, timing: &Timings, token: &CancellationToken) {
    let Some(deadline) = channel.next_deadline(timing, SystemTime::now()) else {
        // Lost without auto-retry: park until a manual restart cancels the
        // loop.
        tokio::select! {
            biased;
            _ = token.cancelled() => {}
        }
        return;
    };
    let wait = deadline
        .duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO);
    tokio::select! {
        biased;
        _ = token.cancelled() => {}
        _ = tokio::time::sleep(wait) => {}
    }
}

/// One TCP binding round: reuse the control connection when it is alive,
/// otherwise reconnect to the servers in order.
async fn tcp_binding_round(
    control: &mut Option<(SocketAddr, TcpStream)>,
    servers: &[SocketAddr],
    timeout: Duration,
    token: &CancellationToken,
) -> Result<QueryOutcome, Vec<ClientError>> {
    let mut errors = Vec::new();
    if let Some((server, stream)) = control.as_mut() {
        match client::binding_tcp_once(stream, timeout, token).await {
            Ok(mapped) => {
                return Ok(QueryOutcome {
                    server: *server,
                    mapped,
                });
            }
            Err(ClientError::Cancelled) => return Err(vec![ClientError::Cancelled]),
            Err(error) => {
                errors.push(error);
                *control = None;
            }
        }
    }
    for server in servers {
        let mut stream = match client::connect_tcp(*server, timeout, token).await {
            Ok(stream) => stream,
            Err(ClientError::Cancelled) => return Err(vec![ClientError::Cancelled]),
            Err(error) => {
                errors.push(error);
                continue;
            }
        };
        match client::binding_tcp_once(&mut stream, timeout, token).await {
            Ok(mapped) => {
                *control = Some((*server, stream));
                return Ok(QueryOutcome {
                    server: *server,
                    mapped,
                });
            }
            Err(ClientError::Cancelled) => return Err(vec![ClientError::Cancelled]),
            Err(error) => errors.push(error),
        }
    }
    Err(errors)
}

/// Concurrent consistency probe after a fresh (or changed) mapping: more
/// than one server is required for a real comparison, a single server is
/// trivially consistent with itself.
async fn probe_consistency(
    runtime: &Arc<Runtime>,
    handle: &Arc<EntryHandle>,
    servers: &[SocketAddr],
    socket: &UdpSocket,
    timing: &Timings,
    token: &CancellationToken,
    transition: &Transition,
) {
    if !matches!(
        transition,
        Transition::Mapped { .. } | Transition::Changed { .. }
    ) {
        return;
    }
    let report: ConsistencyReport = if servers.len() > 1 {
        client::check_consistency(socket, servers, timing.stun_timeout, token).await
    } else {
        ConsistencyReport {
            pairs: Vec::new(),
            verdict: ConsistencyVerdict::Consistent,
        }
    };
    if token.is_cancelled() {
        return;
    }
    let consistent = match report.verdict {
        ConsistencyVerdict::Unknown => None,
        ConsistencyVerdict::Consistent => Some(true),
        ConsistencyVerdict::PortDivergent | ConsistencyVerdict::IpDivergent => Some(false),
    };
    runtime.set_consistent(&handle.key, consistent);
    if consistent == Some(false) {
        tracing::debug!(
            module = "stun",
            rule = %handle.name,
            verdict = ?report.verdict,
            "STUN 服务器返回的映射不一致（可能为端口受限或对称型 NAT）"
        );
    }
}

/// TCP keep-alive: one long-lived connection per target, reconnecting with
/// the configured delay when it drops.
async fn keep_alive_loop(name: String, servers: Vec<SocketAddr>, token: CancellationToken) {
    let mut index = 0usize;
    while !token.is_cancelled() {
        let server = servers[index % servers.len()];
        index += 1;
        let connect = TcpStream::connect(server);
        match tokio::time::timeout(limits::KEEP_ALIVE_CONNECT_TIMEOUT, connect).await {
            Ok(Ok(mut stream)) => {
                tracing::debug!(
                    module = "stun",
                    rule = %name,
                    target = %server,
                    "TCP keep-alive connection established"
                );
                let mut buf = [0u8; 512];
                loop {
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => return,
                        result = stream.read(&mut buf) => {
                            match result {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                    }
                }
                tracing::debug!(
                    module = "stun",
                    rule = %name,
                    target = %server,
                    "TCP keep-alive connection dropped"
                );
            }
            _ => {
                tracing::debug!(
                    module = "stun",
                    rule = %name,
                    target = %server,
                    "TCP keep-alive connect failed"
                );
            }
        }
        tokio::select! {
            biased;
            _ = token.cancelled() => return,
            _ = tokio::time::sleep(limits::KEEP_ALIVE_RECONNECT_DELAY) => {}
        }
    }
}

fn cancelled(errors: &[ClientError]) -> bool {
    errors
        .iter()
        .any(|error| matches!(error, ClientError::Cancelled))
}

fn binding_error(errors: &[ClientError]) -> String {
    if errors.is_empty() {
        return "STUN 查询失败：没有可用的服务器".to_owned();
    }
    format!(
        "STUN 查询失败：{}",
        errors
            .iter()
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("；")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle_with(key: &str, state: &'static str) -> Arc<EntryHandle> {
        Arc::new(EntryHandle {
            key: key.to_owned(),
            name: key.to_owned(),
            protocol: Proto::Udp,
            loop_id: 1,
            view: Mutex::new(EntryView {
                state,
                local_addr: None,
                public_addr: None,
                since: None,
                last_error: None,
                nat_consistent: Some(true),
            }),
            notify: Arc::new(EntryNotify {
                webhook: WebhookConfig::default(),
                webhook_only_on_change: false,
                script_enable: false,
                script: String::new(),
                last_notified: Mutex::new(None),
            }),
        })
    }

    #[tokio::test]
    async fn metrics_up_and_connections_reflect_snapshot() {
        let config = Arc::new(AsyncRwLock::new(FileConfig::default()));
        let runtime = Runtime::new(config, None, None);
        runtime.record_connection("ready1");
        runtime.record_connection("ready1");
        runtime.record_connection("lost1");
        {
            let mut handles = runtime.handles.lock().expect("handles lock");
            handles.insert("ready1".to_owned(), handle_with("ready1", "ready"));
            handles.insert("lost1".to_owned(), handle_with("lost1", "lost"));
        }
        runtime.publish();
        let metrics = runtime.metrics();
        let up = |key: &str| -> f64 {
            metrics
                .iter()
                .find(|sample| {
                    sample.name == "ferrumgate_stun_up"
                        && sample.labels.get("rule").map(String::as_str) == Some(key)
                })
                .map(|sample| sample.value)
                .expect("up sample")
        };
        let forwarded = |key: &str| -> f64 {
            metrics
                .iter()
                .find(|sample| {
                    sample.name == "ferrumgate_stun_connections_total"
                        && sample.labels.get("rule").map(String::as_str) == Some(key)
                })
                .map(|sample| sample.value)
                .expect("counter sample")
        };
        assert_eq!(up("ready1"), 1.0);
        assert_eq!(up("lost1"), 0.0);
        assert_eq!(forwarded("ready1"), 2.0);
        assert_eq!(forwarded("lost1"), 1.0);
    }

    #[tokio::test]
    async fn resolve_bind_modes_map_to_local_addresses() {
        let mut rule = Rule {
            local_port: 40_000,
            ..Rule::default()
        };
        rule.bind.mode = BindMode::Ip;
        rule.bind.ip = "127.0.0.1".into();
        assert_eq!(
            resolve_bind(&rule).expect("ip mode"),
            "127.0.0.1:40000".parse::<SocketAddr>().expect("addr")
        );
        rule.bind.ip = "not-an-ip".into();
        assert!(resolve_bind(&rule).is_err());
        // Interface mode with an interface that cannot exist.
        rule.bind.mode = BindMode::Interface;
        rule.bind.interface = "definitely-not-an-interface-42".into();
        assert!(resolve_bind(&rule).is_err());
    }
}
