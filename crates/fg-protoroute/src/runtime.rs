//! Protocol routing runtime (WP-35 §3.3): TCP listeners, lock-free
//! `ArcSwap` hot-reloading, hit-counter inheritance by [`MatchKey`],
//! pre-sniff source access control and quotas, incremental sniffing with
//! timeout, SPA handoff to the port-knock module, per-target PROXY
//! protocol v1/v2, target failover, and zero-loss bidirectional passthrough.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use arc_swap::ArcSwap;
use fg_net::fwopen;
use fg_net::openports::{OpenPort, Proto};
use fg_net::quota::{PortQuota, QuotaResult, SourceQuota};
use fg_net::source_rule::{AccessFilter, RawSourceRule, SourceRule};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::Deps;
use crate::model::{FileConfig, Net, Protocol, ProxyProtocol, Rule, Settings, limits};
use crate::router::{MatchKey, RouteTable, Target};
use crate::sniff::{SniffOutcome, SniffResult, SniffState};
use crate::validate;

/// Per-rule atomic hit and admission counters shared across hot updates.
#[derive(Debug)]
pub struct RuleCounters {
    /// Hit counters aligned with `rule.routes`.
    pub routes: Vec<Arc<AtomicU64>>,
    /// Connections routed to the rule's default target.
    pub default_hits: Arc<AtomicU64>,
    /// Connections dropped because no route matched and no default target was set.
    pub dropped: Arc<AtomicU64>,
    /// Connections rejected before forwarding (ban / access list / knock / quota).
    pub denied: Arc<AtomicU64>,
    /// Currently active connections on this rule.
    pub active: Arc<AtomicI64>,
}

impl RuleCounters {
    fn new(route_count: usize) -> Self {
        Self {
            routes: (0..route_count)
                .map(|_| Arc::new(AtomicU64::new(0)))
                .collect(),
            default_hits: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
            denied: Arc::new(AtomicU64::new(0)),
            active: Arc::new(AtomicI64::new(0)),
        }
    }

    fn inherit(old: &RuleRuntime, new_rule: &Rule, new_table: &RouteTable) -> Self {
        let mut old_enabled: HashMap<MatchKey, VecDeque<Arc<AtomicU64>>> = HashMap::new();
        let mut old_disabled: HashMap<MatchKey, VecDeque<Arc<AtomicU64>>> = HashMap::new();
        for (idx, route) in old.rule.routes.iter().enumerate() {
            let Some(key) = old.table.keys().get(idx) else {
                continue;
            };
            let Some(counter) = old.counters.routes.get(idx) else {
                continue;
            };
            let bucket = if route.disabled {
                old_disabled.entry(key.clone()).or_default()
            } else {
                old_enabled.entry(key.clone()).or_default()
            };
            bucket.push_back(Arc::clone(counter));
        }

        let mut routes = Vec::with_capacity(new_rule.routes.len());
        for (idx, route) in new_rule.routes.iter().enumerate() {
            let key = &new_table.keys()[idx];
            let inherited = if route.disabled {
                old_disabled
                    .get_mut(key)
                    .and_then(VecDeque::pop_front)
                    .or_else(|| old_enabled.get_mut(key).and_then(VecDeque::pop_front))
            } else {
                old_enabled
                    .get_mut(key)
                    .and_then(VecDeque::pop_front)
                    .or_else(|| old_disabled.get_mut(key).and_then(VecDeque::pop_front))
            };
            routes.push(inherited.unwrap_or_else(|| Arc::new(AtomicU64::new(0))));
        }

        let default_hits = if old.table.has_default() && new_table.has_default() {
            Arc::clone(&old.counters.default_hits)
        } else {
            Arc::new(AtomicU64::new(0))
        };

        Self {
            routes,
            default_hits,
            dropped: Arc::clone(&old.counters.dropped),
            denied: Arc::clone(&old.counters.denied),
            active: Arc::clone(&old.counters.active),
        }
    }

    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            route_hits: self
                .routes
                .iter()
                .map(|c| c.load(Ordering::Relaxed))
                .collect(),
            default_hits: self.default_hits.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            denied: self.denied.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed).max(0) as u64,
        }
    }
}

/// Read-only point-in-time counter values for API status and metrics.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CounterSnapshot {
    pub route_hits: Vec<u64>,
    pub default_hits: u64,
    pub dropped: u64,
    pub denied: u64,
    pub active: u64,
}

/// Immutable per-rule routing snapshot published behind `ArcSwap`.
/// Each accepted connection loads this once.
pub struct RuleRuntime {
    pub rule: Rule,
    pub table: RouteTable,
    pub access: AccessFilter,
    pub sniff_timeout: Duration,
    pub dial_timeout: Duration,
    pub listen_ports: Vec<u16>,
    pub default_ports: Vec<u16>,
    pub counters: Arc<RuleCounters>,
}

impl RuleRuntime {
    fn compile(
        rule: &Rule,
        settings: &Settings,
        deps: &Deps,
        prev: Option<&RuleRuntime>,
    ) -> Result<Self> {
        let default_exists = !rule.target_addresses.is_empty();
        let table = RouteTable::compile(&rule.routes, default_exists, prev.map(|p| &p.table))
            .map_err(|errs| anyhow::anyhow!("compile route table: {}", errs.join("; ")))?;

        let source_rule = if rule.access.enable {
            let allow = (!rule.access.whitelist.is_empty()).then(|| rule.access.whitelist.clone());
            SourceRule::compile(RawSourceRule {
                allow,
                deny: rule.access.blacklist.clone(),
            })
            .map_err(|e| anyhow::anyhow!("compile source access rule: {e}"))?
        } else {
            SourceRule::default()
        };

        let mut access = AccessFilter::new(source_rule);
        if let Some(ban) = &deps.ban {
            access = access.with_ban(Arc::clone(ban));
        }

        let listen_ports = expand_ports(&rule.listen_ports)?;
        let default_ports = validate::parse_port_list(&rule.target_ports);
        let sniff_secs = validate::clamp_sniff_timeout(rule.sniff_timeout);
        let sniff_timeout = Duration::from_millis((f64::from(sniff_secs) * 1000.0).round() as u64);
        let dial_secs = if settings.dial_timeout == 0 {
            limits::DIAL_TIMEOUT_DEFAULT_SECS
        } else {
            settings.dial_timeout
        };
        let dial_timeout = Duration::from_secs(u64::from(dial_secs));

        let counters = match prev {
            Some(old) => Arc::new(RuleCounters::inherit(old, rule, &table)),
            None => Arc::new(RuleCounters::new(rule.routes.len())),
        };

        Ok(Self {
            rule: rule.clone(),
            table,
            access,
            sniff_timeout,
            dial_timeout,
            listen_ports,
            default_ports,
            counters,
        })
    }

    fn default_port_for(&self, listen_port: u16) -> u16 {
        if self.default_ports.is_empty() {
            return listen_port;
        }
        if self.default_ports.len() == 1 {
            return self.default_ports[0];
        }
        if self.default_ports.len() == self.listen_ports.len()
            && let Some(pos) = self.listen_ports.iter().position(|&p| p == listen_port)
        {
            return self.default_ports[pos];
        }
        self.default_ports[0]
    }
}

/// Listener-binding properties that require a rule restart if changed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ListenSpec {
    protocols: Vec<Net>,
    listen_address: String,
    ports: Vec<u16>,
    max_connections: u32,
    max_conns_per_source: u32,
    per_source_exempt: Vec<String>,
    auto_firewall: bool,
}

impl ListenSpec {
    fn from_rule(rule: &Rule, settings: &Settings) -> Result<Self> {
        let mut protocols = rule.protocols.clone();
        protocols.sort();
        protocols.dedup();
        let ports = expand_ports(&rule.listen_ports)?;
        let (max_connections, max_conns_per_source) = validate::effective_limits(rule, settings);
        Ok(Self {
            protocols,
            listen_address: rule.listen_address.clone(),
            ports,
            max_connections,
            max_conns_per_source,
            per_source_exempt: settings.per_source_exempt.clone(),
            auto_firewall: rule.auto_firewall,
        })
    }
}

/// Status of one bound or failed `(protocol, port)` listener.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListenerStatus {
    pub protocol: String,
    pub port: u16,
    pub listening: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Read-only runtime status for a single rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleStatus {
    pub listening: bool,
    pub listeners: Vec<ListenerStatus>,
    pub listen_errors: Vec<String>,
    pub counters: CounterSnapshot,
    pub firewall_status: String,
    pub firewall_failed: bool,
}

struct ActiveRule {
    spec: ListenSpec,
    runtime: Arc<ArcSwap<RuleRuntime>>,
    listeners: Vec<ListenerStatus>,
    bound_ports: Vec<(Net, u16)>,
    accept_cancel: CancellationToken,
    accept_tasks: Vec<JoinHandle<()>>,
}

impl ActiveRule {
    /// Whether this running rule can be updated in place without restarting
    /// listeners: listening protocol/address/ports/limits unchanged AND every
    /// configured listener is currently healthy (WP-35 §3.3).
    fn can_update(&self, new_rule: &Rule, new_settings: &Settings) -> bool {
        if self.listeners.iter().any(|l| !l.listening) {
            return false;
        }
        match ListenSpec::from_rule(new_rule, new_settings) {
            Ok(new_spec) => new_spec == self.spec,
            Err(_) => false,
        }
    }

    fn update(&self, new_rule: &Rule, new_settings: &Settings, deps: &Deps) -> Result<()> {
        let old = self.runtime.load();
        let next = RuleRuntime::compile(new_rule, new_settings, deps, Some(&old))?;
        self.runtime.store(Arc::new(next));
        Ok(())
    }

    fn status(&self, key: &str, deps: &Deps) -> RuleStatus {
        let rt = self.runtime.load();
        let listen_errors: Vec<String> = self
            .listeners
            .iter()
            .filter_map(|l| {
                l.error
                    .as_ref()
                    .map(|e| format!("{}:{}: {e}", l.protocol, l.port))
            })
            .collect();
        let listening = self.listeners.iter().any(|l| l.listening);
        let (firewall_status, firewall_failed) = if let Some(fw) = &deps.fw_open {
            if self.spec.auto_firewall {
                let bound_addr = parse_listen_ip(&self.spec.listen_address);
                if fwopen::is_loopback(bound_addr) {
                    (fwopen::LOOPBACK_NOTE.to_owned(), false)
                } else {
                    (fw.status(key), fw.failed(key))
                }
            } else {
                (String::new(), false)
            }
        } else {
            (String::new(), false)
        };
        RuleStatus {
            listening,
            listeners: self.listeners.clone(),
            listen_errors,
            counters: rt.counters.snapshot(),
            firewall_status,
            firewall_failed,
        }
    }
}

struct State {
    config: FileConfig,
    running: bool,
    active: BTreeMap<String, ActiveRule>,
}

/// Manages all protocol-routing rules, their listeners, hot updates,
/// firewall openings, and graceful shutdown.
pub struct Manager {
    deps: Deps,
    state: tokio::sync::Mutex<State>,
    /// Cancelled only on full module shutdown to terminate long-lived relays.
    relay_cancel: CancellationToken,
    /// Tracks active connection handler tasks for clean drain on shutdown.
    conn_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Manager {
    /// Creates a stopped manager holding the normalized configuration.
    pub fn new(config: FileConfig, deps: Deps) -> Self {
        let config = validate::normalize(config);
        Self {
            deps,
            state: tokio::sync::Mutex::new(State {
                config,
                running: false,
                active: BTreeMap::new(),
            }),
            relay_cancel: CancellationToken::new(),
            conn_tasks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn deps(&self) -> &Deps {
        &self.deps
    }

    /// Returns a clone of the current normalized configuration.
    pub async fn config(&self) -> FileConfig {
        self.state.lock().await.config.clone()
    }

    /// Starts listeners for every enabled rule (when `settings.enable` is true).
    pub async fn start(&self) -> Result<()> {
        let mut st = self.state.lock().await;
        st.running = true;
        let cfg = st.config.clone();
        self.reconcile_locked(&mut st, &cfg).await
    }

    /// Replaces the configuration, hot-updating eligible rules in place and
    /// restarting only rules whose listener spec changed, failed, or toggled.
    pub async fn apply(&self, config: FileConfig) -> Result<()> {
        let config = validate::normalize(config);
        let mut st = self.state.lock().await;
        st.config = config.clone();
        if st.running {
            self.reconcile_locked(&mut st, &config).await?;
        }
        Ok(())
    }

    /// Returns the runtime status of one rule, or an empty default status if
    /// the rule is disabled / not running.
    pub async fn rule_status(&self, key: &str) -> RuleStatus {
        let st = self.state.lock().await;
        if let Some(active) = st.active.get(key) {
            active.status(key, &self.deps)
        } else {
            let route_count = st
                .config
                .rules
                .iter()
                .find(|r| r.key == key)
                .map(|r| r.routes.len())
                .unwrap_or(0);
            RuleStatus {
                counters: CounterSnapshot {
                    route_hits: vec![0; route_count],
                    ..CounterSnapshot::default()
                },
                ..RuleStatus::default()
            }
        }
    }

    /// Returns runtime status for all configured rules keyed by `rule.key`.
    pub async fn all_statuses(&self) -> BTreeMap<String, RuleStatus> {
        let st = self.state.lock().await;
        let mut out = BTreeMap::new();
        for rule in &st.config.rules {
            let status = if let Some(active) = st.active.get(&rule.key) {
                active.status(&rule.key, &self.deps)
            } else {
                RuleStatus {
                    counters: CounterSnapshot {
                        route_hits: vec![0; rule.routes.len()],
                        ..CounterSnapshot::default()
                    },
                    ..RuleStatus::default()
                }
            };
            out.insert(rule.key.clone(), status);
        }
        out
    }

    /// Returns sorted TCP ports currently carrying an enabled `spa` route so
    /// firewall / knock integrations never block SPA delivery (WP-35 §3.3).
    pub async fn spa_ports(&self) -> Vec<u16> {
        let st = self.state.lock().await;
        if !st.config.settings.enable {
            return Vec::new();
        }
        let mut ports = Vec::new();
        for rule in &st.config.rules {
            if !rule.enable {
                continue;
            }
            let has_spa = rule
                .routes
                .iter()
                .any(|r| !r.disabled && r.protocol == Protocol::Spa);
            if has_spa && let Ok(expanded) = expand_ports(&rule.listen_ports) {
                ports.extend(expanded);
            }
        }
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Stops all listeners and drains in-flight connections within
    /// [`limits::SHUTDOWN_DEADLINE`].
    pub async fn shutdown(&self) {
        let stopped: Vec<ActiveRule> = {
            let mut st = self.state.lock().await;
            st.running = false;
            std::mem::take(&mut st.active).into_values().collect()
        };

        for rule in stopped {
            stop_active_rule(rule).await;
        }

        if let Some(open_ports) = &self.deps.open_ports {
            open_ports.set("protoroute", &[]);
        }
        if let Some(fw) = &self.deps.fw_open {
            fw.clear_all();
        }

        let tasks: Vec<JoinHandle<()>> = {
            let mut guard = self.conn_tasks.lock().expect("conn_tasks lock");
            std::mem::take(&mut *guard)
        };
        if !tasks.is_empty() {
            let drain = async {
                for task in tasks {
                    let _ = task.await;
                }
            };
            if tokio::time::timeout(limits::SHUTDOWN_DEADLINE, drain)
                .await
                .is_err()
            {
                self.relay_cancel.cancel();
            }
        }
    }

    async fn reconcile_locked(&self, st: &mut State, cfg: &FileConfig) -> Result<()> {
        let mut desired: BTreeMap<String, &Rule> = BTreeMap::new();
        if cfg.settings.enable {
            for rule in &cfg.rules {
                if rule.enable && !rule.key.is_empty() {
                    desired.insert(rule.key.clone(), rule);
                }
            }
        }

        // Stop removed or disabled rules first so their ports are freed.
        let to_remove: Vec<String> = st
            .active
            .keys()
            .filter(|k| !desired.contains_key(*k))
            .cloned()
            .collect();
        for key in to_remove {
            if let Some(old) = st.active.remove(&key) {
                stop_active_rule(old).await;
            }
            if let Some(fw) = &self.deps.fw_open {
                fw.want(&key, Vec::new());
            }
        }

        // Update existing or restart / start newly enabled rules.
        for (key, rule) in desired {
            if let Some(existing) = st.active.get(&key) {
                if existing.can_update(rule, &cfg.settings) {
                    if let Err(err) = existing.update(rule, &cfg.settings, &self.deps) {
                        tracing::warn!(
                            target: "fg_protoroute::runtime",
                            rule = %key,
                            error = %err,
                            "hot update failed; keeping previous snapshot"
                        );
                    }
                    continue;
                }
                if let Some(old) = st.active.remove(&key) {
                    stop_active_rule(old).await;
                }
            }
            match self.start_rule(rule, &cfg.settings).await {
                Ok(active) => {
                    self.sync_rule_fw(&key, &active);
                    st.active.insert(key, active);
                }
                Err(err) => {
                    tracing::warn!(
                        target: "fg_protoroute::runtime",
                        rule = %key,
                        error = %err,
                        "failed to start protoroute rule"
                    );
                }
            }
        }

        self.sync_open_ports(st);
        Ok(())
    }

    fn sync_rule_fw(&self, key: &str, active: &ActiveRule) {
        let Some(fw) = &self.deps.fw_open else {
            return;
        };
        if !active.spec.auto_firewall {
            fw.want(key, Vec::new());
            return;
        }
        let host = parse_listen_ip(&active.spec.listen_address);
        let mut by_net: BTreeMap<Net, Vec<u16>> = BTreeMap::new();
        for &(net, port) in &active.bound_ports {
            by_net.entry(net).or_default().push(port);
        }
        let mut fw_ports = Vec::new();
        for (net, ports) in by_net {
            fw_ports.extend(fwopen::for_listen(net.as_str(), host, &ports, &[]));
        }
        fw.want(key, fw_ports);
    }

    fn sync_open_ports(&self, st: &State) {
        let Some(open_ports) = &self.deps.open_ports else {
            return;
        };
        let mut ports: Vec<OpenPort> = st
            .active
            .values()
            .flat_map(|active| {
                active.bound_ports.iter().map(|&(_, port)| OpenPort {
                    proto: Proto::Tcp,
                    port,
                })
            })
            .collect();
        ports.sort_by_key(|p| p.port);
        ports.dedup();
        open_ports.set("protoroute", &ports);
    }

    async fn start_rule(&self, rule: &Rule, settings: &Settings) -> Result<ActiveRule> {
        let spec = ListenSpec::from_rule(rule, settings)?;
        let runtime = Arc::new(ArcSwap::from_pointee(RuleRuntime::compile(
            rule, settings, &self.deps, None,
        )?));
        let exempt_nets: Vec<ipnet::IpNet> = settings
            .per_source_exempt
            .iter()
            .filter_map(|e| validate::parse_ip_or_cidr(e))
            .collect();

        let accept_cancel = CancellationToken::new();
        let mut listeners = Vec::new();
        let mut bound_ports = Vec::new();
        let mut accept_tasks = Vec::new();

        for &port in &spec.ports {
            // Per-port quotas are shared across protocol families bound on the same port.
            let port_quota = Arc::new(PortQuota::new(spec.max_connections));
            let source_quota = Arc::new(SourceQuota::new(
                spec.max_conns_per_source,
                false,
                exempt_nets.clone(),
            ));

            for &net in &spec.protocols {
                match bind_tcp(net, &spec.listen_address, port).await {
                    Ok(listener) => {
                        let actual_port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
                        listeners.push(ListenerStatus {
                            protocol: net.as_str().to_owned(),
                            port: actual_port,
                            listening: true,
                            error: None,
                        });
                        bound_ports.push((net, actual_port));

                        let task = spawn_accept_loop(
                            listener,
                            actual_port,
                            Arc::clone(&runtime),
                            Arc::clone(&port_quota),
                            Arc::clone(&source_quota),
                            self.deps.clone(),
                            accept_cancel.clone(),
                            self.relay_cancel.clone(),
                            Arc::clone(&self.conn_tasks),
                        );
                        accept_tasks.push(task);
                    }
                    Err(err) => {
                        tracing::warn!(
                            target: "fg_protoroute::runtime",
                            rule = %rule.key,
                            protocol = net.as_str(),
                            port,
                            error = %err,
                            "listener bind failed; continuing with remaining ports"
                        );
                        listeners.push(ListenerStatus {
                            protocol: net.as_str().to_owned(),
                            port,
                            listening: false,
                            error: Some(err.to_string()),
                        });
                    }
                }
            }
        }

        Ok(ActiveRule {
            spec,
            runtime,
            listeners,
            bound_ports,
            accept_cancel,
            accept_tasks,
        })
    }
}

async fn stop_active_rule(active: ActiveRule) {
    active.accept_cancel.cancel();
    for task in active.accept_tasks {
        let _ = task.await;
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_accept_loop(
    listener: TcpListener,
    listen_port: u16,
    runtime: Arc<ArcSwap<RuleRuntime>>,
    port_quota: Arc<PortQuota>,
    source_quota: Arc<SourceQuota>,
    deps: Deps,
    accept_cancel: CancellationToken,
    relay_cancel: CancellationToken,
    conn_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                biased;
                _ = accept_cancel.cancelled() => break,
                res = listener.accept() => res,
            };
            let (stream, peer_addr) = match accepted {
                Ok(pair) => pair,
                Err(err) => {
                    tracing::warn!(
                        target: "fg_protoroute::runtime",
                        port = listen_port,
                        error = %err,
                        "accept error"
                    );
                    tokio::select! {
                        _ = accept_cancel.cancelled() => break,
                        _ = tokio::time::sleep(limits::ACCEPT_RETRY) => continue,
                    }
                }
            };
            let local_addr = stream.local_addr().unwrap_or_else(|_| {
                SocketAddr::new(
                    match peer_addr {
                        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    },
                    listen_port,
                )
            });

            let rt = runtime.load_full();
            let port_quota = Arc::clone(&port_quota);
            let source_quota = Arc::clone(&source_quota);
            let deps = deps.clone();
            let sniff_cancel = accept_cancel.clone();
            let relay_cancel = relay_cancel.clone();

            let handle = tokio::spawn(async move {
                handle_connection(
                    stream,
                    peer_addr,
                    local_addr,
                    listen_port,
                    rt,
                    port_quota,
                    source_quota,
                    deps,
                    sniff_cancel,
                    relay_cancel,
                )
                .await;
            });

            // Prune finished connection handles periodically so the vec stays bounded.
            let mut guard = conn_tasks.lock().expect("conn_tasks lock");
            if guard.len() >= 64 {
                guard.retain(|h| !h.is_finished());
            }
            guard.push(handle);
        }
    })
}

struct ActiveGuard(Arc<AtomicI64>);

impl ActiveGuard {
    fn enter(counter: &Arc<AtomicI64>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(counter))
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    listen_port: u16,
    rt: Arc<RuleRuntime>,
    port_quota: Arc<PortQuota>,
    source_quota: Arc<SourceQuota>,
    deps: Deps,
    sniff_cancel: CancellationToken,
    relay_cancel: CancellationToken,
) {
    let _active = ActiveGuard::enter(&rt.counters.active);
    let peer_ip = peer_addr.ip().to_canonical();

    // 1. Quotas & source access control BEFORE reading any client byte.
    let Some(_port_permit) = port_quota.try_acquire() else {
        rt.counters.denied.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let _source_permit = match source_quota.try_acquire(peer_ip) {
        QuotaResult::Acquired(permit) => Some(permit),
        QuotaResult::Exempt => None,
        QuotaResult::Full => {
            if source_quota.should_warn(Instant::now()) {
                tracing::warn!(
                    target: "fg_protoroute::runtime",
                    rule = %rt.rule.key,
                    ip = %peer_ip,
                    "per-source connection quota reached"
                );
            }
            rt.counters.denied.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    if !rt.access.admits(peer_ip) {
        rt.counters.denied.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // Rule-level knock gate: when no enabled SPA route exists, reject before
    // reading any byte. When an enabled SPA route exists, allow sniffing only
    // to recognize an incoming SPA knock packet.
    let rule_knock_open = match rt.rule.knock.as_deref() {
        None => true,
        Some(knock_key) => deps
            .knock
            .as_ref()
            .is_some_and(|kp| kp.is_open(knock_key, peer_ip)),
    };
    if !rule_knock_open && !rt.table.has_spa() {
        rt.counters.denied.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // 2. Sniff within `sniff_timeout`.
    let sniffed = match sniff_stream(&mut client, &rt, &sniff_cancel).await {
        SniffStreamResult::Identified(result) => Some(result),
        SniffStreamResult::Unidentified(raw) => {
            if !rule_knock_open {
                rt.counters.denied.fetch_add(1, Ordering::Relaxed);
                return;
            }
            if !rt.table.has_default() {
                rt.counters.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            rt.counters.default_hits.fetch_add(1, Ordering::Relaxed);
            let port = rt.default_port_for(listen_port);
            forward(
                client,
                peer_addr,
                local_addr,
                &rt.rule.target_addresses,
                port,
                rt.rule.proxy_protocol,
                rt.dial_timeout,
                &raw,
                &relay_cancel,
            )
            .await;
            return;
        }
        SniffStreamResult::ClientClosed | SniffStreamResult::Cancelled => {
            // Client closed before sniff completed (or rule stopped): discard silently.
            return;
        }
    };

    let result = sniffed.expect("checked Some");

    // 3. Route selection.
    match rt.table.route(&result) {
        Target::Spa(_idx) => {
            // Hand the captured SPA packet to the knock module: no reply, no
            // forwarding, no route-hit increment (WP-35 §3.3).
            if let Some(kp) = &deps.knock {
                kp.handle_spa(peer_ip, listen_port, &result.raw);
            }
        }
        Target::Route(idx) => {
            if !rule_knock_open {
                rt.counters.denied.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let route = &rt.rule.routes[idx];
            if let Some(knock_key) = route.knock.as_deref()
                && !deps
                    .knock
                    .as_ref()
                    .is_some_and(|kp| kp.is_open(knock_key, peer_ip))
            {
                rt.counters.denied.fetch_add(1, Ordering::Relaxed);
                return;
            }
            rt.counters.routes[idx].fetch_add(1, Ordering::Relaxed);
            let target_port = if route.target_port == 0 {
                listen_port
            } else {
                route.target_port
            };
            forward(
                client,
                peer_addr,
                local_addr,
                &route.target_addresses,
                target_port,
                route.proxy_protocol,
                rt.dial_timeout,
                &result.raw,
                &relay_cancel,
            )
            .await;
        }
        Target::Default => {
            if !rule_knock_open {
                rt.counters.denied.fetch_add(1, Ordering::Relaxed);
                return;
            }
            rt.counters.default_hits.fetch_add(1, Ordering::Relaxed);
            let port = rt.default_port_for(listen_port);
            forward(
                client,
                peer_addr,
                local_addr,
                &rt.rule.target_addresses,
                port,
                rt.rule.proxy_protocol,
                rt.dial_timeout,
                &result.raw,
                &relay_cancel,
            )
            .await;
        }
        Target::Drop => {
            if !rule_knock_open {
                rt.counters.denied.fetch_add(1, Ordering::Relaxed);
                return;
            }
            rt.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

enum SniffStreamResult {
    Identified(SniffResult),
    Unidentified(Vec<u8>),
    ClientClosed,
    Cancelled,
}

async fn sniff_stream(
    client: &mut TcpStream,
    rt: &RuleRuntime,
    cancel: &CancellationToken,
) -> SniffStreamResult {
    let mut state = SniffState::new(rt.table.has_spa());
    let mut chunk = [0u8; limits::READ_CHUNK];
    let mut deadline = tokio::time::Instant::now() + rt.sniff_timeout;
    let mut spa_deadline_set = false;

    loop {
        if state.spa_pending() && !spa_deadline_set {
            deadline = tokio::time::Instant::now() + limits::SPA_READ_TIMEOUT;
            spa_deadline_set = true;
        }

        let read_res = tokio::select! {
            biased;
            _ = cancel.cancelled() => return SniffStreamResult::Cancelled,
            res = tokio::time::timeout_at(deadline, client.read(&mut chunk)) => res,
        };

        match read_res {
            Err(_elapsed) => {
                if state.read() == 0 {
                    // Server-speaks-first: client sent nothing within sniffTimeout.
                    return SniffStreamResult::Identified(SniffResult {
                        protocol: Protocol::Timeout,
                        server_name: None,
                        alpn: Vec::new(),
                        host: None,
                        raw: Vec::new(),
                    });
                }
                if let Some(spa) = state.finish_spa() {
                    return SniffStreamResult::Identified(spa);
                }
                return SniffStreamResult::Unidentified(state.take_raw());
            }
            Ok(Err(_io_err)) => return SniffStreamResult::ClientClosed,
            Ok(Ok(0)) => {
                if let Some(spa) = state.finish_spa() {
                    return SniffStreamResult::Identified(spa);
                }
                return SniffStreamResult::ClientClosed;
            }
            Ok(Ok(n)) => match state.feed(&chunk[..n]) {
                SniffOutcome::NeedMore => continue,
                SniffOutcome::Done(result) => return SniffStreamResult::Identified(result),
                SniffOutcome::NotProtocol | SniffOutcome::Malformed => {
                    return SniffStreamResult::Unidentified(state.take_raw());
                }
            },
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    targets: &[String],
    port: u16,
    proxy_protocol: ProxyProtocol,
    dial_timeout: Duration,
    raw: &[u8],
    relay_cancel: &CancellationToken,
) {
    let Some(mut upstream) = dial_failover(targets, port, dial_timeout).await else {
        tracing::warn!(
            target: "fg_protoroute::runtime",
            targets = ?targets,
            port,
            "all targets failed"
        );
        return;
    };

    if let Some(header) = encode_proxy_header(proxy_protocol, peer_addr, local_addr)
        && upstream.write_all(&header).await.is_err()
    {
        return;
    }

    if !raw.is_empty() && upstream.write_all(raw).await.is_err() {
        return;
    }

    let _ = tokio::select! {
        biased;
        _ = relay_cancel.cancelled() => Ok((0, 0)),
        res = tokio::io::copy_bidirectional(&mut client, &mut upstream) => res,
    };
}

/// Dials each target address in order until one succeeds (failover).
async fn dial_failover(targets: &[String], port: u16, dial_timeout: Duration) -> Option<TcpStream> {
    for host in targets {
        let attempt = if let Ok(ip) = host.parse::<IpAddr>() {
            tokio::time::timeout(dial_timeout, TcpStream::connect(SocketAddr::new(ip, port))).await
        } else {
            tokio::time::timeout(dial_timeout, TcpStream::connect((host.as_str(), port))).await
        };
        if let Ok(Ok(stream)) = attempt {
            let _ = stream.set_nodelay(true);
            return Some(stream);
        }
    }
    None
}

/// Encodes a PROXY protocol v1 or v2 header for the client connection.
pub fn encode_proxy_header(
    proto: ProxyProtocol,
    peer: SocketAddr,
    local: SocketAddr,
) -> Option<Vec<u8>> {
    match proto {
        ProxyProtocol::None => None,
        ProxyProtocol::V1 => Some(encode_proxy_v1(peer, local)),
        ProxyProtocol::V2 => Some(encode_proxy_v2(peer, local)),
    }
}

fn encode_proxy_v1(peer: SocketAddr, local: SocketAddr) -> Vec<u8> {
    match (peer.ip().to_canonical(), local.ip().to_canonical()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => format!(
            "PROXY TCP4 {src} {dst} {} {}\r\n",
            peer.port(),
            local.port()
        )
        .into_bytes(),
        (IpAddr::V6(src), IpAddr::V6(dst)) => format!(
            "PROXY TCP6 {src} {dst} {} {}\r\n",
            peer.port(),
            local.port()
        )
        .into_bytes(),
        _ => b"PROXY UNKNOWN\r\n".to_vec(),
    }
}

fn encode_proxy_v2(peer: SocketAddr, local: SocketAddr) -> Vec<u8> {
    const SIG: [u8; 12] = [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];
    let mut out = Vec::with_capacity(52);
    out.extend_from_slice(&SIG);
    out.push(0x21); // version 2, command PROXY
    match (peer.ip().to_canonical(), local.ip().to_canonical()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            out.push(0x11); // AF_INET + STREAM
            out.extend_from_slice(&12u16.to_be_bytes());
            out.extend_from_slice(&src.octets());
            out.extend_from_slice(&dst.octets());
            out.extend_from_slice(&peer.port().to_be_bytes());
            out.extend_from_slice(&local.port().to_be_bytes());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            out.push(0x21); // AF_INET6 + STREAM
            out.extend_from_slice(&36u16.to_be_bytes());
            out.extend_from_slice(&src.octets());
            out.extend_from_slice(&dst.octets());
            out.extend_from_slice(&peer.port().to_be_bytes());
            out.extend_from_slice(&local.port().to_be_bytes());
        }
        _ => {
            out.push(0x00); // AF_UNSPEC + UNSPEC
            out.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    out
}

async fn bind_tcp(net: Net, listen_address: &str, port: u16) -> Result<TcpListener> {
    if !listen_address.is_empty() {
        let ip: IpAddr = listen_address
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid listen address: {listen_address}"))?;
        if (net == Net::Tcp4 && ip.is_ipv6()) || (net == Net::Tcp6 && ip.is_ipv4()) {
            anyhow::bail!(
                "listen address {listen_address} does not match protocol {}",
                net.as_str()
            );
        }
        return Ok(TcpListener::bind(SocketAddr::new(ip, port)).await?);
    }

    match net {
        Net::Tcp4 => {
            Ok(TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)).await?)
        }
        Net::Tcp6 => {
            Ok(TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)).await?)
        }
        Net::Tcp => {
            match TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)).await
            {
                Ok(listener) => Ok(listener),
                Err(_) => Ok(TcpListener::bind(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    port,
                ))
                .await?),
            }
        }
    }
}

fn expand_ports(raw: &str) -> Result<Vec<u16>> {
    let ranges = validate::parse_listen_ports(raw)
        .map_err(|reason| anyhow::anyhow!("invalid listen ports: {reason}"))?;
    let mut ports = Vec::new();
    for (first, last) in ranges {
        ports.extend(first..=last);
    }
    Ok(ports)
}

fn parse_listen_ip(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        trimmed.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_v1_and_v2_encode_ipv4_and_ipv6() {
        let peer: SocketAddr = "192.0.2.10:54321".parse().unwrap();
        let local: SocketAddr = "198.51.100.2:443".parse().unwrap();
        assert_eq!(encode_proxy_header(ProxyProtocol::None, peer, local), None);
        assert_eq!(
            encode_proxy_header(ProxyProtocol::V1, peer, local).unwrap(),
            b"PROXY TCP4 192.0.2.10 198.51.100.2 54321 443\r\n"
        );
        let v2 = encode_proxy_header(ProxyProtocol::V2, peer, local).unwrap();
        assert_eq!(v2.len(), 16 + 12);
        assert_eq!(&v2[..12], b"\r\n\r\n\x00\r\nQUIT\n");
        assert_eq!(v2[12], 0x21);
        assert_eq!(v2[13], 0x11);
        assert_eq!(&v2[14..16], &12u16.to_be_bytes());
        assert_eq!(&v2[16..20], &[192, 0, 2, 10]);
        assert_eq!(&v2[20..24], &[198, 51, 100, 2]);
        assert_eq!(&v2[24..26], &54321u16.to_be_bytes());
        assert_eq!(&v2[26..28], &443u16.to_be_bytes());

        // IPv4-mapped IPv6 addresses canonicalize to TCP4.
        let mapped_peer: SocketAddr = "[::ffff:192.0.2.10]:54321".parse().unwrap();
        assert_eq!(
            encode_proxy_header(ProxyProtocol::V1, mapped_peer, local).unwrap(),
            b"PROXY TCP4 192.0.2.10 198.51.100.2 54321 443\r\n"
        );

        let peer6: SocketAddr = "[2001:db8::1]:12345".parse().unwrap();
        let local6: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        assert_eq!(
            encode_proxy_header(ProxyProtocol::V1, peer6, local6).unwrap(),
            b"PROXY TCP6 2001:db8::1 2001:db8::2 12345 443\r\n"
        );
        let v2_6 = encode_proxy_header(ProxyProtocol::V2, peer6, local6).unwrap();
        assert_eq!(v2_6.len(), 16 + 36);
        assert_eq!(v2_6[13], 0x21);
        assert_eq!(&v2_6[14..16], &36u16.to_be_bytes());
    }
}
