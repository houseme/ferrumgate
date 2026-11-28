//! Web service runtime observability (WP-28): per-minute site statistics,
//! first-byte latency histograms, live request connections, network topology,
//! replay frames, visitor audit, structured access logs, Prometheus metrics,
//! and the fixed 5-step request finish sequence [`finish_request`].

pub mod access_log;
pub mod connections;
pub mod latency;
pub mod metrics;
pub mod minute_ring;
pub mod recorder;
pub mod replay;
pub mod routes;
pub mod topology;
pub mod visitors;

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use self::{
    access_log::{AccessLogEntry, AccessLogSink},
    connections::{ConnRegistry, ResolvedAddr},
    latency::LatencyHist,
    metrics::{
        ListenerActionMetricRow, MetricsSnapshot, SiteMetricRow, UpstreamMetricRow, listener_label,
        render_prometheus, site_label, upstream_display_url,
    },
    minute_ring::{BackendPerfSnapshot, MinuteRing, SitePerfSnapshot, unix_minute},
    recorder::{DENY_KIND_COUNT, DenyKind, Recorder, status_class_index},
    replay::{ReplaySettings, ReplayStore},
    topology::{
        BackendNode, ListenerActionNode, ListenerNode, MAX_TOPO_API_IPS, MAX_TOPO_SUMMARY_IPS,
        RecentIpsView, SiteNode, Topo, TopologySnapshot, normalize_rate_window,
    },
    visitors::{ADMIN_IDENTITY, VisitorEvent, VisitorStore, VisitorsConfig},
};

/// Path-probe report forwarded to the intrusion guard (WP-52) during step 4 of
/// [`finish_request`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathProbeReport {
    pub ip: IpAddr,
    pub host: String,
    pub path: String,
    pub status: u16,
    pub site_key: String,
    pub is_default_site: bool,
}

/// Callback invoked in step 4 of [`finish_request`] to report potential path
/// probing to WP-52 (`fg-guard`).
pub type PathProbeHook = Arc<dyn Fn(PathProbeReport) + Send + Sync>;

/// Optional GeoIP country-code resolver (`IpAddr -> Option<"US">`).
pub type GeoIpLookup = Arc<dyn Fn(IpAddr) -> Option<String> + Send + Sync>;

/// One of the five ordered steps executed inside [`finish_request`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinishStep {
    Latency,
    VisitorAudit,
    AccessLog,
    PathProbe,
    StatsCounters,
}

/// Summary returned by [`finish_request`] for observability and testing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinishOutcome {
    pub executed_steps: Vec<FinishStep>,
    pub effective_status: u16,
    pub recorded_latency: Option<Duration>,
    pub logged_access: bool,
    pub reported_path_probe: Option<u16>,
}

/// Runtime observability state for one upstream backend under a site.
pub struct UpstreamObs {
    /// Display URL with credentials and query string stripped.
    pub url: String,
    /// Route label (path prefix or per-user split), empty for the main pool.
    pub route: String,
    pub weight: u32,
    pub backup: bool,
    pub up: AtomicBool,
    pub topo: Topo,
    pub response_bytes: AtomicU64,
}

impl UpstreamObs {
    pub fn new(raw_url: &str, route: impl Into<String>, weight: u32, backup: bool) -> Self {
        Self {
            url: upstream_display_url(raw_url),
            route: route.into(),
            weight: weight.max(1),
            backup,
            up: AtomicBool::new(true),
            topo: Topo::new(),
            response_bytes: AtomicU64::new(0),
        }
    }

    pub fn set_healthy(&self, healthy: bool) {
        self.up.store(healthy, Ordering::Release);
    }

    pub fn is_healthy(&self) -> bool {
        self.up.load(Ordering::Acquire)
    }

    /// Records a forwarded backend exchange.
    ///
    /// Direction follows WP-28 §3.3 (gateway perspective):
    /// - `bytes_to_backend` = `up` (request body sent to backend)
    /// - `bytes_from_backend` = `down` (response received from backend)
    pub fn record_exchange(
        &self,
        now_sec: i64,
        status: u16,
        bytes_to_backend: u64,
        bytes_from_backend: u64,
        client_ip: Option<IpAddr>,
    ) {
        self.topo.record_request(
            now_sec,
            status,
            DenyKind::None,
            bytes_to_backend,
            bytes_from_backend,
            client_ip,
        );
        self.response_bytes
            .fetch_add(bytes_from_backend, Ordering::Relaxed);
    }
}

/// Site metadata stored alongside live counters (updated in place on site edits
/// without resetting counters).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteMeta {
    pub key: String,
    pub name: String,
    pub domains: Vec<String>,
    pub enabled: bool,
    pub is_default: bool,
    pub access_log: bool,
    /// `exact` | `wildcard` | `any` | `default`.
    pub match_kind: String,
    /// `proxy` | `redirect` | `static` | `text` | `close`.
    pub site_type: String,
    /// Target label for redirect/static/text/close sites.
    pub target_label: Option<String>,
}

impl SiteMeta {
    /// Builds [`SiteMeta`] from a [`crate::web::model::Site`].
    pub fn from_site(site: &crate::web::model::Site, access_log: bool) -> Self {
        let is_default = site.domains.is_empty();
        let match_kind = if is_default {
            "default"
        } else if site.domains.iter().any(|d| d.trim() == "*") {
            "any"
        } else if site.domains.iter().any(|d| d.contains('*')) {
            "wildcard"
        } else {
            "exact"
        };
        let site_type = if site.site_type.is_empty() {
            "proxy".to_owned()
        } else {
            site.site_type.clone()
        };
        let target_label = match site_type.as_str() {
            "redirect" => Some(site.redirect_to.clone()),
            "static" => Some(site.root.clone()),
            "text" => Some(format!(
                "text({})",
                if site.text_status_code == 0 {
                    200
                } else {
                    site.text_status_code
                }
            )),
            "close" => Some("close(444)".to_owned()),
            _ => None,
        };
        Self {
            key: site.key.clone(),
            name: site.name.clone(),
            domains: site.domains.clone(),
            enabled: site.enable,
            is_default,
            access_log,
            match_kind: match_kind.to_owned(),
            site_type,
            target_label,
        }
    }

    pub fn display_name(&self) -> String {
        site_label(&self.name, &self.domains, &self.key)
    }
}

/// Runtime observability container for one site. Reused across site edits
/// (preserving stats) and recreated/reset when the parent listener is edited.
pub struct SiteObs {
    pub listener_key: String,
    pub listener_name: String,
    pub meta: RwLock<SiteMeta>,
    pub minute_ring: MinuteRing,
    pub latency: LatencyHist,
    pub topo: Topo,
    /// Cumulative response bytes sent to visitors (for Prometheus counter).
    pub cum_response_bytes: AtomicU64,
    /// Cumulative response counts by status class (`2xx..5xx`).
    pub cum_by_class: [AtomicU64; 4],
    pub upstreams: RwLock<Vec<Arc<UpstreamObs>>>,
}

impl SiteObs {
    pub fn new(
        listener_key: impl Into<String>,
        listener_name: impl Into<String>,
        meta: SiteMeta,
    ) -> Self {
        Self {
            listener_key: listener_key.into(),
            listener_name: listener_name.into(),
            meta: RwLock::new(meta),
            minute_ring: MinuteRing::new(),
            latency: LatencyHist::new(),
            topo: Topo::new(),
            cum_response_bytes: AtomicU64::new(0),
            cum_by_class: std::array::from_fn(|_| AtomicU64::new(0)),
            upstreams: RwLock::new(Vec::new()),
        }
    }

    pub fn meta_snapshot(&self) -> SiteMeta {
        self.meta
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn update_meta(&self, meta: SiteMeta) {
        *self
            .meta
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = meta;
    }

    pub fn set_upstreams(&self, upstreams: Vec<Arc<UpstreamObs>>) {
        *self
            .upstreams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = upstreams;
    }

    pub fn upstreams_snapshot(&self) -> Vec<Arc<UpstreamObs>> {
        self.upstreams
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Resets all in-memory counters for this site.
    pub fn reset(&self) {
        self.minute_ring.reset();
        self.latency.reset();
        self.topo.reset();
        self.cum_response_bytes.store(0, Ordering::Relaxed);
        for c in &self.cum_by_class {
            c.store(0, Ordering::Relaxed);
        }
        for u in self.upstreams_snapshot() {
            u.topo.reset();
            u.response_bytes.store(0, Ordering::Relaxed);
        }
    }

    /// Produces a ~60 s performance snapshot readable by WP-69 (`fg-perf`).
    pub fn perf_snapshot(&self, now: Instant, now_sec: i64) -> SitePerfSnapshot {
        let meta = self.meta_snapshot();
        let rate60 = self.topo.rate.rates(now_sec, 60);
        let now_min = now_sec.div_euclid(60);
        let summary = self.minute_ring.summary(now_min.saturating_sub(1), now_min);
        let window_requests = summary.requests;
        let err5xx = if window_requests > 0 {
            Some((summary.errors5xx as f64 / window_requests as f64) * 100.0)
        } else {
            None
        };
        let latency_p95 = self
            .latency
            .quantile(Duration::from_secs(60), now, 0.95)
            .map(|d| d.as_secs_f64() * 1000.0);

        let backends = self
            .upstreams_snapshot()
            .into_iter()
            .map(|u| BackendPerfSnapshot {
                name: if u.route.is_empty() {
                    u.url.clone()
                } else {
                    format!("{} ({})", u.url, u.route)
                },
                healthy: u.is_healthy(),
                conns: u64::from(u.topo.active.load(Ordering::Relaxed)),
            })
            .collect();

        SitePerfSnapshot {
            name: meta.display_name(),
            active: u64::from(self.topo.active.load(Ordering::Relaxed)),
            qps: Some(rate60.qps),
            err5xx,
            latency_p95,
            window_requests,
            window_span_secs: 60,
            backends,
        }
    }
}

/// Runtime observability container for one listener and its sites/actions.
pub struct ListenerObs {
    pub key: String,
    pub name: RwLock<String>,
    pub listen_addr: RwLock<String>,
    pub enabled: AtomicBool,
    pub running: AtomicBool,
    pub error: RwLock<Option<String>>,
    pub sites: RwLock<HashMap<String, Arc<SiteObs>>>,
    pub site_order: RwLock<Vec<String>>,
    pub action_default_close: Topo,
    pub action_https_redirect: Topo,
    pub action_not_found: Topo,
}

impl ListenerObs {
    pub fn new(
        key: impl Into<String>,
        name: impl Into<String>,
        listen_addr: impl Into<String>,
        enabled: bool,
    ) -> Self {
        Self {
            key: key.into(),
            name: RwLock::new(name.into()),
            listen_addr: RwLock::new(listen_addr.into()),
            enabled: AtomicBool::new(enabled),
            running: AtomicBool::new(enabled),
            error: RwLock::new(None),
            sites: RwLock::new(HashMap::new()),
            site_order: RwLock::new(Vec::new()),
            action_default_close: Topo::new(),
            action_https_redirect: Topo::new(),
            action_not_found: Topo::new(),
        }
    }

    pub fn name(&self) -> String {
        self.name
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn log_source_tag(&self) -> String {
        listener_label(&self.name(), &self.key)
    }

    pub fn set_status(&self, running: bool, error: Option<String>) {
        self.running.store(running, Ordering::Release);
        *self
            .error
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = error;
    }

    /// Inserts or updates a site while **preserving** its existing counters and
    /// histograms across site configuration edits (WP-28 §3.3).
    pub fn upsert_site(&self, meta: SiteMeta) -> Arc<SiteObs> {
        let key = meta.key.clone();
        let listener_name = self.name();
        let mut sites = self
            .sites
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = sites.get(&key) {
            existing.update_meta(meta);
            return Arc::clone(existing);
        }
        let obs = Arc::new(SiteObs::new(self.key.clone(), listener_name, meta));
        sites.insert(key.clone(), Arc::clone(&obs));
        let mut order = self
            .site_order
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !order.contains(&key) {
            order.push(key);
        }
        obs
    }

    pub fn site(&self, site_key: &str) -> Option<Arc<SiteObs>> {
        self.sites
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(site_key)
            .cloned()
    }

    /// Resets all listener action counters and every site's stats under this
    /// listener (called when listener-level settings such as port/TLS change).
    pub fn reset_all(&self) {
        self.action_default_close.reset();
        self.action_https_redirect.reset();
        self.action_not_found.reset();
        let sites: Vec<Arc<SiteObs>> = self
            .sites
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect();
        for site in sites {
            site.reset();
        }
    }
}

/// Central observability hub shared by the web data plane, management routes,
/// replay loop, and WP-69 perf reader.
pub struct ObsHub {
    pub listeners: RwLock<HashMap<String, Arc<ListenerObs>>>,
    pub listener_order: RwLock<Vec<String>>,
    pub connections: Arc<ConnRegistry>,
    pub visitors: Arc<VisitorStore>,
    pub replay: Arc<ReplayStore>,
    pub access_log_sink: RwLock<Option<AccessLogSink>>,
    pub path_probe_hook: RwLock<Option<PathProbeHook>>,
    pub geoip_lookup: RwLock<Option<GeoIpLookup>>,
}

impl Default for ObsHub {
    fn default() -> Self {
        Self::new(VisitorsConfig::default(), ReplaySettings::default())
    }
}

impl ObsHub {
    pub fn new(visitors_cfg: VisitorsConfig, replay_cfg: ReplaySettings) -> Self {
        Self {
            listeners: RwLock::new(HashMap::new()),
            listener_order: RwLock::new(Vec::new()),
            connections: Arc::new(ConnRegistry::new()),
            visitors: Arc::new(VisitorStore::new(visitors_cfg)),
            replay: Arc::new(ReplayStore::new(replay_cfg)),
            access_log_sink: RwLock::new(None),
            path_probe_hook: RwLock::new(None),
            geoip_lookup: RwLock::new(None),
        }
    }

    pub fn set_access_log_sink(&self, sink: AccessLogSink) {
        *self
            .access_log_sink
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(sink);
    }

    pub fn set_path_probe_hook(&self, hook: PathProbeHook) {
        *self
            .path_probe_hook
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hook);
    }

    pub fn set_geoip_lookup(&self, lookup: GeoIpLookup) {
        *self
            .geoip_lookup
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(lookup);
    }

    /// Registers or returns an existing listener container.
    pub fn register_listener(
        &self,
        key: impl Into<String>,
        name: impl Into<String>,
        listen_addr: impl Into<String>,
        enabled: bool,
    ) -> Arc<ListenerObs> {
        let key = key.into();
        let name = name.into();
        let listen_addr = listen_addr.into();
        let mut map = self
            .listeners
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = map.get(&key) {
            *existing
                .name
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = name;
            *existing
                .listen_addr
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = listen_addr;
            existing.enabled.store(enabled, Ordering::Release);
            return Arc::clone(existing);
        }
        let listener = Arc::new(ListenerObs::new(key.clone(), name, listen_addr, enabled));
        map.insert(key.clone(), Arc::clone(&listener));
        let mut order = self
            .listener_order
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !order.contains(&key) {
            order.push(key);
        }
        listener
    }

    /// Reloads a listener after a listener-level setting change (port, TLS,
    /// network, etc.), resetting counters for that listener and its sites.
    pub fn reset_listener(
        &self,
        key: &str,
        name: impl Into<String>,
        listen_addr: impl Into<String>,
        enabled: bool,
    ) -> Arc<ListenerObs> {
        let listener = self.register_listener(key, name, listen_addr, enabled);
        listener.reset_all();
        // Clear finished connection history for sites on this listener as well.
        let site_keys: Vec<String> = listener
            .sites
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .keys()
            .cloned()
            .collect();
        for sk in site_keys {
            self.connections.clear_site_history(&sk);
        }
        listener
    }

    pub fn listener(&self, key: &str) -> Option<Arc<ListenerObs>> {
        self.listeners
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(key)
            .cloned()
    }

    pub fn site(&self, listener_key: &str, site_key: &str) -> Option<Arc<SiteObs>> {
        self.listener(listener_key)?.site(site_key)
    }

    /// Builds a complete [`TopologySnapshot`] at Unix second `now_sec`.
    pub fn build_topology_snapshot(&self, window_secs: u64, now_sec: i64) -> TopologySnapshot {
        let win = normalize_rate_window(window_secs);
        let order: Vec<String> = self
            .listener_order
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let listener_map = self
            .listeners
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();

        let mut listeners_out = Vec::with_capacity(order.len());
        let mut total_qps = 0.0f64;
        let mut total_up = 0.0f64;
        let mut total_down = 0.0f64;
        let mut total_active = 0u32;
        let mut global_ips: HashSet<IpAddr> = HashSet::new();
        let mut global_truncated = false;

        for lkey in order {
            let Some(listener) = listener_map.get(&lkey) else {
                continue;
            };
            let enabled = listener.enabled.load(Ordering::Acquire);
            let running = enabled && listener.running.load(Ordering::Acquire);
            let error = listener
                .error
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            let listen_addr = listener
                .listen_addr
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();

            let site_order = listener
                .site_order
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            let site_map = listener
                .sites
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();

            let mut sites_out = Vec::with_capacity(site_order.len());
            for skey in site_order {
                let Some(site) = site_map.get(&skey) else {
                    continue;
                };
                let meta = site.meta_snapshot();
                let site_running = running && meta.enabled;
                let rate = site.topo.rate.rates(now_sec, win);
                let active = site.topo.active.load(Ordering::Relaxed);
                let active_ips = self.connections.active_ips(Some(&meta.key));
                let recent_view =
                    site.topo
                        .recent_ips
                        .snapshot(now_sec, &active_ips, MAX_TOPO_API_IPS);
                if recent_view.truncated {
                    global_truncated = true;
                }
                for ip_str in &recent_view.ips {
                    if global_ips.len() >= MAX_TOPO_SUMMARY_IPS {
                        global_truncated = true;
                        break;
                    }
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        global_ips.insert(ip);
                    }
                }

                total_qps += rate.qps;
                total_up += rate.bytes_up_per_sec;
                total_down += rate.bytes_down_per_sec;
                total_active = total_active.saturating_add(active);

                let backends = site
                    .upstreams_snapshot()
                    .into_iter()
                    .map(|u| {
                        let brate = u.topo.rate.rates(now_sec, win);
                        let brecent = u.topo.recent_ips.snapshot(now_sec, &[], MAX_TOPO_API_IPS);
                        BackendNode {
                            url: u.url.clone(),
                            route: u.route.clone(),
                            healthy: u.is_healthy(),
                            weight: u.weight,
                            backup: u.backup,
                            active: u.topo.active.load(Ordering::Relaxed),
                            cum_requests: u.topo.cum_requests.load(Ordering::Relaxed),
                            cum_errors: u.topo.cum_errors.load(Ordering::Relaxed),
                            bytes_up_per_sec: brate.bytes_up_per_sec,
                            bytes_down_per_sec: brate.bytes_down_per_sec,
                            qps: brate.qps,
                            recent_ips: brecent,
                        }
                    })
                    .collect();

                sites_out.push(SiteNode {
                    key: meta.key.clone(),
                    name: meta.display_name(),
                    enabled: meta.enabled,
                    running: site_running,
                    match_kind: meta.match_kind,
                    site_type: meta.site_type,
                    target_label: meta.target_label,
                    active,
                    qps: rate.qps,
                    bytes_up_per_sec: rate.bytes_up_per_sec,
                    bytes_down_per_sec: rate.bytes_down_per_sec,
                    cum_requests: site.topo.cum_requests.load(Ordering::Relaxed),
                    cum_errors: site.topo.cum_errors.load(Ordering::Relaxed),
                    blocked: site.topo.blocked_snapshot(),
                    status_hist: site.topo.status_hist_snapshot(),
                    recent_ips: recent_view,
                    backends,
                });
            }

            let actions = vec![
                build_action_node(
                    "default_close",
                    &listener.action_default_close,
                    now_sec,
                    win,
                ),
                build_action_node(
                    "https_redirect",
                    &listener.action_https_redirect,
                    now_sec,
                    win,
                ),
                build_action_node("not_found", &listener.action_not_found, now_sec, win),
            ];
            for act in &actions {
                total_qps += act.qps;
                if act.recent_ips.truncated {
                    global_truncated = true;
                }
                for ip_str in &act.recent_ips.ips {
                    if global_ips.len() >= MAX_TOPO_SUMMARY_IPS {
                        global_truncated = true;
                        break;
                    }
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        global_ips.insert(ip);
                    }
                }
            }

            listeners_out.push(ListenerNode {
                key: listener.key.clone(),
                name: listener.name(),
                listen_addr,
                enabled,
                running,
                error,
                sites: sites_out,
                actions,
            });
        }

        // Merge any active connection IPs across all sites into the global view.
        for ip in self.connections.active_ips(None) {
            if global_ips.len() >= MAX_TOPO_SUMMARY_IPS {
                global_truncated = true;
                break;
            }
            global_ips.insert(ip);
        }
        let total_ip_count = global_ips.len();
        if total_ip_count > MAX_TOPO_API_IPS {
            global_truncated = true;
        }
        let mut ip_list: Vec<String> = global_ips.into_iter().map(|ip| ip.to_string()).collect();
        ip_list.sort();
        ip_list.truncate(MAX_TOPO_API_IPS);

        TopologySnapshot {
            timestamp: now_sec,
            window_secs: win,
            total_qps,
            total_bytes_up_per_sec: total_up,
            total_bytes_down_per_sec: total_down,
            total_active,
            recent_ips: RecentIpsView {
                ips: ip_list,
                total: total_ip_count,
                truncated: global_truncated,
            },
            listeners: listeners_out,
        }
    }

    /// Builds a [`MetricsSnapshot`] and renders Prometheus 0.0.4 exposition.
    pub fn render_metrics(&self) -> String {
        render_prometheus(&self.metrics_snapshot())
    }

    /// Collects current site & listener counters into a [`MetricsSnapshot`].
    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        let order: Vec<String> = self
            .listener_order
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let listener_map = self
            .listeners
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();

        let mut sites_out = Vec::new();
        let mut listeners_out = Vec::new();

        for lkey in order {
            let Some(listener) = listener_map.get(&lkey) else {
                continue;
            };
            let l_label = listener.log_source_tag();
            listeners_out.push(ListenerActionMetricRow {
                listener: l_label.clone(),
                https_redirect_total: listener
                    .action_https_redirect
                    .cum_requests
                    .load(Ordering::Relaxed),
                not_found_total: listener
                    .action_not_found
                    .cum_requests
                    .load(Ordering::Relaxed),
            });

            let site_order = listener
                .site_order
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            let site_map = listener
                .sites
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();

            for skey in site_order {
                let Some(site) = site_map.get(&skey) else {
                    continue;
                };
                let meta = site.meta_snapshot();
                let upstreams = site
                    .upstreams_snapshot()
                    .into_iter()
                    .map(|u| UpstreamMetricRow {
                        upstream: u.url.clone(),
                        route: u.route.clone(),
                        up: u.is_healthy(),
                        requests_total: u.topo.cum_requests.load(Ordering::Relaxed),
                        response_bytes_total: u.response_bytes.load(Ordering::Relaxed),
                    })
                    .collect();

                sites_out.push(SiteMetricRow {
                    listener: l_label.clone(),
                    site: meta.display_name(),
                    requests_total: site.topo.cum_requests.load(Ordering::Relaxed),
                    errors_total: site.topo.cum_errors.load(Ordering::Relaxed),
                    active_requests: site.topo.active.load(Ordering::Relaxed),
                    response_bytes_total: site.cum_response_bytes.load(Ordering::Relaxed),
                    responses_by_class: [
                        site.cum_by_class[0].load(Ordering::Relaxed),
                        site.cum_by_class[1].load(Ordering::Relaxed),
                        site.cum_by_class[2].load(Ordering::Relaxed),
                        site.cum_by_class[3].load(Ordering::Relaxed),
                    ],
                    blocked_by_reason: site.topo.blocked_snapshot(),
                    duration_hist: site.latency.prometheus_snapshot(),
                    upstreams,
                });
            }
        }

        MetricsSnapshot {
            sites: sites_out,
            listeners: listeners_out,
        }
    }

    /// Exports ~60 s site snapshots for WP-69 (`fg-perf`).
    pub fn perf_site_snapshots(&self, now: Instant, now_sec: i64) -> Vec<SitePerfSnapshot> {
        let order: Vec<String> = self
            .listener_order
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let listener_map = self
            .listeners
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let mut out = Vec::new();
        for lkey in order {
            let Some(listener) = listener_map.get(&lkey) else {
                continue;
            };
            let site_order = listener
                .site_order
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            let site_map = listener
                .sites
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            for skey in site_order {
                if let Some(site) = site_map.get(&skey) {
                    out.push(site.perf_snapshot(now, now_sec));
                }
            }
        }
        out
    }
}

fn build_action_node(action: &str, topo: &Topo, now_sec: i64, win: u64) -> ListenerActionNode {
    let rate = topo.rate.rates(now_sec, win);
    ListenerActionNode {
        action: action.to_owned(),
        qps: rate.qps,
        cum_requests: topo.cum_requests.load(Ordering::Relaxed),
        recent_ips: topo.recent_ips.snapshot(now_sec, &[], MAX_TOPO_API_IPS),
    }
}

/// Context passed into the fixed 5-step request finish sequence
/// [`finish_request`] (WP-28 §3.2/§3.3).
pub struct FinishCtx<'a> {
    pub recorder: &'a Recorder,
    pub site: Option<&'a SiteObs>,
    pub listener_source: &'a str,
    pub addr: &'a ResolvedAddr,
    pub method: &'a str,
    pub host: &'a str,
    pub orig_path: &'a str,
    pub proto: &'a str,
    pub referer: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub started: Instant,
    pub finished_at: SystemTime,
    pub visitors: Option<&'a VisitorStore>,
    pub access_log_sink: Option<&'a AccessLogSink>,
    pub path_probe_hook: Option<&'a PathProbeHook>,
    pub geoip_lookup: Option<&'a GeoIpLookup>,
    /// Optional observer invoked as each of the 5 steps executes (for order assertions).
    pub step_trace: Option<&'a dyn Fn(FinishStep)>,
}

/// Executes the fixed 5-step request finish sequence (WP-28 §3.3):
///
/// 1. **First-byte latency** — skips upgraded, killed, unwritten, and 444 requests.
/// 2. **Visitor audit** — runs for ALL requests (including default site & unmatched),
///    regardless of `accessLog`; records admin as `"admin"`; never records identity
///    on denied or 401 requests.
/// 3. **Access log** — emitted when site `accessLog` is enabled; escapes & truncates
///    `Referer` and `User-Agent`, strips query strings from `/__gately_auth/...`.
/// 4. **Path probe report** — forwards to WP-52 guard: normal site access-control
///    close (444) reports as `403`; default site reports `444`; admin-killed skipped;
///    trusted authenticated users skipped on normal sites (not on default site).
/// 5. **Stats & counters** — updates `MinuteRing`, `Topo` (`RateRing`, cumulative
///    totals, blocked reasons, status histogram, `RecentIps`), and Prometheus counters.
pub fn finish_request(cx: FinishCtx<'_>) -> FinishOutcome {
    let mut executed_steps = Vec::with_capacity(5);
    let effective_status = cx.recorder.effective_status();
    let site_meta = cx.site.map(SiteObs::meta_snapshot);
    let is_default_site = site_meta.as_ref().is_none_or(|m| m.is_default);
    let now_sec = system_time_to_unix_secs(cx.finished_at);
    let now_min = unix_minute(cx.finished_at);

    // -------------------------------------------------------------------------
    // Step 1: First-byte latency (skip upgraded, killed, unwritten, 444)
    // -------------------------------------------------------------------------
    executed_steps.push(FinishStep::Latency);
    if let Some(trace) = cx.step_trace {
        trace(FinishStep::Latency);
    }
    let recorded_latency = cx.recorder.first_byte_latency(cx.started);
    if let (Some(dur), Some(site)) = (recorded_latency, cx.site) {
        site.latency.observe(dur);
    }

    // -------------------------------------------------------------------------
    // Step 2: Visitor audit (all sites, default & unmatched, ignores accessLog)
    // -------------------------------------------------------------------------
    executed_steps.push(FinishStep::VisitorAudit);
    if let Some(trace) = cx.step_trace {
        trace(FinishStep::VisitorAudit);
    }
    if let Some(visitors) = cx.visitors {
        let is_denied = cx.recorder.deny.is_denied() || cx.recorder.visitor_deny_reason().is_some();
        let identity = if is_denied || effective_status == 401 {
            None
        } else if cx.recorder.admin.is_some() {
            Some(ADMIN_IDENTITY.to_owned())
        } else {
            cx.recorder.identity.clone()
        };
        let site_name = site_meta
            .as_ref()
            .filter(|m| !m.is_default)
            .map(SiteMeta::display_name);

        visitors.record(VisitorEvent {
            ip: cx.addr.ip,
            site: site_name,
            unmatched_or_default: is_default_site,
            raw_path: cx.orig_path.to_owned(),
            status: effective_status,
            deny_reason: cx.recorder.visitor_deny_reason().map(str::to_owned),
            bytes_out: cx.recorder.bytes_out,
            identity,
            is_authed: !is_denied && effective_status != 401 && cx.recorder.is_authed(),
            user_agent: cx.user_agent.map(str::to_owned),
            now: cx.finished_at,
        });
    }

    // -------------------------------------------------------------------------
    // Step 3: Access log (only when site accessLog is enabled)
    // -------------------------------------------------------------------------
    executed_steps.push(FinishStep::AccessLog);
    if let Some(trace) = cx.step_trace {
        trace(FinishStep::AccessLog);
    }
    let mut logged_access = false;
    let access_log_enabled = site_meta.as_ref().is_some_and(|m| m.access_log);
    if access_log_enabled && let Some(sink) = cx.access_log_sink {
        let duration_ms = Instant::now()
            .saturating_duration_since(cx.started)
            .as_millis()
            .min(u64::MAX as u128) as u64;
        let entry: AccessLogEntry = access_log::build_entry(
            cx.listener_source,
            cx.addr.ip,
            cx.addr.via,
            cx.host,
            cx.method,
            cx.orig_path,
            cx.proto,
            effective_status,
            cx.recorder.bytes_out,
            duration_ms,
            cx.recorder.deny,
            cx.recorder.admin.clone(),
            if cx.recorder.deny.is_denied() || effective_status == 401 {
                None
            } else {
                cx.recorder.identity.clone()
            },
            cx.referer,
            cx.user_agent,
        );
        sink(entry);
        logged_access = true;
    }

    // -------------------------------------------------------------------------
    // Step 4: Path probe report to intrusion guard (WP-52)
    // -------------------------------------------------------------------------
    executed_steps.push(FinishStep::PathProbe);
    if let Some(trace) = cx.step_trace {
        trace(FinishStep::PathProbe);
    }
    let mut reported_path_probe = None;
    let skip_probe = cx.recorder.is_killed() || (cx.recorder.trusted_user && !is_default_site);
    if !skip_probe && let Some(hook) = cx.path_probe_hook {
        let probe_status = if !is_default_site
            && effective_status == 444
            && cx.recorder.deny.is_access_control()
        {
            403
        } else if is_default_site && effective_status == 444 {
            444
        } else {
            effective_status
        };
        let site_key = site_meta
            .as_ref()
            .map(|m| m.key.clone())
            .unwrap_or_default();
        hook(PathProbeReport {
            ip: cx.addr.ip,
            host: cx.host.to_owned(),
            path: visitors::strip_path_query(cx.orig_path).to_owned(),
            status: probe_status,
            site_key,
            is_default_site,
        });
        reported_path_probe = Some(probe_status);
    }

    // -------------------------------------------------------------------------
    // Step 5: MinuteRing, Topology RateRing, and Prometheus counters
    // -------------------------------------------------------------------------
    executed_steps.push(FinishStep::StatsCounters);
    if let Some(trace) = cx.step_trace {
        trace(FinishStep::StatsCounters);
    }
    if let Some(site) = cx.site {
        let country = cx.geoip_lookup.and_then(|lookup| lookup(cx.addr.ip));
        site.minute_ring.record(
            now_min,
            effective_status,
            cx.recorder.deny,
            cx.recorder.bytes_in,
            cx.recorder.bytes_out,
            recorded_latency,
            Some(cx.addr.ip),
            country.as_deref(),
        );
        site.topo.record_request(
            now_sec,
            effective_status,
            cx.recorder.deny,
            cx.recorder.bytes_out,
            cx.recorder.bytes_in,
            Some(cx.addr.ip),
        );
        site.cum_response_bytes
            .fetch_add(cx.recorder.bytes_out, Ordering::Relaxed);
        if let Some(class) = status_class_index(effective_status) {
            site.cum_by_class[class].fetch_add(1, Ordering::Relaxed);
        }
    }

    FinishOutcome {
        executed_steps,
        effective_status,
        recorded_latency,
        logged_access,
        reported_path_probe,
    }
}

fn system_time_to_unix_secs(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::StatusCode;
    use std::sync::Mutex;

    fn test_site(is_default: bool, access_log: bool) -> SiteObs {
        SiteObs::new(
            "l1",
            "main",
            SiteMeta {
                key: if is_default { "default" } else { "app" }.into(),
                name: if is_default { "" } else { "app" }.into(),
                domains: if is_default {
                    vec![]
                } else {
                    vec!["app.test".into()]
                },
                enabled: true,
                is_default,
                access_log,
                match_kind: if is_default { "default" } else { "exact" }.into(),
                site_type: "proxy".into(),
                target_label: None,
            },
        )
    }

    #[test]
    fn finish_skips_latency_for_upgrade_and_kill() {
        let site = test_site(false, false);
        let addr = ResolvedAddr::direct("203.0.113.5:50000".parse().unwrap());
        let start = Instant::now();

        // Upgraded (WebSocket)
        let mut rec_ws = Recorder::new();
        rec_ws.write_header_at(
            StatusCode::SWITCHING_PROTOCOLS,
            start + Duration::from_millis(4),
        );
        rec_ws.mark_upgraded();
        let out_ws = finish_request(FinishCtx {
            recorder: &rec_ws,
            site: Some(&site),
            listener_source: "main#l1",
            addr: &addr,
            method: "GET",
            host: "app.test",
            orig_path: "/ws",
            proto: "ws",
            referer: None,
            user_agent: None,
            started: start,
            finished_at: SystemTime::now(),
            visitors: None,
            access_log_sink: None,
            path_probe_hook: None,
            geoip_lookup: None,
            step_trace: None,
        });
        assert_eq!(out_ws.recorded_latency, None);

        // Killed by admin
        let mut rec_kill = Recorder::new();
        rec_kill.write_header_at(StatusCode::OK, start + Duration::from_millis(8));
        rec_kill.mark_killed();
        let out_kill = finish_request(FinishCtx {
            recorder: &rec_kill,
            site: Some(&site),
            listener_source: "main#l1",
            addr: &addr,
            method: "GET",
            host: "app.test",
            orig_path: "/stream",
            proto: "h1",
            referer: None,
            user_agent: None,
            started: start,
            finished_at: SystemTime::now(),
            visitors: None,
            access_log_sink: None,
            path_probe_hook: None,
            geoip_lookup: None,
            step_trace: None,
        });
        assert_eq!(out_kill.recorded_latency, None);

        // Unwritten (444)
        let rec_444 = Recorder::new();
        let out_444 = finish_request(FinishCtx {
            recorder: &rec_444,
            site: Some(&site),
            listener_source: "main#l1",
            addr: &addr,
            method: "GET",
            host: "app.test",
            orig_path: "/drop",
            proto: "h1",
            referer: None,
            user_agent: None,
            started: start,
            finished_at: SystemTime::now(),
            visitors: None,
            access_log_sink: None,
            path_probe_hook: None,
            geoip_lookup: None,
            step_trace: None,
        });
        assert_eq!(out_444.effective_status, 444);
        assert_eq!(out_444.recorded_latency, None);
        assert_eq!(site.latency.prometheus_snapshot().count, 0);
    }

    #[test]
    fn path_probe_report_403_or_444_by_site_kind() {
        let normal = test_site(false, false);
        let default = test_site(true, false);
        let addr = ResolvedAddr::direct("203.0.113.9:4321".parse().unwrap());
        let reports: Arc<Mutex<Vec<PathProbeReport>>> = Arc::new(Mutex::new(Vec::new()));
        let reports_ref = Arc::clone(&reports);
        let hook: PathProbeHook = Arc::new(move |r| {
            reports_ref.lock().unwrap().push(r);
        });

        // 1. Normal site + access-control deny close (444) -> reports 403.
        let mut r1 = Recorder::new();
        r1.set_deny(DenyKind::IpList);
        let out1 = finish_request(FinishCtx {
            recorder: &r1,
            site: Some(&normal),
            listener_source: "main#l1",
            addr: &addr,
            method: "GET",
            host: "app.test",
            orig_path: "/secret?x=1",
            proto: "h1",
            referer: None,
            user_agent: None,
            started: Instant::now(),
            finished_at: SystemTime::now(),
            visitors: None,
            access_log_sink: None,
            path_probe_hook: Some(&hook),
            geoip_lookup: None,
            step_trace: None,
        });
        assert_eq!(out1.reported_path_probe, Some(403));

        // 2. Default site + close (444) -> reports 444.
        let r2 = Recorder::new();
        let out2 = finish_request(FinishCtx {
            recorder: &r2,
            site: Some(&default),
            listener_source: "main#l1",
            addr: &addr,
            method: "GET",
            host: "unknown.test",
            orig_path: "/.env",
            proto: "h1",
            referer: None,
            user_agent: None,
            started: Instant::now(),
            finished_at: SystemTime::now(),
            visitors: None,
            access_log_sink: None,
            path_probe_hook: Some(&hook),
            geoip_lookup: None,
            step_trace: None,
        });
        assert_eq!(out2.reported_path_probe, Some(444));

        // 3. Trusted authenticated user on normal site -> skipped.
        let mut r3 = Recorder::new();
        r3.set_identity("alice", true);
        r3.write_header(StatusCode::NOT_FOUND);
        let out3 = finish_request(FinishCtx {
            recorder: &r3,
            site: Some(&normal),
            listener_source: "main#l1",
            addr: &addr,
            method: "GET",
            host: "app.test",
            orig_path: "/missing",
            proto: "h2",
            referer: None,
            user_agent: None,
            started: Instant::now(),
            finished_at: SystemTime::now(),
            visitors: None,
            access_log_sink: None,
            path_probe_hook: Some(&hook),
            geoip_lookup: None,
            step_trace: None,
        });
        assert_eq!(out3.reported_path_probe, None);

        // 4. Trusted authenticated user on DEFAULT site -> STILL reported!
        let mut r4 = Recorder::new();
        r4.set_identity("alice", true);
        let out4 = finish_request(FinishCtx {
            recorder: &r4,
            site: Some(&default),
            listener_source: "main#l1",
            addr: &addr,
            method: "GET",
            host: "evil.test",
            orig_path: "/wp-admin",
            proto: "h1",
            referer: None,
            user_agent: None,
            started: Instant::now(),
            finished_at: SystemTime::now(),
            visitors: None,
            access_log_sink: None,
            path_probe_hook: Some(&hook),
            geoip_lookup: None,
            step_trace: None,
        });
        assert_eq!(out4.reported_path_probe, Some(444));

        // 5. Admin-killed request -> skipped even on default site.
        let r5 = Recorder::new();
        r5.mark_killed();
        let out5 = finish_request(FinishCtx {
            recorder: &r5,
            site: Some(&default),
            listener_source: "main#l1",
            addr: &addr,
            method: "GET",
            host: "evil.test",
            orig_path: "/x",
            proto: "h1",
            referer: None,
            user_agent: None,
            started: Instant::now(),
            finished_at: SystemTime::now(),
            visitors: None,
            access_log_sink: None,
            path_probe_hook: Some(&hook),
            geoip_lookup: None,
            step_trace: None,
        });
        assert_eq!(out5.reported_path_probe, None);

        let list = reports.lock().unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].status, 403);
        assert_eq!(list[0].path, "/secret");
        assert_eq!(list[1].status, 444);
        assert_eq!(list[2].status, 444);
    }

    #[test]
    fn finish_request_executes_exact_five_step_order() {
        let site = test_site(false, true);
        let addr = ResolvedAddr::direct("203.0.113.1:9999".parse().unwrap());
        let visitors = VisitorStore::default();
        let sink: AccessLogSink = Arc::new(|_| {});
        let hook: PathProbeHook = Arc::new(|_| {});
        let start = Instant::now();
        let mut rec = Recorder::new();
        rec.write_header_at(StatusCode::OK, start + Duration::from_millis(5));
        let trace_log: Mutex<Vec<FinishStep>> = Mutex::new(Vec::new());
        let trace_fn = |step: FinishStep| {
            trace_log.lock().unwrap().push(step);
        };

        let out = finish_request(FinishCtx {
            recorder: &rec,
            site: Some(&site),
            listener_source: "main#l1",
            addr: &addr,
            method: "GET",
            host: "app.test",
            orig_path: "/ok",
            proto: "h2",
            referer: None,
            user_agent: Some("test-agent"),
            started: start,
            finished_at: SystemTime::now(),
            visitors: Some(&visitors),
            access_log_sink: Some(&sink),
            path_probe_hook: Some(&hook),
            geoip_lookup: None,
            step_trace: Some(&trace_fn),
        });

        let expected = vec![
            FinishStep::Latency,
            FinishStep::VisitorAudit,
            FinishStep::AccessLog,
            FinishStep::PathProbe,
            FinishStep::StatsCounters,
        ];
        assert_eq!(out.executed_steps, expected);
        assert_eq!(*trace_log.lock().unwrap(), expected);
        assert!(out.logged_access);
        assert!(out.recorded_latency.is_some());
    }
}
