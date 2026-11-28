//! Performance monitoring runtime (WP-69 §3.3): periodic 5-second sampling
//! of host, process, managed-process and site metrics; three-tier in-memory
//! history; alert state evaluation with `perf.alert` / `perf.recovered`
//! publication on the event bus; site-rename propagation; and Prometheus
//! metric export (`ferrumgate_perf_alerts_firing`).

use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use anyhow::Context as _;
use fg_core::{
    events::{Event, EventBus, Kind},
    metrics::{self, Sample as MetricSample},
    sysstat::{DiskUsage, HostStats, Procfs, Sysstat},
};
use serde::Serialize;
use tokio::sync::{RwLock, watch};

use crate::{
    alerts::{AlertEvent, AlertState, Evaluator, Readings, SiteReading},
    history::{ExtraMetric, History, ProcPoint, ProcValues, Sample, SiteValues, Values},
    model::{AlertRule, CmpOp, FileConfig, Level, Metric, Window, limits},
    procs::{self, ProcHandle, ProcTracker, ProcView, RawProc, RawReader},
    rfc3339,
    series::Series,
    validate,
};

/// Wall clock source (injectable for deterministic tests).
pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// Reads per-site statistics from WP-28 (shared ~60 s window).
pub type SiteStatsReader = Arc<dyn Fn() -> Vec<SiteSnapshot> + Send + Sync>;

/// Lists currently running managed processes from WP-43's registry.
pub type ManagedProcsReader = Arc<dyn Fn() -> Vec<ProcHandle> + Send + Sync>;

/// Writes the whole [`FileConfig`] to `perf.json`.
pub type PersistFn = Arc<dyn Fn(&FileConfig) -> anyhow::Result<()> + Send + Sync>;

/// Per-backend status and active connection count provided by WP-28.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendSnapshot {
    pub name: String,
    pub healthy: bool,
    pub conns: u64,
}

/// One site's instantaneous and ~60 s window readings provided by WP-28.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SiteSnapshot {
    pub name: String,
    pub active: u64,
    pub qps: Option<f64>,
    pub err5xx: Option<f64>,
    pub latency_p95: Option<f64>,
    pub window_requests: u64,
    pub window_span: Duration,
    pub backends: Vec<BackendSnapshot>,
}

/// Row returned by `GET /api/perf/sites`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteView {
    pub name: String,
    pub active: u64,
    pub qps: Option<f64>,
    pub err5xx: Option<f64>,
    pub latency_p95: Option<f64>,
    pub window_requests: u64,
    pub healthy_backends: usize,
    pub total_backends: usize,
    pub backends: Vec<BackendSnapshot>,
}

impl From<&SiteSnapshot> for SiteView {
    fn from(site: &SiteSnapshot) -> Self {
        let healthy_backends = site.backends.iter().filter(|b| b.healthy).count();
        Self {
            name: site.name.clone(),
            active: site.active,
            qps: site.qps,
            err5xx: site.err5xx,
            latency_p95: site.latency_p95,
            window_requests: site.window_requests,
            healthy_backends,
            total_backends: site.backends.len(),
            backends: site.backends.clone(),
        }
    }
}

/// One process row in `GET /api/perf/processes`, including its ~60 s mini curve.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessRowView {
    pub key: String,
    pub name: String,
    pub pid: Option<u32>,
    pub cpu: Option<f64>,
    pub rss: Option<u64>,
    pub gone: bool,
    pub history: Vec<ProcPoint>,
}

/// Response payload of `GET /api/perf/processes`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessesView {
    pub processes: Vec<ProcessRowView>,
    pub total_cpu: Option<f64>,
    pub total_rss: Option<u64>,
}

/// Response item of `GET /api/perf/alerts`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveAlertView {
    pub rule: String,
    pub rule_name: String,
    pub metric: Option<Metric>,
    pub level: Option<Level>,
    pub object: Option<String>,
    pub state: &'static str,
    pub value: Option<f64>,
    pub since: String,
    pub duration_secs: u64,
}

/// Alert counters included in `GET /api/perf/overview`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertsSummary {
    pub firing: usize,
    pub pending: usize,
}

/// Response payload of `GET /api/perf/overview`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OverviewView {
    pub range: &'static str,
    pub step: u32,
    pub series: BTreeMap<&'static str, Series>,
    pub alerts: AlertsSummary,
}

/// External capabilities injected by the assembler (conventions §3.4).
#[derive(Clone)]
pub struct Deps {
    /// Host & Gately process statistics provider (WP-17).
    pub sysstat: Arc<dyn Sysstat>,
    /// Path of the config directory used to pick the matching disk mount.
    pub config_mount: Option<PathBuf>,
    /// Site statistics reader (WP-28); `None` when the web module is absent.
    pub site_stats: Option<SiteStatsReader>,
    /// Managed process list reader (WP-43); `None` when unused.
    pub managed_procs: Option<ManagedProcsReader>,
    /// Per-process CPU/RSS reader (defaults to `/proc` on Linux, `ps` on macOS).
    pub proc_reader: RawReader,
    /// Wall clock (defaults to [`SystemTime::now`]).
    pub clock: Clock,
    /// Sampling cadence (defaults to [`limits::SAMPLE_INTERVAL`], 5 seconds).
    pub sample_interval: Duration,
}

impl Default for Deps {
    fn default() -> Self {
        Self {
            sysstat: Arc::new(Procfs),
            config_mount: None,
            site_stats: None,
            managed_procs: None,
            proc_reader: procs::sys_reader(),
            clock: Arc::new(SystemTime::now),
            sample_interval: limits::SAMPLE_INTERVAL,
        }
    }
}

#[derive(Clone, Debug)]
struct RuleMeta {
    name: String,
    metric: Metric,
    op: CmpOp,
    threshold: f64,
    level: Level,
}

impl From<&AlertRule> for RuleMeta {
    fn from(rule: &AlertRule) -> Self {
        Self {
            name: rule.name.clone(),
            metric: rule.metric,
            op: rule.op,
            threshold: rule.threshold,
            level: rule.level,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct NetBaseline {
    rx: u64,
    tx: u64,
    at: SystemTime,
}

#[derive(Debug, Default)]
struct PerfState {
    history: History,
    evaluator: Evaluator,
    procs: ProcTracker,
    last_sites: Vec<SiteSnapshot>,
    last_procs: Vec<ProcView>,
    last_net: Option<NetBaseline>,
    rule_meta: BTreeMap<String, RuleMeta>,
    rules_total: usize,
    rules_enabled: usize,
}

/// Core performance monitoring service shared by the background sampler,
/// management routes, and root-level hooks (metrics, `rename_sites`,
/// `site_removed`).
pub struct PerfService {
    config: Arc<RwLock<FileConfig>>,
    persist: PersistFn,
    events: EventBus,
    deps: Deps,
    state: Mutex<PerfState>,
}

impl PerfService {
    /// Creates a new service initialized with `initial_rules` (used to seed
    /// rule metadata and Prometheus counters before the first sample).
    pub fn new(
        config: Arc<RwLock<FileConfig>>,
        initial_rules: &[AlertRule],
        persist: PersistFn,
        events: EventBus,
        deps: Deps,
    ) -> Arc<Self> {
        let mut state = PerfState::default();
        update_rule_counts(&mut state, initial_rules);
        record_rule_meta(&mut state, initial_rules);
        Arc::new(Self {
            config,
            persist,
            events,
            deps,
            state: Mutex::new(state),
        })
    }

    /// Live desired `perf.json` configuration.
    pub fn config(&self) -> Arc<RwLock<FileConfig>> {
        Arc::clone(&self.config)
    }

    /// Persistence callback for `perf.json`.
    pub fn persist(&self) -> &PersistFn {
        &self.persist
    }

    /// Runs one sampling & alert-evaluation pass. Blocking OS readers run on
    /// Tokio's blocking pool so the state mutex is never held across I/O.
    pub async fn sample_once(&self) -> Vec<AlertEvent> {
        let rules = self.config.read().await.rules.clone();
        let deps = self.deps.clone();
        let gathered = tokio::task::spawn_blocking(move || gather_raw(&deps)).await;
        let Ok(raw) = gathered else {
            tracing::warn!("perf sampling task aborted");
            return Vec::new();
        };
        let now = (self.deps.clock)();
        let (emitted, metas) = {
            let mut state = self.lock();
            update_rule_counts(&mut state, &rules);
            record_rule_meta(&mut state, &rules);

            let (net_rx_bps, net_tx_bps) = compute_net_rates(&mut state.last_net, &raw.host, now);
            let proc_raw_map: BTreeMap<String, RawProc> = raw
                .procs
                .iter()
                .map(|(handle, raw_proc)| (handle.key.clone(), *raw_proc))
                .collect();
            let handles: Vec<ProcHandle> =
                raw.procs.iter().map(|(handle, _)| handle.clone()).collect();
            let lookup: RawReader = Arc::new(move |handle: &ProcHandle| {
                proc_raw_map.get(&handle.key).copied().unwrap_or_default()
            });
            let proc_views = state.procs.sample(&handles, &lookup, now);

            let host_mem = (raw.host.mem_total > 0)
                .then(|| raw.host.mem_used as f64 / raw.host.mem_total as f64 * 100.0);
            let host_disk = disk_usage_percent(&raw.host.disks, self.deps.config_mount.as_deref());
            let host_load1 = host_load1(&raw.host);
            let proc_rss =
                (raw.proc_stats.rss_bytes > 0).then_some(raw.proc_stats.rss_bytes as f64);

            let mut sample_sites = BTreeMap::new();
            let mut reading_sites = BTreeMap::new();
            let mut reading_backends = BTreeMap::new();
            for site in &raw.sites {
                let mut backend_conns = BTreeMap::new();
                for backend in &site.backends {
                    backend_conns.insert(backend.name.clone(), backend.conns as f64);
                }
                sample_sites.insert(
                    site.name.clone(),
                    SiteValues {
                        active: Some(site.active as f64),
                        qps: site.qps,
                        err5xx: site.err5xx,
                        latency_p95: site.latency_p95,
                        backends: backend_conns.clone(),
                    },
                );
                reading_sites.insert(
                    site.name.clone(),
                    SiteReading {
                        active: Some(site.active as f64),
                        qps: site.qps,
                        err5xx: site.err5xx,
                        latency_p95: site.latency_p95,
                        window_requests: site.window_requests,
                        window_span: site.window_span,
                    },
                );
                if !backend_conns.is_empty() {
                    reading_backends.insert(site.name.clone(), backend_conns);
                }
            }

            let mut sample_procs = BTreeMap::new();
            for view in &proc_views {
                sample_procs.insert(
                    view.key.clone(),
                    ProcValues {
                        cpu: view.cpu,
                        rss: view.rss.map(|bytes| bytes as f64),
                    },
                );
            }

            let sample = Sample {
                at: now,
                values: Values {
                    host_cpu: raw.host.cpu_percent,
                    host_mem,
                    host_disk,
                    host_load1,
                    net_rx_bps,
                    net_tx_bps,
                    proc_cpu: raw.proc_stats.cpu_percent,
                    proc_rss,
                },
                sites: sample_sites,
                procs: sample_procs,
            };
            state.history.push(sample);
            state.last_sites = raw.sites;
            state.last_procs = proc_views;

            let readings = Readings {
                host_cpu: raw.host.cpu_percent,
                host_mem,
                host_disk,
                proc_cpu: raw.proc_stats.cpu_percent,
                proc_rss,
                sites: reading_sites,
                backends: reading_backends,
            };
            let events = state.evaluator.evaluate(&rules, &readings, now);
            let metas = state.rule_meta.clone();
            prune_rule_meta(&mut state, &rules);
            (events, metas)
        };
        self.publish_events(&emitted, &metas, now);
        emitted
    }

    /// Reconciles rule mutations (edit, enable/disable, delete) immediately
    /// against the evaluator and publishes any resulting recovery events.
    pub fn sync_rules(&self, rules: &[AlertRule]) -> Vec<AlertEvent> {
        let now = (self.deps.clock)();
        let (emitted, metas) = {
            let mut state = self.lock();
            update_rule_counts(&mut state, rules);
            record_rule_meta(&mut state, rules);
            let events = state.evaluator.sync_rules(rules, now);
            let metas = state.rule_meta.clone();
            prune_rule_meta(&mut state, rules);
            (events, metas)
        };
        self.publish_events(&emitted, &metas, now);
        emitted
    }

    /// Clears a deleted or stopped site's active alerts without emitting a
    /// recovery notification (WP-69 §3.3.3).
    pub fn site_removed(&self, site: &str) {
        let mut state = self.lock();
        state.evaluator.site_removed(site);
        state.last_sites.retain(|entry| entry.name != site);
    }

    /// Propagates web-site renames into `rules[].sites` and persists
    /// `perf.json`. Returns `Ok(false)` when no rule references any renamed
    /// site (no-op); leaves in-memory state untouched if persistence fails.
    pub async fn rename_sites(&self, renames: &BTreeMap<String, String>) -> anyhow::Result<bool> {
        if renames.is_empty() {
            return Ok(false);
        }
        let mut guard = self.config.write().await;
        let mut candidate = guard.clone();
        let mut changed = false;
        for rule in &mut candidate.rules {
            let mut updated = Vec::with_capacity(rule.sites.len());
            let mut seen = HashSet::with_capacity(rule.sites.len());
            for site in &rule.sites {
                let next = renames.get(site).cloned().unwrap_or_else(|| site.clone());
                if next != *site {
                    changed = true;
                }
                if seen.insert(next.clone()) {
                    updated.push(next);
                } else {
                    changed = true;
                }
            }
            rule.sites = updated;
        }
        if !changed {
            return Ok(false);
        }
        candidate = validate::normalize(candidate);
        let problems = validate::validate(&candidate);
        if let Some(first) = problems.first() {
            anyhow::bail!(
                "invalid perf configuration after site rename: {} {}",
                first.field,
                first.reason
            );
        }
        let persist = Arc::clone(&self.persist);
        let saved = candidate.clone();
        tokio::task::spawn_blocking(move || persist(&saved))
            .await
            .context("join perf.json persist task")??;
        let rules_snapshot = candidate.rules.clone();
        *guard = candidate;
        drop(guard);
        self.sync_rules(&rules_snapshot);
        Ok(true)
    }

    /// Runs the periodic 5-second sampling and evaluation loop until `drain`
    /// transitions to `true` (or its sender is dropped).
    pub async fn run_loop(self: Arc<Self>, mut drain: watch::Receiver<bool>) {
        if *drain.borrow_and_update() {
            return;
        }
        let interval_duration = if self.deps.sample_interval.is_zero() {
            limits::SAMPLE_INTERVAL
        } else {
            self.deps.sample_interval
        };
        let mut ticker = tokio::time::interval(interval_duration);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = wait_drain(&mut drain) => break,
                _ = ticker.tick() => {
                    self.sample_once().await;
                }
            }
        }
    }

    /// Chart series and alert summary for `GET /api/perf/overview`.
    pub fn overview(&self, window: Window) -> OverviewView {
        let state = self.lock();
        let mut series = BTreeMap::new();
        for metric in Metric::ALL {
            series.insert(metric.tag(), state.history.series(metric, window));
        }
        for extra in ExtraMetric::ALL {
            series.insert(extra.tag(), state.history.extra_series(extra, window));
        }
        OverviewView {
            range: window.range(),
            step: window.step(),
            series,
            alerts: AlertsSummary {
                firing: state.evaluator.firing_count(),
                pending: state.evaluator.pending_count(),
            },
        }
    }

    /// Snapshot of current sites for `GET /api/perf/sites`.
    pub fn sites(&self) -> Vec<SiteView> {
        let state = self.lock();
        state.last_sites.iter().map(SiteView::from).collect()
    }

    /// Snapshot of managed processes and their ~60 s mini curves for
    /// `GET /api/perf/processes`. When `scope` is non-empty, only processes
    /// whose key equals `scope` or starts with `"{scope}:"` are returned.
    pub fn processes(&self, scope: Option<&str>) -> ProcessesView {
        let scope = scope.map(str::trim).filter(|s| !s.is_empty());
        let state = self.lock();
        let mut processes = Vec::new();
        let mut total_cpu: Option<f64> = None;
        let mut total_rss: Option<u64> = None;
        for view in &state.last_procs {
            if let Some(prefix) = scope {
                let matches = view.key == prefix
                    || view
                        .key
                        .strip_prefix(prefix)
                        .is_some_and(|rest| rest.starts_with(':'));
                if !matches {
                    continue;
                }
            }
            if let Some(cpu) = view.cpu {
                total_cpu = Some(total_cpu.unwrap_or(0.0) + cpu);
            }
            if let Some(rss) = view.rss {
                total_rss = Some(total_rss.unwrap_or(0).saturating_add(rss));
            }
            processes.push(ProcessRowView {
                key: view.key.clone(),
                name: view.name.clone(),
                pid: view.pid,
                cpu: view.cpu,
                rss: view.rss,
                gone: view.gone,
                history: state.history.proc_history(&view.key),
            });
        }
        ProcessesView {
            processes,
            total_cpu,
            total_rss,
        }
    }

    /// Active (pending and firing) alerts for `GET /api/perf/alerts`.
    pub fn active_alerts(&self) -> Vec<ActiveAlertView> {
        let now = (self.deps.clock)();
        let state = self.lock();
        state
            .evaluator
            .active()
            .into_iter()
            .filter_map(|active| {
                let (label, since) = match active.state {
                    AlertState::Normal => return None,
                    AlertState::Pending { since } => ("pending", since),
                    AlertState::Firing { since } => ("firing", since),
                };
                let meta = state.rule_meta.get(&active.rule);
                Some(ActiveAlertView {
                    rule_name: meta
                        .map(|m| m.name.clone())
                        .unwrap_or_else(|| active.rule.clone()),
                    metric: meta.map(|m| m.metric),
                    level: meta.map(|m| m.level),
                    rule: active.rule,
                    object: active.object,
                    state: label,
                    value: active.value,
                    since: rfc3339(since),
                    duration_secs: now.duration_since(since).unwrap_or_default().as_secs(),
                })
            })
            .collect()
    }

    /// Number of currently firing alert objects (`ferrumgate_perf_alerts_firing`).
    pub fn firing_count(&self) -> usize {
        self.lock().evaluator.firing_count()
    }

    /// Number of currently pending alert objects.
    pub fn pending_count(&self) -> usize {
        self.lock().evaluator.pending_count()
    }

    /// Prometheus metric samples for this module (WP-69 §3.3).
    pub fn metric_samples(&self) -> Vec<MetricSample> {
        let state = self.lock();
        vec![
            MetricSample::gauge(
                "ferrumgate_perf_alerts_firing",
                "Number of currently firing performance alerts.",
                state.evaluator.firing_count() as f64,
            ),
            MetricSample::gauge(
                "ferrumgate_perf_alerts_pending",
                "Number of currently pending performance alerts.",
                state.evaluator.pending_count() as f64,
            ),
            MetricSample::gauge(
                "ferrumgate_perf_rules_total",
                "Total configured performance alert rules.",
                state.rules_total as f64,
            ),
            MetricSample::gauge(
                "ferrumgate_perf_rules_enabled",
                "Enabled performance alert rules.",
                state.rules_enabled as f64,
            ),
        ]
    }

    /// Renders this module's Prometheus text exposition (`GET /api/perf/metrics`).
    pub fn render_metrics(&self) -> String {
        metrics::write_text(&self.metric_samples())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PerfState> {
        self.state.lock().expect("perf state poisoned")
    }

    fn publish_events(
        &self,
        events: &[AlertEvent],
        metas: &BTreeMap<String, RuleMeta>,
        now: SystemTime,
    ) {
        for alert in events {
            match alert {
                AlertEvent::Fired {
                    rule,
                    object,
                    value,
                } => {
                    let meta = metas.get(rule);
                    let mut event = Event::new(Kind::PerfAlert, crate::MODULE_ID);
                    event.time = now;
                    if let Some(meta) = meta {
                        event.level = meta.level.event_level();
                        event.args.push(("rule", meta.name.clone()));
                        event.args.push(("metric", meta.metric.tag().to_owned()));
                        event.args.push(("op", meta.op.tag().to_owned()));
                        event
                            .args
                            .push(("threshold", format_number(meta.threshold)));
                        event.fields.push(("metric", meta.metric.tag().to_owned()));
                    } else {
                        event.args.push(("rule", rule.clone()));
                    }
                    event.args.push(("ruleKey", rule.clone()));
                    event.args.push(("value", format_number(*value)));
                    event.fields.push(("ruleKey", rule.clone()));
                    if let Some(object) = object {
                        event.args.push(("object", object.clone()));
                        event.fields.push(("object", object.clone()));
                    }
                    event.dedup = Some(format!("perf:{rule}:{}", object.as_deref().unwrap_or("")));
                    self.events.publish(event);
                }
                AlertEvent::Recovered {
                    rule,
                    object,
                    reason,
                } => {
                    let meta = metas.get(rule);
                    let mut event = Event::new(Kind::PerfRecovered, crate::MODULE_ID);
                    event.time = now;
                    event.level = fg_core::events::Level::Info;
                    let rule_name = meta.map(|m| m.name.clone()).unwrap_or_else(|| rule.clone());
                    event.args.push(("rule", rule_name));
                    event.args.push(("ruleKey", rule.clone()));
                    event.args.push(("reason", reason.tag().to_owned()));
                    event.fields.push(("ruleKey", rule.clone()));
                    event.fields.push(("reason", reason.tag().to_owned()));
                    if let Some(meta) = meta {
                        event.args.push(("metric", meta.metric.tag().to_owned()));
                        event.fields.push(("metric", meta.metric.tag().to_owned()));
                    }
                    if let Some(object) = object {
                        event.args.push(("object", object.clone()));
                        event.fields.push(("object", object.clone()));
                    }
                    self.events.publish(event);
                }
            }
        }
    }
}

struct RawSample {
    host: HostStats,
    proc_stats: fg_core::sysstat::ProcStats,
    sites: Vec<SiteSnapshot>,
    procs: Vec<(ProcHandle, RawProc)>,
}

fn gather_raw(deps: &Deps) -> RawSample {
    let host = deps.sysstat.host();
    let proc_stats = deps.sysstat.proc();
    let sites = deps
        .site_stats
        .as_ref()
        .map(|reader| reader())
        .unwrap_or_default();
    let procs = deps
        .managed_procs
        .as_ref()
        .map(|list| {
            list()
                .into_iter()
                .map(|handle| {
                    let raw = (deps.proc_reader)(&handle);
                    (handle, raw)
                })
                .collect()
        })
        .unwrap_or_default();
    RawSample {
        host,
        proc_stats,
        sites,
        procs,
    }
}

fn update_rule_counts(state: &mut PerfState, rules: &[AlertRule]) {
    state.rules_total = rules.len();
    state.rules_enabled = rules.iter().filter(|rule| rule.enable).count();
}

fn record_rule_meta(state: &mut PerfState, rules: &[AlertRule]) {
    for rule in rules {
        state
            .rule_meta
            .insert(rule.key.clone(), RuleMeta::from(rule));
    }
}

fn prune_rule_meta(state: &mut PerfState, rules: &[AlertRule]) {
    let live: HashSet<&str> = rules.iter().map(|rule| rule.key.as_str()).collect();
    state.rule_meta.retain(|key, _| live.contains(key.as_str()));
}

fn host_load1(host: &HostStats) -> Option<f64> {
    if !host.load1.is_finite() {
        return None;
    }
    if host.load1 == 0.0
        && host.cpu_percent.is_none()
        && host.mem_total == 0
        && host.disks.is_empty()
    {
        return None;
    }
    Some(host.load1)
}

fn disk_usage_percent(disks: &[DiskUsage], config_mount: Option<&Path>) -> Option<f64> {
    let target = config_mount.and_then(|path| path.to_str());
    let matched = target.and_then(|path| {
        disks
            .iter()
            .filter(|disk| disk.total > 0 && mount_matches(&disk.mount, path))
            .max_by_key(|disk| disk.mount.len())
    });
    let chosen = matched
        .or_else(|| {
            disks
                .iter()
                .find(|disk| disk.total > 0 && disk.mount == "/")
        })
        .or_else(|| disks.iter().find(|disk| disk.total > 0))?;
    Some(chosen.used as f64 / chosen.total as f64 * 100.0)
}

fn mount_matches(mount: &str, path: &str) -> bool {
    if mount == "/" {
        return path.starts_with('/');
    }
    let mount = mount.trim_end_matches('/');
    path == mount
        || path
            .strip_prefix(mount)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn compute_net_rates(
    baseline: &mut Option<NetBaseline>,
    host: &HostStats,
    now: SystemTime,
) -> (Option<f64>, Option<f64>) {
    if host.net.is_empty() {
        return (None, None);
    }
    let non_lo: Vec<_> = host
        .net
        .iter()
        .filter(|iface| iface.interface != "lo" && iface.interface != "lo0")
        .collect();
    let selected = if non_lo.is_empty() {
        host.net.iter().collect::<Vec<_>>()
    } else {
        non_lo
    };
    let rx: u64 = selected
        .iter()
        .fold(0u64, |acc, iface| acc.saturating_add(iface.received));
    let tx: u64 = selected
        .iter()
        .fold(0u64, |acc, iface| acc.saturating_add(iface.sent));
    let rates = match *baseline {
        Some(prev) if rx >= prev.rx && tx >= prev.tx => {
            let elapsed = now
                .duration_since(prev.at)
                .map(|delta| delta.as_secs_f64())
                .unwrap_or(0.0);
            if elapsed > 0.0 {
                (
                    Some((rx - prev.rx) as f64 / elapsed),
                    Some((tx - prev.tx) as f64 / elapsed),
                )
            } else {
                (None, None)
            }
        }
        _ => (None, None),
    };
    *baseline = Some(NetBaseline { rx, tx, at: now });
    rates
}

fn format_number(value: f64) -> String {
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{}", value as i64)
    } else {
        format!("{value:.2}")
    }
}

async fn wait_drain(drain: &mut watch::Receiver<bool>) {
    while !*drain.borrow_and_update() {
        if drain.changed().await.is_err() {
            break;
        }
    }
}
