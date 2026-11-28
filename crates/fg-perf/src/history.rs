//! Three-tier in-memory history (WP-69 §3.3): the 60-second tier keeps
//! every 5-second sample, the 1-hour tier averages one point per minute
//! and the 24-hour tier one point per 5 minutes; every aggregate also
//! keeps the period peak so the charts can draw the peak line. Data
//! lives only in memory — a restart clears it (long-term history is a
//! Prometheus concern, not this module's).

use std::{
    collections::{BTreeMap, VecDeque},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

use crate::model::{Metric, Window, limits};

/// The instantaneous global readings of one sample (WP-69 §3.3 采样):
/// host metrics, host network rates and the Gately process. Metrics the
/// platform cannot provide stay `None` — the interface renders "no data".
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Values {
    pub host_cpu: Option<f64>,
    pub host_mem: Option<f64>,
    pub host_disk: Option<f64>,
    pub host_load1: Option<f64>,
    pub net_rx_bps: Option<f64>,
    pub net_tx_bps: Option<f64>,
    pub proc_cpu: Option<f64>,
    pub proc_rss: Option<f64>,
}

/// Per-site readings of one sample; `backends` carries the current
/// forwarded connection count per backend node.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SiteValues {
    pub active: Option<f64>,
    pub qps: Option<f64>,
    pub err5xx: Option<f64>,
    pub latency_p95: Option<f64>,
    pub backends: BTreeMap<String, f64>,
}

/// Per managed-process readings of one sample (CPU percent, RSS bytes).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProcValues {
    pub cpu: Option<f64>,
    pub rss: Option<f64>,
}

/// One sample pushed every [`limits::SAMPLE_INTERVAL`].
#[derive(Clone, Debug, PartialEq)]
pub struct Sample {
    pub at: SystemTime,
    pub values: Values,
    pub sites: BTreeMap<String, SiteValues>,
    pub procs: BTreeMap<String, ProcValues>,
}

impl Default for Sample {
    fn default() -> Self {
        Self {
            at: UNIX_EPOCH,
            values: Values::default(),
            sites: BTreeMap::new(),
            procs: BTreeMap::new(),
        }
    }
}

/// One point of a managed-process mini curve (the last ~60 s).
#[derive(Clone, Debug, PartialEq)]
pub struct ProcPoint {
    pub at: SystemTime,
    pub cpu: Option<f64>,
    pub rss: Option<f64>,
}

impl Serialize for ProcPoint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let mut state = serializer.serialize_struct("ProcPoint", 3)?;
        state.serialize_field("at", &crate::rfc3339(self.at))?;
        state.serialize_field("cpu", &self.cpu)?;
        state.serialize_field("rss", &self.rss)?;
        state.end()
    }
}

/// Running sum / count / peak over one metric inside a longer period.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Agg {
    sum: f64,
    count: u32,
    peak: Option<f64>,
}

impl Agg {
    fn push(&mut self, value: Option<f64>) {
        if let Some(value) = value {
            self.sum += value;
            self.count += 1;
            self.peak = Some(match self.peak {
                Some(peak) => peak.max(value),
                None => value,
            });
        }
    }

    pub(crate) fn mean(&self) -> Option<f64> {
        (self.count > 0).then(|| self.sum / f64::from(self.count))
    }

    pub(crate) fn peak(&self) -> Option<f64> {
        self.peak
    }
}

/// Extra overview-only series that are charted alongside the alertable
/// [`Metric`] values (1-minute load average, host network throughput, and
/// managed-process totals).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtraMetric {
    HostLoad1,
    NetRxBps,
    NetTxBps,
    ManagedCpu,
    ManagedRss,
}

impl ExtraMetric {
    pub const ALL: [ExtraMetric; 5] = [
        ExtraMetric::HostLoad1,
        ExtraMetric::NetRxBps,
        ExtraMetric::NetTxBps,
        ExtraMetric::ManagedCpu,
        ExtraMetric::ManagedRss,
    ];

    pub fn tag(self) -> &'static str {
        match self {
            ExtraMetric::HostLoad1 => "hostLoad1",
            ExtraMetric::NetRxBps => "netRxBps",
            ExtraMetric::NetTxBps => "netTxBps",
            ExtraMetric::ManagedCpu => "managedCpu",
            ExtraMetric::ManagedRss => "managedRss",
        }
    }
}

/// Aggregates of one longer period (minute or 5 minutes).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AggSet {
    host_cpu: Agg,
    host_mem: Agg,
    host_disk: Agg,
    host_load1: Agg,
    net_rx: Agg,
    net_tx: Agg,
    proc_cpu: Agg,
    proc_rss: Agg,
    site_active: Agg,
    site_qps: Agg,
    site_5xx: Agg,
    site_latency: Agg,
    backend_conns: Agg,
    managed_cpu: Agg,
    managed_rss: Agg,
}

impl AggSet {
    fn push(&mut self, sample: &Sample) {
        self.host_cpu.push(sample.values.host_cpu);
        self.host_mem.push(sample.values.host_mem);
        self.host_disk.push(sample.values.host_disk);
        self.host_load1.push(sample.values.host_load1);
        self.net_rx.push(sample.values.net_rx_bps);
        self.net_tx.push(sample.values.net_tx_bps);
        self.proc_cpu.push(sample.values.proc_cpu);
        self.proc_rss.push(sample.values.proc_rss);
        self.site_active
            .push(sample_value(sample, Metric::SiteActive));
        self.site_qps.push(sample_value(sample, Metric::SiteQps));
        self.site_5xx.push(sample_value(sample, Metric::Site5xx));
        self.site_latency
            .push(sample_value(sample, Metric::SiteLatencyP95));
        self.backend_conns
            .push(sample_value(sample, Metric::BackendConns));
        self.managed_cpu
            .push(extra_sample_value(sample, ExtraMetric::ManagedCpu));
        self.managed_rss
            .push(extra_sample_value(sample, ExtraMetric::ManagedRss));
    }
}

/// The metric → aggregate mapping for the long windows.
pub(crate) fn agg_for(set: &AggSet, metric: Metric) -> &Agg {
    match metric {
        Metric::HostCpu => &set.host_cpu,
        Metric::HostMem => &set.host_mem,
        Metric::HostDisk => &set.host_disk,
        Metric::ProcCpu => &set.proc_cpu,
        Metric::ProcRss => &set.proc_rss,
        Metric::SiteActive => &set.site_active,
        Metric::SiteQps => &set.site_qps,
        Metric::Site5xx => &set.site_5xx,
        Metric::SiteLatencyP95 => &set.site_latency,
        Metric::BackendConns => &set.backend_conns,
    }
}

pub(crate) fn extra_agg_for(set: &AggSet, metric: ExtraMetric) -> &Agg {
    match metric {
        ExtraMetric::HostLoad1 => &set.host_load1,
        ExtraMetric::NetRxBps => &set.net_rx,
        ExtraMetric::NetTxBps => &set.net_tx,
        ExtraMetric::ManagedCpu => &set.managed_cpu,
        ExtraMetric::ManagedRss => &set.managed_rss,
    }
}

pub(crate) fn extra_sample_value(sample: &Sample, metric: ExtraMetric) -> Option<f64> {
    match metric {
        ExtraMetric::HostLoad1 => sample.values.host_load1,
        ExtraMetric::NetRxBps => sample.values.net_rx_bps,
        ExtraMetric::NetTxBps => sample.values.net_tx_bps,
        ExtraMetric::ManagedCpu => total(sample.procs.values().map(|proc| proc.cpu)),
        ExtraMetric::ManagedRss => total(sample.procs.values().map(|proc| proc.rss)),
    }
}

/// The metric value of a single sample. Site counters sum across sites,
/// ratio/latency metrics average the per-site observations — the same
/// semantics as [`Mode`].
pub(crate) fn sample_value(sample: &Sample, metric: Metric) -> Option<f64> {
    match metric {
        Metric::HostCpu => sample.values.host_cpu,
        Metric::HostMem => sample.values.host_mem,
        Metric::HostDisk => sample.values.host_disk,
        Metric::ProcCpu => sample.values.proc_cpu,
        Metric::ProcRss => sample.values.proc_rss,
        Metric::SiteActive => total(sample.sites.values().map(|site| site.active)),
        Metric::SiteQps => total(sample.sites.values().map(|site| site.qps)),
        Metric::Site5xx => mean(sample.sites.values().map(|site| site.err5xx)),
        Metric::SiteLatencyP95 => mean(sample.sites.values().map(|site| site.latency_p95)),
        Metric::BackendConns => total(
            sample
                .sites
                .values()
                .flat_map(|site| site.backends.values().copied())
                .map(Some),
        ),
    }
}

fn total(values: impl Iterator<Item = Option<f64>>) -> Option<f64> {
    values.fold(None, |acc, value| match (acc, value) {
        (_, Some(value)) => Some(acc.unwrap_or(0.0) + value),
        (acc, None) => acc,
    })
}

fn mean(values: impl Iterator<Item = Option<f64>>) -> Option<f64> {
    let (mut sum, mut count) = (0.0, 0u32);
    for value in values.flatten() {
        sum += value;
        count += 1;
    }
    (count > 0).then(|| sum / f64::from(count))
}

fn unix_secs(at: SystemTime) -> i64 {
    at.duration_since(UNIX_EPOCH)
        .map(|delta| delta.as_secs() as i64)
        .unwrap_or(0)
}

/// One minute (or 5-minute) bucket: its wall-clock key plus aggregates.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Bucket {
    pub(crate) key: i64,
    pub(crate) agg: AggSet,
}

/// The three-tier history. `push` is called once per sample; the rings
/// wrap by dropping the oldest bucket beyond their capacity.
#[derive(Debug, Default)]
pub struct History {
    short: VecDeque<Sample>,
    hour: VecDeque<Bucket>,
    day: VecDeque<Bucket>,
}

impl History {
    /// Pushes one sample (every 5 seconds): the short ring keeps it raw,
    /// the minute and 5-minute buckets merge or open a new period on the
    /// wall-clock boundaries. Stale samples (clock behind the last one)
    /// are ignored.
    pub fn push(&mut self, sample: Sample) {
        if let Some(last) = self.short.back()
            && sample.at < last.at
        {
            return;
        }
        let secs = unix_secs(sample.at);
        self.short.push_back(sample.clone());
        while self.short.len() > limits::SHORT_SLOTS {
            self.short.pop_front();
        }
        merge_or_push(&mut self.hour, secs / 60, &sample, limits::HOUR_SLOTS);
        merge_or_push(&mut self.day, secs / 300, &sample, limits::DAY_SLOTS);
    }

    /// The chart series for one metric and window (WP-69 §3.2).
    pub fn series(&self, metric: Metric, window: Window) -> crate::series::Series {
        crate::series::build(self, metric, window)
    }

    /// The chart series for an extra overview metric (load, network rates,
    /// managed-process totals).
    pub fn extra_series(&self, metric: ExtraMetric, window: Window) -> crate::series::Series {
        crate::series::build_extra(self, metric, window)
    }

    /// The managed-process mini curve (the last ~60 seconds).
    pub fn proc_history(&self, key: &str) -> Vec<ProcPoint> {
        self.short
            .iter()
            .filter_map(|sample| {
                sample.procs.get(key).map(|proc| ProcPoint {
                    at: sample.at,
                    cpu: proc.cpu,
                    rss: proc.rss,
                })
            })
            .collect()
    }

    /// The newest sample (current snapshot for the sites/processes views).
    pub fn last(&self) -> Option<&Sample> {
        self.short.back()
    }

    pub(crate) fn short(&self) -> &VecDeque<Sample> {
        &self.short
    }

    pub(crate) fn hour(&self) -> &VecDeque<Bucket> {
        &self.hour
    }

    pub(crate) fn day(&self) -> &VecDeque<Bucket> {
        &self.day
    }
}

fn merge_or_push(ring: &mut VecDeque<Bucket>, key: i64, sample: &Sample, capacity: usize) {
    if let Some(back) = ring.back() {
        if key < back.key {
            return; // stale period after a clock jump backwards
        }
        if back.key == key {
            if let Some(bucket) = ring.back_mut() {
                bucket.agg.push(sample);
            }
            return;
        }
    }
    let mut bucket = Bucket {
        key,
        agg: AggSet::default(),
    };
    bucket.agg.push(sample);
    ring.push_back(bucket);
    while ring.len() > capacity {
        ring.pop_front();
    }
}
