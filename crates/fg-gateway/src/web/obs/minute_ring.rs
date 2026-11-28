//! Per-site 25-hour minute ring buffer (WP-28 §3.2/§3.3).
//!
//! Stores 1,500 one-minute buckets (`25 * 60` to cover 24 hours across
//! timezone/DST boundaries). Hot-path increments are lock-free atomics; slot
//! rotation only acquires a per-bucket mutex on the first request of a new
//! minute. Top source IP and country maps are strictly bounded to
//! [`MAX_TOP_SOURCES`] (5,000) distinct keys.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use super::{
    latency::{CompactLatencyHist, LATENCY_BUCKETS, quantile_from_counts},
    recorder::{DENY_KIND_COUNT, DenyKind, status_class_index},
};

/// Hours retained in the minute ring (24 h display + 1 h boundary guard).
pub const RING_HOURS: usize = 25;
/// Total slots in [`MinuteRing`].
pub const RING_MINUTES: usize = RING_HOURS * 60;
/// Maximum distinct source entries tracked in top leaderboards (WP-28 §3.4).
pub const MAX_TOP_SOURCES: usize = 5_000;
/// Number of top IPs / countries returned by the stats API.
pub const TOP_LEADERBOARD_LIMIT: usize = 10;

/// Converts a [`SystemTime`] to its Unix minute index (`unix_secs / 60`).
pub fn unix_minute(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() / 60) as i64,
        Err(_) => 0,
    }
}

/// Bounded frequency counter capped at `cap` distinct keys.
#[derive(Debug)]
pub struct TopSet {
    cap: usize,
    inner: Mutex<HashMap<String, u64>>,
    overflowed: AtomicU64,
}

impl TopSet {
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            inner: Mutex::new(HashMap::new()),
            overflowed: AtomicU64::new(0),
        }
    }

    /// Increments `key`, or drops it if already at `cap` distinct keys.
    pub fn add(&self, key: &str) {
        if key.is_empty() {
            return;
        }
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = map.get_mut(key) {
            *count = count.saturating_add(1);
        } else if map.len() < self.cap {
            map.insert(key.to_owned(), 1);
        } else {
            self.overflowed.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn clear(&self) {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        map.clear();
        map.shrink_to_fit();
        self.overflowed.store(0, Ordering::Relaxed);
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn overflowed(&self) -> u64 {
        self.overflowed.load(Ordering::Relaxed)
    }

    /// Merges entries into `acc`, respecting `cap` distinct keys.
    pub fn merge_into(&self, acc: &mut HashMap<String, u64>, cap: usize) {
        let map = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (k, v) in map.iter() {
            if let Some(existing) = acc.get_mut(k) {
                *existing = existing.saturating_add(*v);
            } else if acc.len() < cap {
                acc.insert(k.clone(), *v);
            }
        }
    }
}

/// One leaderboard row (Top IP or Top Country).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopItem {
    pub key: String,
    pub count: u64,
}

/// One minute's atomic counters in [`MinuteRing`].
#[derive(Debug)]
pub struct MinuteBucket {
    /// Unix minute currently stored in this slot (`i64::MIN` = empty).
    minute: AtomicI64,
    rotate_lock: Mutex<()>,
    pub requests: AtomicU64,
    pub errors4xx: AtomicU64,
    pub errors5xx: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    /// `0=2xx, 1=3xx, 2=4xx, 3=5xx`.
    pub by_class: [AtomicU64; 4],
    /// `0=ban, 1=ip, 2=country, 3=rateLimit, 4=waf`.
    pub blocked: [AtomicU64; DENY_KIND_COUNT],
    /// Per-minute latency histogram (lazily allocated on first observation).
    latency: OnceLock<Box<CompactLatencyHist>>,
    /// Per-minute top source IPs (bounded at [`MAX_TOP_SOURCES`]).
    pub top: TopSet,
    /// Per-minute top country codes (bounded at [`MAX_TOP_SOURCES`]).
    pub countries: TopSet,
}

impl Default for MinuteBucket {
    fn default() -> Self {
        Self::new()
    }
}

impl MinuteBucket {
    fn new() -> Self {
        Self {
            minute: AtomicI64::new(i64::MIN),
            rotate_lock: Mutex::new(()),
            requests: AtomicU64::new(0),
            errors4xx: AtomicU64::new(0),
            errors5xx: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            by_class: std::array::from_fn(|_| AtomicU64::new(0)),
            blocked: std::array::from_fn(|_| AtomicU64::new(0)),
            latency: OnceLock::new(),
            top: TopSet::new(MAX_TOP_SOURCES),
            countries: TopSet::new(MAX_TOP_SOURCES),
        }
    }

    /// Returns the Unix minute currently occupying this bucket.
    pub fn minute(&self) -> i64 {
        self.minute.load(Ordering::Acquire)
    }

    /// Ensures this slot is aligned to `minute`. Returns `false` if `minute` is
    /// older than the already-stored minute (e.g. clock rolled backwards).
    fn ensure_minute(&self, minute: i64) -> bool {
        let cur = self.minute.load(Ordering::Acquire);
        if cur == minute {
            return true;
        }
        if minute < cur {
            return false;
        }
        let _guard = self
            .rotate_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let recheck = self.minute.load(Ordering::Acquire);
        if recheck == minute {
            return true;
        }
        if minute < recheck {
            return false;
        }
        self.clear_counters();
        self.minute.store(minute, Ordering::Release);
        true
    }

    fn clear_counters(&self) {
        self.requests.store(0, Ordering::Relaxed);
        self.errors4xx.store(0, Ordering::Relaxed);
        self.errors5xx.store(0, Ordering::Relaxed);
        self.bytes_in.store(0, Ordering::Relaxed);
        self.bytes_out.store(0, Ordering::Relaxed);
        for c in &self.by_class {
            c.store(0, Ordering::Relaxed);
        }
        for b in &self.blocked {
            b.store(0, Ordering::Relaxed);
        }
        if let Some(hist) = self.latency.get() {
            hist.reset();
        }
        self.top.clear();
        self.countries.clear();
    }

    fn reset(&self) {
        let _guard = self
            .rotate_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.minute.store(i64::MIN, Ordering::Release);
        self.clear_counters();
    }

    /// Observes a latency sample in this minute bucket.
    pub fn observe_latency(&self, dur: Duration) {
        let hist = self
            .latency
            .get_or_init(|| Box::new(CompactLatencyHist::new()));
        hist.observe(dur);
    }

    /// Computes a quantile (in milliseconds) for this minute.
    pub fn latency_quantile_ms(&self, q: f64) -> Option<f64> {
        self.latency
            .get()
            .and_then(|h| h.quantile(q))
            .map(|d| d.as_secs_f64() * 1000.0)
    }
}

/// One point in a minute time-series response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MinutePoint {
    pub minute: i64,
    pub timestamp: i64,
    pub requests: u64,
    pub errors4xx: u64,
    pub errors5xx: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub by_class: [u64; 4],
    pub blocked: [u64; DENY_KIND_COUNT],
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
}

impl MinutePoint {
    fn empty(minute: i64) -> Self {
        Self {
            minute,
            timestamp: minute * 60,
            requests: 0,
            errors4xx: 0,
            errors5xx: 0,
            bytes_in: 0,
            bytes_out: 0,
            by_class: [0; 4],
            blocked: [0; DENY_KIND_COUNT],
            p50_ms: None,
            p95_ms: None,
        }
    }
}

/// Aggregated statistics for a requested window (`1h` / `6h` / `24h`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowSummary {
    pub from_minute: i64,
    pub to_minute: i64,
    pub requests: u64,
    pub errors4xx: u64,
    pub errors5xx: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub by_class: [u64; 4],
    pub blocked: [u64; DENY_KIND_COUNT],
    pub peak_p95_ms: Option<f64>,
    pub overall_p50_ms: Option<f64>,
    pub overall_p95_ms: Option<f64>,
    pub top_ips: Vec<TopItem>,
    pub top_countries: Vec<TopItem>,
    pub series: Vec<MinutePoint>,
}

/// Backend row exported to WP-69 (`fg-perf`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendPerfSnapshot {
    pub name: String,
    pub healthy: bool,
    pub conns: u64,
}

/// Site performance snapshot readable by WP-69 (`fg-perf::SiteSnapshot` parity).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SitePerfSnapshot {
    pub name: String,
    pub active: u64,
    pub qps: Option<f64>,
    pub err5xx: Option<f64>,
    pub latency_p95: Option<f64>,
    pub window_requests: u64,
    pub window_span_secs: u64,
    pub backends: Vec<BackendPerfSnapshot>,
}

/// 25-hour circular buffer of [`MinuteBucket`]s.
#[derive(Debug)]
pub struct MinuteRing {
    minutes: Box<[MinuteBucket]>,
}

impl Default for MinuteRing {
    fn default() -> Self {
        Self::new()
    }
}

impl MinuteRing {
    pub fn new() -> Self {
        let minutes: Vec<MinuteBucket> = (0..RING_MINUTES).map(|_| MinuteBucket::new()).collect();
        Self {
            minutes: minutes.into_boxed_slice(),
        }
    }

    #[inline]
    fn slot_index(minute: i64) -> usize {
        minute.rem_euclid(RING_MINUTES as i64) as usize
    }

    /// Returns the bucket for `minute`, advancing/clearing the slot when a
    /// newer minute arrives.
    pub fn get(&self, minute: i64) -> &MinuteBucket {
        let bucket = &self.minutes[Self::slot_index(minute)];
        let _ = bucket.ensure_minute(minute);
        bucket
    }

    /// Records one completed request into the bucket for `minute`.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        minute: i64,
        status: u16,
        deny: DenyKind,
        bytes_in: u64,
        bytes_out: u64,
        latency: Option<Duration>,
        ip: Option<IpAddr>,
        country: Option<&str>,
    ) {
        let bucket = &self.minutes[Self::slot_index(minute)];
        if !bucket.ensure_minute(minute) {
            return;
        }
        bucket.requests.fetch_add(1, Ordering::Relaxed);
        bucket.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        bucket.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);

        if let Some(class) = status_class_index(status) {
            bucket.by_class[class].fetch_add(1, Ordering::Relaxed);
            if class == 2 {
                bucket.errors4xx.fetch_add(1, Ordering::Relaxed);
            } else if class == 3 {
                bucket.errors5xx.fetch_add(1, Ordering::Relaxed);
            }
        }
        if let Some(deny_idx) = deny.index() {
            bucket.blocked[deny_idx].fetch_add(1, Ordering::Relaxed);
        }
        if let Some(dur) = latency {
            bucket.observe_latency(dur);
        }
        if let Some(addr) = ip {
            bucket.top.add(&addr.to_string());
        }
        if let Some(cc) = country
            && !cc.is_empty()
        {
            bucket.countries.add(cc);
        }
    }

    /// Returns one [`MinutePoint`] per minute across `[from, to]` (inclusive,
    /// capped to [`RING_MINUTES`] points).
    pub fn series(&self, from: i64, to: i64) -> Vec<MinutePoint> {
        if to < from {
            return Vec::new();
        }
        let span = (to - from + 1).min(RING_MINUTES as i64);
        let start = to - span + 1;
        let mut out = Vec::with_capacity(span as usize);
        for m in start..=to {
            let bucket = &self.minutes[Self::slot_index(m)];
            if bucket.minute() != m {
                out.push(MinutePoint::empty(m));
                continue;
            }
            let by_class = [
                bucket.by_class[0].load(Ordering::Relaxed),
                bucket.by_class[1].load(Ordering::Relaxed),
                bucket.by_class[2].load(Ordering::Relaxed),
                bucket.by_class[3].load(Ordering::Relaxed),
            ];
            let blocked = [
                bucket.blocked[0].load(Ordering::Relaxed),
                bucket.blocked[1].load(Ordering::Relaxed),
                bucket.blocked[2].load(Ordering::Relaxed),
                bucket.blocked[3].load(Ordering::Relaxed),
                bucket.blocked[4].load(Ordering::Relaxed),
            ];
            out.push(MinutePoint {
                minute: m,
                timestamp: m * 60,
                requests: bucket.requests.load(Ordering::Relaxed),
                errors4xx: bucket.errors4xx.load(Ordering::Relaxed),
                errors5xx: bucket.errors5xx.load(Ordering::Relaxed),
                bytes_in: bucket.bytes_in.load(Ordering::Relaxed),
                bytes_out: bucket.bytes_out.load(Ordering::Relaxed),
                by_class,
                blocked,
                p50_ms: bucket.latency_quantile_ms(0.50),
                p95_ms: bucket.latency_quantile_ms(0.95),
            });
        }
        out
    }

    /// Aggregates series, totals, peak/overall P95, and Top 10 IPs / countries
    /// over `[from, to]` (inclusive).
    pub fn summary(&self, from: i64, to: i64) -> WindowSummary {
        let series = self.series(from, to);
        let mut requests = 0u64;
        let mut errors4xx = 0u64;
        let mut errors5xx = 0u64;
        let mut bytes_in = 0u64;
        let mut bytes_out = 0u64;
        let mut by_class = [0u64; 4];
        let mut blocked = [0u64; DENY_KIND_COUNT];
        let mut peak_p95_ms: Option<f64> = None;

        for pt in &series {
            requests = requests.saturating_add(pt.requests);
            errors4xx = errors4xx.saturating_add(pt.errors4xx);
            errors5xx = errors5xx.saturating_add(pt.errors5xx);
            bytes_in = bytes_in.saturating_add(pt.bytes_in);
            bytes_out = bytes_out.saturating_add(pt.bytes_out);
            for (dst, src) in by_class.iter_mut().zip(pt.by_class.iter()) {
                *dst = dst.saturating_add(*src);
            }
            for (dst, src) in blocked.iter_mut().zip(pt.blocked.iter()) {
                *dst = dst.saturating_add(*src);
            }
            if let Some(p95) = pt.p95_ms {
                peak_p95_ms = Some(match peak_p95_ms {
                    Some(prev) => prev.max(p95),
                    None => p95,
                });
            }
        }

        let mut ip_acc: HashMap<String, u64> = HashMap::new();
        let mut cc_acc: HashMap<String, u64> = HashMap::new();
        let mut lat_acc = [(0u64, 0u64); LATENCY_BUCKETS];

        if to >= from {
            let span = (to - from + 1).min(RING_MINUTES as i64);
            let start = to - span + 1;
            for m in start..=to {
                let bucket = &self.minutes[Self::slot_index(m)];
                if bucket.minute() != m {
                    continue;
                }
                bucket.top.merge_into(&mut ip_acc, MAX_TOP_SOURCES);
                bucket.countries.merge_into(&mut cc_acc, MAX_TOP_SOURCES);
                if let Some(hist) = bucket.latency.get() {
                    let snap = hist.snapshot();
                    for (dst, (c, t)) in lat_acc.iter_mut().zip(snap.iter()) {
                        dst.0 = dst.0.saturating_add(*c);
                        dst.1 = dst.1.saturating_add(*t);
                    }
                }
            }
        }

        let overall_p50_ms = quantile_from_counts(&lat_acc, 0.50).map(|d| d.as_secs_f64() * 1000.0);
        let overall_p95_ms = quantile_from_counts(&lat_acc, 0.95).map(|d| d.as_secs_f64() * 1000.0);

        WindowSummary {
            from_minute: from,
            to_minute: to,
            requests,
            errors4xx,
            errors5xx,
            bytes_in,
            bytes_out,
            by_class,
            blocked,
            peak_p95_ms,
            overall_p50_ms,
            overall_p95_ms,
            top_ips: top_n(ip_acc, TOP_LEADERBOARD_LIMIT),
            top_countries: top_n(cc_acc, TOP_LEADERBOARD_LIMIT),
            series,
        }
    }

    /// Clears all 1,500 buckets in the ring.
    pub fn reset(&self) {
        for b in self.minutes.iter() {
            b.reset();
        }
    }
}

fn top_n(map: HashMap<String, u64>, limit: usize) -> Vec<TopItem> {
    let mut items: Vec<TopItem> = map
        .into_iter()
        .map(|(key, count)| TopItem { key, count })
        .collect();
    items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    items.truncate(limit);
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn minute_ring_wraps_after_25h() {
        let ring = MinuteRing::new();
        let m0 = 1_000_000i64;
        ring.record(
            m0,
            200,
            DenyKind::None,
            100,
            500,
            Some(Duration::from_millis(12)),
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            Some("US"),
        );
        assert_eq!(ring.series(m0, m0)[0].requests, 1);

        // Exactly 25 hours later wraps to the same slot and resets the old count.
        let m_wrap = m0 + RING_MINUTES as i64;
        ring.record(
            m_wrap,
            502,
            DenyKind::None,
            10,
            20,
            Some(Duration::from_millis(80)),
            Some(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))),
            Some("DE"),
        );

        let wrapped = ring.series(m_wrap, m_wrap);
        assert_eq!(wrapped[0].requests, 1);
        assert_eq!(wrapped[0].errors5xx, 1);
        assert_eq!(wrapped[0].bytes_out, 20);

        // Old minute now reads as empty because the slot holds m_wrap.
        assert_eq!(ring.series(m0, m0)[0].requests, 0);
    }

    #[test]
    fn minute_ring_ignores_clock_rollback_and_caps_top_sources() {
        let ring = MinuteRing::new();
        let m = 2_000_000i64;
        ring.record(m, 200, DenyKind::None, 0, 10, None, None, None);
        // Earlier minute mapping to the same slot (25h earlier) must be ignored.
        ring.record(
            m - RING_MINUTES as i64,
            500,
            DenyKind::Waf,
            0,
            999,
            None,
            None,
            None,
        );
        let pt = &ring.series(m, m)[0];
        assert_eq!(pt.requests, 1);
        assert_eq!(pt.errors5xx, 0);

        // TopSet caps at MAX_TOP_SOURCES (5000).
        for i in 0..5_500u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i));
            ring.record(m, 200, DenyKind::None, 0, 1, None, Some(ip), None);
        }
        assert_eq!(ring.get(m).top.len(), MAX_TOP_SOURCES);
        assert!(ring.get(m).top.overflowed() >= 500);
    }

    #[test]
    fn minute_ring_reset_clears_all() {
        let ring = MinuteRing::new();
        ring.record(100, 200, DenyKind::None, 1, 2, None, None, None);
        ring.reset();
        assert_eq!(ring.series(100, 100)[0].requests, 0);
    }
}
