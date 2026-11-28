//! First-byte latency histogram and quantile estimation (WP-28 §3.2/§3.3).
//!
//! Uses 50 fixed buckets spanning 1 ms to 60 s (adjacent buckets differ by
//! ~20%–25%, plus an overflow bucket above 60 s). Each bucket stores only two
//! lock-free atomics (`count` and `total_us`) so quantiles are estimated from
//! the target bucket's mean duration without retaining per-request samples.
//!
//! For sub-minute windowed queries (e.g. WP-69's ~60 s window), [`LatencyHist`]
//! also maintains a 60-slot 1-second ring alongside the cumulative histogram.

use std::{
    sync::{
        Mutex,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// Total number of histogram buckets (49 bounded + 1 overflow > 60 s).
pub const LATENCY_BUCKETS: usize = 50;

/// Number of 1-second rolling slices retained for windowed quantile queries.
pub const WINDOW_SLOTS: usize = 60;

/// Upper boundaries in microseconds for buckets `0..49`.
/// Bucket 49 holds observations strictly greater than 60,000,000 us (60 s).
/// Adjacent boundaries increase by ~20%–26%.
pub const LATENCY_BOUNDS_US: [u64; LATENCY_BUCKETS - 1] = [
    1_000,      // 0: <= 1 ms
    1_250,      // 1: <= 1.25 ms
    1_550,      // 2: <= 1.55 ms
    1_950,      // 3: <= 1.95 ms
    2_450,      // 4: <= 2.45 ms
    3_100,      // 5: <= 3.1 ms
    3_900,      // 6: <= 3.9 ms
    4_900,      // 7: <= 4.9 ms
    6_150,      // 8: <= 6.15 ms
    7_750,      // 9: <= 7.75 ms
    9_750,      // 10: <= 9.75 ms
    12_250,     // 11: <= 12.25 ms
    15_400,     // 12: <= 15.4 ms
    19_400,     // 13: <= 19.4 ms
    24_400,     // 14: <= 24.4 ms
    30_700,     // 15: <= 30.7 ms
    38_600,     // 16: <= 38.6 ms
    48_500,     // 17: <= 48.5 ms
    61_000,     // 18: <= 61 ms
    76_700,     // 19: <= 76.7 ms
    96_500,     // 20: <= 96.5 ms
    121_000,    // 21: <= 121 ms
    152_000,    // 22: <= 152 ms
    191_000,    // 23: <= 191 ms
    240_000,    // 24: <= 240 ms
    302_000,    // 25: <= 302 ms
    380_000,    // 26: <= 380 ms
    478_000,    // 27: <= 478 ms
    601_000,    // 28: <= 601 ms
    756_000,    // 29: <= 756 ms
    950_000,    // 30: <= 950 ms
    1_200_000,  // 31: <= 1.2 s
    1_510_000,  // 32: <= 1.51 s
    1_900_000,  // 33: <= 1.9 s
    2_390_000,  // 34: <= 2.39 s
    3_000_000,  // 35: <= 3 s
    3_780_000,  // 36: <= 3.78 s
    4_750_000,  // 37: <= 4.75 s
    5_980_000,  // 38: <= 5.98 s
    7_520_000,  // 39: <= 7.52 s
    9_460_000,  // 40: <= 9.46 s
    11_900_000, // 41: <= 11.9 s
    15_000_000, // 42: <= 15 s
    18_850_000, // 43: <= 18.85 s
    23_700_000, // 44: <= 23.7 s
    29_800_000, // 45: <= 29.8 s
    37_500_000, // 46: <= 37.5 s
    47_500_000, // 47: <= 47.5 s
    60_000_000, // 48: <= 60 s
];

/// Maps a duration in microseconds to its bucket index `0..LATENCY_BUCKETS`.
pub fn bucket_index(us: u64) -> usize {
    match LATENCY_BOUNDS_US.binary_search(&us) {
        Ok(idx) => idx,
        Err(idx) => idx,
    }
}

/// Lower (exclusive for idx > 0) and upper (inclusive for idx < 49) bounds in
/// microseconds for a given bucket index.
pub fn bucket_bounds_us(idx: usize) -> (u64, Option<u64>) {
    let lower = if idx == 0 {
        0
    } else {
        LATENCY_BOUNDS_US[idx - 1]
    };
    let upper = LATENCY_BOUNDS_US.get(idx).copied();
    (lower, upper)
}

/// One atomic histogram bucket.
#[derive(Debug, Default)]
pub struct LatencyBucket {
    pub count: AtomicU64,
    pub total_us: AtomicU64,
}

impl LatencyBucket {
    #[inline]
    fn record(&self, us: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.total_us.fetch_add(us, Ordering::Relaxed);
    }

    #[inline]
    fn reset(&self) {
        self.count.store(0, Ordering::Relaxed);
        self.total_us.store(0, Ordering::Relaxed);
    }

    #[inline]
    fn snapshot(&self) -> (u64, u64) {
        (
            self.count.load(Ordering::Relaxed),
            self.total_us.load(Ordering::Relaxed),
        )
    }
}

/// Compact 50-bucket histogram without rolling time slices (used inside
/// per-minute ring buckets to keep memory footprint minimal).
#[derive(Debug)]
pub struct CompactLatencyHist {
    buckets: Box<[LatencyBucket]>,
}

impl Default for CompactLatencyHist {
    fn default() -> Self {
        Self::new()
    }
}

impl CompactLatencyHist {
    pub fn new() -> Self {
        let buckets: Vec<LatencyBucket> = (0..LATENCY_BUCKETS)
            .map(|_| LatencyBucket::default())
            .collect();
        Self {
            buckets: buckets.into_boxed_slice(),
        }
    }

    pub fn observe(&self, dur: Duration) {
        let us = dur.as_micros().min(u64::MAX as u128) as u64;
        let idx = bucket_index(us);
        self.buckets[idx].record(us);
    }

    pub fn reset(&self) {
        for b in self.buckets.iter() {
            b.reset();
        }
    }

    pub fn snapshot(&self) -> [(u64, u64); LATENCY_BUCKETS] {
        let mut out = [(0u64, 0u64); LATENCY_BUCKETS];
        for (slot, b) in out.iter_mut().zip(self.buckets.iter()) {
            *slot = b.snapshot();
        }
        out
    }

    pub fn quantile(&self, q: f64) -> Option<Duration> {
        quantile_from_counts(&self.snapshot(), q)
    }

    pub fn total_count(&self) -> u64 {
        self.buckets
            .iter()
            .map(|b| b.count.load(Ordering::Relaxed))
            .sum()
    }
}

/// One 1-second time slice for windowed latency queries.
#[derive(Debug)]
struct LatencySlice {
    /// Seconds elapsed since [`LatencyHist::origin`]; `-1` means unused.
    sec: AtomicI64,
    rotate_lock: Mutex<()>,
    buckets: Box<[LatencyBucket]>,
}

impl LatencySlice {
    fn new() -> Self {
        let buckets: Vec<LatencyBucket> = (0..LATENCY_BUCKETS)
            .map(|_| LatencyBucket::default())
            .collect();
        Self {
            sec: AtomicI64::new(-1),
            rotate_lock: Mutex::new(()),
            buckets: buckets.into_boxed_slice(),
        }
    }

    fn record(&self, sec: i64, idx: usize, us: u64) {
        let cur = self.sec.load(Ordering::Acquire);
        if cur != sec {
            if sec < cur {
                return;
            }
            let _guard = self
                .rotate_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let recheck = self.sec.load(Ordering::Acquire);
            if sec < recheck {
                return;
            }
            if sec > recheck {
                for b in self.buckets.iter() {
                    b.reset();
                }
                self.sec.store(sec, Ordering::Release);
            }
        }
        self.buckets[idx].record(us);
    }

    fn reset(&self) {
        let _guard = self
            .rotate_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.sec.store(-1, Ordering::Release);
        for b in self.buckets.iter() {
            b.reset();
        }
    }
}

/// Prometheus histogram snapshot (cumulative bucket counts + sum + total count).
#[derive(Clone, Debug, PartialEq)]
pub struct PrometheusHistogram {
    /// `(le_seconds, cumulative_count)` for the 49 finite bounds.
    pub buckets: Vec<(f64, u64)>,
    pub count: u64,
    pub sum_seconds: f64,
}

/// Site-level first-byte latency histogram with 50 buckets (1 ms – 60 s) and a
/// 60-second rolling window for short-window quantile queries.
#[derive(Debug)]
pub struct LatencyHist {
    /// Cumulative buckets since start / last reset (feeds Prometheus histogram).
    pub buckets: Box<[LatencyBucket]>,
    origin: Instant,
    slices: Box<[LatencySlice]>,
}

impl Default for LatencyHist {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyHist {
    pub fn new() -> Self {
        Self::with_origin(Instant::now())
    }

    pub fn with_origin(origin: Instant) -> Self {
        let buckets: Vec<LatencyBucket> = (0..LATENCY_BUCKETS)
            .map(|_| LatencyBucket::default())
            .collect();
        let slices: Vec<LatencySlice> = (0..WINDOW_SLOTS).map(|_| LatencySlice::new()).collect();
        Self {
            buckets: buckets.into_boxed_slice(),
            origin,
            slices: slices.into_boxed_slice(),
        }
    }

    /// Records a single first-byte latency observation at `Instant::now()`.
    pub fn observe(&self, dur: Duration) {
        self.observe_at(dur, Instant::now());
    }

    /// Deterministic observation with an explicit timestamp.
    pub fn observe_at(&self, dur: Duration, now: Instant) {
        let us = dur.as_micros().min(u64::MAX as u128) as u64;
        let idx = bucket_index(us);
        self.buckets[idx].record(us);

        let sec = now.saturating_duration_since(self.origin).as_secs() as i64;
        let slot = (sec as usize) % WINDOW_SLOTS;
        self.slices[slot].record(sec, idx, us);
    }

    /// Estimates quantile `q` (in `0.0..=1.0`, e.g. `0.50` or `0.95`) over the
    /// trailing `window` ending at `now`.
    ///
    /// When `window` is within 60 seconds, aggregates the active 1-second
    /// slices inside `[now - window, now]`; for larger windows or
    /// `Duration::ZERO`, uses the cumulative histogram.
    pub fn quantile(&self, window: Duration, now: Instant, q: f64) -> Option<Duration> {
        if window.is_zero() || window > Duration::from_secs(WINDOW_SLOTS as u64) {
            return self.quantile_all(q);
        }
        let now_sec = now.saturating_duration_since(self.origin).as_secs() as i64;
        let win_secs = window.as_secs().clamp(1, WINDOW_SLOTS as u64) as i64;
        let min_sec = now_sec - win_secs + 1;

        let mut acc = [(0u64, 0u64); LATENCY_BUCKETS];
        for slice in self.slices.iter() {
            let s = slice.sec.load(Ordering::Acquire);
            if s >= min_sec && s <= now_sec {
                for (dst, b) in acc.iter_mut().zip(slice.buckets.iter()) {
                    let (c, t) = b.snapshot();
                    dst.0 = dst.0.saturating_add(c);
                    dst.1 = dst.1.saturating_add(t);
                }
            }
        }
        quantile_from_counts(&acc, q)
    }

    /// Estimates quantile `q` across all cumulative observations since reset.
    pub fn quantile_all(&self, q: f64) -> Option<Duration> {
        let mut acc = [(0u64, 0u64); LATENCY_BUCKETS];
        for (dst, b) in acc.iter_mut().zip(self.buckets.iter()) {
            *dst = b.snapshot();
        }
        quantile_from_counts(&acc, q)
    }

    /// Returns cumulative Prometheus histogram buckets, total count, and sum in
    /// seconds.
    pub fn prometheus_snapshot(&self) -> PrometheusHistogram {
        let mut out = Vec::with_capacity(LATENCY_BOUNDS_US.len());
        let mut cum = 0u64;
        let mut total_us = 0u128;
        for (idx, bound_us) in LATENCY_BOUNDS_US.iter().enumerate() {
            let (c, t) = self.buckets[idx].snapshot();
            cum = cum.saturating_add(c);
            total_us += u128::from(t);
            out.push(((*bound_us as f64) / 1_000_000.0, cum));
        }
        // Add overflow bucket (idx = 49) into count & sum.
        let (ov_c, ov_t) = self.buckets[LATENCY_BUCKETS - 1].snapshot();
        cum = cum.saturating_add(ov_c);
        total_us += u128::from(ov_t);

        PrometheusHistogram {
            buckets: out,
            count: cum,
            sum_seconds: (total_us as f64) / 1_000_000.0,
        }
    }

    /// Resets both cumulative buckets and rolling slices.
    pub fn reset(&self) {
        for b in self.buckets.iter() {
            b.reset();
        }
        for s in self.slices.iter() {
            s.reset();
        }
    }
}

/// Computes quantile `q` from `(count, total_us)` pairs using the target
/// bucket's mean duration (WP-28 §3.3).
pub fn quantile_from_counts(counts: &[(u64, u64); LATENCY_BUCKETS], q: f64) -> Option<Duration> {
    let total: u64 = counts.iter().map(|(c, _)| *c).sum();
    if total == 0 {
        return None;
    }
    let q = q.clamp(0.0, 1.0);
    let target = ((total as f64) * q).ceil().max(1.0) as u64;
    let mut seen = 0u64;
    for (c, total_us) in counts.iter() {
        if *c == 0 {
            continue;
        }
        seen = seen.saturating_add(*c);
        if seen >= target {
            let mean_us = total_us / c;
            return Some(Duration::from_micros(mean_us));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_bounds_strictly_increasing_1ms_to_60s() {
        assert_eq!(LATENCY_BOUNDS_US.len(), 49);
        assert_eq!(LATENCY_BOUNDS_US[0], 1_000);
        assert_eq!(LATENCY_BOUNDS_US[48], 60_000_000);
        for pair in LATENCY_BOUNDS_US.windows(2) {
            assert!(pair[1] > pair[0], "bounds must strictly increase");
            let ratio = pair[1] as f64 / pair[0] as f64;
            assert!(
                (1.10..=1.30).contains(&ratio),
                "step ratio {ratio} out of expected range for {} -> {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn latency_quantile_within_bucket_width() {
        let origin = Instant::now();
        let hist = LatencyHist::with_origin(origin);
        // 100 observations at 10ms, 20ms, ..., 1000ms
        for i in 1..=100u64 {
            hist.observe_at(Duration::from_millis(i * 10), origin);
        }
        let p50 = hist
            .quantile(Duration::from_secs(60), origin, 0.50)
            .expect("p50 present");
        let p95 = hist
            .quantile(Duration::from_secs(60), origin, 0.95)
            .expect("p95 present");

        // Exact P50 is 500ms -> bucket containing 500ms (478ms..=601ms).
        let idx50 = bucket_index(500_000);
        let (lo50, hi50) = bucket_bounds_us(idx50);
        let p50_us = p50.as_micros() as u64;
        assert!(
            p50_us >= lo50 && p50_us <= hi50.unwrap(),
            "p50={p50_us}us outside [{lo50}, {:?}]",
            hi50
        );

        // Exact P95 is 950ms -> bucket containing 950ms (756ms..=950ms).
        let idx95 = bucket_index(950_000);
        let (lo95, hi95) = bucket_bounds_us(idx95);
        let p95_us = p95.as_micros() as u64;
        assert!(
            p95_us >= lo95 && p95_us <= hi95.unwrap(),
            "p95={p95_us}us outside [{lo95}, {:?}]",
            hi95
        );
    }

    #[test]
    fn latency_window_expires_old_slices() {
        let origin = Instant::now();
        let hist = LatencyHist::with_origin(origin);
        hist.observe_at(Duration::from_millis(50), origin);
        assert!(
            hist.quantile(
                Duration::from_secs(60),
                origin + Duration::from_secs(30),
                0.95
            )
            .is_some()
        );
        assert!(
            hist.quantile(
                Duration::from_secs(60),
                origin + Duration::from_secs(65),
                0.95
            )
            .is_none()
        );
        // Cumulative still retains it.
        assert!(hist.quantile_all(0.95).is_some());
    }
}
