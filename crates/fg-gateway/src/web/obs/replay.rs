//! Topology replay recorder: 5-second frames, gzip compression, identical-frame
//! run-length deduplication, bounded memory ring, overview downsampling with
//! 2-minute cache, and point-in-time frame lookup (WP-28 §3.3/§3.4).

use std::{
    collections::VecDeque,
    io::{Read as _, Write as _},
    sync::{Arc, Mutex},
    time::Duration,
};

use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use ring::digest;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::topology::TopologySnapshot;

/// Interval between consecutive replay frames (5 seconds).
pub const FRAME_INTERVAL: Duration = Duration::from_secs(5);
/// Maximum gap (seconds) between two identical snapshots that may be merged via RLE.
pub const MAX_DEDUPE_GAP_SECS: i64 = 10;
/// Default memory ceiling in MiB.
pub const DEFAULT_MAX_MB: u32 = 8;
/// Minimum configurable memory ceiling in MiB.
pub const MIN_MAX_MB: u32 = 1;
/// Maximum configurable memory ceiling in MiB.
pub const MAX_MAX_MB: u32 = 256;
/// Default number of overview timeline points.
pub const DEFAULT_OVERVIEW_POINTS: usize = 400;
/// Maximum number of overview timeline points.
pub const MAX_OVERVIEW_POINTS: usize = 1_000;
/// Overview query cache TTL (2 minutes).
pub const OVERVIEW_CACHE_TTL_SECS: i64 = 120;

/// Replay configuration persisted under `webservice.json -> settings.replay`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplaySettings {
    pub enabled: bool,
    pub max_mb: u32,
}

impl Default for ReplaySettings {
    fn default() -> Self {
        Self {
            enabled: false,
            max_mb: DEFAULT_MAX_MB,
        }
    }
}

impl ReplaySettings {
    /// Clamps `max_mb` into `1..=256` (treating `0` as the default 8 MiB).
    pub fn normalize(mut self) -> Self {
        if self.max_mb == 0 {
            self.max_mb = DEFAULT_MAX_MB;
        } else {
            self.max_mb = self.max_mb.clamp(MIN_MAX_MB, MAX_MAX_MB);
        }
        self
    }

    pub fn max_bytes(&self) -> usize {
        (self.max_mb.clamp(MIN_MAX_MB, MAX_MAX_MB) as usize) * 1024 * 1024
    }
}

/// One compressed, run-length-encoded replay frame stored in memory.
#[derive(Clone, Debug)]
struct StoredFrame {
    first_ts: i64,
    last_ts: i64,
    repeat_count: u32,
    content_hash: [u8; 32],
    compressed: Vec<u8>,
    /// Pre-extracted summary values for fast overview rendering without gunzip.
    total_qps: f64,
    bytes_up_per_sec: f64,
    bytes_down_per_sec: f64,
    total_active: u32,
}

impl StoredFrame {
    fn memory_bytes(&self) -> usize {
        self.compressed.len() + std::mem::size_of::<Self>()
    }
}

/// One point on the replay overview timeline area chart.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayPoint {
    pub ts: i64,
    pub qps: f64,
    pub bytes_up_per_sec: f64,
    pub bytes_down_per_sec: f64,
    pub active: u32,
}

/// Response payload for `GET /api/webservice/topology/replay`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayOverview {
    pub enabled: bool,
    pub max_mb: u32,
    pub used_bytes: usize,
    pub stored_frames: usize,
    pub logical_frames: u64,
    pub earliest_ts: Option<i64>,
    pub latest_ts: Option<i64>,
    pub points: Vec<ReplayPoint>,
}

/// Response payload for `GET /api/webservice/topology/replay/frame`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayFrameResponse {
    pub ts: i64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub snapshot: TopologySnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CacheKey {
    from: Option<i64>,
    to: Option<i64>,
    points: usize,
}

#[derive(Clone, Debug)]
struct CachedOverview {
    key: CacheKey,
    cached_at: i64,
    response: ReplayOverview,
}

struct ReplayInner {
    settings: ReplaySettings,
    max_bytes_override: Option<usize>,
    frames: VecDeque<StoredFrame>,
    total_bytes: usize,
    logical_frames: u64,
    cache: Option<CachedOverview>,
}

impl ReplayInner {
    fn budget_bytes(&self) -> usize {
        self.max_bytes_override
            .unwrap_or_else(|| self.settings.max_bytes())
    }

    fn evict_to_budget(&mut self) {
        let budget = self.budget_bytes();
        while self.total_bytes > budget && !self.frames.is_empty() {
            if let Some(old) = self.frames.pop_front() {
                self.total_bytes = self.total_bytes.saturating_sub(old.memory_bytes());
                self.logical_frames = self
                    .logical_frames
                    .saturating_sub(u64::from(old.repeat_count));
            }
        }
    }
}

/// In-memory bounded topology replay recorder.
pub struct ReplayStore {
    inner: Mutex<ReplayInner>,
}

impl Default for ReplayStore {
    fn default() -> Self {
        Self::new(ReplaySettings::default())
    }
}

impl ReplayStore {
    pub fn new(settings: ReplaySettings) -> Self {
        Self {
            inner: Mutex::new(ReplayInner {
                settings: settings.normalize(),
                max_bytes_override: None,
                frames: VecDeque::new(),
                total_bytes: 0,
                logical_frames: 0,
                cache: None,
            }),
        }
    }

    /// Creates a store with an explicit byte budget (for deterministic eviction
    /// tests without allocating megabytes).
    pub fn with_max_bytes(settings: ReplaySettings, max_bytes: usize) -> Self {
        let store = Self::new(settings);
        store
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .max_bytes_override = Some(max_bytes);
        store
    }

    pub fn settings(&self) -> ReplaySettings {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .settings
    }

    /// Updates replay settings; evicts oldest frames immediately if the budget
    /// shrinks and clears the overview cache.
    pub fn update_settings(&self, settings: ReplaySettings) -> ReplaySettings {
        let normalized = settings.normalize();
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.settings = normalized;
        inner.max_bytes_override = None;
        inner.evict_to_budget();
        inner.cache = None;
        normalized
    }

    /// Clears all stored frames and resets memory usage to zero.
    pub fn clear(&self) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.frames.clear();
        inner.total_bytes = 0;
        inner.logical_frames = 0;
        inner.cache = None;
    }

    /// Current compressed storage footprint in bytes.
    pub fn used_bytes(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .total_bytes
    }

    /// Number of distinct compressed frames currently in memory (after RLE).
    pub fn stored_frame_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .frames
            .len()
    }

    /// Total logical 5-second ticks represented by the stored frames.
    pub fn logical_frame_count(&self) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .logical_frames
    }

    /// Records a topology snapshot at Unix timestamp `ts_sec`.
    ///
    /// Returns `true` if recorded (either newly pushed or merged via RLE), or
    /// `false` if recording is disabled or timestamp went backwards.
    pub fn record_at(&self, ts_sec: i64, snapshot: &TopologySnapshot) -> bool {
        let enabled = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .settings
            .enabled;
        if !enabled {
            return false;
        }

        // Canonicalize timestamp to 0 when hashing content so identical idle
        // topologies deduplicate even as the wall clock ticks forward.
        let mut hashable = snapshot.clone();
        hashable.timestamp = 0;
        let Ok(hash_json) = serde_json::to_vec(&hashable) else {
            return false;
        };
        let digest = digest::digest(&digest::SHA256, &hash_json);
        let mut content_hash = [0u8; 32];
        content_hash.copy_from_slice(digest.as_ref());

        // Fast check for RLE merge before compressing.
        {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !inner.settings.enabled {
                return false;
            }
            if let Some(last) = inner.frames.back_mut() {
                if ts_sec < last.last_ts {
                    return false;
                }
                if last.content_hash == content_hash
                    && (ts_sec - last.last_ts) <= MAX_DEDUPE_GAP_SECS
                {
                    last.last_ts = ts_sec;
                    last.repeat_count = last.repeat_count.saturating_add(1);
                    inner.logical_frames = inner.logical_frames.saturating_add(1);
                    return true;
                }
            }
        }

        // Serialize and gzip-compress outside the lock.
        let Ok(raw_json) = serde_json::to_vec(snapshot) else {
            return false;
        };
        let Ok(compressed) = gzip_compress(&raw_json) else {
            return false;
        };

        let frame = StoredFrame {
            first_ts: ts_sec,
            last_ts: ts_sec,
            repeat_count: 1,
            content_hash,
            compressed,
            total_qps: snapshot.total_qps,
            bytes_up_per_sec: snapshot.total_bytes_up_per_sec,
            bytes_down_per_sec: snapshot.total_bytes_down_per_sec,
            total_active: snapshot.total_active,
        };
        let size = frame.memory_bytes();

        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !inner.settings.enabled {
            return false;
        }
        // Re-check ordering / dedupe under lock in case of concurrent callers.
        if let Some(last) = inner.frames.back_mut() {
            if ts_sec < last.last_ts {
                return false;
            }
            if last.content_hash == content_hash && (ts_sec - last.last_ts) <= MAX_DEDUPE_GAP_SECS {
                last.last_ts = ts_sec;
                last.repeat_count = last.repeat_count.saturating_add(1);
                inner.logical_frames = inner.logical_frames.saturating_add(1);
                return true;
            }
        }
        inner.frames.push_back(frame);
        inner.total_bytes = inner.total_bytes.saturating_add(size);
        inner.logical_frames = inner.logical_frames.saturating_add(1);
        inner.evict_to_budget();
        true
    }

    /// Returns a downsampled overview series for `[from, to]` with at most
    /// `max_points` points (default 400, hard cap 1000). Results are cached for
    /// 2 minutes (`OVERVIEW_CACHE_TTL_SECS`).
    pub fn overview(
        &self,
        from: Option<i64>,
        to: Option<i64>,
        max_points: Option<usize>,
        now_sec: i64,
    ) -> ReplayOverview {
        let target_points = max_points
            .unwrap_or(DEFAULT_OVERVIEW_POINTS)
            .clamp(1, MAX_OVERVIEW_POINTS);
        let key = CacheKey {
            from,
            to,
            points: target_points,
        };

        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(ref cached) = inner.cache
            && cached.key == key
            && (now_sec - cached.cached_at).abs() < OVERVIEW_CACHE_TTL_SECS
        {
            return cached.response.clone();
        }

        let earliest_ts = inner.frames.front().map(|f| f.first_ts);
        let latest_ts = inner.frames.back().map(|f| f.last_ts);

        let range_from = from.or(earliest_ts).unwrap_or(0);
        let range_to = to.or(latest_ts).unwrap_or(range_from);

        let mut expanded: Vec<ReplayPoint> = Vec::new();
        if !inner.frames.is_empty() && range_to >= range_from {
            let step = FRAME_INTERVAL.as_secs() as i64;
            for frame in &inner.frames {
                if frame.last_ts < range_from || frame.first_ts > range_to {
                    continue;
                }
                let start = frame.first_ts.max(range_from);
                let end = frame.last_ts.min(range_to);
                let mut ts = start;
                // Cap expansion per frame cleanly so even long idle RLE spans stay fast.
                let span_steps = ((end - start) / step).max(0) + 1;
                if span_steps <= (target_points as i64 * 2) {
                    while ts <= end {
                        expanded.push(ReplayPoint {
                            ts,
                            qps: frame.total_qps,
                            bytes_up_per_sec: frame.bytes_up_per_sec,
                            bytes_down_per_sec: frame.bytes_down_per_sec,
                            active: frame.total_active,
                        });
                        ts += step;
                    }
                } else {
                    // Emit start, midpoint, and end of long identical RLE span.
                    let stride = ((end - start) / (target_points as i64)).max(step);
                    while ts < end {
                        expanded.push(ReplayPoint {
                            ts,
                            qps: frame.total_qps,
                            bytes_up_per_sec: frame.bytes_up_per_sec,
                            bytes_down_per_sec: frame.bytes_down_per_sec,
                            active: frame.total_active,
                        });
                        ts += stride;
                    }
                    expanded.push(ReplayPoint {
                        ts: end,
                        qps: frame.total_qps,
                        bytes_up_per_sec: frame.bytes_up_per_sec,
                        bytes_down_per_sec: frame.bytes_down_per_sec,
                        active: frame.total_active,
                    });
                }
            }
        }

        let points = downsample_points(expanded, target_points);
        let response = ReplayOverview {
            enabled: inner.settings.enabled,
            max_mb: inner.settings.max_mb,
            used_bytes: inner.total_bytes,
            stored_frames: inner.frames.len(),
            logical_frames: inner.logical_frames,
            earliest_ts,
            latest_ts,
            points,
        };
        inner.cache = Some(CachedOverview {
            key,
            cached_at: now_sec,
            response: response.clone(),
        });
        response
    }

    /// Looks up the frame covering `target_ts` (or the nearest preceding frame
    /// if `target_ts` lies between recorded frames), decompressing its snapshot.
    pub fn frame_at(&self, target_ts: i64) -> Option<ReplayFrameResponse> {
        let found: Option<(i64, i64, Vec<u8>)> = {
            let inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if inner.frames.is_empty() {
                return None;
            }
            // Binary search for the first frame with `last_ts >= target_ts`.
            let idx = inner.frames.partition_point(|f| f.last_ts < target_ts);
            let candidate = if idx < inner.frames.len() {
                let f = &inner.frames[idx];
                if f.first_ts <= target_ts {
                    Some(f)
                } else if idx > 0 {
                    // Between two frames: pick whichever is closer within MAX_DEDUPE_GAP_SECS, else previous.
                    let prev = &inner.frames[idx - 1];
                    if (f.first_ts - target_ts) < (target_ts - prev.last_ts) {
                        Some(f)
                    } else {
                        Some(prev)
                    }
                } else {
                    Some(f)
                }
            } else {
                inner.frames.back()
            };
            candidate.map(|f| (f.first_ts, f.last_ts, f.compressed.clone()))
        };

        let (first_ts, last_ts, compressed) = found?;
        let raw = gzip_decompress(&compressed).ok()?;
        let mut snapshot: TopologySnapshot = serde_json::from_slice(&raw).ok()?;
        let clamped_ts = target_ts.clamp(first_ts, last_ts);
        snapshot.timestamp = clamped_ts;
        Some(ReplayFrameResponse {
            ts: clamped_ts,
            first_ts,
            last_ts,
            snapshot,
        })
    }
}

/// Runs a periodic recorder loop that invokes `snapshot_fn` every `interval`
/// (typically [`FRAME_INTERVAL`] = 5 s) until `cancel` is triggered.
pub async fn run_recorder_loop<F, C>(
    store: Arc<ReplayStore>,
    interval: Duration,
    clock: C,
    mut snapshot_fn: F,
    cancel: CancellationToken,
) where
    F: FnMut(i64) -> TopologySnapshot + Send,
    C: Fn() -> i64 + Send,
{
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {
                let now_sec = clock();
                if store.settings().enabled {
                    let snap = snapshot_fn(now_sec);
                    store.record_at(now_sec, &snap);
                }
            }
        }
    }
}

fn downsample_points(points: Vec<ReplayPoint>, max_points: usize) -> Vec<ReplayPoint> {
    if points.len() <= max_points {
        return points;
    }
    let mut out = Vec::with_capacity(max_points);
    let len = points.len();
    for bucket in 0..max_points {
        let start = bucket * len / max_points;
        let end = ((bucket + 1) * len / max_points).max(start + 1).min(len);
        let slice = &points[start..end];
        let count = slice.len() as f64;
        let ts = slice[slice.len() / 2].ts;
        let qps = slice.iter().map(|p| p.qps).sum::<f64>() / count;
        let up = slice.iter().map(|p| p.bytes_up_per_sec).sum::<f64>() / count;
        let down = slice.iter().map(|p| p.bytes_down_per_sec).sum::<f64>() / count;
        let active = slice.iter().map(|p| p.active).max().unwrap_or(0);
        out.push(ReplayPoint {
            ts,
            qps,
            bytes_up_per_sec: up,
            bytes_down_per_sec: down,
            active,
        });
    }
    out
}

fn gzip_compress(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

fn gzip_decompress(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::obs::topology::RecentIpsView;

    fn sample_snapshot(ts: i64, qps: f64) -> TopologySnapshot {
        TopologySnapshot {
            timestamp: ts,
            window_secs: 10,
            total_qps: qps,
            total_bytes_up_per_sec: qps * 100.0,
            total_bytes_down_per_sec: qps * 20.0,
            total_active: qps as u32,
            recent_ips: RecentIpsView::default(),
            listeners: Vec::new(),
        }
    }

    #[test]
    fn replay_drops_oldest_beyond_limit_and_merges_identical() {
        let settings = ReplaySettings {
            enabled: true,
            max_mb: 1,
        };
        // Identical frames merge via RLE without growing stored_frame_count.
        let store = ReplayStore::new(settings);
        let idle = sample_snapshot(1000, 0.0);
        assert!(store.record_at(1000, &idle));
        assert!(store.record_at(1005, &idle));
        assert!(store.record_at(1010, &idle));
        assert_eq!(store.stored_frame_count(), 1);
        assert_eq!(store.logical_frame_count(), 3);

        // A gap > 10s creates a new frame rather than merging across the gap.
        assert!(store.record_at(1050, &idle));
        assert_eq!(store.stored_frame_count(), 2);

        // Point-in-time lookup inside the RLE range returns the snapshot at requested ts.
        let frame = store.frame_at(1005).expect("frame present");
        assert_eq!(frame.ts, 1005);
        assert_eq!(frame.first_ts, 1000);
        assert_eq!(frame.last_ts, 1010);

        // Tight budget evicts oldest frames when exceeded.
        let small = ReplayStore::with_max_bytes(settings, 900);
        for i in 0..30i64 {
            small.record_at(2000 + i * 5, &sample_snapshot(2000 + i * 5, i as f64 + 1.0));
        }
        assert!(small.used_bytes() <= 900);
        assert!(small.stored_frame_count() < 30);
        // Oldest frame was evicted, newest remains.
        let latest = small.frame_at(2000 + 29 * 5).expect("latest present");
        assert!((latest.snapshot.total_qps - 30.0).abs() < 1e-6);
    }

    #[test]
    fn replay_settings_normalize_bounds() {
        assert_eq!(
            ReplaySettings {
                enabled: true,
                max_mb: 0
            }
            .normalize()
            .max_mb,
            DEFAULT_MAX_MB
        );
        assert_eq!(
            ReplaySettings {
                enabled: true,
                max_mb: 999
            }
            .normalize()
            .max_mb,
            MAX_MAX_MB
        );
    }
}
