//! Network topology counters, 60-second zero-alloc rate ring, bounded recent
//! IP tracking, and topology snapshot models (WP-28 §3.2/§3.3).
//!
//! ## Traffic direction semantics (gateway perspective)
//! - On **site / visitor** nodes:
//!   - `up` (`bytes_up`): bytes sent **to the visitor** (HTTP response / WS send).
//!   - `down` (`bytes_down`): bytes received **from the visitor** (request body / WS recv).
//! - On **backend / upstream** nodes:
//!   - `up` (`bytes_up`): bytes sent **to the backend** (proxied request).
//!   - `down` (`bytes_down`): bytes received **from the backend** (backend response).

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{
        Mutex,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
};

use serde::{Deserialize, Serialize};

use super::recorder::{DENY_KIND_COUNT, DenyKind, status_hist_index};

/// Number of 1-second slots in [`RateRing`].
pub const RATE_SLOTS: usize = 60;
/// Supported rate averaging windows in seconds (default [`DEFAULT_RATE_WINDOW_SECS`]).
pub const VALID_RATE_WINDOWS: [u64; 5] = [1, 5, 10, 30, 60];
/// Default rate averaging window (10 seconds).
pub const DEFAULT_RATE_WINDOW_SECS: u64 = 10;
/// Maximum recent IPs tracked per topology node (site, backend, listener action).
pub const MAX_RECENT_IPS_PER_NODE: usize = 1024;
/// Sliding window for recent IPs (60 seconds).
pub const RECENT_IP_WINDOW_SECS: i64 = 60;
/// Maximum IPs returned in a single topology API response.
pub const MAX_TOPO_API_IPS: usize = 500;
/// Maximum distinct IPs processed when aggregating topology summaries.
pub const MAX_TOPO_SUMMARY_IPS: usize = 5_000;

/// Normalizes a requested rate window to one of `1, 5, 10, 30, 60` (defaults to 10).
pub const fn normalize_rate_window(secs: u64) -> u64 {
    match secs {
        1 | 5 | 10 | 30 | 60 => secs,
        _ => DEFAULT_RATE_WINDOW_SECS,
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct RateSlot {
    sec: i64,
    requests: u64,
    bytes_up: u64,
    bytes_down: u64,
}

/// Instantaneous averaged rate over a requested trailing window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateSample {
    pub window_secs: u64,
    pub qps: f64,
    pub bytes_up_per_sec: f64,
    pub bytes_down_per_sec: f64,
}

/// 60-slot one-second ring buffer for QPS and up/down throughput.
///
/// Hot-path [`Self::record`] only locks a compact fixed-size `[RateSlot; 60]`
/// array and performs index arithmetic with **zero heap allocations**.
#[derive(Debug)]
pub struct RateRing {
    slots: Mutex<[RateSlot; RATE_SLOTS]>,
}

impl Default for RateRing {
    fn default() -> Self {
        Self::new()
    }
}

impl RateRing {
    pub fn new() -> Self {
        Self {
            slots: Mutex::new(
                [RateSlot {
                    sec: i64::MIN,
                    requests: 0,
                    bytes_up: 0,
                    bytes_down: 0,
                }; RATE_SLOTS],
            ),
        }
    }

    /// Records traffic for Unix second `now_sec`. Zero allocations.
    pub fn record(&self, now_sec: i64, requests: u64, bytes_up: u64, bytes_down: u64) {
        let idx = now_sec.rem_euclid(RATE_SLOTS as i64) as usize;
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let slot = &mut slots[idx];
        if slot.sec == now_sec {
            slot.requests = slot.requests.saturating_add(requests);
            slot.bytes_up = slot.bytes_up.saturating_add(bytes_up);
            slot.bytes_down = slot.bytes_down.saturating_add(bytes_down);
        } else if now_sec > slot.sec {
            slot.sec = now_sec;
            slot.requests = requests;
            slot.bytes_up = bytes_up;
            slot.bytes_down = bytes_down;
        }
    }

    /// Computes average QPS and up/down bytes per second over the trailing
    /// `window_secs` (`1`, `5`, `10`, `30`, or `60`, default `10`) ending at
    /// `now_sec` (inclusive).
    pub fn rates(&self, now_sec: i64, window_secs: u64) -> RateSample {
        let win = normalize_rate_window(window_secs);
        let min_sec = now_sec - (win as i64) + 1;
        let slots = self
            .slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut reqs = 0u64;
        let mut up = 0u64;
        let mut down = 0u64;
        for slot in slots.iter() {
            if slot.sec >= min_sec && slot.sec <= now_sec {
                reqs = reqs.saturating_add(slot.requests);
                up = up.saturating_add(slot.bytes_up);
                down = down.saturating_add(slot.bytes_down);
            }
        }
        let denom = win as f64;
        RateSample {
            window_secs: win,
            qps: reqs as f64 / denom,
            bytes_up_per_sec: up as f64 / denom,
            bytes_down_per_sec: down as f64 / denom,
        }
    }

    /// Resets all 60 slots.
    pub fn reset(&self) {
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for slot in slots.iter_mut() {
            *slot = RateSlot {
                sec: i64::MIN,
                requests: 0,
                bytes_up: 0,
                bytes_down: 0,
            };
        }
    }
}

/// Snapshot of recent + active IPs for a node or API response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentIpsView {
    pub ips: Vec<String>,
    pub total: usize,
    pub truncated: bool,
}

#[derive(Debug, Default)]
struct RecentIpsInner {
    entries: HashMap<IpAddr, i64>,
    overflowed: bool,
}

/// Bounded set of recent visitor IPs for one topology node (max
/// [`MAX_RECENT_IPS_PER_NODE`] = 1024 entries, 60-second sliding window).
#[derive(Debug)]
pub struct RecentIps {
    cap: usize,
    inner: Mutex<RecentIpsInner>,
}

impl Default for RecentIps {
    fn default() -> Self {
        Self::new()
    }
}

impl RecentIps {
    pub fn new() -> Self {
        Self::with_cap(MAX_RECENT_IPS_PER_NODE)
    }

    pub fn with_cap(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            inner: Mutex::new(RecentIpsInner::default()),
        }
    }

    /// Records `ip` as active at Unix second `now_sec`.
    pub fn record(&self, ip: IpAddr, now_sec: i64) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(ts) = inner.entries.get_mut(&ip) {
            if now_sec > *ts {
                *ts = now_sec;
            }
            return;
        }
        if inner.entries.len() >= self.cap {
            let cutoff = now_sec - RECENT_IP_WINDOW_SECS;
            inner.entries.retain(|_, ts| *ts >= cutoff);
        }
        if inner.entries.len() < self.cap {
            inner.entries.insert(ip, now_sec);
        } else {
            inner.overflowed = true;
        }
    }

    /// Returns the number of currently tracked entries (before expiry pruning).
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Builds a deduplicated, sorted list of recent (last 60 s) plus active
    /// IPs, capped at `max_return` (e.g. [`MAX_TOPO_API_IPS`] = 500).
    pub fn snapshot(
        &self,
        now_sec: i64,
        active_ips: &[IpAddr],
        max_return: usize,
    ) -> RecentIpsView {
        let cutoff = now_sec - RECENT_IP_WINDOW_SECS;
        let mut seen: HashSet<IpAddr> = HashSet::new();
        let node_overflowed;
        {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            inner.entries.retain(|_, ts| *ts >= cutoff);
            if inner.entries.len() < self.cap {
                // Once pressure drops below cap we still report overflow for
                // this snapshot if it happened recently, then clear it.
                node_overflowed = inner.overflowed;
                inner.overflowed = false;
            } else {
                node_overflowed = inner.overflowed;
            }
            for ip in inner.entries.keys() {
                seen.insert(*ip);
            }
        }
        for ip in active_ips {
            if seen.len() >= MAX_TOPO_SUMMARY_IPS {
                break;
            }
            seen.insert(*ip);
        }
        let total = seen.len();
        let truncated = node_overflowed || total > max_return;
        let mut list: Vec<String> = seen.into_iter().map(|ip| ip.to_string()).collect();
        list.sort();
        list.truncate(max_return);
        RecentIpsView {
            ips: list,
            total,
            truncated,
        }
    }

    pub fn clear(&self) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.entries.clear();
        inner.entries.shrink_to_fit();
        inner.overflowed = false;
    }
}

/// Per-node runtime counters shared by sites, backends, and listener actions.
#[derive(Debug)]
pub struct Topo {
    pub rate: RateRing,
    pub active: AtomicU32,
    pub cum_requests: AtomicU64,
    pub cum_errors: AtomicU64,
    /// `0=ban, 1=ip, 2=country, 3=rateLimit, 4=waf`.
    pub blocked: [AtomicU64; DENY_KIND_COUNT],
    /// `0=2xx, 1=3xx, 2=4xx, 3=5xx, 4=other/444`.
    pub status_hist: [AtomicU64; 5],
    pub recent_ips: RecentIps,
}

impl Default for Topo {
    fn default() -> Self {
        Self::new()
    }
}

impl Topo {
    pub fn new() -> Self {
        Self {
            rate: RateRing::new(),
            active: AtomicU32::new(0),
            cum_requests: AtomicU64::new(0),
            cum_errors: AtomicU64::new(0),
            blocked: std::array::from_fn(|_| AtomicU64::new(0)),
            status_hist: std::array::from_fn(|_| AtomicU64::new(0)),
            recent_ips: RecentIps::new(),
        }
    }

    pub fn inc_active(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active(&self) {
        // Saturating decrement prevents underflow if reset raced with an in-flight request.
        let _ = self
            .active
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
    }

    /// Records a completed request onto this topology node.
    pub fn record_request(
        &self,
        now_sec: i64,
        status: u16,
        deny: DenyKind,
        bytes_up: u64,
        bytes_down: u64,
        ip: Option<IpAddr>,
    ) {
        self.rate.record(now_sec, 1, bytes_up, bytes_down);
        self.cum_requests.fetch_add(1, Ordering::Relaxed);
        if status >= 500 || status == 444 {
            self.cum_errors.fetch_add(1, Ordering::Relaxed);
        }
        self.status_hist[status_hist_index(status)].fetch_add(1, Ordering::Relaxed);
        if let Some(idx) = deny.index() {
            self.blocked[idx].fetch_add(1, Ordering::Relaxed);
        }
        if let Some(addr) = ip {
            self.recent_ips.record(addr, now_sec);
        }
    }

    /// Records a listener-level action (e.g. `https_redirect`, `not_found`, `default_close`).
    pub fn record_action(&self, now_sec: i64, status: u16, bytes_up: u64, ip: Option<IpAddr>) {
        self.record_request(now_sec, status, DenyKind::None, bytes_up, 0, ip);
    }

    pub fn blocked_snapshot(&self) -> [u64; DENY_KIND_COUNT] {
        [
            self.blocked[0].load(Ordering::Relaxed),
            self.blocked[1].load(Ordering::Relaxed),
            self.blocked[2].load(Ordering::Relaxed),
            self.blocked[3].load(Ordering::Relaxed),
            self.blocked[4].load(Ordering::Relaxed),
        ]
    }

    pub fn status_hist_snapshot(&self) -> [u64; 5] {
        [
            self.status_hist[0].load(Ordering::Relaxed),
            self.status_hist[1].load(Ordering::Relaxed),
            self.status_hist[2].load(Ordering::Relaxed),
            self.status_hist[3].load(Ordering::Relaxed),
            self.status_hist[4].load(Ordering::Relaxed),
        ]
    }

    pub fn reset(&self) {
        self.rate.reset();
        self.active.store(0, Ordering::Relaxed);
        self.cum_requests.store(0, Ordering::Relaxed);
        self.cum_errors.store(0, Ordering::Relaxed);
        for b in &self.blocked {
            b.store(0, Ordering::Relaxed);
        }
        for s in &self.status_hist {
            s.store(0, Ordering::Relaxed);
        }
        self.recent_ips.clear();
    }
}

/// Backend target node in a topology snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendNode {
    /// Display URL with credentials and query string stripped.
    pub url: String,
    /// Optional route label for path-split or per-user split backends.
    pub route: String,
    pub healthy: bool,
    pub weight: u32,
    pub backup: bool,
    pub active: u32,
    pub cum_requests: u64,
    pub cum_errors: u64,
    /// Bytes sent to backend per second (`up` from gateway to backend).
    pub bytes_up_per_sec: f64,
    /// Bytes received from backend per second (`down` from backend to gateway).
    pub bytes_down_per_sec: f64,
    pub qps: f64,
    pub recent_ips: RecentIpsView,
}

/// Site node in a topology snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteNode {
    pub key: String,
    pub name: String,
    pub enabled: bool,
    pub running: bool,
    /// `exact` | `wildcard` | `any` | `default`.
    pub match_kind: String,
    /// `proxy` | `redirect` | `static` | `text` | `close`.
    pub site_type: String,
    /// Destination description for non-proxy sites (redirect URL, static root, text, close).
    pub target_label: Option<String>,
    pub active: u32,
    pub qps: f64,
    /// Bytes sent to visitors per second.
    pub bytes_up_per_sec: f64,
    /// Bytes received from visitors per second.
    pub bytes_down_per_sec: f64,
    pub cum_requests: u64,
    pub cum_errors: u64,
    pub blocked: [u64; DENY_KIND_COUNT],
    pub status_hist: [u64; 5],
    pub recent_ips: RecentIpsView,
    pub backends: Vec<BackendNode>,
}

/// Listener-level action node (`default_close`, `https_redirect`, `not_found`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListenerActionNode {
    pub action: String,
    pub qps: f64,
    pub cum_requests: u64,
    pub recent_ips: RecentIpsView,
}

/// Listener node in a topology snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListenerNode {
    pub key: String,
    pub name: String,
    pub listen_addr: String,
    pub enabled: bool,
    pub running: bool,
    /// Non-empty when listener failed to start (rendered red in UI).
    pub error: Option<String>,
    pub sites: Vec<SiteNode>,
    pub actions: Vec<ListenerActionNode>,
}

/// Complete topology snapshot returned by `GET /api/webservice/topology` and
/// recorded as frames by [`super::replay::ReplayStore`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopologySnapshot {
    pub timestamp: i64,
    pub window_secs: u64,
    pub total_qps: f64,
    pub total_bytes_up_per_sec: f64,
    pub total_bytes_down_per_sec: f64,
    pub total_active: u32,
    /// Aggregated recent/active visitor IPs across all nodes (capped at 500).
    pub recent_ips: RecentIpsView,
    pub listeners: Vec<ListenerNode>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn rate_ring_computes_windows_without_allocation() {
        let ring = RateRing::new();
        for s in 100..110i64 {
            ring.record(s, 10, 1000, 200);
        }
        let r10 = ring.rates(109, 10);
        assert_eq!(r10.window_secs, 10);
        assert!((r10.qps - 10.0).abs() < 1e-6);
        assert!((r10.bytes_up_per_sec - 1000.0).abs() < 1e-6);
        assert!((r10.bytes_down_per_sec - 200.0).abs() < 1e-6);

        let r1 = ring.rates(109, 1);
        assert!((r1.qps - 10.0).abs() < 1e-6);

        // Invalid window normalizes to default 10s.
        let r_def = ring.rates(109, 7);
        assert_eq!(r_def.window_secs, 10);
    }

    #[test]
    fn topology_caps_recent_ips_per_node() {
        let recent = RecentIps::new();
        let now = 1_000i64;
        for i in 0..1_500u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i));
            recent.record(ip, now);
        }
        assert_eq!(recent.len(), MAX_RECENT_IPS_PER_NODE);

        let view = recent.snapshot(now, &[], MAX_TOPO_API_IPS);
        assert_eq!(view.ips.len(), MAX_TOPO_API_IPS);
        assert!(view.truncated);
    }
}
