//! Cross-site visitor audit: per-IP aggregation, bounded top sets, scanner
//! classification, retention & capacity eviction, query/detail APIs, and
//! gzipped JSON Lines persistence (WP-28 §3.2–§3.4).
//!
//! Privacy invariants:
//! - Stores aggregated per-IP counters only — never individual request logs.
//! - Paths strip query strings and fragments before recording.
//! - Cookies, request bodies, and credentials are never stored.
//! - Failed authentication attempts and denied requests never record identity.

use std::{
    collections::{BTreeMap, HashMap},
    fs::OpenOptions,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::IpAddr,
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, bail};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use serde::{Deserialize, Serialize};

use super::recorder::status_hist_index;

/// Default visitor retention period (days).
pub const DEFAULT_RETAIN_DAYS: u32 = 30;
/// Minimum configurable retention period (days).
pub const MIN_RETAIN_DAYS: u32 = 1;
/// Maximum configurable retention period (days).
pub const MAX_RETAIN_DAYS: u32 = 180;
/// Default maximum tracked visitors.
pub const DEFAULT_MAX_VISITORS: usize = 10_000;
/// Minimum configurable visitor cap.
pub const MIN_MAX_VISITORS: usize = 100;
/// Maximum configurable visitor cap.
pub const MAX_MAX_VISITORS: usize = 100_000;
/// Per-visitor TopSet ceilings (WP-28 §3.4).
pub const MAX_VISITOR_SITES: usize = 12;
pub const MAX_VISITOR_PATHS: usize = 10;
pub const MAX_VISITOR_IDENTITIES: usize = 6;
pub const MAX_VISITOR_AGENTS: usize = 4;
pub const MAX_VISITOR_DENY_REASONS: usize = 8;
/// Debounced flush interval (10 minutes, WP-28 §3.4).
pub const SAVE_DELAY: Duration = Duration::from_secs(600);
/// Relative persistence path under the config directory.
pub const PERSIST_REL_PATH: &str = "visitors/visitors.jsonl.gz";
/// Maximum decompressed bytes accepted when loading `visitors.jsonl.gz` (64 MiB).
pub const MAX_LOAD_BYTES: u64 = 64 * 1024 * 1024;
/// Identity label recorded when the request carries a valid admin session.
pub const ADMIN_IDENTITY: &str = "admin";
/// Maximum field lengths after clipping.
const MAX_PATH_CHARS: usize = 256;
const MAX_SITE_CHARS: usize = 128;
const MAX_IDENTITY_CHARS: usize = 128;
const MAX_UA_CHARS: usize = 200;
const MAX_DENY_CHARS: usize = 32;
/// Future timestamp tolerance before clamping to `now`.
const FUTURE_CLOCK_TOLERANCE: Duration = Duration::from_secs(300);

/// Visitor audit configuration (`webservice.json -> settings.visitors`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct VisitorsConfig {
    pub enabled: bool,
    pub retain_days: u32,
    pub max_visitors: usize,
}

impl Default for VisitorsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retain_days: DEFAULT_RETAIN_DAYS,
            max_visitors: DEFAULT_MAX_VISITORS,
        }
    }
}

impl VisitorsConfig {
    /// Clamps invalid values back into documented bounds (`0` falls back to
    /// defaults).
    pub fn normalize(mut self) -> Self {
        if self.retain_days == 0 {
            self.retain_days = DEFAULT_RETAIN_DAYS;
        } else {
            self.retain_days = self.retain_days.clamp(MIN_RETAIN_DAYS, MAX_RETAIN_DAYS);
        }
        if self.max_visitors == 0 {
            self.max_visitors = DEFAULT_MAX_VISITORS;
        } else {
            self.max_visitors = self.max_visitors.clamp(MIN_MAX_VISITORS, MAX_MAX_VISITORS);
        }
        self
    }
}

/// One entry in a bounded per-visitor [`TopSet`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopEntry {
    pub key: String,
    pub count: u64,
}

/// Small bounded frequency list (capacity 4..=12). When full and a new key
/// arrives, replaces the entry with the smallest count (WP-28 §3.3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopSet {
    pub cap: usize,
    pub entries: Vec<TopEntry>,
}

impl TopSet {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            entries: Vec::new(),
        }
    }

    /// Increments `key`, inserts if below capacity, or replaces the
    /// least-frequent entry when full.
    pub fn add(&mut self, key: &str) {
        if key.is_empty() || self.cap == 0 {
            return;
        }
        if let Some(entry) = self.entries.iter_mut().find(|e| e.key == key) {
            entry.count = entry.count.saturating_add(1);
            return;
        }
        if self.entries.len() < self.cap {
            self.entries.push(TopEntry {
                key: key.to_owned(),
                count: 1,
            });
            return;
        }
        // Replace the least-used entry (tie-break: last matching minimum).
        if let Some((min_idx, _)) = self
            .entries
            .iter()
            .enumerate()
            .min_by(|(ia, a), (ib, b)| a.count.cmp(&b.count).then_with(|| ib.cmp(ia)))
        {
            self.entries[min_idx] = TopEntry {
                key: key.to_owned(),
                count: 1,
            };
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn contains(&self, key: &str) -> bool {
        self.entries.iter().any(|e| e.key == key)
    }

    /// Returns entries sorted by descending count, then ascending key.
    pub fn sorted(&self) -> Vec<TopEntry> {
        let mut out = self.entries.clone();
        out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
        out
    }

    fn enforce_cap(&mut self, cap: usize) {
        self.cap = cap;
        if self.entries.len() > cap {
            self.entries
                .sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
            self.entries.truncate(cap);
        }
    }
}

/// Per-day request histogram keyed by days since Unix epoch (UTC).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DayHistogram {
    pub days: BTreeMap<i32, u64>,
}

impl DayHistogram {
    pub fn record(&mut self, day: i32) {
        let entry = self.days.entry(day).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    pub fn prune_older_than(&mut self, min_day: i32) {
        self.days.retain(|&d, _| d >= min_day);
    }

    /// Renders `(YYYY-MM-DD, count)` pairs for the detail API.
    pub fn to_bars(&self) -> Vec<DayBar> {
        self.days
            .iter()
            .map(|(&day, &count)| DayBar {
                date: format_utc_day(day),
                count,
            })
            .collect()
    }
}

/// One bar in the visitor's daily request chart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DayBar {
    pub date: String,
    pub count: u64,
}

/// Aggregated per-IP visitor record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Visitor {
    pub ip: IpAddr,
    pub first_unix: i64,
    pub last_unix: i64,
    pub requests: u64,
    pub blocked: u64,
    /// Requests that were either blocked OR hit an unmatched/default site.
    pub noise_requests: u64,
    pub bytes_out: u64,
    pub closed_444: u64,
    pub ever_authed: bool,
    pub per_day: DayHistogram,
    /// `0=2xx, 1=3xx, 2=4xx, 3=5xx, 4=other/444`.
    pub status_hist: [u64; 5],
    pub deny_hist: TopSet,
    pub sites: TopSet,
    pub paths: TopSet,
    pub identities: TopSet,
    pub agents: TopSet,
}

impl Visitor {
    fn new(ip: IpAddr, now_unix: i64) -> Self {
        Self {
            ip,
            first_unix: now_unix,
            last_unix: now_unix,
            requests: 0,
            blocked: 0,
            noise_requests: 0,
            bytes_out: 0,
            closed_444: 0,
            ever_authed: false,
            per_day: DayHistogram::default(),
            status_hist: [0; 5],
            deny_hist: TopSet::new(MAX_VISITOR_DENY_REASONS),
            sites: TopSet::new(MAX_VISITOR_SITES),
            paths: TopSet::new(MAX_VISITOR_PATHS),
            identities: TopSet::new(MAX_VISITOR_IDENTITIES),
            agents: TopSet::new(MAX_VISITOR_AGENTS),
        }
    }

    /// First seen timestamp as [`SystemTime`].
    pub fn first(&self) -> SystemTime {
        unix_to_system_time(self.first_unix)
    }

    /// Last seen timestamp as [`SystemTime`].
    pub fn last(&self) -> SystemTime {
        unix_to_system_time(self.last_unix)
    }

    /// Scanner / noise classification (WP-28 §3.3):
    /// only blocked and/or unmatched requests, and never authenticated.
    pub fn is_scanner(&self) -> bool {
        !self.ever_authed
            && self.identities.is_empty()
            && self.requests > 0
            && self.noise_requests >= self.requests
    }

    fn sanitize(&mut self, now_unix: i64, min_day: i32) {
        let max_allowed = now_unix + FUTURE_CLOCK_TOLERANCE.as_secs() as i64;
        if self.first_unix > max_allowed {
            self.first_unix = now_unix;
        }
        if self.last_unix > max_allowed {
            self.last_unix = now_unix;
        }
        if self.first_unix > self.last_unix {
            self.first_unix = self.last_unix;
        }
        self.per_day.prune_older_than(min_day);
        self.deny_hist.enforce_cap(MAX_VISITOR_DENY_REASONS);
        self.sites.enforce_cap(MAX_VISITOR_SITES);
        self.paths.enforce_cap(MAX_VISITOR_PATHS);
        self.identities.enforce_cap(MAX_VISITOR_IDENTITIES);
        self.agents.enforce_cap(MAX_VISITOR_AGENTS);
    }
}

/// One request's sanitized input to [`VisitorStore::record`].
#[derive(Clone, Debug)]
pub struct VisitorEvent {
    pub ip: IpAddr,
    /// Site display name (`None` when unmatched or default catch-all).
    pub site: Option<String>,
    /// True when the request hit no configured site or the default catch-all.
    pub unmatched_or_default: bool,
    /// Raw request path/URI (query & fragment will be stripped).
    pub raw_path: String,
    pub status: u16,
    /// Deny reason tag (e.g. `ban`, `ip`, `country`, `rateLimit`, `waf`, `auth`, `knock`, `denyList`).
    pub deny_reason: Option<String>,
    pub bytes_out: u64,
    /// Verified identity (`Some("admin")` for admin session, or verified site user).
    /// Ignored when blocked or when `status == 401`.
    pub identity: Option<String>,
    pub is_authed: bool,
    pub user_agent: Option<String>,
    pub now: SystemTime,
}

/// Query parameters for `GET /api/webservice/visitors`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VisitorQuery {
    pub search: Option<String>,
    pub site: Option<String>,
    /// `"all"` | `"scanner"` | `"authed"` | `"blocked"` | `"normal"`.
    pub filter: Option<String>,
    /// `"last"` | `"requests"` | `"blocked"` | `"bytes"`.
    pub sort: Option<String>,
    pub offset: usize,
    pub limit: usize,
}

/// Summary row in `GET /api/webservice/visitors`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VisitorSummary {
    pub ip: String,
    pub first_unix: i64,
    pub last_unix: i64,
    pub requests: u64,
    pub blocked: u64,
    pub bytes_out: u64,
    pub closed_444: u64,
    pub is_scanner: bool,
    pub ever_authed: bool,
    pub top_sites: Vec<String>,
    pub identities: Vec<String>,
}

/// Paginated response for `GET /api/webservice/visitors`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VisitorListResponse {
    pub total: usize,
    pub scanners: usize,
    pub authed: usize,
    pub items: Vec<VisitorSummary>,
}

/// Detailed view returned by `GET /api/webservice/visitors/detail`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VisitorDetail {
    pub ip: String,
    pub ban_target: Option<String>,
    pub first_unix: i64,
    pub last_unix: i64,
    pub requests: u64,
    pub blocked: u64,
    pub bytes_out: u64,
    pub closed_444: u64,
    pub is_scanner: bool,
    pub ever_authed: bool,
    pub per_day: Vec<DayBar>,
    pub status_hist: [u64; 5],
    pub deny_hist: Vec<TopEntry>,
    pub sites: Vec<TopEntry>,
    pub paths: Vec<TopEntry>,
    pub identities: Vec<TopEntry>,
    pub agents: Vec<TopEntry>,
}

struct VisitorStoreInner {
    config: VisitorsConfig,
    visitors: HashMap<IpAddr, Visitor>,
}

/// Thread-safe, bounded per-IP visitor audit store.
pub struct VisitorStore {
    inner: Mutex<VisitorStoreInner>,
    dirty: AtomicBool,
}

impl Default for VisitorStore {
    fn default() -> Self {
        Self::new(VisitorsConfig::default())
    }
}

impl VisitorStore {
    pub fn new(config: VisitorsConfig) -> Self {
        Self {
            inner: Mutex::new(VisitorStoreInner {
                config: config.normalize(),
                visitors: HashMap::new(),
            }),
            dirty: AtomicBool::new(false),
        }
    }

    pub fn settings(&self) -> VisitorsConfig {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .config
    }

    /// Updates settings and immediately prunes expired / over-cap entries
    /// (WP-28 §3.3: decreasing `retainDays` removes out-of-range data immediately).
    pub fn update_settings(&self, config: VisitorsConfig, now: SystemTime) -> VisitorsConfig {
        let normalized = config.normalize();
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.config = normalized;
        let removed = prune_and_evict(&mut inner, now);
        if removed > 0 {
            self.dirty.store(true, Ordering::Release);
        }
        normalized
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .visitors
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Acquire)
    }

    /// Records a single request event. No-op when `config.enabled` is false.
    pub fn record(&self, event: VisitorEvent) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !inner.config.enabled {
            return;
        }
        let now_unix = system_time_to_unix(event.now);
        let today = unix_day(now_unix);
        let min_day = today - inner.config.retain_days as i32 + 1;

        let visitor = inner
            .visitors
            .entry(event.ip)
            .or_insert_with(|| Visitor::new(event.ip, now_unix));

        // Clamp future timestamps if the stored record was ahead of clock.
        if visitor.last_unix > now_unix + FUTURE_CLOCK_TOLERANCE.as_secs() as i64 {
            visitor.last_unix = now_unix;
        }
        if visitor.first_unix > now_unix {
            visitor.first_unix = now_unix;
        }
        if now_unix > visitor.last_unix {
            visitor.last_unix = now_unix;
        }

        visitor.requests = visitor.requests.saturating_add(1);
        visitor.bytes_out = visitor.bytes_out.saturating_add(event.bytes_out);
        if event.status == 444 {
            visitor.closed_444 = visitor.closed_444.saturating_add(1);
        }
        visitor.status_hist[status_hist_index(event.status)] =
            visitor.status_hist[status_hist_index(event.status)].saturating_add(1);
        visitor.per_day.record(today);
        visitor.per_day.prune_older_than(min_day);

        let is_blocked = event.deny_reason.as_deref().is_some_and(|r| !r.is_empty());
        if is_blocked {
            visitor.blocked = visitor.blocked.saturating_add(1);
            if let Some(reason) = event.deny_reason.as_deref() {
                let cleaned = clip_string(reason, MAX_DENY_CHARS);
                visitor.deny_hist.add(&cleaned);
            }
        }
        if is_blocked || event.unmatched_or_default {
            visitor.noise_requests = visitor.noise_requests.saturating_add(1);
        }

        if let Some(site) = event.site.as_deref() {
            let cleaned = clip_string(site, MAX_SITE_CHARS);
            if !cleaned.is_empty() {
                visitor.sites.add(&cleaned);
            }
        }

        // Strip query string and fragment before clipping and recording path.
        let clean_path = strip_path_query(&event.raw_path);
        let clipped_path = clip_string(clean_path, MAX_PATH_CHARS);
        if !clipped_path.is_empty() {
            visitor.paths.add(&clipped_path);
        }

        // Identity is NEVER recorded for blocked requests or failed auth (401).
        if !is_blocked && event.status != 401 {
            if let Some(id) = event.identity.as_deref() {
                let cleaned = clip_string(id, MAX_IDENTITY_CHARS);
                if !cleaned.is_empty() {
                    visitor.identities.add(&cleaned);
                    visitor.ever_authed = true;
                }
            } else if event.is_authed {
                visitor.ever_authed = true;
            }
        }

        if let Some(ua) = event.user_agent.as_deref() {
            let cleaned = clip_string(ua, MAX_UA_CHARS);
            if !cleaned.is_empty() {
                visitor.agents.add(&cleaned);
            }
        }

        if inner.visitors.len() > inner.config.max_visitors {
            prune_and_evict(&mut inner, event.now);
        }
        self.dirty.store(true, Ordering::Release);
    }

    /// Queries the visitor list with optional search, site, class filter, sort,
    /// and pagination.
    pub fn query(&self, query: &VisitorQuery, now: SystemTime) -> VisitorListResponse {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = prune_expired(&mut inner, now);
        if removed > 0 {
            self.dirty.store(true, Ordering::Release);
        }

        let search = query
            .search
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let site_filter = query
            .site
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());

        let mut scanners = 0usize;
        let mut authed = 0usize;
        let mut matched: Vec<&Visitor> = Vec::new();

        for v in inner.visitors.values() {
            let is_scanner = v.is_scanner();
            if is_scanner {
                scanners += 1;
            }
            if v.ever_authed {
                authed += 1;
            }

            if let Some(site) = site_filter
                && !v.sites.contains(site)
            {
                continue;
            }
            if let Some(filter) = query.filter.as_deref() {
                match filter {
                    "scanner" if !is_scanner => continue,
                    "authed" if !v.ever_authed => continue,
                    "blocked" if v.blocked == 0 => continue,
                    "normal" if is_scanner => continue,
                    _ => {}
                }
            }
            if let Some(ref q) = search {
                let ip_match = v.ip.to_string().to_ascii_lowercase().contains(q);
                let site_match = v
                    .sites
                    .entries
                    .iter()
                    .any(|e| e.key.to_ascii_lowercase().contains(q));
                let id_match = v
                    .identities
                    .entries
                    .iter()
                    .any(|e| e.key.to_ascii_lowercase().contains(q));
                let path_match = v
                    .paths
                    .entries
                    .iter()
                    .any(|e| e.key.to_ascii_lowercase().contains(q));
                if !(ip_match || site_match || id_match || path_match) {
                    continue;
                }
            }
            matched.push(v);
        }

        let sort = query.sort.as_deref().unwrap_or("last");
        matched.sort_by(|a, b| match sort {
            "requests" => b
                .requests
                .cmp(&a.requests)
                .then_with(|| b.last_unix.cmp(&a.last_unix)),
            "blocked" => b
                .blocked
                .cmp(&a.blocked)
                .then_with(|| b.last_unix.cmp(&a.last_unix)),
            "bytes" => b
                .bytes_out
                .cmp(&a.bytes_out)
                .then_with(|| b.last_unix.cmp(&a.last_unix)),
            _ => b
                .last_unix
                .cmp(&a.last_unix)
                .then_with(|| b.requests.cmp(&a.requests)),
        });

        let total = matched.len();
        let limit = if query.limit == 0 {
            100
        } else {
            query.limit.min(500)
        };
        let items = matched
            .into_iter()
            .skip(query.offset)
            .take(limit)
            .map(|v| VisitorSummary {
                ip: v.ip.to_string(),
                first_unix: v.first_unix,
                last_unix: v.last_unix,
                requests: v.requests,
                blocked: v.blocked,
                bytes_out: v.bytes_out,
                closed_444: v.closed_444,
                is_scanner: v.is_scanner(),
                ever_authed: v.ever_authed,
                top_sites: v
                    .sites
                    .sorted()
                    .into_iter()
                    .take(3)
                    .map(|e| e.key)
                    .collect(),
                identities: v.identities.sorted().into_iter().map(|e| e.key).collect(),
            })
            .collect();

        VisitorListResponse {
            total,
            scanners,
            authed,
            items,
        }
    }

    /// Returns detailed audit metrics for a single visitor IP.
    pub fn detail(&self, ip: IpAddr, now: SystemTime) -> Option<VisitorDetail> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = prune_expired(&mut inner, now);
        if removed > 0 {
            self.dirty.store(true, Ordering::Release);
        }
        let v = inner.visitors.get(&ip)?;
        let ban_target = super::connections::BanTarget::from_ip(v.ip).map(|t| t.to_string());
        Some(VisitorDetail {
            ip: v.ip.to_string(),
            ban_target,
            first_unix: v.first_unix,
            last_unix: v.last_unix,
            requests: v.requests,
            blocked: v.blocked,
            bytes_out: v.bytes_out,
            closed_444: v.closed_444,
            is_scanner: v.is_scanner(),
            ever_authed: v.ever_authed,
            per_day: v.per_day.to_bars(),
            status_hist: v.status_hist,
            deny_hist: v.deny_hist.sorted(),
            sites: v.sites.sorted(),
            paths: v.paths.sorted(),
            identities: v.identities.sorted(),
            agents: v.agents.sorted(),
        })
    }

    /// Deletes specific visitor IPs. Returns count removed.
    pub fn delete(&self, ips: &[IpAddr]) -> usize {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut removed = 0usize;
        for ip in ips {
            if inner.visitors.remove(ip).is_some() {
                removed += 1;
            }
        }
        if removed > 0 {
            self.dirty.store(true, Ordering::Release);
        }
        removed
    }

    /// Clears all visitor records. Returns count removed.
    pub fn clear(&self) -> usize {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = inner.visitors.len();
        inner.visitors.clear();
        if count > 0 {
            self.dirty.store(true, Ordering::Release);
        }
        count
    }

    /// Persists all visitor records as gzipped JSON Lines (`0600` on Unix)
    /// using an atomic newly-created temp file + `sync_all` + `rename`.
    ///
    /// On failure, keeps `dirty = true` so the next flush retries.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let snapshot: Vec<Visitor> = {
            let inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            inner.visitors.values().cloned().collect()
        };

        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .context("visitor persistence path has no parent directory")?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create visitor dir {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }

        // Create a fresh unique temp file with O_CREAT|O_EXCL so a pre-planted
        // symlink at a predictable temp path can never be followed.
        let mut rand_bytes = [0u8; 8];
        getrandom::fill(&mut rand_bytes).map_err(|e| anyhow::anyhow!("random suffix: {e}"))?;
        let suffix: String = rand_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("visitors.jsonl.gz");
        let tmp_path = parent.join(format!(".{file_name}.{suffix}.tmp"));

        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let file = opts
            .open(&tmp_path)
            .with_context(|| format!("create temp visitor file {}", tmp_path.display()))?;

        let write_result = (|| -> anyhow::Result<()> {
            let mut gz = GzEncoder::new(file, Compression::default());
            for visitor in &snapshot {
                serde_json::to_writer(&mut gz, visitor)?;
                gz.write_all(b"\n")?;
            }
            let file = gz.finish()?;
            file.sync_all()?;
            Ok(())
        })();

        if let Err(err) = write_result {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 0600 {}", tmp_path.display()))?;
        }

        if let Err(err) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err).with_context(|| format!("rename to {}", path.display()));
        }

        self.dirty.store(false, Ordering::Release);
        Ok(())
    }

    /// Restores visitor records from a gzipped JSON Lines file.
    ///
    /// Rejects symlinks and non-regular files, caps decompressed size at
    /// [`MAX_LOAD_BYTES`], clamps future timestamps, enforces retention &
    /// capacity limits, and tolerates a truncated trailing line.
    pub fn load(&self, path: &Path, now: SystemTime) -> anyhow::Result<usize> {
        let meta = std::fs::symlink_metadata(path)
            .with_context(|| format!("stat visitor file {}", path.display()))?;
        if !meta.file_type().is_file() {
            bail!("visitor persistence path must be a regular file (symlinks rejected)");
        }
        let file = std::fs::File::open(path)
            .with_context(|| format!("open visitor file {}", path.display()))?;
        let gz = GzDecoder::new(file);
        let limited = gz.take(MAX_LOAD_BYTES + 1);
        let mut reader = BufReader::new(limited);

        let now_unix = system_time_to_unix(now);
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let cutoff = now_unix - (i64::from(inner.config.retain_days) * 86_400);
        let min_day = unix_day(now_unix) - inner.config.retain_days as i32 + 1;

        let mut total_read = 0u64;
        let mut loaded = 0usize;
        let mut line = String::new();
        loop {
            line.clear();
            let n = match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => {
                    // Tolerate a truncated gzip stream tail after reading valid lines.
                    break;
                }
            };
            total_read += n as u64;
            if total_read > MAX_LOAD_BYTES {
                bail!("visitor persistence file exceeds maximum decompressed size");
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(mut visitor) = serde_json::from_str::<Visitor>(trimmed) else {
                // Skip corrupted/truncated trailing line.
                continue;
            };
            visitor.sanitize(now_unix, min_day);
            if visitor.last_unix < cutoff {
                continue;
            }
            inner.visitors.insert(visitor.ip, visitor);
            loaded += 1;
            if inner.visitors.len() > inner.config.max_visitors + 256 {
                prune_and_evict(&mut inner, now);
            }
        }
        prune_and_evict(&mut inner, now);
        self.dirty.store(false, Ordering::Release);
        Ok(loaded.min(inner.visitors.len()))
    }
}

/// Strips `?query` and `#fragment` from a raw request path.
pub fn strip_path_query(raw: &str) -> &str {
    raw.split(['?', '#']).next().unwrap_or(raw)
}

/// Strips ASCII control characters, zero-width / invisible formatting runes,
/// and BiDi control runes, then clips to `max_chars` characters.
pub fn clip_string(input: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(input.len().min(max_chars));
    let mut count = 0usize;
    for ch in input.trim().chars() {
        if is_invisible_or_control(ch) {
            continue;
        }
        if count >= max_chars {
            break;
        }
        out.push(ch);
        count += 1;
    }
    out
}

fn is_invisible_or_control(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{00AD}'
        )
}

fn prune_expired(inner: &mut VisitorStoreInner, now: SystemTime) -> usize {
    let now_unix = system_time_to_unix(now);
    let cutoff = now_unix - (i64::from(inner.config.retain_days) * 86_400);
    let min_day = unix_day(now_unix) - inner.config.retain_days as i32 + 1;
    let before = inner.visitors.len();
    inner.visitors.retain(|_, v| {
        if v.last_unix < cutoff {
            return false;
        }
        v.per_day.prune_older_than(min_day);
        true
    });
    before - inner.visitors.len()
}

/// Eviction order (WP-28 §3.3):
/// 1. Expired visitors (`last < now - retain_days`).
/// 2. Scanners (`is_scanner() == true`), oldest `last_unix` first.
/// 3. Anonymous non-scanners (`!ever_authed`), oldest `last_unix` first.
/// 4. Authenticated visitors, oldest `last_unix` first.
fn prune_and_evict(inner: &mut VisitorStoreInner, now: SystemTime) -> usize {
    let mut removed = prune_expired(inner, now);
    if inner.visitors.len() <= inner.config.max_visitors {
        return removed;
    }
    let excess = inner.visitors.len() - inner.config.max_visitors;
    let mut candidates: Vec<(u8, i64, IpAddr)> = inner
        .visitors
        .iter()
        .map(|(&ip, v)| {
            let tier = if v.is_scanner() {
                0
            } else if !v.ever_authed && v.identities.is_empty() {
                1
            } else {
                2
            };
            (tier, v.last_unix, ip)
        })
        .collect();
    candidates.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.cmp(&b.2))
    });
    for (_, _, ip) in candidates.into_iter().take(excess) {
        if inner.visitors.remove(&ip).is_some() {
            removed += 1;
        }
    }
    removed
}

fn system_time_to_unix(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

fn unix_to_system_time(unix: i64) -> SystemTime {
    if unix >= 0 {
        UNIX_EPOCH + Duration::from_secs(unix as u64)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(unix.unsigned_abs()))
            .unwrap_or(UNIX_EPOCH)
    }
}

fn unix_day(unix_secs: i64) -> i32 {
    unix_secs.div_euclid(86_400) as i32
}

/// Converts days since 1970-01-01 to `YYYY-MM-DD` (Howard Hinnant's algorithm).
fn format_utc_day(days: i32) -> String {
    let z = i64::from(days) + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn visitors_top_sets_replace_least_used() {
        let mut set = TopSet::new(4);
        for _ in 0..5 {
            set.add("a");
        }
        for _ in 0..3 {
            set.add("b");
        }
        set.add("c"); // least used (1)
        for _ in 0..2 {
            set.add("d");
        }
        // Adding "e" must replace "c" (count 1).
        set.add("e");
        assert_eq!(set.len(), 4);
        assert!(set.contains("a"));
        assert!(set.contains("b"));
        assert!(set.contains("d"));
        assert!(set.contains("e"));
        assert!(!set.contains("c"));
    }

    #[test]
    fn visitors_scan_class_definition() {
        let store = VisitorStore::new(VisitorsConfig::default());
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let scanner_ip: IpAddr = "198.51.100.1".parse().unwrap();
        let normal_ip: IpAddr = "198.51.100.2".parse().unwrap();
        let authed_ip: IpAddr = "198.51.100.3".parse().unwrap();

        // Only blocked / unmatched -> scanner.
        store.record(VisitorEvent {
            ip: scanner_ip,
            site: None,
            unmatched_or_default: true,
            raw_path: "/.env".into(),
            status: 444,
            deny_reason: Some("waf".into()),
            bytes_out: 0,
            identity: None,
            is_authed: false,
            user_agent: None,
            now,
        });
        assert!(store.detail(scanner_ip, now).unwrap().is_scanner);

        // One legitimate matched request -> not scanner.
        store.record(VisitorEvent {
            ip: normal_ip,
            site: Some("app".into()),
            unmatched_or_default: false,
            raw_path: "/index.html".into(),
            status: 200,
            deny_reason: None,
            bytes_out: 100,
            identity: None,
            is_authed: false,
            user_agent: None,
            now,
        });
        assert!(!store.detail(normal_ip, now).unwrap().is_scanner);

        // Authenticated visitor hitting unmatched later -> still NOT scanner.
        store.record(VisitorEvent {
            ip: authed_ip,
            site: Some("app".into()),
            unmatched_or_default: true,
            raw_path: "/admin".into(),
            status: 200,
            deny_reason: None,
            bytes_out: 50,
            identity: Some(ADMIN_IDENTITY.into()),
            is_authed: true,
            user_agent: None,
            now,
        });
        assert!(!store.detail(authed_ip, now).unwrap().is_scanner);
    }

    #[test]
    fn visitors_retention_and_cap_eviction_order() {
        let store = VisitorStore::new(VisitorsConfig {
            enabled: true,
            retain_days: 30,
            max_visitors: 100,
        });
        let base = UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        // Insert 1 authed visitor (oldest), 50 normal anonymous, 50 scanners (newest).
        let authed_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        store.record(VisitorEvent {
            ip: authed_ip,
            site: Some("app".into()),
            unmatched_or_default: false,
            raw_path: "/".into(),
            status: 200,
            deny_reason: None,
            bytes_out: 10,
            identity: Some("alice".into()),
            is_authed: true,
            user_agent: None,
            now: base,
        });

        for i in 1..=50u32 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 0, i as u8));
            store.record(VisitorEvent {
                ip,
                site: Some("app".into()),
                unmatched_or_default: false,
                raw_path: "/".into(),
                status: 200,
                deny_reason: None,
                bytes_out: 10,
                identity: None,
                is_authed: false,
                user_agent: None,
                now: base + Duration::from_secs(u64::from(i)),
            });
        }

        // Insert 60 scanners (newer than authed and normal). Total = 111 -> must evict 11 scanners first!
        for i in 1..=60u32 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 2, 0, i as u8));
            store.record(VisitorEvent {
                ip,
                site: None,
                unmatched_or_default: true,
                raw_path: "/wp-login.php".into(),
                status: 403,
                deny_reason: Some("waf".into()),
                bytes_out: 0,
                identity: None,
                is_authed: false,
                user_agent: None,
                now: base + Duration::from_secs(100 + u64::from(i)),
            });
        }

        assert_eq!(store.len(), 100);
        // Authed visitor survived even though it was the oldest.
        assert!(
            store
                .detail(authed_ip, base + Duration::from_secs(200))
                .is_some()
        );
        // Oldest scanner (10.2.0.1) was evicted first.
        assert!(
            store
                .detail(
                    IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1)),
                    base + Duration::from_secs(200)
                )
                .is_none()
        );
        // Newest scanner (10.2.0.60) survived.
        assert!(
            store
                .detail(
                    IpAddr::V4(Ipv4Addr::new(10, 2, 0, 60)),
                    base + Duration::from_secs(200)
                )
                .is_some()
        );

        // Decreasing retain_days immediately prunes entries older than the new window.
        let future = base + Duration::from_secs(10 * 86_400);
        store.update_settings(
            VisitorsConfig {
                enabled: true,
                retain_days: 5,
                max_visitors: 100,
            },
            future,
        );
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn clip_strips_invisible_runes_and_formats_utc_day() {
        assert_eq!(
            clip_string("he\u{200B}llo\r\n\u{FEFF}world", 20),
            "helloworld"
        );
        assert_eq!(format_utc_day(0), "1970-01-01");
        assert_eq!(format_utc_day(19_723), "2024-01-01");
    }
}
