//! Bounded byte-budget LRU response cache storage (WP-27 §3.2–3.4), CORS
//! header strip/regeneration helpers, and `X-Cache` / `Age` header helpers.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use axum::{
    body::Bytes,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::web::proxy::cors::Cors;

use super::{
    key::CacheKey,
    rule::{CacheRule, MAX_CACHE_TTL, match_rule_path, normalize_path, validate_rules},
};

/// Default memory budget in MiB.
pub const DEFAULT_MAX_MB: usize = 64;
/// Minimum allowed memory budget in MiB.
pub const MIN_MAX_MB: usize = 1;
/// Maximum allowed memory budget in MiB.
pub const MAX_MAX_MB: usize = 4096;
/// Hard per-entry size ceiling (4 MiB).
pub const MAX_ENTRY_BYTES: usize = 4 * 1024 * 1024;

/// Age in whole seconds reported via the HTTP `Age` header.
pub type Age = u64;

/// Site-level response cache configuration (WP-27 §3.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct CacheConfig {
    pub enabled: bool,
    /// Fallback TTL (`0..=30 days`); `0` caches only responses with explicit
    /// upstream freshness directives.
    #[serde(with = "duration_secs")]
    pub ttl: Duration,
    /// Total memory budget in MiB (default 64, range `1..=4096`).
    pub max_mb: usize,
    pub rules: Vec<CacheRule>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl: Duration::ZERO,
            max_mb: DEFAULT_MAX_MB,
            rules: Vec::new(),
        }
    }
}

impl CacheConfig {
    /// Validates TTL, memory budget bounds, and all per-path rules.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.ttl > MAX_CACHE_TTL {
            errors.push(format!(
                "cache.ttl exceeds maximum {} seconds",
                MAX_CACHE_TTL.as_secs()
            ));
        }
        let max_mb = if self.max_mb == 0 {
            DEFAULT_MAX_MB
        } else {
            self.max_mb
        };
        if !(MIN_MAX_MB..=MAX_MAX_MB).contains(&max_mb) {
            errors.push(format!(
                "cache.maxMb must be between {MIN_MAX_MB} and {MAX_MAX_MB}"
            ));
        }
        if let Err(rule_errs) = validate_rules(&self.rules, self.ttl) {
            errors.extend(rule_errs);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Effective total byte budget (`max_mb` clamped/defaulted to `64 MiB`).
    pub fn max_bytes(&self) -> usize {
        let mb = if self.max_mb == 0 {
            DEFAULT_MAX_MB
        } else {
            self.max_mb.clamp(MIN_MAX_MB, MAX_MAX_MB)
        };
        mb.saturating_mul(1024 * 1024)
    }
}

mod duration_secs {
    use super::*;

    pub fn serialize<S: Serializer>(val: &Duration, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_u64(val.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(de)?;
        Ok(Duration::from_secs(secs))
    }
}

/// One cached HTTP response entry (WP-27 §3.2).
#[derive(Clone, Debug)]
pub struct Entry {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub stored_at: SystemTime,
    pub ttl: Duration,
    pub vary_origin: bool,
}

impl Entry {
    /// Byte footprint accounted against the cache memory budget.
    pub fn size_bytes(&self) -> usize {
        let headers_bytes: usize = self
            .headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.as_bytes().len())
            .sum();
        self.body.len().saturating_add(headers_bytes)
    }
}

/// Live cache status snapshot returned by `GET /api/webservice/cache`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheStats {
    pub enabled: bool,
    pub entries: usize,
    pub bytes: usize,
    pub max_bytes: usize,
}

struct LruNode {
    entry: Arc<Entry>,
    size: usize,
    seq: u64,
}

struct LruState {
    map: HashMap<CacheKey, LruNode>,
    order: BTreeMap<u64, CacheKey>,
    total_bytes: usize,
    next_seq: u64,
}

/// Thread-safe, byte-budgeted LRU response cache.
pub struct ResponseCache {
    enabled: bool,
    max_bytes: usize,
    state: Mutex<LruState>,
}

impl ResponseCache {
    /// Builds a [`ResponseCache`] from a site's [`CacheConfig`].
    pub fn new(cfg: &CacheConfig) -> Self {
        Self::with_max_bytes(cfg.enabled, cfg.max_bytes())
    }

    /// Builds a [`ResponseCache`] with an explicit byte budget (useful for
    /// deterministic small-budget eviction tests).
    pub fn with_max_bytes(enabled: bool, max_bytes: usize) -> Self {
        Self {
            enabled,
            max_bytes,
            state: Mutex::new(LruState {
                map: HashMap::new(),
                order: BTreeMap::new(),
                total_bytes: 0,
                next_seq: 1,
            }),
        }
    }

    /// Whether caching is enabled on this cache instance.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Maximum size of a single cacheable entry: `min(4 MiB, max_bytes / 4)`.
    pub fn max_entry_bytes(&self) -> usize {
        MAX_ENTRY_BYTES.min(self.max_bytes / 4)
    }

    /// Looks up `key` at time `now`.
    ///
    /// Returns `(entry, age_seconds)` if present and not expired, promoting
    /// the entry to most-recently-used. Expired entries are evicted lazily.
    pub fn lookup(&self, key: &CacheKey, now: SystemTime) -> Option<(Arc<Entry>, Age)> {
        if !self.enabled {
            return None;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (expired, age) = {
            let node = state.map.get(key)?;
            let elapsed = now
                .duration_since(node.entry.stored_at)
                .unwrap_or(Duration::ZERO);
            (elapsed >= node.entry.ttl, elapsed.as_secs())
        };

        if expired {
            if let Some(removed) = state.map.remove(key) {
                state.order.remove(&removed.seq);
                state.total_bytes = state.total_bytes.saturating_sub(removed.size);
            }
            return None;
        }

        let seq = state.next_seq;
        state.next_seq = state.next_seq.wrapping_add(1);
        let node = state.map.get_mut(key)?;
        let old_seq = node.seq;
        node.seq = seq;
        let entry = Arc::clone(&node.entry);
        state.order.remove(&old_seq);
        state.order.insert(seq, key.clone());
        Some((entry, age))
    }

    /// Inserts or replaces an entry in the cache, evicting least-recently-used
    /// entries until `total_bytes + entry_size <= max_bytes`.
    ///
    /// Returns `true` if stored, or `false` if disabled, expired/zero-TTL, or
    /// larger than [`Self::max_entry_bytes`].
    pub fn store(&self, key: CacheKey, mut entry: Entry, now: SystemTime) -> bool {
        if !self.enabled || entry.ttl.is_zero() {
            return false;
        }
        entry.stored_at = now;
        let size = entry.size_bytes();
        if size > self.max_entry_bytes() {
            return false;
        }

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if let Some(prev) = state.map.remove(&key) {
            state.order.remove(&prev.seq);
            state.total_bytes = state.total_bytes.saturating_sub(prev.size);
        }

        while state.total_bytes.saturating_add(size) > self.max_bytes {
            let Some((_, oldest_key)) = state.order.pop_first() else {
                break;
            };
            if let Some(removed) = state.map.remove(&oldest_key) {
                state.total_bytes = state.total_bytes.saturating_sub(removed.size);
            }
        }

        if state.total_bytes.saturating_add(size) > self.max_bytes {
            return false;
        }

        let seq = state.next_seq;
        state.next_seq = state.next_seq.wrapping_add(1);
        state.order.insert(seq, key.clone());
        state.map.insert(
            key,
            LruNode {
                entry: Arc::new(entry),
                size,
                seq,
            },
        );
        state.total_bytes = state.total_bytes.saturating_add(size);
        true
    }

    /// Removes all cached entries whose normalized path matches `rule_path`
    /// using the exact same segment-prefix / wildcard semantics as cache rules.
    pub fn purge_path(&self, rule_path: &str) -> usize {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let keys_to_remove: Vec<CacheKey> = state
            .map
            .keys()
            .filter(|k| match_rule_path(rule_path, &normalize_path(k.path())))
            .cloned()
            .collect();

        let count = keys_to_remove.len();
        for key in keys_to_remove {
            if let Some(removed) = state.map.remove(&key) {
                state.order.remove(&removed.seq);
                state.total_bytes = state.total_bytes.saturating_sub(removed.size);
            }
        }
        count
    }

    /// Removes every entry from the cache, returning the count removed.
    pub fn purge_all(&self) -> usize {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = state.map.len();
        state.map.clear();
        state.order.clear();
        state.total_bytes = 0;
        count
    }

    /// Returns a snapshot of current cache metrics.
    pub fn stats(&self) -> CacheStats {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        CacheStats {
            enabled: self.enabled,
            entries: state.map.len(),
            bytes: state.total_bytes,
            max_bytes: self.max_bytes,
        }
    }
}

/// Strips Gately-injected per-origin CORS headers before storing a response in
/// the cache so that hits can regenerate them for each visitor's `Origin`.
pub fn strip_cors_headers(headers: &mut HeaderMap) {
    headers.remove(header::ACCESS_CONTROL_ALLOW_ORIGIN);
    headers.remove(header::ACCESS_CONTROL_ALLOW_METHODS);
    headers.remove(header::ACCESS_CONTROL_ALLOW_HEADERS);
    headers.remove(header::ACCESS_CONTROL_ALLOW_CREDENTIALS);
    headers.remove(header::ACCESS_CONTROL_MAX_AGE);
    headers.remove(header::ACCESS_CONTROL_EXPOSE_HEADERS);
}

/// Regenerates site CORS headers on a cached response for the current
/// request's `Origin`, deduplicating `Vary: Origin`.
pub fn apply_cors_headers(headers: &mut HeaderMap, cors: &Cors, origin: Option<&str>) {
    let Some(origin) = origin else {
        return;
    };
    let generated = cors.response_headers(origin);
    for (name, val) in generated {
        if name == header::VARY {
            let has_origin = headers
                .get_all(header::VARY)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|s| s.split(','))
                .any(|t| t.trim().eq_ignore_ascii_case("origin"));
            if !has_origin {
                headers.append(header::VARY, val);
            }
        } else {
            headers.insert(name, val);
        }
    }
}

/// `X-Cache` header name.
pub static X_CACHE: HeaderName = HeaderName::from_static("x-cache");

/// Sets `X-Cache: HIT` and `Age: <age>` on a cache-hit response.
pub fn apply_cache_hit_headers(headers: &mut HeaderMap, age: Age) {
    headers.insert(X_CACHE.clone(), HeaderValue::from_static("HIT"));
    headers.insert(header::AGE, HeaderValue::from(age));
}

/// Sets `X-Cache: MISS` on a cache-miss response.
pub fn apply_cache_miss_header(headers: &mut HeaderMap) {
    headers.insert(X_CACHE.clone(), HeaderValue::from_static("MISS"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn key(path: &str) -> CacheKey {
        CacheKey::new("example.com", path, "gzip", None, Vec::new())
    }

    fn entry(body: Vec<u8>, ttl_secs: u64, now: SystemTime) -> Entry {
        Entry {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from(body),
            stored_at: now,
            ttl: Duration::from_secs(ttl_secs),
            vary_origin: false,
        }
    }

    #[test]
    fn cache_entry_capped_at_4mb_and_quarter() {
        // 4 MiB total -> 1 MiB per-entry cap (quarter of total).
        let small = ResponseCache::with_max_bytes(true, 4 * 1024 * 1024);
        assert_eq!(small.max_entry_bytes(), 1024 * 1024);
        let t0 = at(1000);
        assert!(!small.store(key("/big"), entry(vec![0u8; 1024 * 1024 + 1], 60, t0), t0));
        assert!(small.store(key("/fit"), entry(vec![0u8; 1024 * 1024], 60, t0), t0));

        // 64 MiB total -> 4 MiB per-entry cap (hard ceiling beats 16 MiB quarter).
        let large = ResponseCache::with_max_bytes(true, 64 * 1024 * 1024);
        assert_eq!(large.max_entry_bytes(), 4 * 1024 * 1024);
        assert!(!large.store(
            key("/over4mb"),
            entry(vec![0u8; 4 * 1024 * 1024 + 1], 60, t0),
            t0
        ));
        assert!(large.store(
            key("/exact4mb"),
            entry(vec![0u8; 4 * 1024 * 1024], 60, t0),
            t0
        ));
    }

    #[test]
    fn cache_lru_evicts_by_total_bytes() {
        // Total budget 400 bytes -> max entry 100 bytes.
        let cache = ResponseCache::with_max_bytes(true, 400);
        let t0 = at(1000);
        assert!(cache.store(key("/a"), entry(vec![b'a'; 100], 60, t0), t0));
        assert!(cache.store(key("/b"), entry(vec![b'b'; 100], 60, t0), t0));
        assert!(cache.store(key("/c"), entry(vec![b'c'; 100], 60, t0), t0));
        assert!(cache.store(key("/d"), entry(vec![b'd'; 100], 60, t0), t0));
        assert_eq!(cache.stats().bytes, 400);

        // Touch `/a` so `/b` becomes least-recently-used.
        assert!(cache.lookup(&key("/a"), at(1005)).is_some());

        // Inserting `/e` (100 bytes) must evict `/b`.
        assert!(cache.store(key("/e"), entry(vec![b'e'; 100], 60, t0), at(1006)));
        assert!(cache.lookup(&key("/b"), at(1007)).is_none());
        assert!(cache.lookup(&key("/a"), at(1007)).is_some());
        assert!(cache.lookup(&key("/e"), at(1007)).is_some());
        assert_eq!(cache.stats().bytes, 400);
        assert_eq!(cache.stats().entries, 4);

        // Expiry removes entry on lookup.
        assert!(cache.lookup(&key("/a"), at(1060)).is_none());
        assert_eq!(cache.stats().entries, 3);
    }
}
