//! In-memory replay cache (WP-54 §3.3 step 6): a used `(credential,
//! random, timestamp)` triple is rejected until it ages out of the
//! `maxAge` window. The cache lives only in memory — packets whose
//! timestamp predates this process start are rejected outright, so a
//! restart invalidates all earlier traffic and the cache cannot be
//! circumvented by restarting the server.

use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use std::time::SystemTime;

use crate::model::limits;

/// The replay key: credential fingerprint, client random value, and the
/// packet timestamp.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReplayKey {
    pub cred: String,
    pub rand: String,
    pub timestamp: i64,
}

impl ReplayKey {
    pub fn new(cred: impl Into<String>, rand: impl Into<String>, timestamp: i64) -> Self {
        Self {
            cred: cred.into(),
            rand: rand.into(),
            timestamp,
        }
    }
}

/// The cache. `started` is this process's start time; the injected clock
/// makes window decisions testable.
pub struct ReplayCache {
    seen: Mutex<Seen>,
    started: SystemTime,
}

#[derive(Default)]
struct Seen {
    set: HashSet<ReplayKey>,
    order: VecDeque<ReplayKey>,
}

impl ReplayCache {
    /// Creates a cache anchored at `started`; packets older than this are
    /// always rejected (see [`ReplayCache::predates_start`]).
    pub fn new(started: SystemTime) -> Self {
        Self {
            seen: Mutex::new(Seen::default()),
            started,
        }
    }

    /// This process's start time.
    pub fn started(&self) -> SystemTime {
        self.started
    }

    /// Whether the packet timestamp predates the current process: such
    /// packets are rejected even when the `maxAge` window would accept
    /// them, because replay records do not survive a restart.
    pub fn predates_start(&self, timestamp: i64) -> bool {
        let start_secs = self
            .started
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        timestamp < start_secs
    }

    /// Records a key; returns false when it was already present (a
    /// replay). The cache is bounded: when full it is cleared wholesale
    /// (documented in `limits::REPLAY_CACHE_MAX`).
    pub fn record(&self, key: ReplayKey) -> bool {
        let mut seen = self.seen.lock().expect("replay cache");
        if seen.set.contains(&key) {
            return false;
        }
        if seen.set.len() >= limits::REPLAY_CACHE_MAX {
            seen.set.clear();
            seen.order.clear();
        }
        seen.set.insert(key.clone());
        seen.order.push_back(key);
        true
    }

    /// Whether the key was already used.
    pub fn contains(&self, key: &ReplayKey) -> bool {
        self.seen.lock().expect("replay cache").set.contains(key)
    }

    /// Entries currently cached (observability).
    pub fn len(&self) -> usize {
        self.seen.lock().expect("replay cache").set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn boot() -> SystemTime {
        std::time::UNIX_EPOCH + Duration::from_secs(1_000_000)
    }

    #[test]
    fn replay_rejected_and_cached() {
        let cache = ReplayCache::new(boot());
        let key = ReplayKey::new("cred", "rand1", 1_000_050);
        assert!(cache.record(key.clone()));
        assert!(cache.contains(&key));
        assert!(!cache.record(key), "same (cred, rand, ts) is a replay");
        // A different random value from the same credential passes.
        assert!(cache.record(ReplayKey::new("cred", "rand2", 1_000_050)));
        // Same random value under a different credential passes.
        assert!(cache.record(ReplayKey::new("other", "rand1", 1_000_050)));
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn timestamp_before_start_rejected() {
        let cache = ReplayCache::new(boot());
        // Sent before this process started (replay after restart).
        assert!(cache.predates_start(999_950));
        // After start, inside the window.
        assert!(!cache.predates_start(1_000_020));
        // Predating records stay rejected even when recorded.
        assert!(cache.record(ReplayKey::new("cred", "old", 999_950)));
        assert!(cache.contains(&ReplayKey::new("cred", "old", 999_950)));
    }

    #[test]
    fn cache_stays_bounded() {
        let cache = ReplayCache::new(boot());
        for i in 0..(limits::REPLAY_CACHE_MAX + 10) {
            cache.record(ReplayKey::new("cred", format!("r{i}"), 1_000_000));
        }
        assert!(cache.len() <= limits::REPLAY_CACHE_MAX);
    }
}
