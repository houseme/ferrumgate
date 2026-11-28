//! Subscription list downloads (WP-26): fetch a feed, cache it in the
//! config dir, parse it into the registry; a failed download keeps the
//! last list and schedules a one-hour retry; an unparseable answer
//! (an error page) reads as an empty list until the next success.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::ip_list::IpSet;

/// The default refresh interval (§3.4: 默认 24 小时).
pub const DEFAULT_REFRESH: Duration = Duration::from_secs(24 * 3600);
/// The refresh bounds (1–720 hours).
pub const MIN_REFRESH: Duration = Duration::from_secs(3600);
pub const MAX_REFRESH: Duration = Duration::from_secs(720 * 3600);
/// The retry backoff after a failed download (§3.4: 1 小时).
pub const RETRY_BACKOFF: Duration = Duration::from_secs(3600);

/// One feed's configuration (the site model's `ipLists[]` entry).
#[derive(Clone, Debug)]
pub struct Feed {
    pub key: String,
    pub enable: bool,
    pub url: String,
    pub refresh: Duration,
}

impl Feed {
    /// Clamps the configured refresh into the valid range; 0 means the
    /// default.
    pub fn refresh_clamped(&self) -> Duration {
        if self.refresh == Duration::ZERO {
            DEFAULT_REFRESH
        } else {
            self.refresh.clamp(MIN_REFRESH, MAX_REFRESH)
        }
    }

    /// The cache file next to the configuration: restarts serve the last
    /// good list without touching the network.
    pub fn cache_path(&self, config_dir: &Path) -> PathBuf {
        config_dir.join(format!("iplist-{}.cache", self.key))
    }
}

/// The download result of one pass.
pub enum Downloaded {
    /// The feed answered; `bytes` is the body to parse.
    Body(Vec<u8>),
    /// The fetch failed (network, status); the cached list stays.
    Failed(String),
}

/// The download outcome after parsing: what lands in the registry.
#[derive(Debug)]
pub enum RefreshOutcome {
    /// Parsed and stored (entries / skipped recorded for the UI).
    Updated { entries: usize, skipped: usize },
    /// The body arrived but parsed to nothing usable (an error page):
    /// an empty list goes into the registry and the retry backoff runs.
    Unparseable { reason: String },
    /// The download failed: the previous list stays, retry in an hour.
    Failed { reason: String },
}

/// Runs one refresh pass for a feed: download (through `fetch`),
/// parse, and hand the result to `store`. Pure orchestration — the
/// HTTP client is injected, so tests drive it.
pub fn refresh_once(
    feed: &Feed,
    config_dir: &Path,
    fetch: &dyn Fn(&str) -> Result<Vec<u8>, String>,
    store: &dyn Fn(&str, Option<Arc<IpSet>>),
) -> RefreshOutcome {
    let _ = (feed, config_dir);
    match fetch(&feed.url) {
        Ok(bytes) => match IpSet::parse(&bytes) {
            Ok(parsed) => {
                // An answer with zero recognized entries and at least one
                // skipped line is an error page, not an empty feed (§3.3:
                // 内容无法识别时按空列表处理).
                if parsed.entries == 0 && !parsed.skipped.is_empty() {
                    store(&feed.key, Some(Arc::new(IpSet::default())));
                    return RefreshOutcome::Unparseable {
                        reason: parsed.skipped.join("; "),
                    };
                }
                let outcome = RefreshOutcome::Updated {
                    entries: parsed.entries,
                    skipped: parsed.skipped.len(),
                };
                store(&feed.key, Some(Arc::new(parsed.set)));
                // Cache the raw body for restarts (best effort — a
                // read-only config dir must not fail the refresh).
                let _ = std::fs::write(feed.cache_path(config_dir), &bytes);
                outcome
            }
            Err(error) => {
                // Unparseable content: an empty list takes over (a
                // whitelist then denies the world, a blacklist stops
                // blocking) — the documented semantics.
                store(&feed.key, Some(Arc::new(IpSet::default())));
                RefreshOutcome::Unparseable {
                    reason: error.to_string(),
                }
            }
        },
        Err(reason) => {
            // Keep serving the cached list: load it into the registry so
            // a first-pass failure on startup still has last run's data.
            if let Ok(bytes) = std::fs::read(feed.cache_path(config_dir))
                && let Ok(parsed) = IpSet::parse(&bytes)
            {
                store(&feed.key, Some(Arc::new(parsed.set)));
            }
            RefreshOutcome::Failed { reason }
        }
    }
}

/// The next wake-up after a pass: the refresh interval on success, the
/// retry backoff on failure.
pub fn next_wake(outcome: &RefreshOutcome, feed: &Feed) -> Duration {
    match outcome {
        RefreshOutcome::Updated { .. } => feed.refresh_clamped(),
        _ => RETRY_BACKOFF,
    }
}

/// Now for the scheduler's bookkeeping (the callers pass injected
/// clocks; this is the wall-clock default).
pub fn now() -> SystemTime {
    SystemTime::now()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_list::Registry;

    fn feed(url: &str) -> Feed {
        Feed {
            key: "feeds".to_owned(),
            enable: true,
            url: url.to_owned(),
            refresh: Duration::ZERO,
        }
    }

    fn temp_config() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("fgnet-feed-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn updated_feed_stores_caches_and_reports_counts() {
        let dir = temp_config();
        let registry = Registry::new();
        let body = b"1.2.3.4\nbad-line\n".to_vec();
        let fetch = |_url: &str| Ok(body.clone());
        let store = |key: &str, set: Option<Arc<IpSet>>| {
            registry.store(key, set);
        };
        let outcome = refresh_once(&feed("http://feed.test/list"), &dir, &fetch, &store);
        match outcome {
            RefreshOutcome::Updated { entries, skipped } => {
                assert_eq!(entries, 1);
                assert_eq!(skipped, 1);
            }
            _ => panic!("expected updated, got {outcome:?}"),
        }
        assert!(registry.get("feeds").expect("stored").contains(
            "1.2.3.4".parse().expect("ip")
        ));
        // The cache file exists for the next restart.
        assert!(dir.join("iplist-feeds.cache").exists());
    }

    #[test]
    fn failed_download_serves_the_cached_list() {
        let dir = temp_config();
        // Seed the cache from a previous successful run.
        std::fs::write(dir.join("iplist-feeds.cache"), b"1.2.3.4\n").expect("cache seed");
        let registry = Registry::new();
        let fetch = |_url: &str| Err::<Vec<u8>, String>("connection refused".to_owned());
        let store = |key: &str, set: Option<Arc<IpSet>>| {
            registry.store(key, set);
        };
        let outcome = refresh_once(&feed("http://feed.test/list"), &dir, &fetch, &store);
        assert!(matches!(outcome, RefreshOutcome::Failed { .. }));
        // The cached list landed in the registry despite the failure.
        assert!(registry.get("feeds").expect("from cache").contains(
            "1.2.3.4".parse().expect("ip")
        ));
        // The next wake is the retry backoff, not the full interval.
        assert_eq!(next_wake(&outcome, &feed("x")), RETRY_BACKOFF);
    }

    #[test]
    fn unparseable_body_reads_as_empty_list() {
        let dir = temp_config();
        let registry = Registry::new();
        let fetch = |_url: &str| Ok(b"<html>error page</html>".to_vec());
        let store = |key: &str, set: Option<Arc<IpSet>>| {
            registry.store(key, set);
        };
        let outcome = refresh_once(&feed("http://feed.test/list"), &dir, &fetch, &store);
        assert!(matches!(outcome, RefreshOutcome::Unparseable { .. }));
        // The empty list took over (a whitelist denies the world now).
        let set = registry.get("feeds").expect("empty list stored");
        assert!(set.is_empty());
        assert!(!set.contains("9.9.9.9".parse().expect("ip")));
        // Retry on the backoff.
        assert_eq!(next_wake(&outcome, &feed("x")), RETRY_BACKOFF);
    }

    #[test]
    fn refresh_clamps_into_bounds() {
        assert_eq!(feed("x").refresh_clamped(), DEFAULT_REFRESH);
        let mut long = feed("x");
        long.refresh = Duration::from_secs(10_000 * 3600);
        assert_eq!(long.refresh_clamped(), MAX_REFRESH);
        let mut short = feed("x");
        short.refresh = Duration::from_secs(30);
        assert_eq!(short.refresh_clamped(), MIN_REFRESH);
        // Success wakes on the clamped interval.
        let outcome = RefreshOutcome::Updated { entries: 1, skipped: 0 };
        assert_eq!(next_wake(&outcome, &feed("x")), DEFAULT_REFRESH);
    }
}
