//! The backend pool (WP-23 steps 2-3): compiled backends, candidate
//! selection with backup fallback, the passive check (3 consecutive dial
//! failures pause a backend for 30s) and probe-driven recovery.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::SystemTime;

use super::{ActiveCheck, Backend, Policy, UpstreamStatus};
use super::{FAILURE_THRESHOLD, MAX_BACKENDS, PAUSE};
use super::select;
use super::target::{Target, TargetError, parse_target};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolError {
    NoBackends,
    TooManyBackends,
    Duplicate(String),
    /// `site.targets[index]` failed to parse; `index` is the 0-based line.
    BadTarget {
        index: usize,
        source: TargetError,
    },
    /// Unknown `lb_policy` value (the raw text).
    BadPolicy(String),
    /// Active-check compilation failed; the message passes the underlying
    /// `health::CheckError` text through unchanged.
    BadCheck(String),
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoBackends => write!(f, "至少需要一个后端"),
            Self::TooManyBackends => write!(f, "后端最多 {MAX_BACKENDS} 个"),
            Self::Duplicate(origin) => write!(f, "后端重复：{origin}"),
            Self::BadTarget { index, source } => {
                write!(f, "第 {} 行后端地址无效：{source}", index + 1)
            }
            Self::BadPolicy(text) => {
                write!(f, "lb_policy 必须是 round_robin/random/ip_hash/least_conn：{text}")
            }
            Self::BadCheck(text) => write!(f, "{text}"),
        }
    }
}

impl std::error::Error for PoolError {}

/// A compiled backend pool. Each config generation owns its own pool and
/// therefore its own [`BackendState`]; no locking beyond the atomics.
pub struct Pool {
    pub backends: Vec<Arc<Backend>>,
    primary: Vec<usize>,
    backup: Vec<usize>,
    pub policy: Policy,
    pub check: Option<ActiveCheck>,
    cursor: AtomicU64,
}

impl Pool {
    pub fn compile(
        targets: Vec<Target>,
        policy: Policy,
        check: Option<ActiveCheck>,
    ) -> Result<Self, PoolError> {
        if targets.is_empty() {
            return Err(PoolError::NoBackends);
        }
        if targets.len() > MAX_BACKENDS {
            return Err(PoolError::TooManyBackends);
        }
        let mut backends = Vec::with_capacity(targets.len());
        let mut primary = Vec::new();
        let mut backup = Vec::new();
        let mut origins = std::collections::HashSet::new();
        for target in targets {
            let backend = Backend::new(target);
            if !origins.insert(backend.origin()) {
                return Err(PoolError::Duplicate(backend.origin()));
            }
            if backend.target.backup {
                backup.push(backends.len());
            } else {
                primary.push(backends.len());
            }
            backends.push(Arc::new(backend));
        }
        if primary.is_empty() {
            return Err(PoolError::NoBackends);
        }
        Ok(Self {
            backends,
            primary,
            backup,
            policy,
            check,
            cursor: AtomicU64::new(0),
        })
    }

    /// Site compile entry for the WP-23 pipeline: parses `site.targets`
    /// line by line ([`parse_target`]), `site.lb_policy` and the active
    /// check ([`ActiveCheck::compile`] with `send_proxy_protocol` as
    /// `force_tcp`), then defers to [`Pool::compile`]. For compatibility
    /// with existing configs a bare `host:port` line — no whitespace
    /// parameters, no `://` — is prefixed with `http://` first. The bridge
    /// still compiles the legacy pool; this public API is what the
    /// migration increments build on.
    pub fn from_site(site: &crate::web::model::Site) -> Result<Self, PoolError> {
        let mut targets = Vec::with_capacity(site.targets.len());
        for (index, line) in site.targets.iter().enumerate() {
            let line = line.trim();
            let line = if line.is_empty()
                || line.contains("://")
                || line.contains(char::is_whitespace)
            {
                line.to_owned()
            } else {
                format!("http://{line}")
            };
            let target =
                parse_target(&line).map_err(|source| PoolError::BadTarget { index, source })?;
            targets.push(target);
        }
        let policy = Policy::parse(&site.lb_policy)
            .ok_or_else(|| PoolError::BadPolicy(site.lb_policy.clone()))?;
        let check = ActiveCheck::compile(site, site.send_proxy_protocol)
            .map_err(|error| PoolError::BadCheck(error.to_string()))?;
        Self::compile(targets, policy, check)
    }

    pub fn len(&self) -> usize {
        self.backends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<Backend>> {
        self.backends.iter()
    }

    pub fn get(&self, index: usize) -> &Arc<Backend> {
        &self.backends[index]
    }

    /// Finds a backend's index by identity; `None` when foreign.
    pub fn position(&self, backend: &Backend) -> Option<usize> {
        self.backends
            .iter()
            .position(|candidate| std::ptr::eq(candidate.as_ref(), backend))
    }

    fn now_millis(now: SystemTime) -> i64 {
        now.duration_since(SystemTime::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as i64)
            .unwrap_or(0)
    }

    /// Is this backend currently in rotation?
    pub fn available(&self, backend: &Backend, now: SystemTime) -> bool {
        let state = &backend.state;
        if state.down.load(Relaxed) {
            return false;
        }
        let paused = state.paused_until.load(Relaxed);
        paused <= Self::now_millis(now)
    }

    /// Candidate order: available primaries, then available backups; when
    /// nothing is available, fall back to all primaries — better to try
    /// than to fail outright. `ip_hash` and weights apply within `pick`.
    pub fn candidates(&self, now: SystemTime) -> Vec<&Arc<Backend>> {
        let mut candidates: Vec<&Arc<Backend>> = self
            .primary
            .iter()
            .filter(|index| self.available(&self.backends[**index], now))
            .map(|index| &self.backends[*index])
            .collect();
        if candidates.is_empty() {
            candidates = self
                .backup
                .iter()
                .filter(|index| self.available(&self.backends[**index], now))
                .map(|index| &self.backends[*index])
                .collect();
        }
        if candidates.is_empty() {
            candidates = self.primary.iter().map(|index| &self.backends[*index]).collect();
        }
        candidates
    }

    /// Applies the pool policy to the candidate list, returning the chosen
    /// backend as a handle that outlives the candidate borrow.
    pub fn pick(&self, candidates: &[&Arc<Backend>], client: std::net::IpAddr) -> Arc<Backend> {
        let refs: Vec<&Backend> = candidates.iter().map(|arc| arc.as_ref()).collect();
        let picked = select::pick(self.policy, &refs, client, &self.cursor);
        candidates
            .iter()
            .find(|arc| std::ptr::eq(arc.as_ref(), picked))
            .map(|arc| (*arc).clone())
            .unwrap_or_else(|| candidates[0].clone())
    }

    /// Passive check bookkeeping for a failed dial. Returns `true` when
    /// the backend just transitioned to unavailable (caller logs and
    /// publishes `upstream.down`). A lone backend without active checks is
    /// never paused — something must keep serving.
    ///
    /// The deadline is stored unconditionally: a `compare_exchange(0, ..)`
    /// would never fire a second time, because after the first pause
    /// expires `paused_until` still holds a past, non-zero timestamp. The
    /// return value is the available -> paused transition: the threshold
    /// is met, the backend is removable, and the previous deadline was
    /// already due (or unset). Re-failures while already paused keep it
    /// paused (fresh deadline) without reporting another transition.
    pub fn note_dial_failure(&self, backend: &Backend, now: SystemTime) -> bool {
        let state = &backend.state;
        let fails = state.fails.fetch_add(1, Relaxed).saturating_add(1);
        if fails < FAILURE_THRESHOLD {
            return false;
        }
        if self.len() <= 1 && self.check.is_none() {
            return false;
        }
        let now_millis = Self::now_millis(now);
        let deadline = now_millis.saturating_add(PAUSE.as_millis() as i64);
        let previous = state.paused_until.swap(deadline, Relaxed);
        previous <= now_millis
    }

    /// A dial (and initial response) succeeded: reset the passive streak
    /// and lift any passive pause. `down` is deliberately left alone — it
    /// is the active probe's flag and recovery from it is probe-driven
    /// ([`Pool::mark_probe`]), not response-driven.
    pub fn note_response(&self, backend: &Backend) {
        let state = &backend.state;
        state.fails.store(0, Relaxed);
        state.paused_until.store(0, Relaxed);
        state.requests.fetch_add(1, Relaxed);
    }

    /// Active probe outcome. When a check is configured, recovery is
    /// entirely probe-driven: `passes` consecutive successes bring the
    /// backend back; `fails` consecutive probe failures mark it down.
    /// Probe streaks live in their own counters — the passive streak is
    /// untouched. Returns the transition (`Some(true)` became up,
    /// `Some(false)` became down) for the caller to log and publish.
    pub fn mark_probe(&self, backend: &Backend, healthy: bool) -> Option<bool> {
        let state = &backend.state;
        let Some(check) = &self.check else {
            return None;
        };
        if healthy {
            let passes = state.passes.fetch_add(1, Relaxed).saturating_add(1);
            state.probe_fails.store(0, Relaxed);
            if passes >= check.passes && state.down.swap(false, Relaxed) {
                state.paused_until.store(0, Relaxed);
                return Some(true);
            }
            None
        } else {
            state.passes.store(0, Relaxed);
            let fails = state.probe_fails.fetch_add(1, Relaxed).saturating_add(1);
            if fails >= check.fails && !state.down.swap(true, Relaxed) {
                return Some(false);
            }
            None
        }
    }

    /// Status rows for the site statistics endpoint.
    pub fn status(&self, now: SystemTime) -> Vec<UpstreamStatus> {
        let now_millis = Self::now_millis(now);
        self.backends
            .iter()
            .map(|backend| {
                let state = &backend.state;
                let paused = state.paused_until.load(Relaxed);
                UpstreamStatus {
                    url: super::target::display_url(&backend.target),
                    weight: backend.target.weight,
                    backup: backend.target.backup,
                    available: self.available(backend, now),
                    fails: state.fails.load(Relaxed),
                    paused_for_secs: (paused > now_millis)
                        .then_some((paused - now_millis).max(0) / 1000),
                    conns: state.conns.load(Relaxed),
                    requests: state.requests.load(Relaxed),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::{CheckMode, FAILURE_THRESHOLD, PAUSE};
    use super::*;
    use crate::web::model::Site;

    fn target(line: &str) -> Target {
        super::super::parse_target(line).expect("valid target line")
    }

    fn compile_pool(lines: &[&str], check: Option<ActiveCheck>) -> Pool {
        let targets: Vec<Target> = lines.iter().map(|line| target(line)).collect();
        Pool::compile(targets, Policy::RoundRobin, check).expect("pool compiles")
    }

    fn tcp_check(fails: u32, passes: u32) -> ActiveCheck {
        ActiveCheck {
            mode: CheckMode::Tcp,
            path: String::new(),
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(3),
            fails,
            passes,
        }
    }

    /// Fails a backend often enough to trip the passive check.
    fn pause_passively(pool: &Pool, index: usize, now: SystemTime) -> bool {
        let backend = pool.get(index);
        let mut transition = false;
        for _ in 0..FAILURE_THRESHOLD {
            transition = pool.note_dial_failure(backend, now);
        }
        transition
    }

    fn origins(pool: &Pool, now: SystemTime) -> Vec<String> {
        pool.candidates(now)
            .iter()
            .map(|backend| backend.origin())
            .collect()
    }

    #[test]
    fn candidates_prefer_primary_then_backup_then_fallback() {
        let now = SystemTime::now();
        let pool = compile_pool(
            &[
                "http://127.0.0.1:9001",
                "http://127.0.0.1:9002",
                "http://127.0.0.1:9003 backup",
            ],
            None,
        );
        assert_eq!(pool.len(), 3);

        // Healthy pool: available primaries only, in config order.
        assert_eq!(
            origins(&pool, now),
            vec!["http://127.0.0.1:9001", "http://127.0.0.1:9002"]
        );

        // Every primary paused: the backup takes over.
        assert!(pause_passively(&pool, 0, now));
        assert!(pause_passively(&pool, 1, now));
        assert_eq!(origins(&pool, now), vec!["http://127.0.0.1:9003"]);

        // Backup paused too: fall back to all primaries — better to try
        // than to fail outright.
        assert!(pause_passively(&pool, 2, now));
        assert_eq!(
            origins(&pool, now),
            vec!["http://127.0.0.1:9001", "http://127.0.0.1:9002"]
        );

        // After the pause expires the primaries return to rotation on
        // their own (passive pause only; nothing is marked down).
        let later = now + PAUSE + Duration::from_secs(1);
        assert_eq!(
            origins(&pool, later),
            vec!["http://127.0.0.1:9001", "http://127.0.0.1:9002"]
        );
    }

    #[test]
    fn passive_check_pauses_after_three_failures() {
        let now = SystemTime::now();
        let pool = compile_pool(&["http://127.0.0.1:9001", "http://127.0.0.1:9002"], None);
        let backend = pool.get(0);

        // Streak below the threshold: no pause, still available.
        assert!(!pool.note_dial_failure(backend, now));
        assert!(!pool.note_dial_failure(backend, now));
        assert!(pool.available(backend, now));

        // Third consecutive failure trips the passive check.
        assert!(pool.note_dial_failure(backend, now));
        assert!(!pool.available(backend, now));
        assert_eq!(backend.state.fails.load(Relaxed), FAILURE_THRESHOLD);

        // Once the pause expires the backend is tried again...
        let later = now + PAUSE + Duration::from_secs(1);
        assert!(pool.available(backend, later));

        // ...and a fresh failure re-pauses it (this is the regression the
        // compare_exchange version could never pass: paused_until holds a
        // past, non-zero timestamp after expiry).
        assert!(pool.note_dial_failure(backend, later));
        assert!(!pool.available(backend, later));

        // A paused backend failing again mid-pause refreshes the deadline
        // without reporting another transition.
        let mid_pause = later + Duration::from_secs(5);
        assert!(!pool.note_dial_failure(backend, mid_pause));
        assert!(!pool.available(backend, later + Duration::from_secs(30)));
    }

    #[test]
    fn single_backend_not_removed_without_active_check() {
        let now = SystemTime::now();
        // The only backend, no active check: never removable, something
        // must keep serving.
        let pool = compile_pool(&["http://127.0.0.1:9001"], None);
        let backend = pool.get(0);
        for _ in 0..=FAILURE_THRESHOLD + 2 {
            assert!(!pool.note_dial_failure(backend, now));
        }
        assert_eq!(backend.state.fails.load(Relaxed), FAILURE_THRESHOLD + 3);
        assert!(pool.available(backend, now));
        assert_eq!(origins(&pool, now), vec!["http://127.0.0.1:9001"]);

        // The only backend WITH an active check: removable, probes will
        // watch it and bring it back.
        let checked = compile_pool(&["http://127.0.0.1:9001"], Some(tcp_check(3, 2)));
        let backend = checked.get(0);
        assert!(!checked.note_dial_failure(backend, now));
        assert!(!checked.note_dial_failure(backend, now));
        assert!(checked.note_dial_failure(backend, now));
        assert!(!checked.available(backend, now));
    }

    #[test]
    fn duplicate_origin_rejected() {
        let policy = Policy::RoundRobin;
        // Same origin twice (parameters aside) is rejected.
        let error = Pool::compile(
            vec![target("http://127.0.0.1:9001"), target("http://127.0.0.1:9001 weight=2")],
            policy,
            None,
        )
        .err()
        .expect("duplicate origin rejected");
        assert_eq!(error, PoolError::Duplicate("http://127.0.0.1:9001".to_string()));

        // More than MAX_BACKENDS is rejected.
        let targets: Vec<Target> = (0..=MAX_BACKENDS)
            .map(|port| target(&format!("http://127.0.0.1:{}", 9000 + port)))
            .collect();
        assert_eq!(targets.len(), MAX_BACKENDS + 1);
        let error = Pool::compile(targets, policy, None)
            .err()
            .expect("too many backends rejected");
        assert_eq!(error, PoolError::TooManyBackends);

        // Exactly MAX_BACKENDS compiles.
        let targets: Vec<Target> = (0..MAX_BACKENDS)
            .map(|port| target(&format!("http://127.0.0.1:{}", 9000 + port)))
            .collect();
        assert_eq!(Pool::compile(targets, policy, None).expect("boundary ok").len(), MAX_BACKENDS);

        // Empty and all-backup pools are both rejected.
        assert_eq!(
            Pool::compile(Vec::new(), policy, None)
                .err()
                .expect("empty rejected"),
            PoolError::NoBackends
        );
        assert_eq!(
            Pool::compile(vec![target("http://127.0.0.1:9001 backup")], policy, None)
                .err()
                .expect("all-backup rejected"),
            PoolError::NoBackends
        );
    }

    #[test]
    fn note_response_resets() {
        let now = SystemTime::now();
        let pool = compile_pool(&["http://127.0.0.1:9001", "http://127.0.0.1:9002"], None);
        let backend = pool.get(0);

        assert!(pause_passively(&pool, 0, now));
        assert!(!pool.available(backend, now));

        pool.note_response(backend);
        assert_eq!(backend.state.fails.load(Relaxed), 0);
        assert_eq!(backend.state.paused_until.load(Relaxed), 0);
        assert_eq!(backend.state.requests.load(Relaxed), 1);
        assert!(pool.available(backend, now));

        // `down` is the active probe's flag: a successful response must
        // not clear it, otherwise a probe-marked-down backend would be
        // revived before the probe saw a single pass.
        let checked = compile_pool(&["http://127.0.0.1:9001"], Some(tcp_check(3, 2)));
        let backend = checked.get(0);
        assert_eq!(checked.mark_probe(backend, false), None);
        assert_eq!(checked.mark_probe(backend, false), None);
        assert_eq!(checked.mark_probe(backend, false), Some(false));
        assert!(backend.state.down.load(Relaxed));

        checked.note_response(backend);
        assert!(backend.state.down.load(Relaxed));
        assert!(!checked.available(backend, now));
    }

    #[test]
    fn mark_probe_transitions() {
        let pool = compile_pool(&["http://127.0.0.1:9001"], Some(tcp_check(3, 2)));
        let backend = pool.get(0);

        // Without a configured check the probe results are ignored.
        let plain = compile_pool(&["http://127.0.0.1:9002"], None);
        let plain_backend = plain.get(0);
        assert_eq!(plain.mark_probe(plain_backend, true), None);
        assert_eq!(plain.mark_probe(plain_backend, false), None);

        // Down on exactly the third (check.fails) consecutive failure.
        assert_eq!(pool.mark_probe(backend, false), None);
        assert_eq!(pool.mark_probe(backend, false), None);
        assert_eq!(pool.mark_probe(backend, false), Some(false));
        assert!(backend.state.down.load(Relaxed));
        // Already down: further failures report nothing new.
        assert_eq!(pool.mark_probe(backend, false), None);

        // One pass is not enough (check.passes = 2) and a failure resets
        // the pass streak.
        assert_eq!(pool.mark_probe(backend, true), None);
        assert_eq!(pool.mark_probe(backend, false), None);
        assert_eq!(backend.state.passes.load(Relaxed), 0);

        // Up on exactly the second (check.passes) consecutive success.
        assert_eq!(pool.mark_probe(backend, true), None);
        assert_eq!(pool.mark_probe(backend, true), Some(true));
        assert!(!backend.state.down.load(Relaxed));
        assert_eq!(backend.state.paused_until.load(Relaxed), 0);
        // Stays up: further successes report nothing new.
        assert_eq!(pool.mark_probe(backend, true), None);

        // And the next down cycle works from scratch again.
        assert_eq!(pool.mark_probe(backend, false), None);
        assert_eq!(pool.mark_probe(backend, false), None);
        assert_eq!(pool.mark_probe(backend, false), Some(false));
    }

    #[test]
    fn status_fields() {
        let now = SystemTime::now();
        let pool = compile_pool(
            &["http://127.0.0.1:9001 weight=3", "http://127.0.0.1:9002 backup"],
            None,
        );
        let backup = pool.get(1);

        assert!(pause_passively(&pool, 0, now));
        pool.note_response(backup);

        let rows = pool.status(now);
        assert_eq!(rows.len(), 2);

        let paused_row = &rows[0];
        assert_eq!(paused_row.url, "http://127.0.0.1:9001");
        assert_eq!(paused_row.weight, 3);
        assert!(!paused_row.backup);
        assert!(!paused_row.available);
        assert_eq!(paused_row.fails, FAILURE_THRESHOLD);
        // Deadline is now + PAUSE, so exactly 30 seconds remain.
        assert_eq!(paused_row.paused_for_secs, Some(30));
        assert_eq!(paused_row.requests, 0);

        let backup_row = &rows[1];
        assert_eq!(backup_row.url, "http://127.0.0.1:9002");
        assert_eq!(backup_row.weight, 1);
        assert!(backup_row.backup);
        assert!(backup_row.available);
        assert_eq!(backup_row.fails, 0);
        assert_eq!(backup_row.paused_for_secs, None);
        assert_eq!(backup_row.requests, 1);

        // After the pause expires the row reports available again with no
        // remaining seconds.
        let later = now + PAUSE + Duration::from_secs(1);
        let rows = pool.status(later);
        assert!(rows[0].available);
        assert_eq!(rows[0].paused_for_secs, None);
    }

    fn site(targets: &[&str], policy: &str) -> Site {
        Site {
            targets: targets.iter().map(|line| line.to_string()).collect(),
            lb_policy: policy.to_owned(),
            ..Site::default()
        }
    }

    /// A proxy site with a check; `interval` is the knob to push out of
    /// range in the rejection test.
    fn health_site(mode: &str, interval: u32) -> Site {
        Site {
            targets: vec!["http://127.0.0.1:9001".to_string()],
            health_mode: mode.to_owned(),
            health_interval_secs: interval,
            health_timeout_secs: 3,
            health_fails: 3,
            health_passes: 2,
            ..Site::default()
        }
    }

    #[test]
    fn from_site_parses_weights_backups_and_policy() {
        let pool = Pool::from_site(&site(
            &["http://10.0.0.2:8080 weight=3 backup", "127.0.0.1:9001"],
            "ip_hash",
        ))
        .expect("site compiles");
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.policy, Policy::IpHash);
        let weighted = pool.get(0);
        assert_eq!(weighted.target.weight, 3);
        assert!(weighted.target.backup);
        let plain = pool.get(1);
        assert_eq!(plain.target.weight, 1);
        assert!(!plain.target.backup);
    }

    #[test]
    fn from_site_bare_target_defaults_to_http() {
        let pool = Pool::from_site(&site(&["127.0.0.1:9001"], "")).expect("site compiles");
        let backend = pool.get(0);
        let uri = &backend.target.uri;
        assert_eq!(uri.scheme_str(), Some("http"));
        assert_eq!(uri.host(), Some("127.0.0.1"));
        assert_eq!(uri.port_u16(), Some(9001));
        assert_eq!(backend.origin(), "http://127.0.0.1:9001");
    }

    #[test]
    fn from_site_rejects_bad_lines_and_policy() {
        // The bad line is reported with its index and the parse reason.
        let error = Pool::from_site(&site(&["http://127.0.0.1:9001", "http://x foo=bar"], ""))
            .err()
            .expect("bad line rejected");
        assert_eq!(
            error,
            PoolError::BadTarget {
                index: 1,
                source: TargetError::UnknownParam("foo=bar".to_string()),
            }
        );
        let text = error.to_string();
        assert!(text.contains("第 2 行"), "unexpected message: {text}");
        assert!(text.contains("未知参数"), "unexpected message: {text}");

        // An unknown lb_policy carries the raw value.
        let error = Pool::from_site(&site(&["http://127.0.0.1:9001"], "weighted"))
            .err()
            .expect("unknown policy rejected");
        assert_eq!(error, PoolError::BadPolicy("weighted".to_string()));
    }

    #[test]
    fn from_site_compiles_health_check() {
        // PROXY protocol to the backend demotes the HTTP check to TCP.
        let mut proxied = health_site("http", 10);
        proxied.send_proxy_protocol = true;
        let pool = Pool::from_site(&proxied).expect("site compiles");
        let check = pool.check.as_ref().expect("check present");
        assert_eq!(check.mode, CheckMode::Tcp);
        assert_eq!(check.path, "");

        // An empty mode compiles no check at all.
        let pool = Pool::from_site(&health_site("", 10)).expect("site compiles");
        assert!(pool.check.is_none());
    }

    #[test]
    fn from_site_rejects_out_of_range_health() {
        let error = Pool::from_site(&health_site("http", 0))
            .err()
            .expect("out-of-range interval rejected");
        assert!(
            matches!(&error, PoolError::BadCheck(text) if text.contains("health.interval_secs")),
            "unexpected error: {error}"
        );
    }
}
