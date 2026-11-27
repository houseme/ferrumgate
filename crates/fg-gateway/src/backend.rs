use std::{
    collections::{HashSet, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering::Relaxed},
    time::Instant,
};

use anyhow::{Context, Result, ensure};
use hyper::{
    Uri,
    header::HeaderValue,
    http::uri::{Authority, Scheme},
};
use serde::Deserialize;

use crate::{
    config::{canonical_host, valid_authority},
    web::upstream::{MAX_ATTEMPTS, Policy},
};

const MAX_PER_ROUTE: usize = 32;
const FAILURE_THRESHOLD: u64 = 3;
const COOLDOWN_MS: u64 = 30_000;

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawBackend {
    upstream: String,
    #[serde(default = "default_weight")]
    weight: u16,
    #[serde(default)]
    backup: bool,
}

fn default_weight() -> u16 {
    1
}

pub(crate) struct Backend {
    pub scheme: Scheme,
    pub authority: Authority,
    pub host: HeaderValue,
    weight: u16,
    // Values below FAILURE_THRESHOLD count failures. Other values are deadlines.
    health: AtomicU64,
    active_down: AtomicBool,
    /// In-flight request count for `least_conn` (WP-23).
    pub(crate) conns: AtomicI32,
}

pub(crate) struct BackendPool {
    primary: Vec<Backend>,
    backup: Vec<Backend>,
    cursor: AtomicU64,
    started: Instant,
    /// WP-23 load policy (`round_robin` | `random` | `ip_hash` |
    /// `least_conn`); the TOML path always compiles the default.
    policy: Policy,
}

impl BackendPool {
    pub fn compile(
        upstream: Option<String>,
        mut backends: Vec<RawBackend>,
        h2c: bool,
        policy: Policy,
    ) -> Result<Self> {
        if let Some(upstream) = upstream {
            ensure!(backends.is_empty(), "specify upstream or backends");
            backends.push(RawBackend {
                upstream,
                weight: default_weight(),
                backup: false,
            });
        }
        ensure!(
            (1..=MAX_PER_ROUTE).contains(&backends.len()),
            "expected 1..={MAX_PER_ROUTE} backends"
        );

        let mut primary = Vec::new();
        let mut backup = Vec::new();
        let mut origins = HashSet::new();
        for (index, raw) in backends.into_iter().enumerate() {
            ensure!(
                (1..=100).contains(&raw.weight),
                "backends[{index}].weight must be in 1..=100"
            );
            let parts = raw
                .upstream
                .parse::<Uri>()
                .ok()
                .filter(|uri| {
                    matches!(uri.scheme_str(), Some("http" | "https"))
                        && uri.path() == "/"
                        && uri.query().is_none()
                        && !raw.upstream.contains('#')
                })
                .map(Uri::into_parts)
                .with_context(|| {
                    format!("invalid backends[{index}].upstream (expected HTTP(S) origin)")
                })?;
            let authority = parts
                .authority
                .filter(valid_authority)
                .with_context(|| format!("invalid backends[{index}].upstream authority"))?;
            let scheme = parts.scheme.context("missing upstream scheme")?;
            ensure!(
                !h2c || scheme == Scheme::HTTP,
                "upstream_h2c requires an http:// upstream"
            );
            let normalized_host = canonical_host(authority.host())
                .expect("validated authority")
                .into_owned();
            let port =
                authority
                    .port_u16()
                    .unwrap_or(if scheme == Scheme::HTTP { 80 } else { 443 });
            ensure!(
                origins.insert((scheme.clone(), normalized_host, port)),
                "duplicate backends[{index}].upstream"
            );
            let host = HeaderValue::from_str(authority.as_str())?;
            let backend = Backend {
                scheme,
                authority,
                host,
                weight: raw.weight,
                health: AtomicU64::new(0),
                active_down: AtomicBool::new(false),
                conns: AtomicI32::new(0),
            };
            if raw.backup {
                backup.push(backend);
            } else {
                primary.push(backend);
            }
        }
        ensure!(!primary.is_empty(), "expected at least one primary backend");
        Ok(Self {
            primary,
            backup,
            cursor: AtomicU64::new(0),
            started: Instant::now(),
            policy,
        })
    }

    pub fn len(&self) -> usize {
        self.primary.len() + self.backup.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Backend> {
        self.primary.iter().chain(&self.backup)
    }

    pub fn select(&self, active: bool) -> Option<&Backend> {
        if !active && self.len() == 1 {
            return self.primary.first();
        }
        let now = if active { 0 } else { self.now_ms() };
        self.select_group(&self.primary, now)
            .or_else(|| self.select_group(&self.backup, now))
    }

    fn select_group<'a>(&self, group: &'a [Backend], now: u64) -> Option<&'a Backend> {
        let mut eligible = 0u32;
        let mut total = 0u64;
        for (index, backend) in group.iter().enumerate() {
            let health = backend.health.load(Relaxed);
            if !backend.active_down.load(Relaxed) && (health < FAILURE_THRESHOLD || health <= now) {
                eligible |= 1 << index;
                total += u64::from(backend.weight);
            }
        }
        if total == 0 {
            return None;
        }
        if eligible.is_power_of_two() {
            return group.get(eligible.trailing_zeros() as usize);
        }
        let mut ticket = self.cursor.fetch_add(1, Relaxed) % total;
        group.iter().enumerate().find_map(|(index, backend)| {
            if eligible & (1 << index) == 0 {
                return None;
            }
            let weight = u64::from(backend.weight);
            if ticket < weight {
                Some(backend)
            } else {
                ticket -= weight;
                None
            }
        })
    }

    /// The retry plan for one request (WP-23): at most [`MAX_ATTEMPTS`]
    /// backends, led by the policy pick. Candidates are the available
    /// primaries (`!active_down` and the passive failure counter is below
    /// the threshold or its cooldown has expired), falling back to the
    /// available backups, and finally to every primary — better to try
    /// than to fail outright. The remaining candidates keep their config
    /// order behind the lead so a dial failure moves on deterministically.
    pub fn attempts(&self, active: bool, client: IpAddr) -> Vec<&Backend> {
        let now = if active { 0 } else { self.now_ms() };
        let mut candidates: Vec<&Backend> = self
            .primary
            .iter()
            .filter(|backend| self.available(backend, now))
            .collect();
        if candidates.is_empty() {
            candidates = self
                .backup
                .iter()
                .filter(|backend| self.available(backend, now))
                .collect();
        }
        if candidates.is_empty() {
            candidates = self.primary.iter().collect();
        }
        let lead = self.pick(&candidates, client);
        let mut order = Vec::with_capacity(MAX_ATTEMPTS);
        order.push(lead);
        for candidate in candidates {
            if !order.iter().any(|chosen| std::ptr::eq(*chosen, candidate)) {
                order.push(candidate);
            }
        }
        order.truncate(MAX_ATTEMPTS);
        order
    }

    /// Is `backend` in rotation? Mirrors the `select_group` eligibility.
    fn available(&self, backend: &Backend, now: u64) -> bool {
        !backend.active_down.load(Relaxed) && {
            let health = backend.health.load(Relaxed);
            health < FAILURE_THRESHOLD || health <= now
        }
    }

    /// Applies the pool policy to a non-empty candidate list. Semantics
    /// mirror `web::upstream::select`, re-implemented for the legacy
    /// `Backend` type.
    fn pick<'a>(&self, candidates: &[&'a Backend], client: IpAddr) -> &'a Backend {
        debug_assert!(!candidates.is_empty(), "attempts hands in candidates");
        if candidates.len() == 1 {
            return candidates[0];
        }
        match self.policy {
            Policy::RoundRobin => {
                let ticket = self.cursor.fetch_add(1, Relaxed);
                pick_by_ticket(&weighted_expand(candidates), ticket)
            }
            Policy::Random => pick_by_ticket(&weighted_expand(candidates), random_u64()),
            Policy::IpHash => {
                let mut hasher = DefaultHasher::new();
                client.hash(&mut hasher);
                pick_by_ticket(&weighted_expand(candidates), hasher.finish())
            }
            Policy::LeastConn => {
                // conns / weight, ties resolved by the earlier candidate.
                let mut best = candidates[0];
                let mut best_score = f64::INFINITY;
                for backend in candidates {
                    let score = f64::from(backend.conns.load(Relaxed)) / f64::from(backend.weight);
                    if score < best_score {
                        best_score = score;
                        best = backend;
                    }
                }
                best
            }
        }
    }

    /// Counts `backend` as an in-flight attempt (drives `least_conn`).
    pub fn enter(&self, backend: &Backend) {
        backend.conns.fetch_add(1, Relaxed);
    }

    /// Counts a finished attempt; the update guards the zero floor.
    pub fn leave(&self, backend: &Backend) {
        let _ = backend
            .conns
            .try_update(Relaxed, Relaxed, |conns| (conns > 0).then(|| conns - 1));
    }

    pub fn connected(&self, backend: &Backend, active: bool) {
        if self.len() > 1 {
            if active {
                let _ = backend.health.try_update(Relaxed, Relaxed, |value| {
                    (value < FAILURE_THRESHOLD).then_some(0)
                });
            } else {
                backend.health.store(0, Relaxed);
            }
        }
    }

    pub fn connection_failed(&self, backend: &Backend) {
        if self.len() > 1 {
            backend.connection_failed(self.now_ms());
        }
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }
}

/// Expands candidates by weight so a weighted ticket maps proportionally
/// (same shape as `web::upstream::select`).
fn weighted_expand<'a>(candidates: &[&'a Backend]) -> Vec<&'a Backend> {
    candidates
        .iter()
        .flat_map(|backend| std::iter::repeat_n(*backend, usize::from(backend.weight)))
        .collect()
}

/// Maps an arbitrary ticket onto the expanded list; `expanded` is never
/// empty because every weight is 1..=100.
fn pick_by_ticket<'a>(expanded: &[&'a Backend], ticket: u64) -> &'a Backend {
    expanded[(ticket % expanded.len() as u64) as usize]
}

/// Random u64 without pulling in the `rand` crate (workspace getrandom).
fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        // Entropy failure is practically impossible; fall back to a
        // counter-ish value so selection still rotates.
        return std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.subsec_nanos() as u64)
            .unwrap_or(0);
    }
    u64::from_le_bytes(bytes)
}

impl Backend {
    pub fn mark_active(&self, healthy: bool) -> bool {
        if healthy {
            let was_passively_down = self.health.swap(0, Relaxed) >= FAILURE_THRESHOLD;
            self.active_down.swap(false, Relaxed) || was_passively_down
        } else {
            !self.active_down.swap(true, Relaxed)
        }
    }

    fn connection_failed(&self, now: u64) {
        let _ = self.health.try_update(Relaxed, Relaxed, |state| {
            if state < FAILURE_THRESHOLD - 1 {
                Some(state + 1)
            } else if state < FAILURE_THRESHOLD || state <= now {
                Some(now.saturating_add(COOLDOWN_MS))
            } else {
                None
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(port: u16, weight: u16, backup: bool) -> RawBackend {
        RawBackend {
            upstream: format!("http://127.0.0.1:{port}"),
            weight,
            backup,
        }
    }

    fn pool(backends: Vec<RawBackend>, policy: Policy) -> BackendPool {
        BackendPool::compile(None, backends, false, policy).unwrap()
    }

    fn port(backend: &Backend) -> u16 {
        backend
            .authority
            .port_u16()
            .expect("test backends have ports")
    }

    #[test]
    fn cooldown_and_recovery_are_scoped_to_the_selected_backend() {
        let pool = pool(
            vec![raw(8001, 1, false), raw(8002, 1, true)],
            Policy::default(),
        );
        let primary = &pool.primary[0];
        let now = 100;
        for _ in 0..2 {
            primary.connection_failed(now);
            assert!(pool.select_group(&pool.primary, now).is_some());
        }
        primary.connection_failed(now);
        assert!(
            pool.select_group(&pool.primary, now + COOLDOWN_MS - 1)
                .is_none()
        );
        assert_eq!(pool.select(false).unwrap().authority.port_u16(), Some(8002));
        assert!(
            pool.select_group(&pool.primary, now + COOLDOWN_MS)
                .is_some()
        );
        pool.connected(primary, false);
        assert_eq!(pool.select(false).unwrap().authority.port_u16(), Some(8001));
    }

    #[test]
    fn attempts_never_exceed_three_and_deduplicate() {
        let pool = pool(
            vec![
                raw(8001, 1, false),
                raw(8002, 1, false),
                raw(8003, 1, false),
            ],
            Policy::default(),
        );
        let order: Vec<u16> = pool
            .attempts(false, "192.0.2.7".parse().unwrap())
            .iter()
            .map(|backend| port(backend))
            .collect();
        assert_eq!(order.len(), 3);
        assert!(
            order.iter().all(|port| [8001, 8002, 8003].contains(port)),
            "every attempt is a distinct pool member: {order:?}"
        );
        assert!(
            order.windows(2).all(|pair| pair[0] != pair[1]),
            "no backend is tried twice: {order:?}"
        );

        let four = BackendPool::compile(
            None,
            (0..4)
                .map(|index| raw(8100 + index as u16, 1, false))
                .collect(),
            false,
            Policy::default(),
        )
        .unwrap();
        assert_eq!(four.attempts(false, "192.0.2.7".parse().unwrap()).len(), 3);
    }

    #[test]
    fn attempts_prefer_available_then_backup_then_all_primaries() {
        let pool = pool(
            vec![raw(8001, 1, false), raw(8002, 1, true)],
            Policy::default(),
        );
        // A healthy pool only ever plans primaries.
        let healthy: Vec<u16> = pool
            .attempts(false, "192.0.2.7".parse().unwrap())
            .iter()
            .map(|backend| port(backend))
            .collect();
        assert_eq!(healthy, [8001]);

        // After the passive threshold the backup takes over.
        for _ in 0..FAILURE_THRESHOLD {
            pool.connection_failed(&pool.primary[0]);
        }
        let failed_over: Vec<u16> = pool
            .attempts(false, "192.0.2.7".parse().unwrap())
            .iter()
            .map(|backend| port(backend))
            .collect();
        assert_eq!(failed_over, [8002]);

        // Backup down too: fall back to all primaries — better to try.
        for _ in 0..FAILURE_THRESHOLD {
            pool.connection_failed(&pool.backup[0]);
        }
        let last_resort: Vec<u16> = pool
            .attempts(false, "192.0.2.7".parse().unwrap())
            .iter()
            .map(|backend| port(backend))
            .collect();
        assert_eq!(last_resort, [8001]);
    }

    #[test]
    fn round_robin_attempts_rotate_with_weights() {
        let pool = pool(
            vec![raw(8001, 3, false), raw(8002, 1, false)],
            Policy::RoundRobin,
        );
        let client = "192.0.2.7".parse().unwrap();
        let mut heavy = 0;
        for _ in 0..8 {
            if port(pool.attempts(false, client)[0]) == 8001 {
                heavy += 1;
            }
        }
        // Weight 3:1 expanded over a shared cursor: exactly 6:2 in 8 leads.
        assert_eq!(heavy, 6);
    }

    #[test]
    fn ip_hash_attempts_map_a_client_stably() {
        let pool = pool(
            vec![raw(8001, 1, false), raw(8002, 1, false)],
            Policy::IpHash,
        );
        let client = "192.0.2.7".parse().unwrap();
        let lead = port(pool.attempts(false, client)[0]);
        for _ in 0..5 {
            assert_eq!(port(pool.attempts(false, client)[0]), lead);
        }
    }

    #[test]
    fn least_conn_attempts_prefer_the_idle_backend() {
        let pool = pool(
            vec![raw(8001, 1, false), raw(8002, 1, false)],
            Policy::LeastConn,
        );
        let client = "192.0.2.7".parse().unwrap();
        // Both idle: the earlier candidate wins the tie.
        assert_eq!(port(pool.attempts(false, client)[0]), 8001);
        pool.enter(&pool.primary[0]);
        assert_eq!(port(pool.attempts(false, client)[0]), 8002);
        pool.leave(&pool.primary[0]);
        assert_eq!(port(pool.attempts(false, client)[0]), 8001);
        // leave never drives the counter below zero.
        assert_eq!(pool.primary[0].conns.load(Relaxed), 0);
        pool.leave(&pool.primary[0]);
        assert_eq!(pool.primary[0].conns.load(Relaxed), 0);
    }

    #[test]
    fn single_backend_pool_returns_that_backend() {
        let pool = pool(vec![raw(8001, 1, false)], Policy::default());
        let client = "192.0.2.7".parse().unwrap();
        for _ in 0..3 {
            let order = pool.attempts(false, client);
            assert_eq!(order.len(), 1);
            assert_eq!(port(order[0]), 8001);
        }
        assert_eq!(
            pool.cursor.load(Relaxed),
            0,
            "no ticket work for one backend"
        );
    }
}
