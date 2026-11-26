use std::{
    collections::{HashMap, hash_map::Entry},
    fmt,
    net::{IpAddr, Ipv6Addr},
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use fg_config::{ConfigStore, Loaded};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

const FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
const UNKNOWN_WINDOW: Duration = Duration::from_secs(10 * 60);
const MAX_LOCK: Duration = Duration::from_secs(24 * 3600);
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const KNOWN_SAVE_INTERVAL: Duration = Duration::from_secs(12 * 3600);
const MAX_ATTEMPTS: u32 = 4;
const MAX_SOURCES: usize = 20_000;
const MAX_KNOWN: usize = 200;
pub(super) const KNOWN_FILE: &str = "login-ips";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoginLimits {
    pub max_failures: u32,
    pub lock_duration: Duration,
    pub unknown_failures: Option<u32>,
}

impl Default for LoginLimits {
    fn default() -> Self {
        Self {
            max_failures: 5,
            lock_duration: FAILURE_WINDOW,
            unknown_failures: Some(20),
        }
    }
}

#[derive(Debug)]
pub enum LoginError {
    InvalidCredentials,
    TotpRequired,
    Locked(Duration),
    Flood,
    Busy,
    Internal(anyhow::Error),
}

impl fmt::Display for LoginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCredentials => "invalid administrator credentials",
            Self::TotpRequired => "two-step verification code required",
            Self::Locked(_) => "login source is temporarily locked",
            Self::Flood => "unfamiliar login source is temporarily limited",
            Self::Busy => "login verification is busy",
            Self::Internal(_) => "administrator authentication failed",
        })
    }
}

impl std::error::Error for LoginError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Internal(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

pub(super) struct LoginLimiter(Mutex<State>);

impl LoginLimiter {
    pub fn load(store: &ConfigStore) -> Result<Self> {
        let mut state = State::new(Instant::now());
        if let Loaded::Found(entries) = store.load::<Vec<KnownSource>>(KNOWN_FILE)? {
            for entry in entries.into_iter().take(MAX_KNOWN) {
                let key = entry.key.strip_suffix("/64").unwrap_or(&entry.key);
                if let Ok(ip) = key.parse() {
                    state.known.insert(source_key(ip), entry);
                }
            }
        }
        Ok(Self(Mutex::new(state)))
    }

    pub fn configure(&self, limits: LoginLimits) -> Result<()> {
        ensure!(
            limits.max_failures > 0,
            "login failure limit must be positive"
        );
        ensure!(
            !limits.lock_duration.is_zero() && limits.lock_duration <= MAX_LOCK,
            "invalid login lock duration"
        );
        ensure!(
            limits
                .unknown_failures
                .is_none_or(|limit| (1..=10_000).contains(&limit)),
            "invalid unfamiliar source budget"
        );
        self.state().limits = limits;
        Ok(())
    }

    pub fn begin(&self, address: IpAddr) -> Result<Attempt<'_>, LoginError> {
        let reservation = self.state().reserve(source_key(address), Instant::now())?;
        Ok(Attempt {
            limiter: self,
            reservation: Some(reservation),
        })
    }

    pub fn take_known(&self) -> Option<Vec<KnownSource>> {
        let mut state = self.state();
        if !std::mem::take(&mut state.known_dirty) {
            return None;
        }
        state.last_known_save = Instant::now();
        Some(state.known.values().cloned().collect())
    }

    pub fn retry_known_save(&self) {
        self.state().known_dirty = true;
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().expect("login limiter poisoned")
    }
}

pub(super) struct Attempt<'a> {
    limiter: &'a LoginLimiter,
    reservation: Option<Reservation>,
}

impl Attempt<'_> {
    pub fn complete(mut self, success: bool) -> Completion {
        let reservation = self.reservation.take().expect("active login reservation");
        self.limiter
            .state()
            .finish(reservation, Some(success), Instant::now())
    }
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if let Some(reservation) = self.reservation.take() {
            self.limiter
                .state()
                .finish(reservation, None, Instant::now());
        }
    }
}

#[derive(Default)]
pub(super) struct Completion {
    pub save_known: bool,
    pub flood: Option<u32>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct KnownSource {
    key: String,
    #[serde(with = "time::serde::rfc3339")]
    first: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last: OffsetDateTime,
}

struct Reservation {
    key: IpAddr,
    unknown: bool,
}

struct Source {
    started: Instant,
    running: u32,
    failed: u32,
    locked_until: Instant,
    strike: Option<(Instant, u32)>,
}

impl Source {
    fn lock(&mut self, now: Instant, base: Duration) -> Duration {
        let count = self
            .strike
            .filter(|(time, _)| now.duration_since(*time) <= MAX_LOCK)
            .map_or(1, |(_, count)| count.saturating_add(1));
        let scale = 1_u32.checked_shl(count - 1).unwrap_or(u32::MAX);
        let duration = base.saturating_mul(scale).min(MAX_LOCK);
        self.strike = Some((now, count));
        self.locked_until = now + duration;
        self.started = now;
        self.failed = 0;
        duration
    }
}

struct Unknown {
    started: Instant,
    running: u32,
    failed: u32,
    reported: bool,
}

struct State {
    limits: LoginLimits,
    sources: HashMap<IpAddr, Source>,
    known: HashMap<IpAddr, KnownSource>,
    unknown: Unknown,
    running: u32,
    last_sweep: Instant,
    last_known_save: Instant,
    known_dirty: bool,
}

impl State {
    fn new(now: Instant) -> Self {
        Self {
            limits: LoginLimits::default(),
            sources: HashMap::new(),
            known: HashMap::new(),
            unknown: Unknown {
                started: now,
                running: 0,
                failed: 0,
                reported: false,
            },
            running: 0,
            last_sweep: now,
            last_known_save: now,
            known_dirty: false,
        }
    }

    fn reserve(&mut self, key: IpAddr, now: Instant) -> Result<Reservation, LoginError> {
        let known = self.known.contains_key(&key);
        let mut unknown = false;
        if let Some(limit) = self.limits.unknown_failures.filter(|_| !known) {
            let budget = &mut self.unknown;
            if budget.running == 0
                && (budget.failed == 0 || now.duration_since(budget.started) >= UNKNOWN_WINDOW)
            {
                budget.started = now;
                budget.failed = 0;
                budget.reported = false;
            }
            if budget.failed >= limit {
                return Err(LoginError::Flood);
            }
            if budget.failed + budget.running >= limit {
                return Err(LoginError::Busy);
            }
            unknown = true;
        }
        if self.running == MAX_ATTEMPTS {
            return Err(LoginError::Busy);
        }
        self.sweep(now);
        // Reserve space for known sources even when unfamiliar addresses fill their share.
        let limit = if known {
            MAX_SOURCES
        } else {
            MAX_SOURCES - MAX_KNOWN
        };
        let has_space = self.sources.len() < limit;
        let source = match self.sources.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) if has_space => entry.insert(Source {
                started: now,
                running: 0,
                failed: 0,
                locked_until: now,
                strike: None,
            }),
            Entry::Vacant(_) => return Err(LoginError::Busy),
        };
        if now < source.locked_until {
            return Err(LoginError::Locked(source.locked_until.duration_since(now)));
        }
        if source.running == 0 && now.duration_since(source.started) >= FAILURE_WINDOW {
            source.started = now;
            source.failed = 0;
        }
        if source.failed >= self.limits.max_failures {
            return Err(LoginError::Locked(
                source.lock(now, self.limits.lock_duration),
            ));
        }
        if source.failed.saturating_add(source.running) >= self.limits.max_failures {
            return Err(LoginError::Busy);
        }
        source.running += 1;
        self.running += 1;
        if unknown {
            self.unknown.running += 1;
        }
        Ok(Reservation { key, unknown })
    }

    fn finish(
        &mut self,
        reservation: Reservation,
        outcome: Option<bool>,
        now: Instant,
    ) -> Completion {
        let mut completion = Completion::default();
        self.running -= 1;
        if reservation.unknown {
            let budget = &mut self.unknown;
            budget.running -= 1;
            if let Some(limit) = self.limits.unknown_failures
                && outcome == Some(false)
            {
                budget.failed += 1;
                if budget.failed >= limit && !budget.reported {
                    budget.reported = true;
                    completion.flood = Some(budget.failed);
                }
            }
        }
        let key = reservation.key;
        let source = self.sources.get_mut(&key).expect("reserved login source");
        source.running -= 1;
        match outcome {
            Some(true) => {
                source.started = now;
                source.failed = 0;
                self.remember(key, now);
                completion.save_known = self.known_dirty;
            }
            Some(false) if now >= source.locked_until => {
                source.failed += 1;
                if source.failed >= self.limits.max_failures {
                    source.lock(now, self.limits.lock_duration);
                }
            }
            _ => {}
        }
        completion
    }

    fn remember(&mut self, key: IpAddr, now: Instant) {
        let utc = OffsetDateTime::now_utc();
        if let Some(entry) = self.known.get_mut(&key) {
            entry.last = utc;
            self.known_dirty |= now.duration_since(self.last_known_save) >= KNOWN_SAVE_INTERVAL;
            return;
        }
        if self.known.len() >= MAX_KNOWN
            && let Some(oldest) = self
                .known
                .iter()
                .min_by_key(|(_, entry)| entry.last)
                .map(|(key, _)| *key)
        {
            self.known.remove(&oldest);
        }
        let label = match key {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("{ip}/64"),
        };
        self.known.insert(
            key,
            KnownSource {
                key: label,
                first: utc,
                last: utc,
            },
        );
        self.known_dirty = true;
    }

    fn sweep(&mut self, now: Instant) {
        if now.duration_since(self.last_sweep) < SWEEP_INTERVAL {
            return;
        }
        self.last_sweep = now;
        self.sources.retain(|_, source| {
            source.running != 0
                || now < source.locked_until
                || now.duration_since(source.started) < FAILURE_WINDOW
                || source
                    .strike
                    .is_some_and(|(strike, _)| now.duration_since(strike) <= MAX_LOCK)
        });
    }
}

fn source_key(address: IpAddr) -> IpAddr {
    match address.to_canonical() {
        IpAddr::V4(ip) => IpAddr::V4(ip),
        IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from_bits(ip.to_bits() & (!0_u128 << 64))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::Ipv4Addr, sync::Barrier, thread};

    const SOURCE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    #[test]
    fn lockout_uses_the_default_window_and_caps_escalation() -> Result<()> {
        let mut now = Instant::now();
        let mut state = State::new(now);
        state.limits.unknown_failures = None;
        for seconds in [
            900, 1_800, 3_600, 7_200, 14_400, 28_800, 57_600, 86_400, 86_400,
        ] {
            for _ in 0..5 {
                let attempt = state.reserve(SOURCE, now)?;
                state.finish(attempt, Some(false), now);
            }
            let interval = Duration::from_secs(seconds);
            assert!(
                matches!(state.reserve(SOURCE, now), Err(LoginError::Locked(time)) if time == interval)
            );
            now += interval;
        }
        now += MAX_LOCK;
        for _ in 0..5 {
            let attempt = state.reserve(SOURCE, now)?;
            state.finish(attempt, Some(false), now);
        }
        assert!(matches!(
            state.reserve(SOURCE, now),
            Err(LoginError::Locked(FAILURE_WINDOW))
        ));
        Ok(())
    }

    #[test]
    fn lockout_reserves_before_concurrent_checks_and_releases_on_drop() -> Result<()> {
        let limiter = LoginLimiter(Mutex::new(State::new(Instant::now())));
        limiter.configure(LoginLimits {
            max_failures: 2,
            ..LoginLimits::default()
        })?;
        let gate = Barrier::new(8);
        let admitted = thread::scope(|scope| {
            let tasks: Vec<_> = (0..8)
                .map(|last| {
                    let (limiter, gate) = (&limiter, &gate);
                    scope.spawn(move || {
                        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, last);
                        let attempt = limiter.begin(ip.into()).ok();
                        gate.wait();
                        attempt.is_some()
                    })
                })
                .collect();
            tasks
                .into_iter()
                .map(|task| task.join().unwrap())
                .filter(|admitted| *admitted)
                .count()
        });
        assert_eq!(admitted, 2);
        let attempts = ["192.0.2.1", "::ffff:192.0.2.1", "192.0.2.2", "192.0.2.3"]
            .map(|ip| limiter.begin(ip.parse().unwrap()).ok().unwrap());
        assert!(matches!(
            limiter.begin("192.0.2.4".parse()?),
            Err(LoginError::Busy)
        ));
        drop(attempts);
        assert!(limiter.begin(SOURCE).is_ok());
        Ok(())
    }

    #[test]
    fn lockout_reserves_flood_budget_and_alerts_only_after_real_failures() -> Result<()> {
        let now = Instant::now();
        let mut state = State::new(now);
        state.limits.unknown_failures = Some(2);
        let other = "192.0.2.2".parse()?;
        let trusted = "192.0.2.3".parse()?;
        let attempt = state.reserve(trusted, now)?;
        assert!(state.finish(attempt, Some(true), now).save_known);
        let first = state.reserve(SOURCE, now)?;
        let second = state.reserve(other, now)?;
        assert!(matches!(state.reserve(other, now), Err(LoginError::Busy)));
        assert_eq!(state.finish(first, Some(false), now).flood, None);
        assert_eq!(state.finish(second, None, now).flood, None);
        let second = state.reserve(other, now)?;
        assert_eq!(state.finish(second, Some(false), now).flood, Some(2));
        assert!(matches!(state.reserve(other, now), Err(LoginError::Flood)));
        assert!(state.reserve(trusted, now).is_ok());
        assert!(state.reserve(other, now + UNKNOWN_WINDOW).is_ok());
        Ok(())
    }

    #[test]
    fn lockout_bounds_source_storage_without_crowding_out_known_sources() -> Result<()> {
        let now = Instant::now();
        let mut state = State::new(now);
        state.limits.unknown_failures = None;
        state.remember(SOURCE, now);
        for index in 0..(MAX_SOURCES - MAX_KNOWN) as u32 {
            let attempt = state.reserve(Ipv4Addr::from(0x0a00_0000 + index).into(), now)?;
            state.finish(attempt, Some(false), now);
        }
        let unseen = "198.51.100.1".parse()?;
        assert!(matches!(state.reserve(unseen, now), Err(LoginError::Busy)));
        let known = state.reserve(SOURCE, now)?;
        state.finish(known, Some(true), now);
        assert!(state.reserve(unseen, now + FAILURE_WINDOW).is_ok());
        assert_eq!(state.sources.len(), 1);
        Ok(())
    }
}
