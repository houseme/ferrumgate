use std::{
    collections::HashSet,
    sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    time::Instant,
};

use anyhow::{Context, Result, ensure};
use hyper::{
    Uri,
    header::HeaderValue,
    http::uri::{Authority, Scheme},
};
use serde::Deserialize;

use crate::config::{canonical_host, valid_authority};

const MAX_PER_ROUTE: usize = 32;
const FAILURE_THRESHOLD: u64 = 3;
const COOLDOWN_MS: u64 = 30_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawBackend {
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
}

pub(crate) struct BackendPool {
    primary: Vec<Backend>,
    backup: Vec<Backend>,
    cursor: AtomicU64,
    started: Instant,
}

impl BackendPool {
    pub fn compile(
        upstream: Option<String>,
        mut backends: Vec<RawBackend>,
        h2c: bool,
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

    #[test]
    fn cooldown_and_recovery_are_scoped_to_the_selected_backend() {
        let raw = |port, backup| RawBackend {
            upstream: format!("http://127.0.0.1:{port}"),
            weight: 1,
            backup,
        };
        let pool =
            BackendPool::compile(None, vec![raw(8001, false), raw(8002, true)], false).unwrap();
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
}
