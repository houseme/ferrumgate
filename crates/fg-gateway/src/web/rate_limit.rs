//! Per-client-IP rate limiting (WP-27): token bucket + concurrent connection
//! cap, bounded bucket table with idle eviction, RAII [`Permit`] release on
//! completion or disconnect, and injectable clock for deterministic tests.

use std::{
    collections::HashMap,
    fmt,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use axum::{
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

/// Default maximum number of distinct client IP buckets tracked per limiter.
pub const DEFAULT_MAX_BUCKETS: usize = 10_000;

/// Default idle duration after which an inactive bucket becomes eligible for
/// eviction.
pub const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(300);

/// Site-level rate limit configuration (WP-27 §3.2).
///
/// When enabled, at least one of `rate` (> 0) or `max_conns` (> 0) must be set.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimit {
    /// Requests per second allowed per client IP (`None` disables token bucket).
    pub rate: Option<f64>,
    /// Burst capacity; when `rate` is set and `burst == 0`, defaults to
    /// `rate.floor() as usize + 1`.
    pub burst: usize,
    /// Maximum concurrent in-flight requests per client IP (`0` = unlimited).
    pub max_conns: usize,
}

/// Wire-level site configuration wrapper carrying the `enable` toggle (§4).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitConfig {
    pub enable: bool,
    pub rate: Option<f64>,
    pub burst: usize,
    pub max_conns: usize,
}

impl From<&RateLimitConfig> for RateLimit {
    fn from(cfg: &RateLimitConfig) -> Self {
        Self {
            rate: cfg.rate,
            burst: cfg.burst,
            max_conns: cfg.max_conns,
        }
    }
}

/// Validation failure for [`RateLimit`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RateLimitError {
    MissingRateAndMaxConns,
    InvalidRate,
}

impl fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRateAndMaxConns => {
                f.write_str("rate limit requires at least one of rate (> 0) or maxConns (> 0)")
            }
            Self::InvalidRate => f.write_str("rate must be a finite positive number"),
        }
    }
}

impl std::error::Error for RateLimitError {}

impl RateLimit {
    /// Validates that at least `rate` or `max_conns` is active and `rate` is
    /// finite and strictly positive when specified.
    pub fn validate(&self) -> Result<(), RateLimitError> {
        let has_rate = match self.rate {
            Some(r) => {
                if !r.is_finite() || r <= 0.0 {
                    return Err(RateLimitError::InvalidRate);
                }
                true
            }
            None => false,
        };
        if !has_rate && self.max_conns == 0 {
            return Err(RateLimitError::MissingRateAndMaxConns);
        }
        Ok(())
    }

    /// Effective token-bucket burst capacity: uses `burst` if non-zero,
    /// otherwise `rate.floor() + 1` when `rate` is configured.
    pub fn effective_burst(&self) -> usize {
        if self.burst > 0 {
            return self.burst;
        }
        match self.rate {
            Some(r) if r.is_finite() && r > 0.0 => (r.floor() as usize).saturating_add(1),
            _ => 0,
        }
    }
}

/// Reason a request was rejected by [`Limiter::acquire`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimited {
    RateExceeded,
    MaxConnsExceeded,
}

impl fmt::Display for RateLimited {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RateExceeded => f.write_str("rate limit exceeded"),
            Self::MaxConnsExceeded => f.write_str("maximum concurrent connections exceeded"),
        }
    }
}

impl std::error::Error for RateLimited {}

/// Builds the standard `429 Too Many Requests` plain-text response.
pub fn too_many_requests_response() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        "429 Too Many Requests\n",
    )
        .into_response()
}

#[derive(Debug)]
struct IpBucket {
    tokens: f64,
    last_refill: SystemTime,
    last_seen: SystemTime,
    active_conns: usize,
}

struct LimiterState {
    buckets: HashMap<IpAddr, IpBucket>,
}

struct LimiterInner {
    rate: Option<f64>,
    burst: usize,
    max_conns: usize,
    max_buckets: usize,
    idle_ttl: Duration,
    state: Mutex<LimiterState>,
}

/// Per-site client-IP rate limiter (token bucket + concurrency limit).
#[derive(Clone)]
pub struct Limiter {
    inner: Arc<LimiterInner>,
}

impl Limiter {
    /// Creates a limiter with default bucket table bounds (`10_000` IPs,
    /// `300s` idle TTL). Call [`RateLimit::validate`] before constructing from
    /// untrusted config, or use [`Limiter::try_new`].
    pub fn new(cfg: RateLimit) -> Self {
        Self::with_limits(cfg, DEFAULT_MAX_BUCKETS, DEFAULT_IDLE_TTL)
    }

    /// Validates `cfg` and constructs a [`Limiter`].
    pub fn try_new(cfg: RateLimit) -> Result<Self, RateLimitError> {
        cfg.validate()?;
        Ok(Self::new(cfg))
    }

    /// Constructs a limiter with explicit bucket table capacity and idle TTL
    /// (useful for bounded-table testing and custom sizing).
    pub fn with_limits(cfg: RateLimit, max_buckets: usize, idle_ttl: Duration) -> Self {
        let burst = cfg.effective_burst();
        let rate = cfg.rate.filter(|r| r.is_finite() && *r > 0.0);
        Self {
            inner: Arc::new(LimiterInner {
                rate,
                burst,
                max_conns: cfg.max_conns,
                max_buckets: max_buckets.max(1),
                idle_ttl,
                state: Mutex::new(LimiterState {
                    buckets: HashMap::new(),
                }),
            }),
        }
    }

    /// Attempts to admit one request from `ip` at timestamp `now`.
    ///
    /// On success returns a [`Permit`] that automatically releases the
    /// concurrency slot when dropped (including when a client disconnects
    /// mid-request and the handler future is cancelled).
    pub fn acquire(&self, ip: IpAddr, now: SystemTime) -> Result<Permit, RateLimited> {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if !state.buckets.contains_key(&ip) && state.buckets.len() >= self.inner.max_buckets {
            evict_idle_locked(&mut state.buckets, now, self.inner.idle_ttl);
            while state.buckets.len() >= self.inner.max_buckets {
                if !evict_oldest_locked(&mut state.buckets) {
                    break;
                }
            }
        }

        let initial_tokens = self.inner.burst as f64;
        let bucket = state.buckets.entry(ip).or_insert_with(|| IpBucket {
            tokens: initial_tokens,
            last_refill: now,
            last_seen: now,
            active_conns: 0,
        });

        // Check concurrent connections before consuming a token.
        if self.inner.max_conns > 0 && bucket.active_conns >= self.inner.max_conns {
            bucket.last_seen = now;
            return Err(RateLimited::MaxConnsExceeded);
        }

        // Refill and check token bucket when rate limiting is enabled.
        if let Some(rate) = self.inner.rate {
            let elapsed = now
                .duration_since(bucket.last_refill)
                .unwrap_or(Duration::ZERO)
                .as_secs_f64();
            if elapsed > 0.0 {
                bucket.tokens = (bucket.tokens + elapsed * rate).min(self.inner.burst as f64);
                bucket.last_refill = now;
            }
            if bucket.tokens < 1.0 {
                bucket.last_seen = now;
                return Err(RateLimited::RateExceeded);
            }
            bucket.tokens -= 1.0;
        }

        bucket.last_seen = now;
        let tracks_conn = self.inner.max_conns > 0;
        if tracks_conn {
            bucket.active_conns += 1;
        }

        Ok(Permit {
            inner: tracks_conn.then(|| Arc::clone(&self.inner)),
            ip,
        })
    }

    /// Explicitly evicts idle buckets older than `idle_ttl` at `now`, returning
    /// the number of buckets removed.
    pub fn evict_idle(&self, now: SystemTime) -> usize {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        evict_idle_locked(&mut state.buckets, now, self.inner.idle_ttl)
    }

    /// Number of client IP buckets currently tracked.
    pub fn bucket_count(&self) -> usize {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .buckets
            .len()
    }

    /// Active concurrent connection count currently held for `ip`.
    pub fn active_conns(&self, ip: IpAddr) -> usize {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .buckets
            .get(&ip)
            .map_or(0, |b| b.active_conns)
    }
}

fn evict_idle_locked(
    buckets: &mut HashMap<IpAddr, IpBucket>,
    now: SystemTime,
    idle_ttl: Duration,
) -> usize {
    let before = buckets.len();
    buckets.retain(|_, b| {
        b.active_conns > 0 || now.duration_since(b.last_seen).unwrap_or(Duration::ZERO) < idle_ttl
    });
    before - buckets.len()
}

fn evict_oldest_locked(buckets: &mut HashMap<IpAddr, IpBucket>) -> bool {
    // Prefer evicting an inactive bucket; fall back to oldest overall if all are active.
    let victim = buckets
        .iter()
        .filter(|(_, b)| b.active_conns == 0)
        .min_by_key(|(_, b)| b.last_seen)
        .map(|(&ip, _)| ip)
        .or_else(|| {
            buckets
                .iter()
                .min_by_key(|(_, b)| b.last_seen)
                .map(|(&ip, _)| ip)
        });
    match victim {
        Some(ip) => {
            buckets.remove(&ip);
            true
        }
        None => false,
    }
}

/// RAII concurrency guard returned by [`Limiter::acquire`].
///
/// Dropping the permit decrements the IP's active connection count even when
/// the request finishes early or the client disconnects.
pub struct Permit {
    inner: Option<Arc<LimiterInner>>,
    ip: IpAddr,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        let mut state = inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(bucket) = state.buckets.get_mut(&self.ip) {
            bucket.active_conns = bucket.active_conns.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::UNIX_EPOCH;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn limiter_token_bucket_defaults_burst() {
        let cfg = RateLimit {
            rate: Some(2.7),
            burst: 0,
            max_conns: 0,
        };
        // floor(2.7) + 1 = 3.
        assert_eq!(cfg.effective_burst(), 3);
        let limiter = Limiter::try_new(cfg).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let t0 = at(1000);
        assert!(limiter.acquire(ip, t0).is_ok());
        assert!(limiter.acquire(ip, t0).is_ok());
        assert!(limiter.acquire(ip, t0).is_ok());
        assert_eq!(
            limiter.acquire(ip, t0).err(),
            Some(RateLimited::RateExceeded)
        );
        // After 1 second, 2.7 tokens refill -> 2 requests succeed, 3rd fails.
        let t1 = at(1001);
        assert!(limiter.acquire(ip, t1).is_ok());
        assert!(limiter.acquire(ip, t1).is_ok());
        assert_eq!(
            limiter.acquire(ip, t1).err(),
            Some(RateLimited::RateExceeded)
        );
    }

    #[test]
    fn limiter_requires_rate_or_max_conns() {
        let empty = RateLimit {
            rate: None,
            burst: 5,
            max_conns: 0,
        };
        assert_eq!(
            empty.validate(),
            Err(RateLimitError::MissingRateAndMaxConns)
        );

        let zero_rate = RateLimit {
            rate: Some(0.0),
            burst: 1,
            max_conns: 5,
        };
        assert_eq!(zero_rate.validate(), Err(RateLimitError::InvalidRate));

        let neg_rate = RateLimit {
            rate: Some(-1.0),
            burst: 1,
            max_conns: 5,
        };
        assert_eq!(neg_rate.validate(), Err(RateLimitError::InvalidRate));

        let nan_rate = RateLimit {
            rate: Some(f64::NAN),
            burst: 1,
            max_conns: 5,
        };
        assert_eq!(nan_rate.validate(), Err(RateLimitError::InvalidRate));

        let rate_only = RateLimit {
            rate: Some(1.0),
            burst: 0,
            max_conns: 0,
        };
        assert!(rate_only.validate().is_ok());

        let conns_only = RateLimit {
            rate: None,
            burst: 0,
            max_conns: 4,
        };
        assert!(conns_only.validate().is_ok());
    }

    #[test]
    fn limiter_buckets_bounded_and_idle_evicted() {
        let limiter = Limiter::with_limits(
            RateLimit {
                rate: Some(10.0),
                burst: 10,
                max_conns: 0,
            },
            3,
            Duration::from_secs(60),
        );
        for i in 1..=5u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, i));
            limiter.acquire(ip, at(1000 + u64::from(i))).unwrap();
            assert!(limiter.bucket_count() <= 3);
        }
        assert_eq!(limiter.bucket_count(), 3);
        // Idle eviction after idle_ttl removes inactive entries.
        let evicted = limiter.evict_idle(at(1200));
        assert_eq!(evicted, 3);
        assert_eq!(limiter.bucket_count(), 0);
    }
}
