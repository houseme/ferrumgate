//! Pre-authentication rate limiting (WP-54 §3.3 step 3): a token bucket
//! per source network (IPv4 /24, IPv6 /64, 10 packets/second) and one
//! global bucket sized in HMAC work units (`keys × ⌈len/512⌉`, 20000
//! units/second), both applied before any HMAC computation so floods cost
//! nothing. The monotonic timestamp is a parameter, so tests drive a
//! synthetic clock; the source table is bounded and evicts idle (fully
//! refilled) sources first — a table full of active sources refuses new
//! ones instead of dropping their traffic later.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use ipnet::IpNet;

use crate::model::limits;

/// A token bucket refilled at `rate` tokens per second with a one-second
/// burst capacity.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
    rate: f64,
}

impl Bucket {
    fn new(rate: u64, now: Instant) -> Self {
        Self {
            tokens: rate as f64,
            last: now,
            rate: rate as f64,
        }
    }

    /// Refills and, when at least `cost` tokens are available, deducts
    /// them and returns true.
    fn take(&mut self, cost: u64, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last);
        self.last = now;
        let refill = elapsed.as_secs_f64() * self.rate;
        if refill > 0.0 {
            self.tokens = (self.tokens + refill).min(self.rate);
        }
        if self.tokens >= cost as f64 {
            self.tokens -= cost as f64;
            true
        } else {
            false
        }
    }

    fn idle(&self) -> bool {
        self.tokens >= self.rate
    }
}

/// The limiter shared by the UDP listener and TCP `submit`.
#[derive(Debug)]
pub struct RateLimiter {
    sources: Mutex<HashMap<IpNet, Bucket>>,
    global: Mutex<Bucket>,
}

impl RateLimiter {
    /// Creates the limiter with the WP-54 rates.
    pub fn new() -> Self {
        let start = Instant::now();
        Self {
            sources: Mutex::new(HashMap::new()),
            global: Mutex::new(Bucket::new(limits::GLOBAL_BUDGET_PER_SEC, start)),
        }
    }

    /// The source network of a peer for bucketing: IPv4 /24, IPv6 /64;
    /// IPv4-mapped IPv6 addresses bucket with their IPv4 form.
    pub fn source_net(peer: IpAddr) -> IpNet {
        match peer {
            IpAddr::V4(v4) => IpNet::new(IpAddr::V4(v4), limits::SOURCE_WINDOW_V4_PREFIX)
                .expect("24 is a valid prefix")
                .trunc(),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return Self::source_net(IpAddr::V4(v4));
                }
                IpNet::new(IpAddr::V6(v6), limits::SOURCE_WINDOW_V6_PREFIX)
                    .expect("64 is a valid prefix")
                    .trunc()
            }
        }
    }

    /// The HMAC budget cost of one packet: keys × ⌈len / 512⌉.
    pub fn packet_cost(packet_len: usize, key_count: usize) -> u64 {
        let units = packet_len.div_ceil(limits::BUDGET_UNIT_BYTES) as u64;
        units.max(1) * key_count.max(1) as u64
    }

    /// Applies both buckets for one packet; `now` is the injectable
    /// monotonic timestamp (tests pass a synthetic timeline).
    pub fn allow(&self, peer: IpAddr, cost: u64, now: Instant) -> bool {
        let net = Self::source_net(peer);
        let source_ok = {
            let mut sources = self.sources.lock().expect("rate limiter sources");
            if let Some(bucket) = sources.get_mut(&net) {
                bucket.take(1, now)
            } else {
                if sources.len() >= limits::RATE_SOURCES_MAX {
                    evict_idlest(&mut sources);
                }
                if sources.len() >= limits::RATE_SOURCES_MAX {
                    false
                } else {
                    sources.insert(net, Bucket::new(limits::SOURCE_RATE_PER_SEC, now));
                    match sources.get_mut(&net) {
                        Some(bucket) => bucket.take(1, now),
                        None => false,
                    }
                }
            }
        };
        source_ok
            && self
                .global
                .lock()
                .expect("rate limiter budget")
                .take(cost, now)
    }

    /// Number of tracked source networks (observability).
    pub fn tracked_sources(&self) -> usize {
        self.sources.lock().expect("rate limiter sources").len()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Removes sources whose bucket is completely refilled (idlest first)
/// until at least one slot is free.
fn evict_idlest(map: &mut HashMap<IpNet, Bucket>) {
    let idle: Vec<IpNet> = map
        .iter()
        .filter(|(_, bucket)| bucket.idle())
        .map(|(net, _)| *net)
        .collect();
    let mut remove = idle
        .len()
        .min(map.len().saturating_sub(limits::RATE_SOURCES_MAX) + 1);
    for net in idle {
        if remove == 0 {
            break;
        }
        map.remove(&net);
        remove -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(groups: [u16; 8]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(
            groups[0], groups[1], groups[2], groups[3], groups[4], groups[5], groups[6], groups[7],
        ))
    }

    fn at(start: Instant, millis: u64) -> Instant {
        start + Duration::from_millis(millis)
    }

    #[test]
    fn rate_limit_per_24_and_64() {
        let limiter = RateLimiter::new();
        let start = Instant::now();
        // Ten packets per second per /24: the 11th from the same /24 —
        // even from another address — is dropped; another /24 still passes.
        for _ in 0..10 {
            assert!(
                limiter.allow(v4(203, 0, 113, 1), 1, start),
                "burst capacity"
            );
        }
        assert!(!limiter.allow(v4(203, 0, 113, 2), 1, start));
        assert!(limiter.allow(v4(198, 51, 100, 1), 1, start));
        // One second later the bucket has refilled.
        assert!(limiter.allow(v4(203, 0, 113, 1), 1, at(start, 1000)));
        // IPv6 buckets by /64.
        for _ in 0..10 {
            assert!(limiter.allow(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]), 1, start));
        }
        let same_64 = v6([0x2001, 0xdb8, 0, 0, 0xffff, 0, 0, 1]);
        assert!(
            !limiter.allow(same_64, 1, start),
            "same /64 shares the bucket"
        );
        let other_64 = v6([0x2001, 0xdb8, 0, 1, 0, 0, 0, 1]);
        assert!(limiter.allow(other_64, 1, start));
    }

    #[test]
    fn global_budget_by_hmac_work() {
        let limiter = RateLimiter::new();
        let start = Instant::now();
        // cost(1500, 68) = 3 × 68 = 204 units; a 20000-unit bucket admits
        // 98 such packets before running dry within the same second.
        assert_eq!(RateLimiter::packet_cost(1500, 68), 204);
        let mut accepted = 0;
        for i in 0..100u16 {
            // Distinct /24 per packet so only the global budget bites.
            let peer = v4(203, 0, (i + 1) as u8, 1);
            if limiter.allow(peer, RateLimiter::packet_cost(1500, 68), start) {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 98, "budget is measured in HMAC work units");
        // Half a second later the bucket has refilled 10000 units: a
        // 15000-unit packet still waits, a cheaper one passes.
        assert!(!limiter.allow(v4(203, 0, 200, 1), 15_000, at(start, 500)));
        assert!(limiter.allow(v4(203, 0, 200, 1), 15_000, at(start, 1100)));
        assert_eq!(RateLimiter::packet_cost(512, 1), 1);
        assert_eq!(RateLimiter::packet_cost(513, 1), 2);
        assert_eq!(RateLimiter::packet_cost(64, 1024), 1024);
    }

    #[test]
    fn source_table_evicts_idle_and_stays_bounded() {
        let limiter = RateLimiter::new();
        let start = Instant::now();
        for i in 0..limits::RATE_SOURCES_MAX as u32 {
            let octets = i.to_be_bytes();
            let peer = IpAddr::V4(Ipv4Addr::new(
                octets[0].max(1),
                octets[1],
                octets[2],
                octets[3],
            ));
            limiter.allow(peer, 1, start);
        }
        assert!(limiter.tracked_sources() <= limits::RATE_SOURCES_MAX);
    }

    #[test]
    fn mapped_ipv6_buckets_with_ipv4() {
        let v4_mapped = IpAddr::V6(Ipv6Addr::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 1,
        ]));
        assert_eq!(
            RateLimiter::source_net(v4_mapped),
            RateLimiter::source_net(v4(203, 0, 113, 1))
        );
    }
}
