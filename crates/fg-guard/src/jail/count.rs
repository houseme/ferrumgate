//! The window counting engine (WP-52 §3.3): pure logic over an
//! injectable clock. Every enabled jail owns one [`WindowCounter`]; a
//! hit counts the source address once, sliding records out of the
//! `findTime` window, and the threshold (`maxRetry`) turns a hit into
//! [`Hit::Triggered`]. IPv6 sources aggregate per /64 — the same
//! normalization the ban table applies to automatic bans.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::IpAddr,
    sync::Mutex,
    time::{Duration, SystemTime},
};

use fg_net::banlist::BanKey;

use super::model::MAX_TRACKED;

/// The outcome of one hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hit {
    /// Counted; the payload is the number of records inside the window.
    Counted(usize),
    /// The threshold was reached; the source's window resets afterwards
    /// so every ban needs a fresh series of matches.
    Triggered,
    /// The source is new and the tracked-map cap is full of sources that
    /// all were active at the same instant, so nothing could be evicted.
    /// Practically unreachable; the hit is dropped (fail-safe).
    Full,
}

/// Sliding-window per-source timestamps. Only the hit source is pruned on
/// a hit; stale sources stay tracked (bounded by [`MAX_TRACKED`]) until
/// the cap evicts the least recently active one.
pub struct WindowCounter {
    max_retry: usize,
    window: Duration,
    cap: usize,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// One entry per tracked source; timestamps ascend.
    map: BTreeMap<BanKey, VecDeque<SystemTime>>,
    /// Last activity per source, mirroring the back of each deque; the
    /// eviction candidate is the smallest one.
    activity: BTreeSet<(SystemTime, BanKey)>,
}

impl WindowCounter {
    pub fn new(max_retry: u32, window: Duration) -> Self {
        Self::with_capacity(max_retry, window, MAX_TRACKED)
    }

    /// Like [`Self::new`] with an explicit tracked-source cap (tests,
    /// embedding hosts that want a smaller footprint).
    pub fn with_capacity(max_retry: u32, window: Duration, cap: usize) -> Self {
        Self {
            max_retry: max_retry.max(1) as usize,
            window,
            cap: cap.max(1),
            state: Mutex::new(State::default()),
        }
    }

    /// Records one hit at `now` for the source address.
    pub fn hit(&self, ip: IpAddr, now: SystemTime) -> Hit {
        let key = BanKey::from_ip(ip);
        let cutoff = now
            .checked_sub(self.window)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let state = &mut *self.state.lock().expect("jail counter poisoned");
        // Prune the hit source's expired records first; a source whose
        // window emptied leaves the tracked set entirely.
        if let Some(deque) = state.map.get_mut(&key) {
            let last = *deque.back().expect("tracked sources keep a timestamp");
            while deque.front().is_some_and(|time| *time < cutoff) {
                deque.pop_front();
            }
            if deque.is_empty() {
                state.map.remove(&key);
                state.activity.remove(&(last, key));
            }
        }
        if state.map.contains_key(&key) {
            let deque = state.map.get_mut(&key).expect("just checked");
            let last = *deque.back().expect("tracked sources keep a timestamp");
            deque.push_back(now);
            state.activity.remove(&(last, key));
            state.activity.insert((now, key));
            if deque.len() >= self.max_retry {
                state.map.remove(&key);
                state.activity.remove(&(now, key));
                return Hit::Triggered;
            }
            return Hit::Counted(deque.len());
        }
        // New source: enforce the tracked cap by evicting the least
        // recently active source.
        if state.map.len() >= self.cap {
            match state.activity.iter().next().copied() {
                Some(oldest) if oldest.0 < now => {
                    state.map.remove(&oldest.1);
                    state.activity.remove(&oldest);
                }
                _ => return Hit::Full,
            }
        }
        state.map.insert(key, VecDeque::from([now]));
        state.activity.insert((now, key));
        // A threshold of one triggers on the very first hit.
        if self.max_retry <= 1 {
            state.map.remove(&key);
            state.activity.remove(&(now, key));
            return Hit::Triggered;
        }
        Hit::Counted(1)
    }

    /// How many sources are currently tracked.
    pub fn tracked(&self) -> usize {
        self.state.lock().expect("jail counter poisoned").map.len()
    }

    /// Drops every tracked source (rule replacement).
    pub fn reset(&self) {
        *self.state.lock().expect("jail counter poisoned") = State::default();
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    fn counter(max_retry: u32, seconds: u64) -> WindowCounter {
        WindowCounter::new(max_retry, Duration::from_secs(seconds))
    }

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn window_triggers_at_max_retry_within_find_time() {
        let counter = counter(5, 600);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        for step in 1..5 {
            assert_eq!(
                counter.hit(ip, at(step)),
                Hit::Counted(step as usize),
                "hits inside the window only count"
            );
        }
        assert_eq!(counter.hit(ip, at(5)), Hit::Triggered);
        // A fresh series is required for the next ban.
        assert_eq!(counter.hit(ip, at(6)), Hit::Counted(1));
    }

    #[test]
    fn window_forgets_old_hits() {
        let counter = counter(3, 600);
        let ip: IpAddr = "203.0.113.10".parse().unwrap();
        assert_eq!(counter.hit(ip, at(0)), Hit::Counted(1));
        assert_eq!(counter.hit(ip, at(300)), Hit::Counted(2));
        // Both earlier records slide out of the window.
        assert_eq!(counter.hit(ip, at(901)), Hit::Counted(1));
        assert_eq!(counter.hit(ip, at(1300)), Hit::Counted(2));
        assert_eq!(counter.hit(ip, at(1501)), Hit::Triggered);
    }

    #[test]
    fn window_counts_v6_per_64() {
        let counter = counter(3, 600);
        let first: IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into();
        let second: IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0xffff, 0, 0, 0).into();
        let other: IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1).into();
        assert_eq!(counter.hit(first, at(1)), Hit::Counted(1));
        assert_eq!(counter.hit(second, at(2)), Hit::Counted(2), "same /64");
        assert_eq!(counter.hit(other, at(3)), Hit::Counted(1), "other /64");
        assert_eq!(counter.hit(first, at(4)), Hit::Triggered);
        assert_eq!(counter.tracked(), 1, "the triggered /64 resets");
        // IPv4-mapped sources collapse to their IPv4 form.
        let mapped: IpAddr = "::ffff:203.0.113.5".parse().unwrap();
        let plain: IpAddr = "203.0.113.5".parse().unwrap();
        assert_eq!(counter.hit(mapped, at(5)), Hit::Counted(1));
        assert_eq!(counter.hit(plain, at(6)), Hit::Counted(2));
    }

    #[test]
    fn window_tracked_sources_capped() {
        // The upstream cap is 50000; the least recently active source is
        // evicted when a new one arrives beyond it.
        let counter = WindowCounter::with_capacity(3, Duration::from_secs(600), MAX_TRACKED);
        for step in 0..MAX_TRACKED {
            let ip: IpAddr = format!(
                "10.{0}.{1}.{2}",
                step >> 16 & 0xff,
                step >> 8 & 0xff,
                step & 0xff
            )
            .parse()
            .unwrap();
            assert_eq!(counter.hit(ip, at(step as u64)), Hit::Counted(1));
        }
        assert_eq!(counter.tracked(), MAX_TRACKED);
        // One more source evicts the oldest (step 0).
        let ip: IpAddr = "203.0.113.77".parse().unwrap();
        assert_eq!(counter.hit(ip, at(50_000)), Hit::Counted(1));
        assert_eq!(counter.tracked(), MAX_TRACKED);
        assert_eq!(
            counter.hit("10.0.0.0".parse().unwrap(), at(50_001)),
            Hit::Counted(1),
            "the evicted source can be tracked again"
        );
    }

    #[test]
    fn window_evicts_least_recently_active() {
        let counter = WindowCounter::with_capacity(3, Duration::from_secs(600), 2);
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let b: IpAddr = "203.0.113.2".parse().unwrap();
        let c: IpAddr = "203.0.113.3".parse().unwrap();
        counter.hit(a, at(1));
        counter.hit(b, at(2));
        // Re-activate `a`, making `b` the least recently active.
        counter.hit(a, at(3));
        counter.hit(c, at(4));
        assert_eq!(counter.tracked(), 2);
        // `a` survived (recently active), `b` was evicted; the third
        // hit reaches the threshold of this small counter.
        assert_eq!(counter.hit(a, at(5)), Hit::Triggered);
        assert_eq!(
            counter.hit(b, at(6)),
            Hit::Counted(1),
            "the evicted source starts fresh"
        );
        // When every tracked source was active at the same instant and
        // the cap is 1, nothing can be evicted: the hit is dropped.
        let tiny = WindowCounter::with_capacity(2, Duration::from_secs(600), 1);
        tiny.hit(a, at(9));
        assert_eq!(tiny.hit(b, at(9)), Hit::Full);
    }

    #[test]
    fn window_reset_clears_everything() {
        let counter = counter(2, 600);
        let ip: IpAddr = "203.0.113.11".parse().unwrap();
        counter.hit(ip, at(1));
        counter.reset();
        assert_eq!(counter.tracked(), 0);
        assert_eq!(counter.hit(ip, at(2)), Hit::Counted(1));
    }
}
