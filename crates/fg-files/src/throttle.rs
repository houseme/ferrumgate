//! Login failure throttling and `fileauth.failed` event reporting shared by
//! WebDAV, FTP, SMB, and self-service password changes (WP-63).

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use fg_core::events::{Event, EventBus, Kind};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// Sliding failure window: 15 minutes (upstream `ThrottleWindow`).
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Maximum failures inside `DEFAULT_WINDOW` before rejecting further logins.
pub const DEFAULT_MAX_FAILURES: u32 = 10;
/// Maximum tracked sources in memory (oldest/expired entries are evicted).
pub const DEFAULT_MAX_ENTRIES: usize = 4096;
/// Minimum interval between `fileauth.failed` events for the same source.
pub const DEFAULT_REPORT_COOLDOWN: Duration = Duration::from_secs(5);

const MAX_USERNAME_FIELD_BYTES: usize = 64;

/// Clock abstraction for deterministic unit tests.
pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// Resolves the effective client IP for throttling and failure reporting using
/// `fg_net::client_addr` (ignoring forwarded headers unless `trust.enabled`
/// and the TCP peer is trusted).
pub fn resolve_client_ip(
    peer: std::net::SocketAddr,
    forwarded_for: Option<&str>,
    real_ip: Option<&str>,
    trust: &fg_net::client_addr::ProxyTrust,
) -> IpAddr {
    fg_net::client_addr::resolve(peer, forwarded_for, real_ip, trust).ip
}

/// Normalizes a client IP into a throttle/report bucket key:
/// - IPv4 -> `/32`
/// - IPv4-mapped IPv6 (`::ffff:a.b.c.d`) -> IPv4 `/32`
/// - IPv6 -> `/64` network prefix
pub fn normalize_source(ip: IpAddr) -> IpNet {
    match ip {
        IpAddr::V4(v4) => ipv4_key(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                ipv4_key(v4)
            } else {
                let net = Ipv6Net::new(v6, 64)
                    .expect("prefix length 64 is always valid for IPv6")
                    .trunc();
                IpNet::V6(net)
            }
        }
    }
}

fn ipv4_key(v4: Ipv4Addr) -> IpNet {
    IpNet::V4(Ipv4Net::new(v4, 32).expect("prefix length 32 is always valid for IPv4"))
}

/// Sliding-window per-source login failure throttle.
///
/// Once a source reaches `max` failures within `window`, `allows` returns
/// `false` until old failures expire from the window. Successful logins do NOT
/// clear recorded failures.
pub struct Throttle {
    window: Duration,
    max: u32,
    max_entries: usize,
    clock: Clock,
    table: Mutex<HashMap<IpNet, VecDeque<SystemTime>>>,
}

impl Default for Throttle {
    fn default() -> Self {
        Self::new()
    }
}

impl Throttle {
    /// Creates a throttle with WP-63 defaults: 15-minute window, 10 failures.
    pub fn new() -> Self {
        Self::with_config(DEFAULT_WINDOW, DEFAULT_MAX_FAILURES, DEFAULT_MAX_ENTRIES)
    }

    /// Creates a throttle with custom window, failure threshold, and capacity.
    pub fn with_config(window: Duration, max: u32, max_entries: usize) -> Self {
        Self::with_clock(window, max, max_entries, Arc::new(SystemTime::now))
    }

    /// Creates a throttle with an injectable clock (useful in tests).
    pub fn with_clock(window: Duration, max: u32, max_entries: usize, clock: Clock) -> Self {
        Self {
            window,
            max,
            max_entries: max_entries.max(1),
            clock,
            table: Mutex::new(HashMap::new()),
        }
    }

    pub fn window(&self) -> Duration {
        self.window
    }

    pub fn max_failures(&self) -> u32 {
        self.max
    }

    /// Returns whether `ip` is permitted to attempt login at `now`.
    pub fn allows(&self, ip: IpAddr, now: SystemTime) -> bool {
        let key = normalize_source(ip);
        let mut table = self.table.lock().expect("throttle table poisoned");
        let Some(entries) = table.get_mut(&key) else {
            return true;
        };
        prune_queue(entries, self.window, now);
        let allowed = entries.len() < self.max as usize;
        if entries.is_empty() {
            table.remove(&key);
        }
        allowed
    }

    /// Returns whether `ip` is permitted to attempt login using the current clock.
    pub fn allows_now(&self, ip: IpAddr) -> bool {
        self.allows(ip, (self.clock)())
    }

    /// Records a failed authentication attempt at `now`.
    /// Returns `true` if the source is now throttled (reached `max` failures).
    pub fn record_failure(&self, ip: IpAddr, now: SystemTime) -> bool {
        let key = normalize_source(ip);
        let mut table = self.table.lock().expect("throttle table poisoned");
        if !table.contains_key(&key) && table.len() >= self.max_entries {
            evict_table(&mut table, self.window, now, self.max_entries);
        }
        let entries = table.entry(key).or_default();
        prune_queue(entries, self.window, now);
        // Cap per-key queue length so repeated throttled hits do not grow memory.
        if entries.len() < self.max as usize {
            entries.push_back(now);
        }
        entries.len() >= self.max as usize
    }

    /// Records a failed authentication attempt using the current clock.
    pub fn record_failure_now(&self, ip: IpAddr) -> bool {
        self.record_failure(ip, (self.clock)())
    }

    /// Returns the number of active failures in the current window for `ip`.
    pub fn failure_count(&self, ip: IpAddr, now: SystemTime) -> usize {
        let key = normalize_source(ip);
        let mut table = self.table.lock().expect("throttle table poisoned");
        let Some(entries) = table.get_mut(&key) else {
            return 0;
        };
        prune_queue(entries, self.window, now);
        let len = entries.len();
        if len == 0 {
            table.remove(&key);
        }
        len
    }

    /// Returns the current number of tracked sources in the table.
    pub fn tracked_sources(&self) -> usize {
        self.table.lock().expect("throttle table poisoned").len()
    }
}

fn prune_queue(entries: &mut VecDeque<SystemTime>, window: Duration, now: SystemTime) {
    let cutoff = now.checked_sub(window);
    while let Some(&front) = entries.front() {
        let expired = match cutoff {
            Some(limit) => front <= limit,
            None => false,
        };
        if expired {
            entries.pop_front();
        } else {
            break;
        }
    }
}

fn evict_table(
    table: &mut HashMap<IpNet, VecDeque<SystemTime>>,
    window: Duration,
    now: SystemTime,
    max_entries: usize,
) {
    table.retain(|_, entries| {
        prune_queue(entries, window, now);
        !entries.is_empty()
    });
    while table.len() >= max_entries {
        let oldest = table
            .iter()
            .filter_map(|(key, entries)| entries.back().map(|&ts| (*key, ts)))
            .min_by_key(|(_, ts)| *ts)
            .map(|(key, _)| key);
        match oldest {
            Some(key) => {
                table.remove(&key);
            }
            None => break,
        }
    }
}

/// Emits `fileauth.failed` events to the event bus, rate-limited to at most
/// one event per source within `cooldown` (default 5 seconds).
pub struct FailureReporter {
    bus: Option<EventBus>,
    cooldown: Duration,
    max_entries: usize,
    clock: Clock,
    last_reported: Mutex<HashMap<IpNet, SystemTime>>,
}

impl Default for FailureReporter {
    fn default() -> Self {
        Self::new(None)
    }
}

impl FailureReporter {
    /// Creates a reporter with WP-63 default 5-second per-source cooldown.
    pub fn new(bus: Option<EventBus>) -> Self {
        Self::with_config(
            bus,
            DEFAULT_REPORT_COOLDOWN,
            DEFAULT_MAX_ENTRIES,
            Arc::new(SystemTime::now),
        )
    }

    /// Creates a reporter with custom cooldown, capacity, and clock.
    pub fn with_config(
        bus: Option<EventBus>,
        cooldown: Duration,
        max_entries: usize,
        clock: Clock,
    ) -> Self {
        Self {
            bus,
            cooldown,
            max_entries: max_entries.max(1),
            clock,
            last_reported: Mutex::new(HashMap::new()),
        }
    }

    /// Reports a failed authentication for `ip` at `now`.
    /// Returns `true` if an event was emitted (not suppressed by the cooldown).
    pub fn report(
        &self,
        service: &'static str,
        ip: IpAddr,
        username: Option<&str>,
        now: SystemTime,
    ) -> bool {
        let key = normalize_source(ip);
        {
            let mut last = self
                .last_reported
                .lock()
                .expect("failure reporter lock poisoned");
            if let Some(&prev) = last.get(&key)
                && now.duration_since(prev).unwrap_or(Duration::ZERO) < self.cooldown
            {
                return false;
            }
            if !last.contains_key(&key) && last.len() >= self.max_entries {
                evict_last_reported(&mut last, self.cooldown, now, self.max_entries);
            }
            last.insert(key, now);
        }

        if let Some(bus) = &self.bus {
            let ip_text = ip.to_string();
            let user_text = username.map(clip_name).filter(|s| !s.is_empty());
            bus.publish_with(|| {
                let mut event = Event::new(Kind::FileAuthFailed, service);
                event.time = now;
                event.fields.push(("ip", ip_text));
                event.fields.push(("service", service.to_string()));
                if let Some(user) = user_text {
                    event.fields.push(("user", user));
                }
                event
            });
        }
        true
    }

    /// Reports a failed authentication using the configured clock.
    pub fn report_now(&self, service: &'static str, ip: IpAddr, username: Option<&str>) -> bool {
        self.report(service, ip, username, (self.clock)())
    }
}

fn evict_last_reported(
    table: &mut HashMap<IpNet, SystemTime>,
    cooldown: Duration,
    now: SystemTime,
    max_entries: usize,
) {
    table.retain(|_, &mut ts| now.duration_since(ts).unwrap_or(Duration::ZERO) < cooldown);
    while table.len() >= max_entries {
        let oldest = table.iter().min_by_key(|(_, ts)| **ts).map(|(key, _)| *key);
        match oldest {
            Some(key) => {
                table.remove(&key);
            }
            None => break,
        }
    }
}

/// Clips a username safely for logs/events without splitting UTF-8 code points
/// or allowing control characters.
pub fn clip_name(raw: &str) -> String {
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).collect();
    if cleaned.len() <= MAX_USERNAME_FIELD_BYTES {
        return cleaned;
    }
    let end = cleaned.floor_char_boundary(MAX_USERNAME_FIELD_BYTES);
    cleaned[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000 + secs)
    }

    #[test]
    fn throttle_10_failures_in_15min() {
        let throttle = Throttle::new();
        let ip: IpAddr = "203.0.113.10".parse().unwrap();

        for i in 0..9 {
            assert!(throttle.allows(ip, at(i)));
            assert!(!throttle.record_failure(ip, at(i)));
        }
        assert!(throttle.allows(ip, at(9)));
        // 10th failure triggers throttle.
        assert!(throttle.record_failure(ip, at(9)));
        assert!(!throttle.allows(ip, at(10)));

        // Still blocked 14m59s after the first failure (no clear on success).
        assert!(!throttle.allows(ip, at(15 * 60 - 1)));
        // Once the earliest failure ages out (15m after t=0), count drops to 9 -> allowed.
        assert!(throttle.allows(ip, at(15 * 60)));
        assert_eq!(throttle.failure_count(ip, at(15 * 60)), 9);
    }

    #[test]
    fn throttle_v6_per_64() {
        let throttle = Throttle::new();
        let a: IpAddr = "2001:db8:abcd:1234::1".parse().unwrap();
        let b: IpAddr = "2001:db8:abcd:1234:ffff::99".parse().unwrap();
        let other: IpAddr = "2001:db8:abcd:1235::1".parse().unwrap();

        for i in 0..10 {
            let src = if i % 2 == 0 { a } else { b };
            throttle.record_failure(src, at(i));
        }
        assert!(!throttle.allows(a, at(10)));
        assert!(!throttle.allows(b, at(10)));
        assert!(throttle.allows(other, at(10)));

        // IPv4-mapped IPv6 collapses to IPv4.
        let v4: IpAddr = "198.51.100.7".parse().unwrap();
        let mapped: IpAddr = "::ffff:198.51.100.7".parse().unwrap();
        assert_eq!(normalize_source(v4), normalize_source(mapped));
    }

    #[test]
    fn throttle_bounded_evicts_oldest() {
        let throttle = Throttle::with_config(DEFAULT_WINDOW, 10, 4);
        for i in 1u8..=8 {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, i));
            throttle.record_failure(ip, at(u64::from(i)));
        }
        assert!(throttle.tracked_sources() <= 4);
    }

    #[tokio::test]
    async fn fileauth_failed_event_throttled_5s() {
        let bus = EventBus::default();
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let _sub = bus
            .subscribe(move |event| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(event).await;
                }
            })
            .unwrap();

        let reporter = FailureReporter::new(Some(bus));
        let ip: IpAddr = "203.0.113.42".parse().unwrap();

        assert!(reporter.report("webdav", ip, Some("alice"), at(100)));
        assert!(!reporter.report("webdav", ip, Some("alice"), at(102)));
        assert!(!reporter.report("webdav", ip, Some("alice"), at(104)));
        // At +5s it is emitted again.
        assert!(reporter.report("webdav", ip, Some("alice"), at(105)));

        let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let second = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.kind, Kind::FileAuthFailed);
        assert_eq!(first.module, "webdav");
        assert_eq!(second.kind, Kind::FileAuthFailed);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn clip_name_strips_controls_and_bounds_utf8() {
        assert_eq!(clip_name("alice\r\n\0bob"), "alicebob");
        let long = "用户".repeat(30);
        let clipped = clip_name(&long);
        assert!(clipped.len() <= MAX_USERNAME_FIELD_BYTES);
        assert!(clipped.is_char_boundary(clipped.len()));
    }
}
