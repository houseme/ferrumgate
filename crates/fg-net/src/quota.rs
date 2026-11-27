//! Per-port and per-source connection quotas (WP-36).
//!
//! `PortQuota` caps concurrent connections on one listening port;
//! `SourceQuota` caps them per source (IPv4 address or IPv6 /64), always
//! exempting loopback and internal sources. Permits release their slot on
//! drop, mirroring the gateway's `SourceLease`.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicI32, Ordering},
    },
    time::{Duration, Instant},
};

use crate::client_addr::is_internal;

/// Cap on the number of tracked source groups, so a flood of distinct
/// addresses cannot grow the table without bound.
const MAX_GROUPS: usize = 4096;

/// Minimum spacing between two `should_warn` reports.
const WARN_INTERVAL: Duration = Duration::from_secs(10);

/// Per-port concurrent-connection ceiling.
pub struct PortQuota {
    max: u32,
    active: Arc<AtomicI32>,
}

impl PortQuota {
    pub fn new(max: u32) -> Self {
        Self {
            max,
            active: Arc::new(AtomicI32::new(0)),
        }
    }

    /// Acquire one slot if `active < max`; released on drop.
    pub fn try_acquire(&self) -> Option<PortPermit> {
        self.active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.max as i32).then_some(active + 1)
            })
            .ok()
            .map(|_| PortPermit {
                active: Arc::clone(&self.active),
            })
    }

    /// Currently held slots.
    pub fn active(&self) -> u32 {
        self.active.load(Ordering::Acquire).max(0) as u32
    }
}

/// One held per-port slot; releases it on drop.
pub struct PortPermit {
    active: Arc<AtomicI32>,
}

impl Drop for PortPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Per-source concurrent-connection quota: one source (IPv4 address or
/// IPv6 /64) may hold at most `limit` connections on one port; loopback and
/// internal sources are always exempt, as are `exempt` ranges.
pub struct SourceQuota {
    limit: u32,
    exempt: Vec<ipnet::IpNet>,
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    last_warn: Mutex<Option<Instant>>,
}

pub enum QuotaResult {
    Acquired(SourcePermit),
    Full,
    Exempt,
}

/// One held per-source slot; releases it on drop (removes the group's
/// entry once its count reaches zero, mirroring `SourceLease`).
pub struct SourcePermit {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    group: IpAddr,
}

impl Drop for SourcePermit {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().expect("source quota lock");
        if let Some(count) = counts.get_mut(&self.group) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.group);
            }
        }
    }
}

impl SourceQuota {
    /// `max` is the port's total connection limit; when `half_default` the
    /// per-source limit is `max / 2` (at least 1). Loopback and internal
    /// sources (`fg_net::client_addr::is_internal`) are exempt, as are
    /// addresses inside `exempt`.
    pub fn new(max: u32, half_default: bool, exempt: Vec<ipnet::IpNet>) -> Self {
        let limit = if half_default { (max / 2).max(1) } else { max };
        Self {
            limit,
            exempt,
            counts: Arc::new(Mutex::new(HashMap::new())),
            last_warn: Mutex::new(None),
        }
    }

    /// IPv6 sources group by /64, IPv4-mapped addresses canonicalize to
    /// their IPv4 form first. The counts table caps at `MAX_GROUPS`: when
    /// full, idle (zero-count) entries are evicted first and a still-full
    /// table rejects the new group as `Full`.
    pub fn try_acquire(&self, peer: IpAddr) -> QuotaResult {
        let canonical = peer.to_canonical();
        if is_internal(canonical) || self.exempt.iter().any(|net| net.contains(&canonical)) {
            return QuotaResult::Exempt;
        }
        let group = source_group(peer);
        let mut counts = self.counts.lock().expect("source quota lock");
        if counts.len() >= MAX_GROUPS && !counts.contains_key(&group) {
            counts.retain(|_, count| *count > 0);
            if counts.len() >= MAX_GROUPS {
                return QuotaResult::Full;
            }
        }
        let count = counts.entry(group).or_default();
        if *count >= self.limit as usize {
            return QuotaResult::Full;
        }
        *count += 1;
        QuotaResult::Acquired(SourcePermit {
            counts: Arc::clone(&self.counts),
            group,
        })
    }

    /// At most one warning per 10 seconds; the first call records `now`.
    pub fn should_warn(&self, now: Instant) -> bool {
        let mut last_warn = self.last_warn.lock().expect("source quota warn lock");
        let due = last_warn.is_none_or(|at| now.saturating_duration_since(at) >= WARN_INTERVAL);
        if due {
            *last_warn = Some(now);
        }
        due
    }
}

/// IPv6 groups by /64; IPv4-mapped addresses canonicalize to IPv4 first
/// (so `::ffff:192.0.2.1` and `192.0.2.1` share one group).
fn source_group(address: IpAddr) -> IpAddr {
    match address.to_canonical() {
        IpAddr::V4(address) => IpAddr::V4(address),
        IpAddr::V6(address) => IpAddr::V6(Ipv6Addr::from(u128::from(address) & (u128::MAX << 64))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> ipnet::IpNet {
        text.parse().expect("valid CIDR")
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("valid address")
    }

    #[test]
    fn quota_half_default_and_exemption() {
        let quota = SourceQuota::new(10, true, vec![net("198.51.100.0/24")]);

        // Half default: 10 → 5 per source. The 6th connection from one
        // source is Full while another source still succeeds.
        let source_a = ip("203.0.113.10");
        let mut holds = Vec::new();
        for _ in 0..5 {
            let permit = quota.try_acquire(source_a);
            assert!(
                matches!(permit, QuotaResult::Acquired(_)),
                "connections 1..=5 succeed"
            );
            holds.push(permit);
        }
        assert!(matches!(quota.try_acquire(source_a), QuotaResult::Full));
        assert!(matches!(
            quota.try_acquire(ip("203.0.113.11")),
            QuotaResult::Acquired(_)
        ));
        drop(holds);

        // An exempt CIDR source is never Full, even far beyond the limit.
        let exempt_source = ip("198.51.100.7");
        for _ in 0..50 {
            let result = quota.try_acquire(exempt_source);
            assert!(
                matches!(result, QuotaResult::Exempt),
                "exempt source is never limited"
            );
        }
        // An address just outside the exempt range is counted normally.
        let outside = ip("198.51.101.7");
        let mut holds = Vec::new();
        for _ in 0..5 {
            holds.push(quota.try_acquire(outside));
        }
        assert!(matches!(quota.try_acquire(outside), QuotaResult::Full));
    }

    #[test]
    fn quota_loopback_private_exempt() {
        let quota = SourceQuota::new(1, false, vec![]);
        for internal in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.0.2",
            "100.100.0.1", // carrier-grade NAT
            "fd00::1",     // IPv6 unique-local
        ] {
            for _ in 0..3 {
                assert!(
                    matches!(quota.try_acquire(ip(internal)), QuotaResult::Exempt),
                    "{internal} should be exempt"
                );
            }
        }
        // A public source is counted: limit 1, so the second is Full.
        let public = ip("203.0.113.1");
        let permit = quota.try_acquire(public);
        assert!(matches!(permit, QuotaResult::Acquired(_)));
        assert!(matches!(quota.try_acquire(public), QuotaResult::Full));
    }

    #[test]
    fn quota_v6_counted_per_64() {
        let quota = SourceQuota::new(1, false, vec![]);

        // Same /64 is one group; a different /64 is independent.
        let hold = quota.try_acquire(ip("2001:db8:1:2::1"));
        assert!(matches!(hold, QuotaResult::Acquired(_)));
        assert!(matches!(
            quota.try_acquire(ip("2001:db8:1:2::2")),
            QuotaResult::Full
        ));
        assert!(matches!(
            quota.try_acquire(ip("2001:db8:1:3::1")),
            QuotaResult::Acquired(_)
        ));
        drop(hold);
        assert!(matches!(
            quota.try_acquire(ip("2001:db8:1:2::2")),
            QuotaResult::Acquired(_)
        ));

        // IPv4-mapped addresses count with their IPv4 form.
        let mapped = quota.try_acquire(ip("::ffff:192.0.2.1"));
        assert!(matches!(mapped, QuotaResult::Acquired(_)));
        assert!(matches!(
            quota.try_acquire(ip("192.0.2.1")),
            QuotaResult::Full
        ));
        assert!(matches!(
            quota.try_acquire(ip("192.0.2.2")),
            QuotaResult::Acquired(_)
        ));
    }

    #[test]
    fn quota_released_on_finish_or_cancel() {
        let quota = SourceQuota::new(1, false, vec![]);
        let public = ip("203.0.113.1");
        let permit = quota.try_acquire(public);
        assert!(matches!(permit, QuotaResult::Acquired(_)));
        assert!(matches!(quota.try_acquire(public), QuotaResult::Full));
        // Dropping the permit frees the slot.
        drop(permit);
        let again = quota.try_acquire(public);
        assert!(matches!(again, QuotaResult::Acquired(_)));
        drop(again);
        assert!(matches!(
            quota.try_acquire(public),
            QuotaResult::Acquired(_)
        ));

        // The port-level quota behaves the same.
        let port = PortQuota::new(1);
        let slot = port.try_acquire();
        assert!(slot.is_some());
        assert_eq!(port.active(), 1);
        assert!(port.try_acquire().is_none());
        drop(slot);
        assert_eq!(port.active(), 0);
        assert!(port.try_acquire().is_some());
    }

    #[test]
    fn quota_warn_throttled_10s() {
        let quota = SourceQuota::new(10, false, vec![]);
        let start = Instant::now();
        assert!(quota.should_warn(start));
        assert!(!quota.should_warn(start + Duration::from_secs(5)));
        assert!(quota.should_warn(start + Duration::from_secs(11)));
    }
}
