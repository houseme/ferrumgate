//! Verification reservation (WP-24 step 4): bcrypt is expensive, so the
//! gates run BEFORE any verification — at most 8 concurrent verifications
//! per source with 64 more queued (overflows reject immediately), and
//! sources with 10 failures inside the 15-minute window are locked out
//! (even correct credentials are refused until the window expires).
//!
//! v1 is a counting model: a queued [`Slot`] marks its holder's place in
//! line but nothing wakes it — promoting a waiter into a running slot is
//! the authenticator wiring batch's concern. Running slots release
//! themselves on drop; queued slots hold their place until
//! [`Reserve::cancel`].
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

/// Failures inside the window before a source is locked.
pub const MAX_FAILURES: u32 = 10;
/// The rolling failure window.
pub const FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Concurrent verifications per source.
pub const MAX_INFLIGHT: usize = 8;
/// Queued verifications per source.
pub const MAX_WAITING: usize = 64;

/// Shared gate state behind an `Arc`: a dropped [`Slot`] must reach the
/// counters it drew its place from.
struct Gates {
    inflight: Mutex<HashMap<IpAddr, usize>>,
    waiting: Mutex<HashMap<IpAddr, usize>>,
    /// (failure count inside the window, window start = first failure).
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

/// Reservation state: per-source concurrency gates and failure counters.
/// Replacing the site table keeps this state (the same object survives).
pub struct Reserve {
    gates: Arc<Gates>,
}

/// Which counter a slot drew from.
enum SlotKind {
    /// One of the MAX_INFLIGHT running positions; released on drop.
    Running,
    /// One of the MAX_WAITING queue positions; held until
    /// [`Reserve::cancel`] (dropping the slot keeps the place).
    Queued,
}

/// A held verification slot; running slots release on drop.
pub struct Slot {
    gates: Arc<Gates>,
    source: IpAddr,
    kind: SlotKind,
}

impl std::fmt::Debug for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Slot")
            .field("source", &self.source)
            .finish()
    }
}

impl Reserve {
    pub fn new() -> Self {
        Self {
            gates: Arc::new(Gates {
                inflight: Mutex::new(HashMap::new()),
                waiting: Mutex::new(HashMap::new()),
                failures: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Acquires a verification slot for the source: up to MAX_INFLIGHT
    /// run at once, the next MAX_WAITING queue (callers block on the
    /// slot's queue entry later — v1 models both counters; the queue
    /// hand-off is the wiring batch's concern), beyond that the attempt
    /// is rejected outright (`None`). The caller refuses the whole
    /// attempt — even correct credentials — while [`Reserve::locked`]
    /// is true, before reaching this.
    pub fn try_acquire(&self, source: IpAddr) -> Option<Slot> {
        let source = source_key(source);
        let running = {
            let mut inflight = self.gates.inflight.lock().expect("reserve inflight lock");
            let held = inflight.entry(source).or_default();
            if *held >= MAX_INFLIGHT {
                false
            } else {
                *held += 1;
                true
            }
        };
        if running {
            return Some(Slot {
                gates: Arc::clone(&self.gates),
                source,
                kind: SlotKind::Running,
            });
        }
        let mut waiting = self.gates.waiting.lock().expect("reserve waiting lock");
        let queued = waiting.entry(source).or_default();
        if *queued >= MAX_WAITING {
            return None;
        }
        *queued += 1;
        Some(Slot {
            gates: Arc::clone(&self.gates),
            source,
            kind: SlotKind::Queued,
        })
    }

    /// Explicitly releases a queue position (a caller that gave up).
    /// A queued [`Slot`] does not release on drop — cancel it here. A
    /// running slot releases itself on drop and must not be cancelled.
    pub fn cancel(&self, source: IpAddr) {
        let mut waiting = self.gates.waiting.lock().expect("reserve waiting lock");
        release_slot(&mut waiting, source_key(source));
    }

    /// Records an authentication failure, starting/advancing the window.
    /// The window starts at the first failure; a failure after the
    /// window lapsed restarts the count at one.
    pub fn record_failure(&self, source: IpAddr, now: Instant) {
        let mut failures = self.gates.failures.lock().expect("reserve failures lock");
        let window = failures.entry(source_key(source)).or_insert((0, now));
        if now >= window.1 + FAILURE_WINDOW {
            *window = (1, now);
        } else {
            window.0 += 1;
        }
    }

    /// Is the source locked out at `now` (failures >= MAX_FAILURES inside
    /// the window)? A locked source stays locked until the window ends;
    /// callers must refuse its attempts (even correct credentials) while
    /// this is true.
    pub fn locked(&self, source: IpAddr, now: Instant) -> bool {
        let failures = self.gates.failures.lock().expect("reserve failures lock");
        failures
            .get(&source_key(source))
            .is_some_and(|&(count, start)| count >= MAX_FAILURES && now < start + FAILURE_WINDOW)
    }

    /// Clears the counters once the window has passed (housekeeping;
    /// `locked` also ignores lapsed entries when read).
    pub fn expire(&self, now: Instant) {
        let mut failures = self.gates.failures.lock().expect("reserve failures lock");
        failures.retain(|_, (_, start)| now < *start + FAILURE_WINDOW);
    }
}

impl Default for Reserve {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if matches!(self.kind, SlotKind::Running) {
            let mut inflight = self.gates.inflight.lock().expect("reserve inflight lock");
            release_slot(&mut inflight, self.source);
        }
        // Queued positions stay held until `Reserve::cancel` — see Slot.
    }
}

/// Counts one slot down and forgets the source once its counter hits
/// zero (matching `source_quota.rs`).
fn release_slot(counter: &mut HashMap<IpAddr, usize>, source: IpAddr) {
    if let Some(held) = counter.get_mut(&source) {
        *held -= 1;
        if *held == 0 {
            counter.remove(&source);
        }
    }
}

/// IPv6 sources ban by /64 (the auto-ban table is WP-26's; this helper
/// is the key normalization shared with it): the low 64 bits are zeroed,
/// IPv4 (incl. v4-mapped IPv6, via `to_canonical`) is kept verbatim.
pub fn source_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(address) => IpAddr::V4(address),
        IpAddr::V6(address) => {
            let mut octets = address.octets();
            octets[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

/// Unix/Instant bridge for tests: wall-clock failures recorded with
/// Instant; the auto-ban event carries SystemTime (see WP-26). Stamps
/// are mapped linearly onto the monotonic timeline anchored at the
/// first call; absurd values clamp to that anchor.
pub fn instant_of(now: SystemTime) -> Instant {
    static ANCHOR: OnceLock<(SystemTime, Instant)> = OnceLock::new();
    let (epoch, monotonic) = *ANCHOR.get_or_init(|| (SystemTime::now(), Instant::now()));
    if now >= epoch {
        monotonic
            .checked_add(now.duration_since(epoch).unwrap_or_default())
            .unwrap_or(monotonic)
    } else {
        monotonic
            .checked_sub(epoch.duration_since(now).unwrap_or_default())
            .unwrap_or(monotonic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(address: &str) -> IpAddr {
        IpAddr::V6(address.parse().expect("valid test address"))
    }

    #[test]
    fn inflight_and_queue_limits_enforced() {
        let reserve = Reserve::new();
        let ip = v4(192, 168, 10, 1);

        let mut slots = Vec::new();
        for _ in 0..MAX_INFLIGHT {
            slots.push(
                reserve
                    .try_acquire(ip)
                    .expect("the first 8 verifications run"),
            );
        }
        for _ in 0..MAX_WAITING {
            slots.push(
                reserve
                    .try_acquire(ip)
                    .expect("the next 64 queue behind them"),
            );
        }
        assert!(
            reserve.try_acquire(ip).is_none(),
            "the 73rd is rejected outright"
        );

        // The gates are per source: another IP is unaffected.
        let other = reserve
            .try_acquire(v4(192, 168, 10, 2))
            .expect("other sources are gated separately");
        drop(other);

        // Dropping a running slot frees a running position, which the
        // next attempt takes; the queue is still full, so the attempt
        // after that is rejected again.
        drop(slots.remove(0));
        let rerun = reserve
            .try_acquire(ip)
            .expect("freed running position is reusable");
        assert!(reserve.try_acquire(ip).is_none());
        slots.push(rerun);

        // `cancel` frees one queued position, then the gates are full again.
        reserve.cancel(ip);
        slots.push(
            reserve
                .try_acquire(ip)
                .expect("cancelled queue position is reusable"),
        );
        assert!(reserve.try_acquire(ip).is_none());

        // Running slots release on drop, queued ones via cancel: after
        // a full drain everything is acquirable again.
        let queued = slots.len() - MAX_INFLIGHT;
        drop(slots);
        for _ in 0..queued {
            reserve.cancel(ip);
        }
        let mut refill = Vec::new();
        for _ in 0..MAX_INFLIGHT + MAX_WAITING {
            refill.push(reserve.try_acquire(ip).expect("gates drained fully"));
        }
        assert!(reserve.try_acquire(ip).is_none());
    }

    #[test]
    fn queued_positions_release_through_cancel_not_drop() {
        let reserve = Reserve::new();
        let ip = v4(192, 168, 20, 1);

        let mut slots = Vec::new();
        for _ in 0..MAX_INFLIGHT + MAX_WAITING {
            slots.push(
                reserve
                    .try_acquire(ip)
                    .expect("8 running plus 64 queued fit"),
            );
        }
        assert!(reserve.try_acquire(ip).is_none());

        let queued = slots.pop().expect("a queued slot is held");
        drop(queued);
        assert!(
            reserve.try_acquire(ip).is_none(),
            "dropping a queued slot keeps the position held"
        );

        reserve.cancel(ip);
        assert!(
            reserve.try_acquire(ip).is_some(),
            "cancel frees one queued position"
        );
        assert!(
            reserve.try_acquire(ip).is_none(),
            "only one position was freed"
        );
    }

    #[test]
    fn auth_failures_locked_after_ten_in_15min() {
        let reserve = Reserve::new();
        let ip = v4(203, 0, 113, 10);
        let other = v4(203, 0, 113, 11);
        let start = Instant::now();

        for _ in 0..MAX_FAILURES - 1 {
            reserve.record_failure(ip, start);
        }
        assert!(!reserve.locked(ip, start), "nine failures do not lock yet");

        reserve.record_failure(ip, start);
        assert!(
            reserve.locked(ip, start),
            "the tenth failure locks the source"
        );
        assert!(
            reserve.locked(ip, start + FAILURE_WINDOW - Duration::from_secs(1)),
            "the lockout holds for the rest of the window"
        );
        assert!(
            !reserve.locked(other, start),
            "other sources are unaffected"
        );
    }

    #[test]
    fn failure_window_expiry_recovers_access() {
        let reserve = Reserve::new();
        let ip = v4(203, 0, 113, 20);
        let start = Instant::now();

        // Failures spread over five minutes: the window starts at the
        // FIRST failure, not the last.
        for i in 0..MAX_FAILURES {
            reserve.record_failure(ip, start + Duration::from_secs(u64::from(i) * 30));
        }
        let lapses = start + FAILURE_WINDOW;
        assert!(reserve.locked(ip, lapses - Duration::from_secs(1)));
        assert!(
            !reserve.locked(ip, lapses),
            "the window lapses 15 minutes after the first failure"
        );
        assert!(
            reserve.try_acquire(ip).is_some(),
            "access is restored once unlocked"
        );

        // A failure after the lapse restarts the window at count one.
        reserve.record_failure(ip, lapses);
        assert!(
            !reserve.locked(ip, lapses + FAILURE_WINDOW - Duration::from_secs(1)),
            "a fresh window counts its own failures only"
        );
        for _ in 0..MAX_FAILURES - 1 {
            reserve.record_failure(ip, lapses);
        }
        assert!(reserve.locked(ip, lapses));
        assert!(!reserve.locked(ip, lapses + FAILURE_WINDOW));

        // `expire` drops the lapsed entries as housekeeping.
        reserve.expire(lapses + FAILURE_WINDOW);
        assert!(
            reserve
                .gates
                .failures
                .lock()
                .expect("reserve failures lock")
                .is_empty()
        );
    }

    #[test]
    fn source_key_folds_ipv6_into_slash_sixty_four_buckets() {
        let folded = v6("2001:db8:1:2::");
        assert_eq!(
            source_key(v6("2001:db8:1:2:3:4:5:6")),
            folded,
            "low 64 bits zeroed"
        );
        assert_eq!(
            source_key(v6("2001:db8:1:2:aabb:ccdd:11ff:2233")),
            folded,
            "the same /64 folds to one key"
        );
        assert_ne!(source_key(v6("2001:db8:1:3::1")), folded);

        let ipv4 = v4(203, 0, 113, 7);
        assert_eq!(source_key(ipv4), ipv4, "IPv4 is kept verbatim");
        // v4-mapped IPv6 collapses onto the IPv4 address.
        assert_eq!(source_key(v6("::ffff:203.0.113.7")), ipv4);
    }

    #[test]
    fn ipv6_failures_share_one_slash_sixty_four_bucket() {
        let reserve = Reserve::new();
        let first = v6("2001:db8:aaaa::4f2:1");
        let second = v6("2001:db8:aaaa::9c8:ff");
        let elsewhere = v6("2001:db8:bbbb::1");
        let start = Instant::now();

        for _ in 0..MAX_FAILURES {
            reserve.record_failure(first, start);
        }
        assert!(
            reserve.locked(second, start),
            "the whole /64 is locked together"
        );
        assert!(
            !reserve.locked(elsewhere, start),
            "a different /64 is unaffected"
        );
    }

    #[test]
    fn instant_of_maps_wall_clock_monotonically() {
        let now = SystemTime::now();
        let later = now + Duration::from_secs(60);
        let mapped_now = instant_of(now);
        let mapped_later = instant_of(later);
        assert!(mapped_later >= mapped_now);
        assert_eq!(
            mapped_later.duration_since(mapped_now),
            Duration::from_secs(60)
        );
    }
}
