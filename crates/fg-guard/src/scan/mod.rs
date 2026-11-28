//! Port scan detection state (WP-53): the one-minute per-source window
//! counter behind the kernel meter (WP-53 §3.3). The kernel already
//! throttled the source into the suspect set; the handshake listener
//! feeds each completed handshake on a non-open port into
//! [`ScanCounter::handshake`], and crossing the threshold hands the hit
//! over to the batching ban writer ([`crate::handshake`]).
//!
//! All timing is pure logic over an injected `now`, so the window, the
//! /64 aggregation and the source cap are testable without sleeping.

pub mod strict;

use std::{
    collections::BTreeMap,
    net::IpAddr,
    time::{Duration, SystemTime},
};

use ipnet::IpNet;

pub use strict::{STRICT_GRACE, StrictMode, Verdict, verdict};

/// Collapses IPv4-mapped IPv6 addresses to their IPv4 form (the same
/// normalization the ban table applies).
fn unwrap_v4_mapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

/// The counting window (WP-53 §3.4: upstream `scanWindow`).
pub const SCAN_WINDOW: Duration = Duration::from_secs(60);
/// Default threshold per window (WP-53 §3.4: upstream
/// `defaultScanThreshold`; upstream recommends not going below 10 —
/// normal clients retry a closed port about 5 times a minute).
pub const DEFAULT_SCAN_THRESHOLD: u32 = 12;
/// Upper bound of a configured threshold.
pub const MAX_SCAN_THRESHOLD: u32 = 1000;
/// How many sources are counted at once (WP-53 §3.4: upstream
/// `scanTrackMax`). When full, expired windows are dropped first; only
/// then are new sources left uncounted.
pub const SCAN_TRACK_MAX: usize = 16384;
/// How long the kernel suspect set keeps a source (upstream
/// `suspectSeconds`; rendered into the firewall rules).
pub const SUSPECT_SECONDS: u64 = 600;
/// Handshake hits are merged before the ban table write so one batch
/// produces one notification (upstream `hsBatchDelay`).
pub const HS_BATCH_DELAY: Duration = Duration::from_secs(1);

/// The counting window of one source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanWindow {
    pub start: SystemTime,
    pub n: u32,
    /// The ports hit inside the window, in hit order; capped so the
    /// ban reason stays readable.
    pub ports: Vec<u16>,
}

/// Upper bound of the port list kept per window (the ban reason lists
/// them; everything past the threshold is repetition).
pub const WINDOW_PORTS_MAX: usize = 32;

/// What one completed handshake did to the counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanOutcome {
    /// The hit counted without crossing the threshold.
    Counted,
    /// The window crossed the threshold; the source moves to the
    /// suspect handling and its window resets.
    Triggered { ports: Vec<u16> },
    /// Not counted: the tracker was full even after dropping expired
    /// windows (new sources are left out rather than evicting live
    /// ones).
    Skipped,
}

/// Per-source scan window counter. Sources aggregate: IPv4 by address,
/// IPv6 by /64 (one device scanning ban-jailed the whole prefix the
/// same way the ban table does).
pub struct ScanCounter {
    threshold: u32,
    window: Duration,
    max: usize,
    tracked: BTreeMap<IpNet, ScanWindow>,
}

impl Default for ScanCounter {
    fn default() -> Self {
        Self::new(DEFAULT_SCAN_THRESHOLD)
    }
}

impl ScanCounter {
    /// A counter with the production window and track cap.
    pub fn new(threshold: u32) -> Self {
        Self::with_limits(threshold, SCAN_WINDOW, SCAN_TRACK_MAX)
    }

    /// A counter with explicit limits (tests).
    pub fn with_limits(threshold: u32, window: Duration, max: usize) -> Self {
        Self {
            threshold: threshold.max(1),
            window,
            max,
            tracked: BTreeMap::new(),
        }
    }

    /// How many sources currently have a window.
    pub fn tracked(&self) -> usize {
        self.tracked.len()
    }

    /// The configured threshold (settings saves compare against it).
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// The counting key of a source: /32 for IPv4 (v4-mapped IPv6
    /// collapses to IPv4), /64 for IPv6.
    pub fn key_of(ip: IpAddr) -> IpNet {
        // IpNet::new does not mask the address, so truncate explicitly —
        // otherwise two addresses in the same /64 produce different keys.
        match unwrap_v4_mapped(ip) {
            IpAddr::V4(v4) => IpNet::new(IpAddr::V4(v4), 32).expect("a /32 is always valid"),
            IpAddr::V6(v6) => IpNet::new(IpAddr::V6(v6), 64)
                .expect("a /64 is always valid")
                .trunc(),
        }
    }

    /// Records one completed handshake of `ip` on a non-open `port`.
    pub fn handshake(&mut self, ip: IpAddr, port: u16, now: SystemTime) -> ScanOutcome {
        let key = Self::key_of(ip);
        if let Some(window) = self.tracked.get_mut(&key)
            && now.duration_since(window.start).unwrap_or_default() < self.window
        {
            window.n += 1;
            if window.ports.len() < WINDOW_PORTS_MAX {
                window.ports.push(port);
            }
            return self.finish(key, now);
        }
        // A new source (or an expired window): respect the track cap —
        // drop expired windows first, then leave the new source out.
        if !self.tracked.contains_key(&key) {
            self.drop_expired(now);
            if self.tracked.len() >= self.max {
                return ScanOutcome::Skipped;
            }
        }
        let window = ScanWindow {
            start: now,
            n: 1,
            ports: vec![port],
        };
        self.tracked.insert(key, window);
        self.finish(key, now)
    }

    /// Closes out the window of `key`: threshold reached → `Triggered`
    /// (and the window resets so a post-suspect-timeout source starts
    /// fresh), otherwise `Counted`.
    fn finish(&mut self, key: IpNet, _now: SystemTime) -> ScanOutcome {
        let Some(window) = self.tracked.get(&key) else {
            return ScanOutcome::Skipped;
        };
        if window.n >= self.threshold {
            let ports = window.ports.clone();
            self.tracked.remove(&key);
            return ScanOutcome::Triggered { ports };
        }
        ScanOutcome::Counted
    }

    /// Drops windows older than the counting window.
    fn drop_expired(&mut self, now: SystemTime) {
        self.tracked
            .retain(|_, window| now.duration_since(window.start).unwrap_or_default() < self.window);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("fixture ip")
    }

    #[test]
    fn scan_counter_triggers_after_threshold() {
        let mut counter = ScanCounter::new(3);
        let source = ip("203.0.113.9");
        assert_eq!(counter.handshake(source, 23, at(10)), ScanOutcome::Counted);
        assert_eq!(
            counter.handshake(source, 8080, at(20)),
            ScanOutcome::Counted
        );
        assert_eq!(counter.tracked(), 1);
        let outcome = counter.handshake(source, 3389, at(30));
        assert_eq!(
            outcome,
            ScanOutcome::Triggered {
                ports: vec![23, 8080, 3389]
            },
            "the third hit inside one minute triggers and lists the ports"
        );
        assert_eq!(
            counter.tracked(),
            0,
            "a triggered source leaves the tracker"
        );

        // Outside the window the counting restarts from zero.
        assert_eq!(
            counter.handshake(source, 23, at(10 + 60)),
            ScanOutcome::Counted
        );
    }

    #[test]
    fn scan_counter_windows_expire_after_one_minute() {
        let mut counter = ScanCounter::new(2);
        let source = ip("198.51.100.4");
        assert_eq!(counter.handshake(source, 23, at(0)), ScanOutcome::Counted);
        // Exactly 60 s later the fixed window expired: the new window
        // counts from one again.
        assert_eq!(counter.handshake(source, 24, at(60)), ScanOutcome::Counted);
        // The second port of the fresh window reaches the threshold and
        // lists both ports of that window.
        assert_eq!(
            counter.handshake(source, 25, at(61)),
            ScanOutcome::Triggered {
                ports: vec![24, 25]
            }
        );
        // A triggered window resets, so the next hit starts counting anew.
        assert_eq!(counter.handshake(source, 26, at(62)), ScanOutcome::Counted);
    }

    #[test]
    fn scan_counter_v6_per_64() {
        let mut counter = ScanCounter::new(2);
        let a = ip("2001:db8:aa::1");
        let b = ip("2001:db8:aa::dead");
        assert_eq!(counter.handshake(a, 23, at(0)), ScanOutcome::Counted);
        // The same /64 counts together.
        assert_eq!(
            counter.handshake(b, 8080, at(1)),
            ScanOutcome::Triggered {
                ports: vec![23, 8080]
            }
        );
        // A different /64 keeps its own window.
        let mut counter = ScanCounter::new(2);
        let other = ip("2001:db8:bb::1");
        assert_eq!(counter.handshake(a, 23, at(0)), ScanOutcome::Counted);
        assert_eq!(counter.handshake(other, 23, at(0)), ScanOutcome::Counted);
        assert_eq!(counter.tracked(), 2);
    }

    #[test]
    fn scan_counter_v4_mapped_counts_as_v4() {
        let mut counter = ScanCounter::new(2);
        let mapped = ip("::ffff:203.0.113.9");
        let plain = ip("203.0.113.9");
        assert_eq!(counter.handshake(mapped, 23, at(0)), ScanOutcome::Counted);
        // The mapped form shares the IPv4 window: the plain address
        // reaches the threshold and the trigger lists the mapped hit.
        assert_eq!(
            counter.handshake(plain, 24, at(0)),
            ScanOutcome::Triggered {
                ports: vec![23, 24]
            }
        );
        assert_eq!(
            counter.tracked(),
            0,
            "a triggered window leaves the tracker"
        );
    }

    #[test]
    fn scan_counter_caps_sources_at_16384() {
        let mut counter = ScanCounter::new(12);
        // Fill the tracker with 16384 live windows.
        for step in 0..SCAN_TRACK_MAX as u32 {
            let source = IpAddr::V4(Ipv4Addr::from(step));
            assert_eq!(counter.handshake(source, 23, at(0)), ScanOutcome::Counted);
        }
        assert_eq!(counter.tracked(), SCAN_TRACK_MAX);
        // A new source is skipped, not evicted.
        assert_eq!(
            counter.handshake(ip("203.0.113.9"), 23, at(1)),
            ScanOutcome::Skipped
        );
        assert_eq!(counter.tracked(), SCAN_TRACK_MAX);
        // Once windows expire, the freed slots take new sources again.
        assert_eq!(
            counter.handshake(ip("203.0.113.9"), 23, at(61)),
            ScanOutcome::Counted,
            "the expired windows were dropped first"
        );
    }

    #[test]
    fn scan_counter_window_ports_capped_for_reason() {
        let mut counter = ScanCounter::new(100);
        let source = ip("203.0.113.9");
        for port in 1..=40u16 {
            let _ = counter.handshake(source, port, at(0));
        }
        let outcome = counter.handshake(source, 41, at(1));
        assert!(matches!(outcome, ScanOutcome::Counted));
        // Internally the port list stays bounded.
        let key = ScanCounter::key_of(source);
        let window = counter.tracked.get(&key).expect("window");
        assert_eq!(window.ports.len(), WINDOW_PORTS_MAX);
        assert_eq!(window.n, 41);
    }
}
