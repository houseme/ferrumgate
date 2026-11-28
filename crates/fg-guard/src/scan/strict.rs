//! IPv6 strict mode (WP-53 §3.3): the whitelist-style detection — an
//! IPv6 source may only connect open ports; the first connection to any
//! other port is banned outright instead of being counted against the
//! threshold. IPv4 sources keep threshold detection.
//!
//! Timing caveats (all covered by [`StrictMode::active`] and the
//! handshake handler):
//!
//! - enabling strict mode (or a restart) carries a grace period of
//!   [`STRICT_GRACE`] during which IPv6 still counts by threshold — the
//!   listener table needs a moment to fill (other programs' ports lag
//!   up to one poll interval behind);
//! - when the system listener table is unavailable (non-Linux) strict
//!   mode cannot distinguish open from closed ports and stays off: the
//!   handler falls back to threshold detection for everyone.

use std::{
    net::IpAddr,
    time::{Duration, SystemTime},
};

/// The grace period after enabling strict mode / restarting (WP-53
/// §3.4: upstream `strictGrace`).
pub const STRICT_GRACE: Duration = Duration::from_secs(15);

/// Whether strict mode is switched on and past its grace period.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrictMode {
    enabled: bool,
    enabled_at: Option<SystemTime>,
    grace: Duration,
}

impl Default for StrictMode {
    fn default() -> Self {
        Self {
            enabled: false,
            enabled_at: None,
            grace: STRICT_GRACE,
        }
    }
}

impl StrictMode {
    /// Sets the switch; enabling stamps the grace start at `now`.
    pub fn new(enabled: bool, now: SystemTime) -> Self {
        Self {
            enabled,
            enabled_at: enabled.then_some(now),
            grace: STRICT_GRACE,
        }
    }

    /// Applies a new enablement; re-enabling restarts the grace period.
    pub fn set_enabled(&mut self, enabled: bool, now: SystemTime) {
        if enabled == self.enabled {
            return;
        }
        self.enabled = enabled;
        self.enabled_at = enabled.then_some(now);
    }

    /// Whether the switch is on (independent of the grace period).
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Whether strict bans may fire yet: enabled *and* the grace period
    /// has fully elapsed.
    pub fn active(&self, now: SystemTime) -> bool {
        self.enabled
            && self
                .enabled_at
                .is_some_and(|at| now.duration_since(at).unwrap_or_default() >= self.grace)
    }
}

/// What the detector does with a handshake on a non-open port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// IPv6 strict mode: ban immediately, no counting.
    StrictBan,
    /// Feed the threshold counter (IPv4 always; IPv6 during grace or
    /// without listener data).
    Count,
}

/// The strict-mode decision for one handshake. `strict_active` is
/// [`StrictMode::active`]; `port_open` is false only when the open-port
/// table is available *and* the port is not in it (without the table the
/// caller passes nothing: everyone counts).
pub fn verdict(strict_active: bool, ip: IpAddr, port_open: bool) -> Verdict {
    if strict_active && !port_open && ip.is_ipv6() {
        return Verdict::StrictBan;
    }
    Verdict::Count
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn strict_first_hit_triggers() {
        // IPv6: the first handshake on a non-open port bans outright.
        let v6: IpAddr = "2001:db8:aa::1".parse().unwrap();
        assert_eq!(verdict(true, v6, false), Verdict::StrictBan);
        assert_eq!(
            verdict(true, v6, true),
            Verdict::Count,
            "open ports are free"
        );
        // IPv4 keeps threshold detection.
        let v4: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(verdict(true, v4, false), Verdict::Count);
        // Without the strict flag everyone counts.
        assert_eq!(verdict(false, v6, false), Verdict::Count);
    }

    #[test]
    fn strict_grace_15s_after_enable() {
        let now = at(100);
        let mut strict = StrictMode::new(false, now);
        assert!(!strict.active(now), "off by default");

        strict.set_enabled(true, now);
        assert!(strict.enabled());
        assert!(
            !strict.active(now + Duration::from_secs(14)),
            "inside the grace window IPv6 still counts by threshold"
        );
        assert!(
            strict.active(now + STRICT_GRACE),
            "exactly after the grace period strict bans fire"
        );

        // Disabling and re-enabling restarts the grace.
        strict.set_enabled(false, now + Duration::from_secs(20));
        strict.set_enabled(true, now + Duration::from_secs(21));
        assert!(!strict.active(now + Duration::from_secs(30)));
        assert!(strict.active(now + Duration::from_secs(21) + STRICT_GRACE));
    }
}
