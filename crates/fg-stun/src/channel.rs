//! Channel state machine (WP-42 §3.2, pure logic): `Binding → Mapped →
//! Checking → Ready`, mapping changes fall back to the check phase and
//! notify, keep-alive failures enter `Lost` where `autoRetry` decides
//! whether the channel retries on its own or waits for a manual restart.
//! All methods take an injected `now`, so timing behavior is unit-testable
//! without a real clock.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use crate::model::{Rule, limits};

/// Timing inputs for [`Channel::tick`], derived from a rule plus the
/// module's address check interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timings {
    /// Binding heartbeat period (mapping keep-alive).
    pub heartbeat: Duration,
    /// Delay before retrying after a failed round.
    pub retry: Duration,
    /// Reachability re-check period (module `addrCheckInterval`).
    pub check: Duration,
    /// Single binding transaction window.
    pub stun_timeout: Duration,
    /// Skip the reachability check (hairpin NAT escape hatch).
    pub disable_check: bool,
    /// Retry failed rounds automatically; off parks the channel until a
    /// manual restart.
    pub auto_retry: bool,
}

impl Timings {
    /// Derives the timings from a rule; values are defensively clamped to
    /// the same floors `normalize` applies.
    pub fn from_rule(rule: &Rule, addr_check_interval_secs: u32) -> Self {
        let interval = |value: u32| -> Duration {
            let ms = match value {
                0 => limits::INTERVAL_DEFAULT_MS,
                below if below < limits::INTERVAL_MIN_MS => limits::INTERVAL_MIN_MS,
                value => value,
            };
            Duration::from_millis(u64::from(ms))
        };
        let check = if addr_check_interval_secs < limits::ADDR_CHECK_INTERVAL_MIN_SECS {
            limits::ADDR_CHECK_INTERVAL_DEFAULT_SECS
        } else {
            addr_check_interval_secs
        };
        Self {
            heartbeat: interval(rule.heartbeat_interval),
            retry: interval(rule.retry_interval),
            check: Duration::from_secs(u64::from(check)),
            stun_timeout: interval(rule.stun_timeout),
            disable_check: rule.disable_check,
            auto_retry: rule.auto_retry,
        }
    }
}

/// Channel lifecycle states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelState {
    /// Binding in progress (or waiting for the next attempt).
    Binding,
    /// A mapping was learned; the reachability check has not succeeded
    /// yet.
    Mapped { addr: SocketAddr, since: SystemTime },
    /// The reachability check is running (distinguishes full-cone from
    /// symmetric mappings).
    Checking { addr: SocketAddr, since: SystemTime },
    /// The mapping is alive and confirmed reachable from the outside.
    Ready {
        public: SocketAddr,
        since: SystemTime,
    },
    /// The mapping could not be established or was lost. `retry_at` is
    /// `None` when `autoRetry` is off: only a manual restart resumes.
    Lost {
        reason: String,
        retry_at: Option<SystemTime>,
    },
}

impl ChannelState {
    /// Stable snapshot name (`binding` / `mapped` / `checking` / `ready` /
    /// `lost`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Binding => "binding",
            Self::Mapped { .. } => "mapped",
            Self::Checking { .. } => "checking",
            Self::Ready { .. } => "ready",
            Self::Lost { .. } => "lost",
        }
    }

    /// The currently mapped public endpoint, when one is known.
    pub fn mapped(&self) -> Option<SocketAddr> {
        match self {
            Self::Mapped { addr, .. }
            | Self::Checking { addr, .. }
            | Self::Ready { public: addr, .. } => Some(*addr),
            _ => None,
        }
    }

    /// When the current mapping was learned.
    pub fn since(&self) -> Option<SystemTime> {
        match self {
            Self::Mapped { since, .. }
            | Self::Checking { since, .. }
            | Self::Ready { since, .. } => Some(*since),
            _ => None,
        }
    }
}

/// What the last operation changed; the runtime reacts by publishing the
/// snapshot and firing notifications.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transition {
    /// Nothing worth publishing.
    None,
    /// A mapping was learned (first time or after being lost).
    Mapped { addr: SocketAddr },
    /// The public endpoint changed: notification due, re-check follows.
    Changed { old: SocketAddr, new: SocketAddr },
    /// The mapping was confirmed reachable.
    Ready { addr: SocketAddr },
    /// The mapping was lost.
    Lost { reason: String },
}

/// What the channel wants the runtime to do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    SendBinding,
    Check,
}

/// Per-rule channel: owns the state plus heartbeat / check pacing.
#[derive(Debug)]
pub struct Channel {
    state: ChannelState,
    /// Start of the last binding round.
    last_attempt: Option<SystemTime>,
    /// Start of the last reachability check.
    last_check: Option<SystemTime>,
    /// Consecutive failed binding rounds.
    failures: u32,
    /// Consecutive failed reachability checks for the current mapping.
    check_failures: u32,
}

impl Channel {
    /// A fresh channel in [`ChannelState::Binding`].
    pub fn new(_now: SystemTime) -> Self {
        Self {
            state: ChannelState::Binding,
            last_attempt: None,
            last_check: None,
            failures: 0,
            check_failures: 0,
        }
    }

    /// The current state.
    pub fn state(&self) -> &ChannelState {
        &self.state
    }

    /// Consecutive failed binding rounds since the last success.
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Records the start of a binding round; a `Lost` channel resumes as
    /// [`ChannelState::Binding`] (the manual restart path).
    pub fn mark_attempt(&mut self, now: SystemTime) {
        self.last_attempt = Some(now);
        if matches!(self.state, ChannelState::Lost { .. }) {
            self.state = ChannelState::Binding;
        }
    }

    /// Records the start of a reachability check; `Mapped` becomes
    /// `Checking` and `Ready` is demoted for the duration of the probe.
    pub fn mark_check(&mut self, now: SystemTime) {
        self.last_check = Some(now);
        match self.state.clone() {
            ChannelState::Mapped { addr, since } => {
                self.state = ChannelState::Checking { addr, since };
            }
            ChannelState::Ready { public, since } => {
                self.state = ChannelState::Checking {
                    addr: public,
                    since,
                };
            }
            _ => {}
        }
    }

    /// A binding round answered: learn (or update) the mapping. A changed
    /// endpoint yields [`Transition::Changed`] (the notification) and
    /// re-enters the check phase. With `disableCheck` the channel goes
    /// straight to `Ready`.
    pub fn on_mapped(&mut self, addr: SocketAddr, now: SystemTime, timing: &Timings) -> Transition {
        self.failures = 0;
        match self.state.clone() {
            ChannelState::Binding | ChannelState::Lost { .. } => {
                self.check_failures = 0;
                self.last_check = None;
                if timing.disable_check {
                    self.state = ChannelState::Ready {
                        public: addr,
                        since: now,
                    };
                    Transition::Ready { addr }
                } else {
                    self.state = ChannelState::Mapped { addr, since: now };
                    Transition::Mapped { addr }
                }
            }
            ChannelState::Mapped { addr: old, .. }
            | ChannelState::Checking { addr: old, .. }
            | ChannelState::Ready { public: old, .. } => {
                if old == addr {
                    return Transition::None;
                }
                self.check_failures = 0;
                self.last_check = None;
                if timing.disable_check {
                    self.state = ChannelState::Ready {
                        public: addr,
                        since: now,
                    };
                } else {
                    self.state = ChannelState::Checking { addr, since: now };
                }
                Transition::Changed { old, new: addr }
            }
        }
    }

    /// A binding round failed: count the failure and move to `Lost`,
    /// scheduling a retry only when `autoRetry` is on.
    pub fn on_timeout(&mut self, now: SystemTime, timing: &Timings) -> Transition {
        self.failures = self.failures.saturating_add(1);
        let had_mapping = self.state.mapped().is_some();
        let reason = if had_mapping {
            "保活失败，无法更新映射"
        } else {
            "无法获取映射地址"
        };
        self.state = ChannelState::Lost {
            reason: reason.to_owned(),
            retry_at: timing.auto_retry.then(|| now + timing.retry),
        };
        Transition::Lost {
            reason: reason.to_owned(),
        }
    }

    /// The reachability check answered. Failures tolerate
    /// [`limits::CHECK_FAILURES_BEFORE_LOST`] strikes before the channel
    /// gives up.
    pub fn on_check(&mut self, ok: bool, now: SystemTime, timing: &Timings) -> Transition {
        self.last_check = Some(now);
        let ChannelState::Checking { addr, since } = self.state.clone() else {
            return Transition::None;
        };
        if ok {
            self.check_failures = 0;
            self.state = ChannelState::Ready {
                public: addr,
                since,
            };
            return Transition::Ready { addr };
        }
        self.check_failures += 1;
        if self.check_failures >= limits::CHECK_FAILURES_BEFORE_LOST {
            let reason = "映射端口从外部不可达".to_owned();
            self.state = ChannelState::Lost {
                reason: reason.clone(),
                retry_at: timing.auto_retry.then(|| now + timing.retry),
            };
            return Transition::Lost { reason };
        }
        // Keep the mapping and let the heartbeat continue; the check is
        // re-run once the period elapses.
        self.state = ChannelState::Mapped { addr, since };
        Transition::None
    }

    /// What the runtime should do now.
    pub fn tick(&self, now: SystemTime, timing: &Timings) -> Vec<Action> {
        let mut actions = Vec::new();
        match &self.state {
            ChannelState::Binding => {
                if self.heartbeat_due(now, timing) {
                    actions.push(Action::SendBinding);
                }
            }
            ChannelState::Lost { retry_at, .. } => {
                if retry_at.is_some_and(|at| now >= at) {
                    actions.push(Action::SendBinding);
                }
            }
            ChannelState::Mapped { .. } | ChannelState::Ready { .. } => {
                if self.heartbeat_due(now, timing) {
                    actions.push(Action::SendBinding);
                }
                if !timing.disable_check && self.check_due(now, timing) {
                    actions.push(Action::Check);
                }
            }
            ChannelState::Checking { .. } => {}
        }
        actions
    }

    /// The earliest point where [`Channel::tick`] would produce an action;
    /// the runtime sleeps until then.
    pub fn next_deadline(&self, timing: &Timings, now: SystemTime) -> Option<SystemTime> {
        match &self.state {
            ChannelState::Binding | ChannelState::Mapped { .. } | ChannelState::Ready { .. } => {
                let heartbeat = self.last_attempt.map(|at| at + timing.heartbeat);
                let check = (!timing.disable_check)
                    .then(|| self.last_check.map_or(now, |at| at + timing.check));
                match (heartbeat, check) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                }
            }
            ChannelState::Lost { retry_at, .. } => *retry_at,
            ChannelState::Checking { .. } => Some(now + timing.stun_timeout),
        }
    }

    fn heartbeat_due(&self, now: SystemTime, timing: &Timings) -> bool {
        self.last_attempt
            .is_none_or(|at| now >= at + timing.heartbeat)
    }

    fn check_due(&self, now: SystemTime, timing: &Timings) -> bool {
        self.last_check.is_none_or(|at| now >= at + timing.check)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port)
    }

    fn epoch() -> SystemTime {
        SystemTime::UNIX_EPOCH
    }

    fn after(ms: u64) -> SystemTime {
        epoch() + Duration::from_millis(ms)
    }

    fn timings() -> Timings {
        Timings {
            heartbeat: Duration::from_millis(3000),
            retry: Duration::from_millis(3000),
            check: Duration::from_millis(60_000),
            stun_timeout: Duration::from_millis(3000),
            disable_check: false,
            auto_retry: true,
        }
    }

    #[test]
    fn channel_transitions_binding_to_ready() {
        let timing = timings();
        let mut channel = Channel::new(epoch());
        // Fresh channels immediately want a binding.
        assert_eq!(channel.tick(epoch(), &timing), vec![Action::SendBinding]);
        channel.mark_attempt(epoch());
        // Learning a mapping moves to the check phase.
        let transition = channel.on_mapped(addr(1000), after(100), &timing);
        assert_eq!(transition, Transition::Mapped { addr: addr(1000) });
        assert_eq!(channel.state().as_str(), "mapped");
        // The check runs right away; the heartbeat is not yet due.
        assert_eq!(channel.tick(after(200), &timing), vec![Action::Check]);
        channel.mark_check(after(200));
        assert_eq!(channel.state().as_str(), "checking");
        // Confirming reachability readies the channel.
        let transition = channel.on_check(true, after(300), &timing);
        assert_eq!(transition, Transition::Ready { addr: addr(1000) });
        assert_eq!(channel.state().as_str(), "ready");
        // A different endpoint later means the mapping changed and must be
        // re-checked (the notification travels with the transition).
        let transition = channel.on_mapped(addr(2000), after(500), &timing);
        assert_eq!(
            transition,
            Transition::Changed {
                old: addr(1000),
                new: addr(2000),
            }
        );
        assert_eq!(channel.state().as_str(), "checking");
        channel.mark_check(after(500));
        channel.on_check(true, after(600), &timing);
        assert_eq!(channel.state().as_str(), "ready");
        // Heartbeats from the ready channel keep the state (no transition).
        channel.mark_attempt(after(3500));
        assert_eq!(
            channel.on_mapped(addr(2000), after(3600), &timing),
            Transition::None
        );
        assert_eq!(channel.state().as_str(), "ready");
    }

    #[test]
    fn channel_heartbeat_and_timeout_respect_intervals() {
        let timing = timings();
        let mut channel = Channel::new(epoch());
        channel.mark_attempt(epoch());
        // Heartbeat not due within the interval…
        assert!(channel.tick(after(2999), &timing).is_empty());
        // …and due right after.
        assert_eq!(
            channel.tick(after(3000), &timing),
            vec![Action::SendBinding]
        );
        // Failed rounds land in Lost with a scheduled retry.
        channel.on_timeout(after(3001), &timing);
        match channel.state() {
            ChannelState::Lost { retry_at, .. } => {
                assert_eq!(*retry_at, Some(after(6001)), "retry at now + retryInterval");
            }
            other => panic!("expected lost, got {other:?}"),
        }
        // The retry tick fires only once the retry interval elapsed.
        assert!(channel.tick(after(6000), &timing).is_empty());
        assert_eq!(
            channel.tick(after(6001), &timing),
            vec![Action::SendBinding]
        );
    }

    #[test]
    fn channel_auto_retry_off_stops() {
        let mut timing = timings();
        timing.auto_retry = false;
        let mut channel = Channel::new(epoch());
        channel.mark_attempt(epoch());
        channel.on_mapped(addr(1000), after(100), &timing);
        channel.mark_check(after(100));
        channel.on_check(true, after(200), &timing);
        assert_eq!(channel.state().as_str(), "ready");
        // Losing the heartbeat without autoRetry parks the channel: no
        // retry is scheduled and tick stays silent forever.
        channel.on_timeout(after(5000), &timing);
        match channel.state() {
            ChannelState::Lost { retry_at, reason } => {
                assert_eq!(*retry_at, None);
                assert!(!reason.is_empty());
            }
            other => panic!("expected lost, got {other:?}"),
        }
        assert!(channel.tick(after(100_000), &timing).is_empty());
        // A manual restart (mark_attempt) resumes the binding loop.
        channel.mark_attempt(after(100_001));
        assert_eq!(channel.state().as_str(), "binding");
        // The round just started: the next binding fires one heartbeat
        // period later.
        assert!(channel.tick(after(100_002), &timing).is_empty());
        assert_eq!(
            channel.tick(after(103_001), &timing),
            vec![Action::SendBinding]
        );
    }

    #[test]
    fn channel_check_failures_end_in_lost_after_three_strikes() {
        let timing = timings();
        let mut channel = Channel::new(epoch());
        channel.mark_attempt(epoch());
        channel.on_mapped(addr(1000), after(100), &timing);
        for round in 0..u64::from(limits::CHECK_FAILURES_BEFORE_LOST) {
            channel.mark_check(after(1000 + round * 1000));
            let transition = channel.on_check(false, after(1100 + round * 1000), &timing);
            if round < u64::from(limits::CHECK_FAILURES_BEFORE_LOST) - 1 {
                assert_eq!(transition, Transition::None);
                assert_eq!(channel.state().as_str(), "mapped");
            } else {
                assert!(matches!(transition, Transition::Lost { .. }));
                assert_eq!(channel.state().as_str(), "lost");
            }
        }
    }

    #[test]
    fn channel_disable_check_skips_straight_to_ready() {
        let mut timing = timings();
        timing.disable_check = true;
        let mut channel = Channel::new(epoch());
        channel.mark_attempt(epoch());
        let transition = channel.on_mapped(addr(1000), after(100), &timing);
        assert_eq!(transition, Transition::Ready { addr: addr(1000) });
        assert_eq!(channel.state().as_str(), "ready");
        // Only heartbeat bindings are requested from here on.
        channel.mark_attempt(after(3100));
        assert_eq!(channel.tick(after(3200), &timing), vec![]);
        assert_eq!(
            channel.tick(after(6100), &timing),
            vec![Action::SendBinding]
        );
    }

    #[test]
    fn timings_from_rule_apply_defaults_and_floors() {
        let mut rule = Rule {
            heartbeat_interval: 0,
            stun_timeout: 100,
            retry_interval: 2_000,
            ..Rule::default()
        };
        let timing = Timings::from_rule(&rule, 5);
        assert_eq!(timing.heartbeat, Duration::from_millis(3000));
        assert_eq!(timing.stun_timeout, Duration::from_millis(500));
        assert_eq!(timing.retry, Duration::from_millis(2000));
        assert_eq!(timing.check, Duration::from_secs(60));
        // No check at all when the rule disables it.
        rule.disable_check = true;
        let timing = Timings::from_rule(&rule, 60);
        assert!(timing.disable_check);
        let mut channel = Channel::new(epoch());
        channel.mark_attempt(epoch());
        channel.on_mapped(addr(1000), after(100), &timing);
        assert!(channel.tick(after(200), &timing).is_empty());
    }
}
