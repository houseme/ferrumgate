//! Handshake confirmation handling (WP-53 §3.3, 实施步骤 7). The kernel
//! redirect (WP-53 firewall side) and the user-mode decoys
//! ([`crate::trap::UserTrapListener`]) both end at this surface:
//!
//! - **decoy hits** ban immediately (`trap` source, the hit port in the
//!   reason) — completing a handshake on a decoy port is never
//!   legitimate;
//! - **suspect hits** (a source the kernel meter already flagged) are
//!   skipped when exempt (whitelist, ignore-private, admin login trust,
//!   confirmed trusted sources — the frps hole-punching scenario), run
//!   through the one-minute [`ScanCounter`], and in IPv6 strict mode ban
//!   on the first non-open port. Triggered sources are merged for
//!   [`scan::HS_BATCH_DELAY`] (1 s) before the ban table write, so a
//!   batch produces exactly one notification listing every address and
//!   port.
//!
//! Only completed handshakes reach this module — a bare SYN never bans.

use std::{
    net::IpAddr,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use fg_core::events::{Event, EventBus, Kind};
use fg_net::banlist::{BanOutcome, Clock, Source, system_clock};

use crate::bans::GuardService;
use crate::model::Settings;
use crate::scan::{self, HS_BATCH_DELAY, ScanCounter, ScanOutcome, StrictMode, Verdict, verdict};

/// Whether `port` counts as open right now. Injected so tests drive the
/// table; production closes it over the effective open-port union.
pub type OpenCheck = Arc<dyn Fn(u16) -> bool + Send + Sync>;

/// Why a suspect hit was not counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// Whitelist / ignore-private / admin login trust.
    Exempt,
    /// Confirmed trusted source (`fg_net::trust_src`): overlay peers
    /// punching holes through many closed ports at once are normal.
    Trusted,
    /// The port is open (defensive: the kernel only redirects closed
    /// ones, but tables lag).
    OpenPort,
}

/// What one suspect handshake did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SuspectOutcome {
    /// Counted without crossing the threshold.
    Counted,
    /// Threshold crossed; the ban is queued for the batch flush.
    Queued { ports: Vec<u16> },
    /// IPv6 strict mode: banned on the first hit, no counting.
    StrictBanned,
    /// Not counted — exempt, trusted source or an open port.
    Skipped(SkipReason),
    /// The per-source tracker was full even after dropping expired
    /// windows; the source is left uncounted rather than evicting live
    /// windows.
    CapFull,
}

/// The settings snapshot the handler works from (trap / scan knobs of
/// `guard.json`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeSettings {
    /// Per-hit ban duration override of `trap.banSeconds`; `None`
    /// follows the module default.
    pub trap_ban: Option<Duration>,
    /// Per-hit ban duration override of `scan.banSeconds`.
    pub scan_ban: Option<Duration>,
    pub threshold: u32,
    pub ipv6_strict: bool,
    /// Whether the open-port table has data (system `/proc` reads work).
    /// Without it strict mode cannot fire and everyone counts.
    pub open_available: bool,
}

impl Default for HandshakeSettings {
    fn default() -> Self {
        Self {
            trap_ban: None,
            scan_ban: None,
            threshold: scan::DEFAULT_SCAN_THRESHOLD,
            ipv6_strict: false,
            open_available: false,
        }
    }
}

/// One triggered source waiting for the batch flush.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingHit {
    ip: IpAddr,
    ports: Vec<u16>,
    at: SystemTime,
}

/// The handshake callback surface shared by the decoy and scan paths.
pub struct Handshake {
    service: Arc<GuardService>,
    events: EventBus,
    clock: Clock,
    open: OpenCheck,
    settings: RwLock<HandshakeSettings>,
    scan: Mutex<ScanCounter>,
    strict: Mutex<StrictMode>,
    pending: Mutex<Vec<PendingHit>>,
    batch_delay: Duration,
    /// Whether a flush is currently writing its batch (status surface).
    flushing: AtomicBool,
}

impl Handshake {
    /// Builds the handler over the shared service; `open` decides which
    /// ports count as open (tests inject, production reads the union of
    /// listening, registered, held and excluded ports).
    pub fn new(service: Arc<GuardService>, events: EventBus, open: OpenCheck) -> Arc<Self> {
        Self::with_clock(service, events, open, system_clock(), HS_BATCH_DELAY)
    }

    /// Explicit clock and batch delay (tests).
    pub fn with_clock(
        service: Arc<GuardService>,
        events: EventBus,
        open: OpenCheck,
        clock: Clock,
        batch_delay: Duration,
    ) -> Arc<Self> {
        let resolved = Self::resolve(&service.settings());
        let strict = StrictMode::new(resolved.ipv6_strict, (clock)());
        let scan = ScanCounter::new(resolved.threshold);
        Arc::new(Self {
            service,
            events,
            clock,
            open,
            settings: RwLock::new(resolved),
            scan: Mutex::new(scan),
            strict: Mutex::new(strict),
            pending: Mutex::new(Vec::new()),
            batch_delay,
            flushing: AtomicBool::new(false),
        })
    }

    /// The snapshot implied by the module settings (trap / scan block).
    fn resolve(settings: &Settings) -> HandshakeSettings {
        HandshakeSettings {
            trap_ban: (settings.trap.ban_seconds > 0)
                .then(|| Duration::from_secs(u64::from(settings.trap.ban_seconds))),
            scan_ban: (settings.scan.ban_seconds > 0)
                .then(|| Duration::from_secs(u64::from(settings.scan.ban_seconds))),
            threshold: settings.scan.threshold.max(1),
            ipv6_strict: settings.scan.ipv6_strict && settings.scan.enable,
            open_available: false,
        }
    }

    /// Applies a settings save: thresholds and strict mode follow
    /// immediately; re-enabling strict mode restarts its grace period.
    pub fn apply_settings(&self, settings: &Settings) {
        let now = (self.clock)();
        let resolved = Self::resolve(settings);
        let mut scan_counter = self.scan.lock().expect("guard scan counter");
        if scan_counter.threshold() != resolved.threshold {
            // A threshold save restarts the counting windows.
            *scan_counter = ScanCounter::new(resolved.threshold);
        }
        drop(scan_counter);
        self.strict
            .lock()
            .expect("guard strict mode")
            .set_enabled(resolved.ipv6_strict, now);
        *self.settings.write().expect("guard handshake settings") = resolved;
    }

    /// Marks whether the open-port table currently has data (the system
    /// refresh loop reports `/proc` availability). Strict bans only fire
    /// while this is set (WP-53 §3.3: 读不到监听端口时按阈值检测).
    pub fn set_open_available(&self, available: bool) {
        self.settings
            .write()
            .expect("guard handshake settings")
            .open_available = available;
    }

    /// The current snapshot (status / tests).
    pub fn settings(&self) -> HandshakeSettings {
        self.settings
            .read()
            .expect("guard handshake settings")
            .clone()
    }

    /// A completed handshake on a decoy port: ban immediately (`trap`
    /// source, port in the reason). Whitelist / login trust / trusted
    /// sources are rejected inside the table like every automatic ban.
    pub fn on_trap(&self, ip: IpAddr, port: u16, now: SystemTime) -> BanOutcome {
        let trap_ban = self
            .settings
            .read()
            .expect("guard handshake settings")
            .trap_ban;
        self.service
            .ban_auto(ip, trap_ban, false, Source::Trap, trap_reason(port), now)
    }

    /// A completed handshake from a suspect source (the kernel meter
    /// flagged it) on a non-open port.
    pub fn on_suspect(&self, ip: IpAddr, port: u16, now: SystemTime) -> SuspectOutcome {
        // The three false-positive protections first: whitelist and
        // ignore-private, the 24 h admin login trust, and confirmed
        // trusted sources (frpc hole punching behind a shared NAT).
        if self.service.detection_exempt(ip) || self.service.login_trusted(ip, now) {
            return SuspectOutcome::Skipped(SkipReason::Exempt);
        }
        if fg_net::trust_src::is_trusted(ip) {
            return SuspectOutcome::Skipped(SkipReason::Trusted);
        }
        let settings = self
            .settings
            .read()
            .expect("guard handshake settings")
            .clone();
        let port_open = (self.open)(port);
        if port_open {
            return SuspectOutcome::Skipped(SkipReason::OpenPort);
        }
        // IPv6 strict mode: first non-open port bans. Only with
        // listener data; without it everyone counts (WP-53 §3.3).
        let strict_active = settings.ipv6_strict
            && settings.open_available
            && self.strict.lock().expect("guard strict mode").active(now);
        if verdict(strict_active, ip, port_open) == Verdict::StrictBan {
            let outcome = self.service.ban_auto(
                ip,
                settings.scan_ban,
                false,
                Source::Scan,
                strict_reason(port),
                now,
            );
            return match outcome {
                // `Unchanged` = already banned (e.g. permanently), which
                // satisfies strict mode all the same.
                BanOutcome::Banned { .. } | BanOutcome::Unchanged => SuspectOutcome::StrictBanned,
                // The table shields the source (table full is the only
                // realistic case here; nothing was counted).
                _ => SuspectOutcome::Skipped(SkipReason::Exempt),
            };
        }
        let outcome = self
            .scan
            .lock()
            .expect("guard scan counter")
            .handshake(ip, port, now);
        match outcome {
            ScanOutcome::Counted => SuspectOutcome::Counted,
            ScanOutcome::Skipped => SuspectOutcome::CapFull,
            ScanOutcome::Triggered { ports } => {
                self.pending
                    .lock()
                    .expect("guard scan pending")
                    .push(PendingHit {
                        ip,
                        ports: ports.clone(),
                        at: now,
                    });
                SuspectOutcome::Queued { ports }
            }
        }
    }

    /// Writes every queued ban older than the batch delay and publishes
    /// one summary notification for the whole batch (addresses and
    /// ports included). Returns how many bans landed.
    pub fn flush_due(&self, now: SystemTime) -> usize {
        let batch: Vec<PendingHit> = {
            let mut pending = self.pending.lock().expect("guard scan pending");
            let due: Vec<PendingHit> = pending
                .iter()
                .filter(|hit| now.duration_since(hit.at).unwrap_or_default() >= self.batch_delay)
                .cloned()
                .collect();
            pending.retain(|hit| now.duration_since(hit.at).unwrap_or_default() < self.batch_delay);
            due
        };
        if batch.is_empty() {
            return 0;
        }
        self.flushing.store(true, Ordering::SeqCst);
        let scan_ban = self
            .settings
            .read()
            .expect("guard handshake settings")
            .scan_ban;
        // One notification per batch: pause the per-ban publications and
        // publish the summary ourselves.
        self.service.pause_ban_events(true);
        let mut landed = 0;
        for hit in &batch {
            let outcome = self.service.ban_auto(
                hit.ip,
                scan_ban,
                false,
                Source::Scan,
                scan_reason(&hit.ports),
                now,
            );
            if matches!(outcome, BanOutcome::Banned { .. } | BanOutcome::Unchanged) {
                landed += 1;
            }
        }
        self.service.pause_ban_events(false);
        self.flushing.store(false, Ordering::SeqCst);
        self.publish_batch(&batch);
        landed
    }

    /// How many triggered sources still wait for the batch flush.
    pub fn pending(&self) -> usize {
        self.pending.lock().expect("guard scan pending").len()
    }

    /// Whether a flush write is in flight (status surface).
    pub fn is_flushing(&self) -> bool {
        self.flushing.load(Ordering::SeqCst)
    }

    /// One `guard.banned` event per batch listing every address and
    /// port (skipped entirely without subscribers, like every
    /// publication).
    fn publish_batch(&self, batch: &[PendingHit]) {
        let addrs = batch
            .iter()
            .map(|hit| hit.ip.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let ports = batch
            .iter()
            .flat_map(|hit| hit.ports.iter().copied())
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(",");
        self.events.publish_with(|| {
            let mut event = Event::new(Kind::GuardBanned, "guard");
            event.args = vec![
                ("source", "scan".to_owned()),
                ("batch", batch.len().to_string()),
                ("addrs", addrs),
                ("ports", ports),
            ];
            event
        });
    }
}

/// The trap ban reason with the hit port.
pub fn trap_reason(port: u16) -> String {
    format!("guard.reason.trap:{port}")
}

/// The scan ban reason listing every hit port of the window.
pub fn scan_reason(ports: &[u16]) -> String {
    let list = ports
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!("guard.reason.scan:{list}")
}

/// The strict-mode ban reason with the first offending port.
pub fn strict_reason(port: u16) -> String {
    format!("guard.reason.strict:{port}")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use fg_core::events::EventBus;
    use fg_net::banlist::BanOutcome;
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use crate::model::{ScanSettings, Settings, TrapSettings};
    use crate::validate;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    struct FakeClock(Mutex<SystemTime>);

    impl FakeClock {
        fn start(secs: u64) -> (Arc<Self>, Clock) {
            let fake = Arc::new(Self(Mutex::new(at(secs))));
            let handle = Arc::clone(&fake);
            (
                Arc::clone(&fake),
                Arc::new(move || *handle.0.lock().expect("clock")),
            )
        }
        fn advance(&self, d: Duration) {
            *self.0.lock().expect("clock") += d;
        }
    }

    /// No port counts as open unless the test says so.
    fn open_none() -> OpenCheck {
        Arc::new(|_| false)
    }

    fn handler(settings: &Settings, clock: Clock) -> Arc<Handshake> {
        let service = GuardService::open_memory_with_clock(
            &validate::normalize(crate::model::FileConfig {
                settings: settings.clone(),
                jails: Vec::new(),
            })
            .settings,
            EventBus::new(64),
            clock.clone(),
        );
        Handshake::with_clock(
            service,
            EventBus::new(64),
            open_none(),
            clock,
            HS_BATCH_DELAY,
        )
    }

    fn settings_with(scan: ScanSettings, trap: TrapSettings) -> Settings {
        Settings {
            scan,
            trap,
            ..Settings::default()
        }
    }

    #[tokio::test]
    async fn handshake_trap_bans_immediately() {
        let (_fake, clock) = FakeClock::start(1000);
        let handler = handler(
            &settings_with(ScanSettings::default(), TrapSettings::default()),
            clock,
        );
        let outcome = handler.on_trap("203.0.113.9".parse().unwrap(), 3389, at(1000));
        let BanOutcome::Banned { entry, .. } = outcome else {
            panic!("expected a ban, got {outcome:?}");
        };
        assert!(
            entry.reason.contains("3389"),
            "the reason carries the port: {}",
            entry.reason
        );
        assert_eq!(entry.source, Source::Trap);
        assert!(
            handler.service.is_banned("203.0.113.9".parse().unwrap()),
            "decoy hits ban without any counting"
        );
        // A whitelisted source is rejected by the table, not banned.
        assert_eq!(
            handler.on_trap("192.168.1.5".parse().unwrap(), 23, at(1000)),
            BanOutcome::Rejected(fg_net::banlist::RejectReason::Whitelisted)
        );
    }

    #[tokio::test]
    async fn handshake_hits_batched_within_1s() {
        let (fake, clock) = FakeClock::start(1000);
        let handler = handler(
            &settings_with(ScanSettings::default(), TrapSettings::default()),
            clock,
        );
        let a: IpAddr = "203.0.113.9".parse().unwrap();
        let b: IpAddr = "203.0.113.10".parse().unwrap();
        assert_eq!(
            handler.on_suspect(a, 23, at(1000)),
            SuspectOutcome::Counted,
            "below the threshold"
        );
        assert_eq!(
            handler.on_suspect(b, 8080, at(1005)),
            SuspectOutcome::Counted
        );
        assert_eq!(handler.pending(), 0);

        // Cross the threshold on both: bans queue up, nothing lands yet.
        for port in [
            8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092,
        ] {
            let _ = handler.on_suspect(a, port, at(1010));
        }
        assert_eq!(
            handler.pending(),
            1,
            "the triggered source waits for the batch"
        );
        assert_eq!(
            handler.flush_due(at(1010)),
            0,
            "inside the 1 s merge window nothing is written"
        );
        assert_eq!(
            handler
                .service
                .count(&fg_net::banlist::BanFilter::default()),
            0,
            "no ban landed inside the merge window"
        );
        assert!(!handler.service.is_banned(a));

        // One second later the flush writes the ban.
        fake.advance(HS_BATCH_DELAY);
        assert_eq!(handler.flush_due(at(1010 + 1)), 1);
        assert!(handler.service.is_banned(a));
        assert_eq!(handler.pending(), 0);
    }

    #[tokio::test]
    async fn handshake_flush_publishes_one_event_per_batch() {
        let (fake, clock) = FakeClock::start(2000);
        let landed = Arc::new(AtomicUsize::new(0));
        let sink = Arc::clone(&landed);
        // One handler over an observable bus: a batch of two triggered
        // sources must produce exactly one event. The subscription must
        // outlive the handler — dropping it disables the subscriber.
        let service = GuardService::open_memory_with_clock(
            &validate::normalize(crate::model::FileConfig::default()).settings,
            EventBus::new(64),
            clock.clone(),
        );
        let bus = EventBus::new(64);
        let _subscription = bus
            .subscribe(move |_event| {
                let sink = Arc::clone(&sink);
                async move {
                    sink.fetch_add(1, AtomicOrdering::SeqCst);
                }
            })
            .expect("subscribe");
        let handler = Handshake::with_clock(
            Arc::clone(&service),
            bus,
            open_none(),
            clock.clone(),
            HS_BATCH_DELAY,
        );
        let a: IpAddr = "203.0.113.9".parse().unwrap();
        let b: IpAddr = "203.0.113.10".parse().unwrap();
        for port in 1..=12u16 {
            let _ = handler.on_suspect(a, port, at(2000));
        }
        for port in 20..=31u16 {
            let _ = handler.on_suspect(b, port, at(2001));
        }
        assert_eq!(handler.pending(), 2);
        fake.advance(HS_BATCH_DELAY);
        assert_eq!(
            handler.flush_due(at(2002)),
            2,
            "both bans land in one flush"
        );
        // Let the subscriber task drain the bus.
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if landed.load(AtomicOrdering::SeqCst) >= 1 {
                break;
            }
        }
        assert_eq!(
            landed.load(AtomicOrdering::SeqCst),
            1,
            "one notification for the whole batch"
        );
    }

    #[tokio::test]
    async fn handshake_skips_login_trusted_and_whitelisted() {
        let (_fake, clock) = FakeClock::start(3000);
        let mut settings = settings_with(ScanSettings::default(), TrapSettings::default());
        settings.ignore_list = vec!["198.51.100.0/24".to_owned()];
        let first = handler(&settings, clock.clone());
        let now = at(3000);
        // Whitelisted network: skipped before counting.
        assert_eq!(
            first.on_suspect("198.51.100.7".parse().unwrap(), 23, now),
            SuspectOutcome::Skipped(SkipReason::Exempt)
        );
        // Admin login trust: skipped for 24 h.
        let trusted: IpAddr = "203.0.113.9".parse().unwrap();
        first.service.trust_login(trusted);
        assert_eq!(
            first.on_suspect(trusted, 23, now),
            SuspectOutcome::Skipped(SkipReason::Exempt)
        );
        // ignore_private covers internal ranges too.
        let mut settings = settings_with(ScanSettings::default(), TrapSettings::default());
        settings.ignore_private = true;
        let handler2 = handler(&settings, clock.clone());
        assert_eq!(
            handler2.on_suspect("10.1.2.3".parse().unwrap(), 23, now),
            SuspectOutcome::Skipped(SkipReason::Exempt)
        );
    }

    #[tokio::test]
    async fn trusted_sources_not_counted() {
        // The frps hole-punching scenario: one shared NAT exit fires at
        // dozens of closed ports in a minute; the vouching owner keeps
        // it out of the counter.
        let owner = "wp53-test-frpc";
        fg_net::trust_src::set(
            owner,
            vec![fg_net::TrustedSource {
                owner: owner.to_owned(),
                addr: "203.0.113.77".parse().unwrap(),
                until: None,
                note: "frpc".to_owned(),
            }],
        );
        let (_fake, clock) = FakeClock::start(4000);
        let handler = handler(
            &settings_with(ScanSettings::default(), TrapSettings::default()),
            clock,
        );
        let now = at(4000);
        for port in 1..=20u16 {
            assert_eq!(
                handler.on_suspect("203.0.113.77".parse().unwrap(), port, now),
                SuspectOutcome::Skipped(SkipReason::Trusted),
                "trusted sources never count, whatever the volume"
            );
        }
        assert_eq!(handler.pending(), 0);
        fg_net::trust_src::clear(owner);
    }

    #[tokio::test]
    async fn handshake_strict_first_hit_bans_v6_counts_v4() {
        let (_fake, clock) = FakeClock::start(5000);
        let scan = ScanSettings {
            enable: true,
            ipv6_strict: true,
            ..ScanSettings::default()
        };
        let handler = handler(&settings_with(scan, TrapSettings::default()), clock);
        handler.set_open_available(true);
        let now = at(5000 + 16);
        // Past the grace period: first v6 hit on a non-open port bans.
        let v6: IpAddr = "2001:db8:aa::1".parse().unwrap();
        assert_eq!(
            handler.on_suspect(v6, 23, now),
            SuspectOutcome::StrictBanned
        );
        assert!(handler.service.is_banned(v6));
        assert!(
            handler
                .service
                .is_banned("2001:db8:aa::dead".parse().unwrap()),
            "the ban is the /64 like every automatic v6 ban"
        );
        // IPv4 keeps threshold detection.
        let v4: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(handler.on_suspect(v4, 23, now), SuspectOutcome::Counted);
    }

    #[tokio::test]
    async fn handshake_strict_needs_open_data_and_grace() {
        let (fake, clock) = FakeClock::start(6000);
        let scan = ScanSettings {
            enable: true,
            ipv6_strict: true,
            ..ScanSettings::default()
        };
        let handler = handler(&settings_with(scan, TrapSettings::default()), clock);
        let now = at(6000);
        let v6: IpAddr = "2001:db8:aa::1".parse().unwrap();
        // Without /proc data strict cannot fire: threshold counting.
        assert_eq!(handler.on_suspect(v6, 23, now), SuspectOutcome::Counted);
        // With data but inside the grace: still counting.
        handler.set_open_available(true);
        assert_eq!(handler.on_suspect(v6, 24, now), SuspectOutcome::Counted);
        fake.advance(Duration::from_secs(20));
        let later = at(6020);
        assert_eq!(
            handler.on_suspect(v6, 25, later),
            SuspectOutcome::StrictBanned,
            "the grace period elapsed"
        );
    }

    #[tokio::test]
    async fn handshake_open_ports_never_count() {
        let (_fake, clock) = FakeClock::start(7000);
        let service = GuardService::open_memory(
            &validate::normalize(crate::model::FileConfig::default()).settings,
            EventBus::new(64),
        );
        let handler = Handshake::with_clock(
            Arc::clone(&service),
            EventBus::new(64),
            Arc::new(|port| port == 8080),
            clock,
            HS_BATCH_DELAY,
        );
        let now = at(7000);
        assert_eq!(
            handler.on_suspect("203.0.113.9".parse().unwrap(), 8080, now),
            SuspectOutcome::Skipped(SkipReason::OpenPort),
            "a lagging table must not count a genuinely open port"
        );
    }

    #[tokio::test]
    async fn handshake_settings_follow_saves() {
        let (_fake, clock) = FakeClock::start(8000);
        let handler = handler(
            &settings_with(ScanSettings::default(), TrapSettings::default()),
            clock,
        );
        let mut settings = settings_with(ScanSettings::default(), TrapSettings::default());
        settings.scan.enable = true;
        settings.scan.threshold = 3;
        settings.scan.ban_seconds = 7200;
        settings.scan.ipv6_strict = true;
        settings.trap.enable = true;
        settings.trap.ban_seconds = 600;
        handler.apply_settings(&settings);
        let snapshot = handler.settings();
        assert_eq!(snapshot.threshold, 3);
        assert_eq!(snapshot.trap_ban, Some(Duration::from_secs(600)));
        assert_eq!(snapshot.scan_ban, Some(Duration::from_secs(7200)));
        assert!(snapshot.ipv6_strict);

        // The new threshold is live: the third suspect hit queues.
        let source: IpAddr = "203.0.113.9".parse().unwrap();
        let now = at(8000);
        assert_eq!(handler.on_suspect(source, 1, now), SuspectOutcome::Counted);
        assert_eq!(handler.on_suspect(source, 2, now), SuspectOutcome::Counted);
        assert_eq!(
            handler.on_suspect(source, 3, now),
            SuspectOutcome::Queued {
                ports: vec![1, 2, 3]
            }
        );
    }

    // A simpler, real assertion for the trap duration override.
    #[tokio::test]
    async fn handshake_trap_ban_seconds_override_applies() {
        let (_fake, clock) = FakeClock::start(8500);
        let handler = handler(
            &settings_with(ScanSettings::default(), TrapSettings::default()),
            clock,
        );
        let mut settings = settings_with(ScanSettings::default(), TrapSettings::default());
        settings.trap.enable = true;
        settings.trap.ban_seconds = 600;
        handler.apply_settings(&settings);
        let outcome = handler.on_trap("203.0.113.9".parse().unwrap(), 23, at(8500));
        let BanOutcome::Banned { entry, .. } = outcome else {
            panic!("expected a ban, got {outcome:?}");
        };
        let until = entry.until.expect("temporary ban");
        assert_eq!(
            until.duration_since(at(8500)).unwrap(),
            Duration::from_secs(600),
            "trap.banSeconds overrides the module default"
        );
    }
}
