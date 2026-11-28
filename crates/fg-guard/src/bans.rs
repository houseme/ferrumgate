//! The guard module's service around the shared ban table (WP-50):
//! opening and applying `guard.json` policy knobs, the automatic and
//! manual ban entries, event publication on `guard.banned`, and the query
//! surface other modules use (they receive [`GuardService::table`], the
//! `fg_net::banlist::BanTable`, through their `Deps` — the same shared
//! type the web service uses, per WP-50 §1). With `settings.firewall` on
//! it also owns the WP-51 firewall sync (WP-51 §3.3 consume pattern: the
//! table's `banned` hook nudges the sync, the 10 s reconcile diffs, the
//! first tick after a successful probe rebuilds the whole table).

use std::{
    net::IpAddr,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use fg_config::ConfigStore;
use fg_core::events::{Event, EventBus, Kind};
use fg_net::banlist::{
    BanCounts, BanFilter, BanHooks, BanOutcome, BanPolicy, BanStats, BanTable, Entry, Source,
    system_clock,
};
use ipnet::IpNet;

use crate::firewall::FirewallSync;
use crate::model::Settings;
use crate::validate;

/// Where the bans file lives inside the config store
/// (`<config dir>/guard/bans.json`, conventions §3.2).
pub const DATA_DIR: &str = "guard";
pub const BANS_FILE: &str = "bans.json";

/// Why a service-level ban request failed. Display strings are stable
/// message fragments the admin API turns into `{"error": …}` bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardBanError {
    InvalidTarget,
    InvalidDuration,
    Loopback,
    AlreadyPermanent,
    Full,
}

impl std::fmt::Display for GuardBanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::InvalidTarget => "target must be an IP address or CIDR network",
            Self::InvalidDuration => "seconds must be -1 (permanent) or between 3600 and 2592000",
            Self::Loopback => "target covers the loopback address",
            Self::AlreadyPermanent => "already permanently banned",
            Self::Full => "ban table is full",
        };
        f.write_str(text)
    }
}

impl std::error::Error for GuardBanError {}

impl From<fg_net::banlist::BanError> for GuardBanError {
    fn from(error: fg_net::banlist::BanError) -> Self {
        match error {
            fg_net::banlist::BanError::Loopback => Self::Loopback,
            fg_net::banlist::BanError::AlreadyPermanent => Self::AlreadyPermanent,
            fg_net::banlist::BanError::Full => Self::Full,
            fg_net::banlist::BanError::InvalidDuration => Self::InvalidDuration,
        }
    }
}

/// Holds the firewall sync while it runs (`None` = disabled or not yet
/// started). The ban hook reads it; the assembly layer may inject a
/// substitute with [`GuardService::set_firewall`].
pub type FirewallSlot = Arc<Mutex<Option<Arc<FirewallSync>>>>;

/// The module state shared between the runtime, the routes and other
/// modules.
pub struct GuardService {
    table: Arc<BanTable>,
    /// The table's clock, mirrored here so the query surface
    /// (`is_banned`/`trust_login`/`counts`) evaluates with the same time
    /// source the entries were written with (tests inject fake time).
    clock: fg_net::banlist::Clock,
    settings: RwLock<Settings>,
    /// Local IPv6 networks, registered by the assembly layer; merged into
    /// the whitelist on every settings application.
    local_v6: Mutex<Vec<IpNet>>,
    /// The module's event bus; `guard.banned` publications go through it
    /// via the table hook, and future publishers (jails) reuse it.
    events: EventBus,
    firewall: FirewallSlot,
    /// Pauses the per-ban `guard.banned` publication while a batched
    /// writer (WP-53 handshake flush: one notification per batch) does
    /// the writing and publishes its own summary event. Shared with the
    /// table hook.
    events_paused: Arc<std::sync::atomic::AtomicBool>,
}

impl GuardService {
    /// The module's event bus, for publishers layered on top (WP-51+).
    pub fn events(&self) -> EventBus {
        self.events.clone()
    }
}

impl GuardService {
    /// Opens the bans file under the config store and applies the given
    /// (already normalized) settings. The `guard.banned` event hook is
    /// wired to the module's event bus and nudges the firewall sync; when
    /// `settings.firewall` is on the sync (and its worker thread) starts
    /// here — every firewall failure stays non-fatal.
    pub fn open(store: &ConfigStore, settings: &Settings, events: EventBus) -> Result<Arc<Self>> {
        let path = store.data_dir(DATA_DIR)?.join(BANS_FILE);
        let firewall: FirewallSlot = Arc::new(Mutex::new(None));
        let events_paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hooks = BanHooks {
            banned: Some(Arc::new({
                let events = events.clone();
                let firewall = Arc::clone(&firewall);
                let paused = Arc::clone(&events_paused);
                move |entry: &fg_net::banlist::Entry| {
                    if !paused.load(std::sync::atomic::Ordering::SeqCst) {
                        publish_banned(&events, entry);
                    }
                    if let Some(sync) = firewall.lock().expect("guard firewall slot").as_ref() {
                        sync.note_banned(entry);
                    }
                }
            })),
            load_warning: Some(Arc::new(|warning: &str| {
                tracing::warn!(module = "guard", "{warning}");
            })),
        };
        let table = BanTable::open(
            &path,
            policy_from_settings(settings, &[]),
            hooks,
            system_clock(),
        )
        .with_context(|| format!("opening the bans file at {}", path.display()))?;
        if settings.firewall {
            *firewall.lock().expect("guard firewall slot") =
                Some(FirewallSync::start(Arc::clone(&table), system_clock()));
        }
        Ok(Arc::new(Self {
            clock: system_clock(),
            table,
            settings: RwLock::new(settings.clone()),
            local_v6: Mutex::new(Vec::new()),
            events,
            firewall,
            events_paused,
        }))
    }

    /// An in-memory service (tests, standalone consumers). Never starts
    /// the firewall sync on its own; inject one with [`set_firewall`]
    /// ([`GuardService::set_firewall`]) if needed.
    pub fn open_memory(settings: &Settings, events: EventBus) -> Arc<Self> {
        Self::open_memory_with_clock(settings, events, fg_net::banlist::system_clock())
    }

    /// Test seam: the same in-memory service sharing the caller's clock,
    /// so fake-time entries are visible to `is_banned` queries.
    pub fn open_memory_with_clock(
        settings: &Settings,
        events: EventBus,
        clock: fg_net::banlist::Clock,
    ) -> Arc<Self> {
        let firewall: FirewallSlot = Arc::new(Mutex::new(None));
        let events_paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hooks = BanHooks {
            banned: Some(Arc::new({
                let events = events.clone();
                let firewall = Arc::clone(&firewall);
                let paused = Arc::clone(&events_paused);
                move |entry: &fg_net::banlist::Entry| {
                    if !paused.load(std::sync::atomic::Ordering::SeqCst) {
                        publish_banned(&events, entry);
                    }
                    if let Some(sync) = firewall.lock().expect("guard firewall slot").as_ref() {
                        sync.note_banned(entry);
                    }
                }
            })),
            load_warning: None,
        };
        Arc::new(Self {
            clock: clock.clone(),
            table: BanTable::open_memory(policy_from_settings(settings, &[]), hooks, clock),
            settings: RwLock::new(settings.clone()),
            local_v6: Mutex::new(Vec::new()),
            events,
            firewall,
            events_paused,
        })
    }

    /// The normalized settings currently in force.
    pub fn settings(&self) -> Settings {
        self.settings.read().expect("guard settings").clone()
    }

    /// Applies new (already normalized) settings: the table policy follows
    /// immediately, and the firewall sync starts, stops (its worker removes
    /// the table before exiting) or re-probes to match `settings.firewall`
    /// — a settings save is also the documented re-probe trigger (WP-51
    /// §4).
    pub fn apply_settings(&self, settings: &Settings) {
        *self.settings.write().expect("guard settings") = settings.clone();
        self.apply_policy(settings);
        let mut slot = self.firewall.lock().expect("guard firewall slot");
        match (&*slot, settings.firewall) {
            (Some(previous), false) => {
                previous.stop();
                *slot = None;
            }
            (Some(previous), true) => previous.reprobe(),
            (None, true) => {
                *slot = Some(FirewallSync::start(Arc::clone(&self.table), system_clock()));
            }
            (None, false) => {}
        }
    }

    /// Replaces the firewall sync (assembly injection, tests). The
    /// previous sync is stopped; its worker removes the table before
    /// exiting, off this thread.
    pub fn set_firewall(&self, sync: Option<Arc<FirewallSync>>) {
        let mut slot = self.firewall.lock().expect("guard firewall slot");
        match (&*slot, &sync) {
            (Some(previous), Some(next)) if Arc::ptr_eq(previous, next) => {}
            (Some(previous), _) => previous.stop(),
            _ => {}
        }
        *slot = sync;
    }

    /// The running firewall sync, if any.
    pub fn firewall(&self) -> Option<Arc<FirewallSync>> {
        self.firewall.lock().expect("guard firewall slot").clone()
    }

    /// Applies the settings to the table policy only (no firewall side
    /// effects); the whitelist combines `ignoreList` with the registered
    /// local IPv6 networks.
    fn apply_policy(&self, settings: &Settings) {
        let local = self.local_v6.lock().expect("guard local nets").clone();
        let mut policy = policy_from_settings(settings, &local);
        policy.clamp_max_duration();
        self.table.set_policy(policy);
    }

    /// Registers the local IPv6 networks (each widened to its /64); the
    /// assembly layer calls this once it knows the interfaces.
    pub fn set_local_networks(&self, networks: Vec<IpNet>) {
        *self.local_v6.lock().expect("guard local nets") = networks;
        self.apply_policy(&self.settings());
    }

    /// Automatic ban entry (jails, decoy ports, scan detection, web
    /// service auth failures — WP-52/53 call this with their own source
    /// and reason).
    pub fn ban_auto(
        &self,
        ip: IpAddr,
        duration: Option<Duration>,
        permanent: bool,
        source: Source,
        reason: String,
        now: SystemTime,
    ) -> BanOutcome {
        self.table
            .ban_auto(ip, duration, permanent, source, reason, now)
    }

    /// Manual ban from the admin API: `target` is an IP or CIDR,
    /// `seconds` is `-1` for permanent or 1..=720 hours.
    pub fn ban_manual(&self, target: &str, seconds: i64) -> Result<Entry, GuardBanError> {
        let cidr = parse_target(target).ok_or(GuardBanError::InvalidTarget)?;
        if !validate::valid_manual_seconds(seconds) {
            return Err(GuardBanError::InvalidDuration);
        }
        let permanent = seconds == validate::MANUAL_PERMANENT;
        let duration = if permanent {
            None
        } else {
            Some(Duration::from_secs(seconds as u64))
        };
        self.table
            .ban_manual(cidr, duration, permanent, SystemTime::now())
            .map_err(GuardBanError::from)
    }

    /// Unban by IP or CIDR; returns how many entries went away.
    pub fn unban(&self, target: &str) -> Result<usize, GuardBanError> {
        let cidr = parse_target(target).ok_or(GuardBanError::InvalidTarget)?;
        Ok(self.table.unban(&cidr, SystemTime::now()))
    }

    /// Filtered, paged listing for the admin API.
    pub fn list(&self, filter: &BanFilter) -> Vec<Entry> {
        self.table.list(SystemTime::now(), filter)
    }

    /// Number of entries matching the filter, ignoring pagination.
    pub fn count(&self, filter: &BanFilter) -> usize {
        self.table.count(SystemTime::now(), filter)
    }

    /// Lock-free hot path query for other modules (web service
    /// accessCheck, L4 source rules, knock packet handling).
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.table.is_banned(ip, (self.clock)())
    }

    /// Called by the admin login flow (WP-12) after a successful login.
    pub fn trust_login(&self, ip: IpAddr) {
        self.table.trust_login(ip, (self.clock)());
    }

    pub fn counts(&self) -> BanCounts {
        self.table.counts(SystemTime::now())
    }

    pub fn stats(&self) -> BanStats {
        self.table.stats()
    }

    /// The table limit (mirrors the policy; status pages).
    pub fn limit(&self) -> usize {
        fg_net::banlist::LIMIT
    }

    /// The shared table itself: hand this to other modules via their
    /// `Deps` — every consumer reads the same entries lock-free.
    pub fn table(&self) -> Arc<BanTable> {
        Arc::clone(&self.table)
    }

    /// Whether the per-ban `guard.banned` publication is currently
    /// paused (batched writers only).
    pub fn ban_events_paused(&self) -> bool {
        self.events_paused.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Pauses or resumes the per-ban `guard.banned` publication. The
    /// WP-53 handshake flush pauses around a batch write and publishes
    /// one summary event per batch instead (WP-53 §3.3: 扫描往往成批
    /// 出现，每批只发一条通知). The firewall nudge still runs per ban.
    pub fn pause_ban_events(&self, paused: bool) {
        self.events_paused
            .store(paused, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether handshake-side detection must skip this source entirely:
    /// the whitelist (built-in ranges, `ignoreList`, registered local
    /// IPv6 networks), or — with `ignore_private` on — any private,
    /// loopback or link-local address (WP-53 §3.3: 白名单与「忽略内网
    /// 地址」覆盖的地址不处理). Login trust and confirmed trusted
    /// sources are separate checks ([`GuardService::login_trusted`] and
    /// `fg_net::trust_src::is_trusted`).
    pub fn detection_exempt(&self, ip: IpAddr) -> bool {
        let settings = self.settings();
        if settings.ignore_private && is_local_address(ip) {
            return true;
        }
        let local = self.local_v6.lock().expect("guard local nets").clone();
        let mut whitelist = fg_net::banlist::default_whitelist();
        whitelist.extend(whitelist_from_settings(&settings));
        whitelist.extend(local);
        whitelist.iter().any(|net| net.contains(&ip))
    }

    /// Whether the address logged into the admin UI recently (WP-50
    /// login trust; the handshake side must not count it for 24 h).
    pub fn login_trusted(&self, ip: IpAddr, now: SystemTime) -> bool {
        self.table.is_login_trusted(ip, now)
    }

    /// Writes pending changes now (shutdown path, tests).
    pub fn flush(&self) -> Result<()> {
        self.table.flush().context("flushing the bans file")
    }
}

/// Whether the address is loopback, private, link-local or unique-local
/// (the "ignore internal addresses" scope).
pub fn is_local_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_loopback() || v4.is_private() || v4.is_link_local();
            }
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// The policy implied by module settings. The whitelist is the built-in
/// internal ranges plus the user's `ignoreList` (`local_v6` joins on
/// apply); the escalation ceiling is clamped to its documented range.
fn policy_from_settings(settings: &Settings, local_v6: &[IpNet]) -> BanPolicy {
    let mut whitelist = fg_net::banlist::default_whitelist();
    whitelist.extend(whitelist_from_settings(settings));
    whitelist.extend(local_v6.iter().copied());
    BanPolicy {
        limit: fg_net::banlist::LIMIT,
        default_duration: Duration::from_secs(u64::from(settings.ban_seconds.max(1))),
        increment: settings.increment,
        max_duration: Duration::from_secs(u64::from(settings.max_ban_seconds.max(1))),
        ignore_private: settings.ignore_private,
        whitelist,
        save_delay: fg_net::banlist::SAVE_DELAY,
    }
}

/// The user-provided whitelist; single IPv6 entries widen to their /64 in
/// the table.
fn whitelist_from_settings(settings: &Settings) -> Vec<IpNet> {
    settings
        .ignore_list
        .iter()
        .filter_map(|entry| validate::parse_net(entry))
        .collect()
}

/// Parses a manual/unban target: an IP (normalized like the table does) or
/// a CIDR.
fn parse_target(target: &str) -> Option<IpNet> {
    let target = target.trim();
    if let Ok(net) = target.parse::<IpNet>() {
        return Some(net);
    }
    let ip: IpAddr = target.parse().ok()?;
    Some(match ip {
        IpAddr::V4(v4) => IpNet::new(IpAddr::V4(v4), 32).ok()?,
        IpAddr::V6(v6) => IpNet::new(IpAddr::V6(v6), 128).ok()?,
    })
}

/// Publishes one `guard.banned` event for a landed ban; skipped entirely
/// when nobody is subscribed or the queue is full (`publish_with`).
fn publish_banned(events: &EventBus, entry: &Entry) {
    events.publish_with(|| {
        let mut event = Event::new(Kind::GuardBanned, "guard");
        event.args = vec![
            ("key", entry.key.to_string()),
            ("source", entry.source.to_tag()),
            ("reason", entry.reason.clone()),
        ];
        event.fields = vec![("count", entry.count.to_string())];
        event
    });
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::firewall::{FirewallSync, FwUnavailable};
    use crate::model::Settings;
    use fg_net::banlist::{BanPolicy, BanTable, system_clock};
    use std::sync::Arc as StdArc;

    /// `EventBus::new` needs a Tokio runtime handle, so every test that
    /// builds a service runs inside `#[tokio::test]`.
    fn service() -> Arc<GuardService> {
        GuardService::open_memory(&Settings::default(), EventBus::default())
    }

    /// A thread-less sync whose probe reports the platform limitation:
    /// exercises the wiring without touching any system firewall.
    fn manual_sync() -> StdArc<FirewallSync> {
        FirewallSync::with_factory(
            BanTable::open_memory(BanPolicy::default(), Default::default(), system_clock()),
            system_clock(),
            StdArc::new(|| Err(FwUnavailable::not_linux())),
        )
    }

    #[tokio::test]
    async fn firewall_slot_follows_settings_and_stops_on_toggle_off() {
        let guard = service();
        assert!(guard.firewall().is_none(), "off by default");
        // Injecting and enabling keeps the injected sync (no production
        // detection is spawned); a settings save re-probes it.
        let sync = manual_sync();
        guard.set_firewall(Some(StdArc::clone(&sync)));
        let enabled = crate::validate::normalize(crate::model::FileConfig {
            settings: Settings {
                firewall: true,
                ..Settings::default()
            },
            jails: Vec::new(),
        })
        .settings;
        guard.apply_settings(&enabled);
        assert!(guard.firewall().is_some());
        assert!(
            StdArc::ptr_eq(&guard.firewall().unwrap(), &sync),
            "a running sync is re-probed, not replaced"
        );
        assert!(sync.status().enabled);
        // Toggling off clears the slot and stops the worker.
        guard.apply_settings(&Settings::default());
        assert!(guard.firewall().is_none());
        // The hook never panics without a running sync.
        guard.ban_auto(
            "203.0.113.7".parse().unwrap(),
            None,
            false,
            Source::Scan,
            "r".to_owned(),
            SystemTime::now(),
        );
    }

    #[tokio::test]
    async fn ban_manual_validates_target_and_seconds() {
        let guard = service();
        let entry = guard
            .ban_manual("198.51.100.7", validate::MANUAL_DEFAULT_SECONDS)
            .unwrap();
        assert_eq!(entry.key.to_string(), "198.51.100.7");
        assert!(guard.is_banned("198.51.100.7".parse().unwrap()));
        assert_eq!(
            guard.ban_manual("bogus", validate::MANUAL_DEFAULT_SECONDS),
            Err(GuardBanError::InvalidTarget)
        );
        assert_eq!(
            guard.ban_manual("127.0.0.1", validate::MANUAL_DEFAULT_SECONDS),
            Err(GuardBanError::Loopback)
        );
        assert_eq!(
            guard.ban_manual("198.51.100.9", 60),
            Err(GuardBanError::InvalidDuration)
        );
        assert_eq!(
            guard
                .ban_manual("198.51.100.9", validate::MANUAL_PERMANENT)
                .unwrap()
                .until,
            None
        );
        assert_eq!(guard.unban("198.51.100.0/24").unwrap(), 2);
    }

    #[tokio::test]
    async fn apply_settings_updates_policy() {
        let guard = service();
        let settings = validate::normalize(crate::model::FileConfig {
            settings: Settings {
                ban_seconds: 60,
                max_ban_seconds: 0,
                ..Settings::default()
            },
            jails: Vec::new(),
        })
        .settings;
        guard.apply_settings(&settings);
        let now = SystemTime::now();
        let outcome = guard.ban_auto(
            "203.0.113.4".parse().unwrap(),
            None,
            false,
            Source::Scan,
            "r".to_owned(),
            now,
        );
        let BanOutcome::Banned { entry, .. } = outcome else {
            panic!("expected Banned, got {outcome:?}");
        };
        let until = entry.until.expect("temporary ban");
        assert_eq!(
            until.duration_since(now).unwrap().as_secs(),
            60,
            "the configured default duration applies"
        );
    }

    #[tokio::test]
    async fn whitelist_from_settings_and_local_networks_merge() {
        let guard = service();
        let settings = validate::normalize(crate::model::FileConfig {
            settings: Settings {
                ignore_list: vec!["9.9.9.0/24".to_owned()],
                ..Settings::default()
            },
            jails: Vec::new(),
        })
        .settings;
        guard.apply_settings(&settings);
        guard.set_local_networks(vec![parse_target("2001:db8:aa::/64").unwrap()]);
        // Whitelisted user network.
        assert_eq!(
            guard.ban_auto(
                "9.9.9.9".parse().unwrap(),
                None,
                false,
                Source::Trap,
                "r".to_owned(),
                SystemTime::now(),
            ),
            BanOutcome::Rejected(fg_net::banlist::RejectReason::Whitelisted)
        );
        // Local IPv6 /64 is protected too.
        assert_eq!(
            guard.ban_auto(
                "2001:db8:aa::1".parse().unwrap(),
                None,
                false,
                Source::Scan,
                "r".to_owned(),
                SystemTime::now(),
            ),
            BanOutcome::Rejected(fg_net::banlist::RejectReason::Whitelisted)
        );
        // Applying settings again keeps the local networks.
        guard.apply_settings(&settings);
        assert_eq!(
            guard.ban_auto(
                "2001:db8:aa::2".parse().unwrap(),
                None,
                false,
                Source::Trap,
                "r".to_owned(),
                SystemTime::now(),
            ),
            BanOutcome::Rejected(fg_net::banlist::RejectReason::Whitelisted)
        );
    }
}
