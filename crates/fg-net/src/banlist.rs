//! Unified ban table shared by every listener, site and service (WP-50):
//! entries are keyed by IPv4 address, IPv6 /64 network or CIDR, repeat
//! offenders inside 30 days get doubling durations up to the configured
//! maximum, the table holds at most [`LIMIT`] entries with upstream's
//! eviction order, and whitelisted / private addresses are never auto
//! banned. Admin logins shield their address for 24 hours against trap and
//! scan sources only.
//!
//! Reads are lock-free: [`BanTable::is_banned`] only loads an
//! `arc_swap::ArcSwap` snapshot and is safe to call on every connection,
//! packet and request. Every mutation happens under a mutex and then
//! republishes a fresh snapshot. Changes are persisted to
//! `<config dir>/guard/bans.json` (compact JSON, 0600, temp file + rename)
//! with a debounce: the write fires `save_delay` after the first unsaved
//! change, merging everything in between into one write.

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use arc_swap::ArcSwap;
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Maximum number of entries in the table (upstream `DefaultLimit`).
pub const LIMIT: usize = 32768;
/// Default ban duration (upstream `defaultBanSeconds`).
pub const DEFAULT_DURATION: Duration = Duration::from_secs(3600);
/// Default escalation ceiling (upstream: 7 days; configurable up to
/// [`MAX_MAX_DURATION`]).
pub const DEFAULT_MAX_DURATION: Duration = Duration::from_secs(7 * 24 * 3600);
/// Hard ceiling for the configurable escalation ceiling: 365 days.
pub const MAX_MAX_DURATION: Duration = Duration::from_secs(365 * 24 * 3600);
/// Repeat offenses inside this window escalate; older ones restart at 1x.
pub const OFFENSE_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
/// How long a successful admin login shields its address (upstream
/// `loginTrustTTL`).
pub const LOGIN_TRUST_TTL: Duration = Duration::from_secs(24 * 3600);
/// Cap on the login trust table; the oldest shields are evicted first.
pub const LOGIN_TRUST_LIMIT: usize = 1024;
/// Debounce window for the bans file (upstream: 2 seconds).
pub const SAVE_DELAY: Duration = Duration::from_secs(2);
/// Default page size for [`BanTable::list`].
pub const DEFAULT_PAGE_LIMIT: usize = 100;
/// Hard cap on the page size for [`BanTable::list`].
pub const MAX_PAGE_LIMIT: usize = 500;

/// A clock: returns the current time. Injectable so the escalation,
/// extension and expiry logic is testable without sleeping.
pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// The real UTC clock.
pub fn system_clock() -> Clock {
    Arc::new(SystemTime::now)
}

/// Where a ban came from. Serialized as `manual`, `webservice`, `trap`,
/// `scan` or `jail:<rule key>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Manual,
    Webservice,
    Trap,
    Scan,
    Jail(String),
}

impl Source {
    /// The stable string form used on the wire and in filters.
    pub fn to_tag(&self) -> String {
        match self {
            Self::Manual => "manual".to_owned(),
            Self::Webservice => "webservice".to_owned(),
            Self::Trap => "trap".to_owned(),
            Self::Scan => "scan".to_owned(),
            Self::Jail(key) => format!("jail:{key}"),
        }
    }

    fn parse(tag: &str) -> Option<Self> {
        match tag {
            "manual" => Some(Self::Manual),
            "webservice" => Some(Self::Webservice),
            "trap" => Some(Self::Trap),
            "scan" => Some(Self::Scan),
            other => other
                .strip_prefix("jail:")
                .map(|key| Self::Jail(key.to_owned())),
        }
    }

    /// Automatic entries are eviction candidates; manual ones are not.
    fn auto(&self) -> bool {
        !matches!(self, Self::Manual)
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_tag())
    }
}

impl Serialize for Source {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_tag())
    }
}

impl<'de> Deserialize<'de> for Source {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let tag = String::deserialize(deserializer)?;
        Self::parse(&tag)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown ban source: {tag}")))
    }
}

/// The normalized key of one ban: a bare IPv4 address, or a network.
/// Bare IPv6 addresses aggregate to their /64 (auto and manual alike),
/// IPv4-mapped IPv6 addresses collapse to their IPv4 form, and explicit
/// CIDRs from manual bans keep their prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BanKey {
    V4(Ipv4Addr),
    Net(IpNet),
}

impl BanKey {
    /// Normalizes an address for automatic bans: IPv4-mapped IPv6 becomes
    /// IPv4 and a bare IPv6 address becomes its /64.
    pub fn from_ip(ip: IpAddr) -> Self {
        match unwrap_v4_mapped(ip) {
            IpAddr::V4(v4) => Self::V4(v4),
            IpAddr::V6(v6) => Self::Net(v6_net(v6, 64)),
        }
    }

    /// Normalizes a manual target given as a CIDR: host-length prefixes
    /// collapse to their address first, so a bare /128 still aggregates to
    /// its /64 while any wider prefix is kept as written.
    pub fn from_net(net: IpNet) -> Self {
        let host_prefix = match net {
            IpNet::V4(_) => 32,
            IpNet::V6(_) => 128,
        };
        if net.prefix_len() == host_prefix {
            Self::from_ip(net.addr())
        } else {
            Self::Net(net)
        }
    }

    /// Parses the serialized form: a CIDR keeps its prefix, a bare address
    /// is normalized like `from_ip`.
    pub fn parse(text: &str) -> Option<Self> {
        if let Ok(net) = text.parse::<IpNet>() {
            return Some(Self::Net(net));
        }
        text.parse::<IpAddr>().ok().map(Self::from_ip)
    }

    /// Whether `ip` falls inside this key.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = unwrap_v4_mapped(ip);
        match *self {
            Self::V4(v4) => ip == IpAddr::V4(v4),
            Self::Net(net) => net.contains(&ip),
        }
    }

    /// Whether this key falls inside `scope` (used for unban: unban a
    /// network removes every entry inside it).
    fn inside(&self, scope: &Self) -> bool {
        if self == scope {
            return true;
        }
        let (net, prefix) = match *self {
            Self::V4(v4) => (IpAddr::V4(v4), 32),
            Self::Net(net) => (net.network(), net.prefix_len()),
        };
        match *scope {
            Self::V4(scope_v4) => {
                prefix >= 32
                    && matches!(net, IpAddr::V4(_))
                    && IpNet::new(IpAddr::V4(scope_v4), 32)
                        .expect("32 is a valid prefix")
                        .contains(&net)
            }
            Self::Net(scope_net) => {
                prefix >= scope_net.prefix_len()
                    && families_match(net, scope_net.network())
                    && scope_net.contains(&net)
            }
        }
    }
}

fn families_match(a: IpAddr, b: IpAddr) -> bool {
    matches!(
        (a, b),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn unwrap_v4_mapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

/// The network of `addr` with `prefix` bits, host bits truncated.
fn v6_net(addr: Ipv6Addr, prefix: u8) -> IpNet {
    IpNet::new(IpAddr::V6(addr), prefix)
        .expect("prefix is valid for IPv6")
        .trunc()
}

impl fmt::Display for BanKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(v4) => write!(f, "{v4}"),
            Self::Net(net) => write!(f, "{net}"),
        }
    }
}

impl Serialize for BanKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for BanKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid ban key: {text}")))
    }
}

/// One stored ban.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    pub key: BanKey,
    /// Unban time; absent means permanent.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "time_option")]
    pub until: Option<SystemTime>,
    #[serde(with = "time_serde")]
    pub created: SystemTime,
    /// i18n reason key; the emitting rule may append parameters such as
    /// the ports that were hit.
    pub reason: String,
    pub source: Source,
    /// How many times this address has been banned in total (this ban
    /// included); mirrors the offense count.
    pub count: u32,
}

impl Entry {
    /// Whether the ban is in force at `now`.
    pub fn active(&self, now: SystemTime) -> bool {
        self.until.is_none_or(|until| now < until)
    }
}

/// Cumulative offense record for one key; survives unbans and restarts and
/// drives the escalating duration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Offense {
    pub count: u32,
    #[serde(with = "time_serde")]
    pub last: SystemTime,
}

/// The persisted file format (`guard/bans.json`). The serde impls serve
/// consumers that embed the types; the file itself is written and parsed
/// by the internal JSON codec ([`bans_io`]) because fg-net carries no JSON
/// dependency.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct BanFile {
    pub bans: Vec<Entry>,
    pub offenses: BTreeMap<BanKey, Offense>,
}

/// Policy knobs for the table. Defaults follow WP-50 §3.4.
#[derive(Clone, Debug)]
pub struct BanPolicy {
    /// Maximum number of entries; auto bans beyond it are evicted or
    /// rejected, manual and permanent entries are never evicted.
    pub limit: usize,
    /// Duration used when a rule does not provide one (3600 s).
    pub default_duration: Duration,
    /// Double the duration for repeat offenders inside [`OFFENSE_TTL`].
    pub increment: bool,
    /// Escalation ceiling (default 7 days, configurable up to 365 days).
    /// Also clamps escalated durations; durations given by a rule pass
    /// through unchanged except for escalation doubling.
    pub max_duration: Duration,
    /// Never auto ban private, loopback or link-local addresses.
    pub ignore_private: bool,
    /// Addresses and networks that are never auto banned. Defaults to the
    /// internal ranges; single IPv6 addresses widen to their /64.
    pub whitelist: Vec<IpNet>,
    /// Debounce window for the bans file (2 s).
    pub save_delay: Duration,
}

impl Default for BanPolicy {
    fn default() -> Self {
        Self {
            limit: LIMIT,
            default_duration: DEFAULT_DURATION,
            increment: true,
            max_duration: DEFAULT_MAX_DURATION,
            ignore_private: false,
            whitelist: default_whitelist(),
            save_delay: SAVE_DELAY,
        }
    }
}

impl BanPolicy {
    /// Normalizes the escalation ceiling: zero falls back to the default
    /// and the configured value cannot exceed [`MAX_MAX_DURATION`].
    pub fn clamp_max_duration(&mut self) {
        self.max_duration = if self.max_duration.is_zero() {
            DEFAULT_MAX_DURATION
        } else {
            self.max_duration.min(MAX_MAX_DURATION)
        };
    }
}

/// The default whitelist: private ranges, loopback, link-local and the
/// Tailscale CGNAT range. Local IPv6 /64s are added at runtime via
/// [`BanTable::set_whitelist`].
pub fn default_whitelist() -> Vec<IpNet> {
    let mut nets = Vec::new();
    for (addr, prefix) in [
        (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
        (IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
        (IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16),
        (IpAddr::V4(Ipv4Addr::LOCALHOST), 8),
        (IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16),
        (IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10),
        (IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
        (IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 10),
        (IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7),
    ] {
        nets.push(IpNet::new(addr, prefix).expect("constant prefixes are valid"));
    }
    nets
}

/// Callback invoked with a stored entry (see [`BanHooks`]).
pub type EntryHook = Arc<dyn Fn(&Entry) + Send + Sync>;
/// Callback invoked with a warning message (see [`BanHooks`]).
pub type WarningHook = Arc<dyn Fn(&str) + Send + Sync>;

/// Hooks out to the embedding module. All hooks are optional and run
/// outside the table locks; slow work belongs in the callee's own task.
#[derive(Clone, Default)]
pub struct BanHooks {
    /// Called after a landed automatic ban, with the stored entry.
    pub banned: Option<EntryHook>,
    /// Called when the bans file cannot be read or parsed at open; the
    /// table starts empty (upstream logs a warning and continues).
    pub load_warning: Option<WarningHook>,
}

/// Statistics counters for observability and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BanStats {
    /// Completed writes of the bans file.
    pub saves: u64,
    /// Failed writes of the bans file.
    pub save_errors: u64,
    /// Entries evicted to make room.
    pub evicted: u64,
    /// Auto bans rejected because nothing could be evicted.
    pub rejected: u64,
    /// Warnings emitted while loading the bans file.
    pub load_warnings: u64,
}

#[derive(Default)]
struct Stats {
    saves: AtomicU64,
    save_errors: AtomicU64,
    evicted: AtomicU64,
    rejected: AtomicU64,
    load_warnings: AtomicU64,
}

/// Live counts for status pages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BanCounts {
    /// Currently active (not expired) entries.
    pub bans: usize,
    pub offenses: usize,
    /// Addresses currently shielded by a recent admin login.
    pub login_trusted: usize,
}

/// Filter for [`BanTable::list`].
#[derive(Clone, Debug, Default)]
pub struct BanFilter {
    /// Exact source tag match; the tag `jail:` matches every jail source.
    pub source: Option<String>,
    /// Case-insensitive substring match on the key or the reason.
    pub search: Option<String>,
    /// Include entries whose `until` already passed (default: active only).
    pub include_expired: bool,
    pub offset: usize,
    /// 0 falls back to [`DEFAULT_PAGE_LIMIT`], capped at [`MAX_PAGE_LIMIT`].
    pub limit: usize,
}

/// The outcome of an automatic ban.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BanOutcome {
    Banned {
        entry: Entry,
        /// How many entries had to be evicted first.
        evicted: usize,
    },
    Rejected(RejectReason),
    /// The entry existed and the new expiry was not later; the offense
    /// count still advanced.
    Unchanged,
}

/// Why an automatic ban was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    Whitelisted,
    PrivateIgnored,
    AlreadyPermanent,
    /// Address logged into the admin UI within [`LOGIN_TRUST_TTL`] and the
    /// source was `trap` or `scan`.
    LoginTrusted,
    /// Address is a confirmed trusted source (`fg_net::trust_src`) and the
    /// source was `trap` or `scan`.
    TrustedSource,
    /// Table full and nothing evictable.
    TableFull,
}

/// Why a manual ban failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BanError {
    /// The target covers the loopback address (locally forwarded
    /// connections all appear as that address).
    Loopback,
    /// The address is already permanently banned.
    AlreadyPermanent,
    /// The table is at its limit and manual entries are never evicted.
    Full,
    /// The requested duration is zero.
    InvalidDuration,
}

impl fmt::Display for BanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Loopback => "target covers the loopback address",
            Self::AlreadyPermanent => "already permanently banned",
            Self::Full => "ban table is full",
            Self::InvalidDuration => "ban duration must be positive",
        };
        f.write_str(text)
    }
}

impl std::error::Error for BanError {}

#[derive(Default)]
struct Snapshot {
    exact: HashMap<BanKey, Entry>,
    /// Network entries for containment lookups (every `BanKey::Net`).
    nets: Vec<(IpNet, Entry)>,
}

impl Snapshot {
    fn build(entries: &BTreeMap<BanKey, Entry>) -> Self {
        let mut exact = HashMap::with_capacity(entries.len());
        let mut nets = Vec::new();
        for (key, entry) in entries {
            exact.insert(*key, entry.clone());
            if let BanKey::Net(net) = key {
                nets.push((*net, entry.clone()));
            }
        }
        Self { exact, nets }
    }
}

struct SaveSignal {
    /// Set when there are unsaved changes, to the time of the first
    /// unsaved change; the save fires `save_delay` later and merges
    /// everything in between.
    dirty_at: Option<Instant>,
}

struct Inner {
    entries: BTreeMap<BanKey, Entry>,
    offenses: BTreeMap<BanKey, Offense>,
    login_trust: BTreeMap<IpAddr, SystemTime>,
    policy: BanPolicy,
}

/// The shared ban table. Share the `Arc` wherever it is needed; every
/// module sees the same entries.
pub struct BanTable {
    inner: Mutex<Inner>,
    snapshot: ArcSwap<Snapshot>,
    signal: Mutex<SaveSignal>,
    save_wake: Condvar,
    io_lock: Mutex<()>,
    path: Option<PathBuf>,
    hooks: BanHooks,
    clock: Clock,
    stats: Stats,
}

impl BanTable {
    /// Opens (or creates) the bans file at `path` (typically
    /// `<config dir>/guard/bans.json`), restores its contents, drops
    /// expired entries, and starts the delayed saver. An unreadable or
    /// invalid file only produces a [`BanHooks::load_warning`] and an
    /// empty table.
    pub fn open(
        path: &Path,
        policy: BanPolicy,
        hooks: BanHooks,
        clock: Clock,
    ) -> std::io::Result<Arc<Self>> {
        if let Some(parent) = path.parent() {
            ensure_private_dir(parent)?;
        }
        let now = (clock)();
        let (file, warnings) = load_file(path, now);
        if let Some(hook) = &hooks.load_warning {
            for warning in &warnings {
                hook(warning);
            }
        }
        let table = Self::assemble(Some(path.to_owned()), policy, hooks, clock);
        {
            let mut inner = table.inner.lock().expect("ban table lock");
            inner.entries = file
                .bans
                .into_iter()
                .map(|entry| (entry.key, entry))
                .collect();
            inner.offenses = file.offenses;
            table.publish(&inner);
        }
        if !warnings.is_empty() {
            table.stats.load_warnings.fetch_add(1, Ordering::Relaxed);
        }
        table.spawn_saver();
        Ok(table)
    }

    /// An in-memory table: same semantics, no persistence.
    pub fn open_memory(policy: BanPolicy, hooks: BanHooks, clock: Clock) -> Arc<Self> {
        let table = Self::assemble(None, policy, hooks, clock);
        table.spawn_saver();
        table
    }

    fn assemble(
        path: Option<PathBuf>,
        policy: BanPolicy,
        hooks: BanHooks,
        clock: Clock,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                entries: BTreeMap::new(),
                offenses: BTreeMap::new(),
                login_trust: BTreeMap::new(),
                policy,
            }),
            snapshot: ArcSwap::from_pointee(Snapshot::default()),
            signal: Mutex::new(SaveSignal { dirty_at: None }),
            save_wake: Condvar::new(),
            io_lock: Mutex::new(()),
            path,
            hooks,
            clock,
            stats: Stats::default(),
        })
    }

    fn spawn_saver(self: &Arc<Self>) {
        if self.path.is_none() {
            return;
        }
        let weak = Arc::downgrade(self);
        std::thread::Builder::new()
            .name("fg-net-banlist-save".to_owned())
            .spawn(move || saver_loop(weak))
            .expect("spawn banlist saver thread");
    }

    /// Lock-free lookup used on every connection, packet and request: an
    /// exact key hit first, then a scan over the manually banned networks.
    /// Expired entries read as not banned until the next write prunes
    /// them.
    pub fn is_banned(&self, ip: IpAddr, now: SystemTime) -> bool {
        let ip = unwrap_v4_mapped(ip);
        let key = BanKey::from_ip(ip);
        let snapshot = self.snapshot.load();
        if snapshot
            .exact
            .get(&key)
            .is_some_and(|entry| entry.active(now))
        {
            return true;
        }
        snapshot
            .nets
            .iter()
            .any(|(net, entry)| net.contains(&ip) && entry.active(now))
    }

    /// Automatic ban entry point (jails, decoy ports, scan detection, web
    /// service auth failures). Applies the whitelist and private-range
    /// exemptions, the escalating duration, the extension rule and the
    /// eviction order; fires [`BanHooks::banned`] after a ban lands.
    pub fn ban_auto(
        &self,
        ip: IpAddr,
        duration: Option<Duration>,
        permanent: bool,
        source: Source,
        reason: String,
        now: SystemTime,
    ) -> BanOutcome {
        let ip = unwrap_v4_mapped(ip);
        let (outcome, entry) = {
            let mut inner = self.inner.lock().expect("ban table lock");
            self.prune_locked(&mut inner, now);
            self.ban_auto_locked(&mut inner, ip, duration, permanent, source, reason, now)
        };
        if entry.is_some() {
            self.mark_dirty();
        }
        if let (Some(entry), BanOutcome::Banned { .. }) = (&entry, &outcome)
            && let Some(hook) = &self.hooks.banned
        {
            hook(entry);
        }
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    fn ban_auto_locked(
        &self,
        inner: &mut Inner,
        ip: IpAddr,
        duration: Option<Duration>,
        permanent: bool,
        source: Source,
        reason: String,
        now: SystemTime,
    ) -> (BanOutcome, Option<Entry>) {
        if inner.policy.whitelist.iter().any(|net| net.contains(&ip)) {
            return (BanOutcome::Rejected(RejectReason::Whitelisted), None);
        }
        if inner.policy.ignore_private && is_private(ip) {
            return (BanOutcome::Rejected(RejectReason::PrivateIgnored), None);
        }
        if matches!(source, Source::Trap | Source::Scan) {
            if crate::trust_src::is_trusted(ip) {
                return (BanOutcome::Rejected(RejectReason::TrustedSource), None);
            }
            if login_trusted(&inner.login_trust, ip, now) {
                return (BanOutcome::Rejected(RejectReason::LoginTrusted), None);
            }
        }
        let key = BanKey::from_ip(ip);
        if inner
            .entries
            .get(&key)
            .is_some_and(|existing| existing.until.is_none())
        {
            return (BanOutcome::Rejected(RejectReason::AlreadyPermanent), None);
        }
        let count = record_offense(&mut inner.offenses, key, now);
        let until = if permanent {
            None
        } else {
            Some(now + escalated_duration(&inner.policy, duration, count))
        };
        let outcome;
        let entry;
        if let Some(existing) = inner.entries.get(&key).cloned() {
            // A temporary entry is extended to the later expiry and its
            // count advances; a new permanent ban turns it permanent.
            let merged_until = match (existing.until, until) {
                (Some(old), Some(new)) => Some(old.max(new)),
                (_, None) => None,
                (None, Some(new)) => Some(new),
            };
            let mut updated = existing.clone();
            updated.until = merged_until;
            updated.count = count;
            updated.reason = reason;
            updated.source = source;
            let extended = updated.until != existing.until;
            inner.entries.insert(key, updated.clone());
            outcome = if extended {
                BanOutcome::Banned {
                    entry: updated.clone(),
                    evicted: 0,
                }
            } else {
                BanOutcome::Unchanged
            };
            entry = updated;
        } else {
            let Some(evicted) = self.evict_locked(inner) else {
                self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                return (BanOutcome::Rejected(RejectReason::TableFull), None);
            };
            let fresh = Entry {
                key,
                until,
                created: now,
                reason,
                source,
                count,
            };
            outcome = BanOutcome::Banned {
                entry: fresh.clone(),
                evicted,
            };
            entry = fresh;
            inner.entries.insert(key, entry.clone());
        }
        self.publish(inner);
        (outcome, Some(entry))
    }

    /// Manual ban of an IP or CIDR from the admin API. Hours are validated
    /// by the caller (`1..=720`; `seconds = -1` maps to `permanent`);
    /// loopback-covering targets are refused because locally forwarded
    /// connections all appear as that address. Manual entries are never
    /// evicted.
    pub fn ban_manual(
        &self,
        cidr: IpNet,
        duration: Option<Duration>,
        permanent: bool,
        now: SystemTime,
    ) -> Result<Entry, BanError> {
        let key = BanKey::from_net(cidr);
        if key_covers_loopback(key) {
            return Err(BanError::Loopback);
        }
        if !permanent && duration.is_none_or(|value| value.is_zero()) {
            return Err(BanError::InvalidDuration);
        }
        let entry = {
            let mut inner = self.inner.lock().expect("ban table lock");
            self.prune_locked(&mut inner, now);
            if inner
                .entries
                .get(&key)
                .is_some_and(|existing| existing.until.is_none())
            {
                return Err(BanError::AlreadyPermanent);
            }
            if inner.entries.len() >= inner.policy.limit && !inner.entries.contains_key(&key) {
                return Err(BanError::Full);
            }
            let count = record_offense(&mut inner.offenses, key, now);
            let until = if permanent {
                None
            } else {
                duration.map(|value| now + value)
            };
            let entry = match inner.entries.get(&key).cloned() {
                Some(existing) => {
                    let mut entry = existing.clone();
                    entry.until = match (existing.until, until) {
                        (Some(old), Some(new)) => Some(old.max(new)),
                        (_, None) => None,
                        (None, Some(new)) => Some(new),
                    };
                    entry.count = count;
                    entry.reason = "guard.reason.manual".to_owned();
                    entry.source = Source::Manual;
                    entry
                }
                None => Entry {
                    key,
                    until,
                    created: now,
                    reason: "guard.reason.manual".to_owned(),
                    source: Source::Manual,
                    count,
                },
            };
            inner.entries.insert(key, entry.clone());
            self.publish(&inner);
            entry
        };
        self.mark_dirty();
        Ok(entry)
    }

    /// Removes every entry inside `cidr` (a bare address removes exactly
    /// that key; a network removes all entries inside it). Returns how
    /// many live entries were removed. Offense history is kept.
    pub fn unban(&self, cidr: &IpNet, now: SystemTime) -> usize {
        let scope = BanKey::from_net(*cidr);
        let removed = {
            let mut inner = self.inner.lock().expect("ban table lock");
            self.prune_locked(&mut inner, now);
            let stale: Vec<BanKey> = inner
                .entries
                .keys()
                .filter(|key| key.inside(&scope))
                .copied()
                .collect();
            for key in &stale {
                inner.entries.remove(key);
            }
            if !stale.is_empty() {
                self.publish(&inner);
            }
            stale.len()
        };
        if removed > 0 {
            self.mark_dirty();
        }
        removed
    }

    /// Filtered, paged listing, newest first. Expired entries are skipped
    /// unless `include_expired` is set.
    pub fn list(&self, now: SystemTime, filter: &BanFilter) -> Vec<Entry> {
        let matches = self.collect(now, filter);
        let limit = if filter.limit == 0 {
            DEFAULT_PAGE_LIMIT
        } else {
            filter.limit.min(MAX_PAGE_LIMIT)
        };
        matches
            .into_iter()
            .skip(filter.offset)
            .take(limit)
            .collect()
    }

    /// Number of entries matching the filter, ignoring pagination.
    pub fn count(&self, now: SystemTime, filter: &BanFilter) -> usize {
        self.collect(now, filter).len()
    }

    /// Filtered, sorted matches without pagination.
    fn collect(&self, now: SystemTime, filter: &BanFilter) -> Vec<Entry> {
        let inner = self.inner.lock().expect("ban table lock");
        let needle = filter.search.as_deref().map(str::to_lowercase);
        let mut matches: Vec<Entry> = inner
            .entries
            .values()
            .filter(|entry| filter.include_expired || entry.active(now))
            .filter(|entry| match &filter.source {
                Some(source) => {
                    let tag = entry.source.to_tag();
                    if source == "jail:" {
                        tag.starts_with("jail:")
                    } else {
                        &tag == source
                    }
                }
                None => true,
            })
            .filter(|entry| {
                needle.as_ref().is_none_or(|needle| {
                    entry.key.to_string().contains(needle)
                        || entry.reason.to_lowercase().contains(needle)
                })
            })
            .cloned()
            .collect();
        matches.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.key.cmp(&b.key)));
        matches
    }

    /// The offense record for one key, if any.
    pub fn offense(&self, key: &BanKey) -> Option<Offense> {
        self.inner
            .lock()
            .expect("ban table lock")
            .offenses
            .get(key)
            .copied()
    }

    /// Replaces the whitelist: user-provided networks plus the local IPv6
    /// networks. Single IPv6 entries widen to their /64 in both lists.
    pub fn set_whitelist(&self, whitelist: Vec<IpNet>, local_v6: Vec<IpNet>) {
        let mut inner = self.inner.lock().expect("ban table lock");
        inner.policy.whitelist = whitelist
            .into_iter()
            .map(widen_single_v6)
            .chain(local_v6.into_iter().map(widen_single_v6))
            .collect();
    }

    /// Replaces the whole policy (including the whitelist); used by the
    /// guard module when `guard.json` changes.
    pub fn set_policy(&self, policy: BanPolicy) {
        let mut inner = self.inner.lock().expect("ban table lock");
        inner.policy = policy;
    }

    /// Called after a successful admin login (WP-12): the address is
    /// shielded for [`LOGIN_TRUST_TTL`] against trap and scan sources.
    pub fn trust_login(&self, ip: IpAddr, now: SystemTime) {
        let mut inner = self.inner.lock().expect("ban table lock");
        inner.login_trust.retain(|_, expires| *expires > now);
        inner
            .login_trust
            .insert(unwrap_v4_mapped(ip), now + LOGIN_TRUST_TTL);
        while inner.login_trust.len() > LOGIN_TRUST_LIMIT {
            inner.login_trust.pop_first();
        }
    }

    /// Whether `ip` holds a current login shield.
    pub fn is_login_trusted(&self, ip: IpAddr, now: SystemTime) -> bool {
        let ip = unwrap_v4_mapped(ip);
        let inner = self.inner.lock().expect("ban table lock");
        login_trusted(&inner.login_trust, ip, now)
    }

    /// Live counts for status pages.
    pub fn counts(&self, now: SystemTime) -> BanCounts {
        let inner = self.inner.lock().expect("ban table lock");
        BanCounts {
            bans: inner.entries.values().filter(|e| e.active(now)).count(),
            offenses: inner.offenses.len(),
            login_trusted: inner.login_trust.len(),
        }
    }

    pub fn stats(&self) -> BanStats {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        BanStats {
            saves: load(&self.stats.saves),
            save_errors: load(&self.stats.save_errors),
            evicted: load(&self.stats.evicted),
            rejected: load(&self.stats.rejected),
            load_warnings: load(&self.stats.load_warnings),
        }
    }

    /// The table's clock (the injected time source; useful for callers
    /// that need to compute expiries against the same time).
    pub fn now(&self) -> SystemTime {
        (self.clock)()
    }

    /// Snapshots the file contents (for tests and shutdown reporting).
    pub fn file_state(&self) -> BanFile {
        let inner = self.inner.lock().expect("ban table lock");
        BanFile {
            bans: inner.entries.values().cloned().collect(),
            offenses: inner.offenses.clone(),
        }
    }

    /// Forces a write if there are unsaved changes. Called by the delayed
    /// saver and by the module on shutdown.
    pub fn flush(&self) -> std::io::Result<()> {
        match self.take_for_save() {
            Some(file) => self.write_file(&file).inspect_err(|_| self.mark_dirty()),
            None => Ok(()),
        }
    }

    // -- internals -------------------------------------------------------

    /// Evicts temporary automatic entries, oldest first, until one more
    /// entry fits; permanent and manual entries are never evicted. Returns
    /// the number evicted, or `None` when nothing could be freed.
    fn evict_locked(&self, inner: &mut Inner) -> Option<usize> {
        let mut evicted = 0;
        while inner.entries.len() >= inner.policy.limit {
            let victim = inner
                .entries
                .iter()
                .filter(|(_, entry)| entry.until.is_some() && entry.source.auto())
                .min_by_key(|(key, entry)| (entry.created, **key))
                .map(|(key, _)| *key)?;
            inner.entries.remove(&victim);
            evicted += 1;
            self.stats.evicted.fetch_add(1, Ordering::Relaxed);
        }
        Some(evicted)
    }

    fn prune_locked(&self, inner: &mut Inner, now: SystemTime) {
        let before = inner.entries.len();
        inner.entries.retain(|_, entry| entry.active(now));
        let before_offenses = inner.offenses.len();
        inner.offenses.retain(|_, offense| {
            now.duration_since(offense.last)
                .is_ok_and(|age| age < OFFENSE_TTL)
        });
        if inner.entries.len() != before || inner.offenses.len() != before_offenses {
            self.publish(inner);
        }
    }

    fn publish(&self, inner: &Inner) {
        self.snapshot
            .store(Arc::new(Snapshot::build(&inner.entries)));
    }

    fn mark_dirty(&self) {
        let mut signal = self.signal.lock().expect("ban save signal");
        if signal.dirty_at.is_none() {
            signal.dirty_at = Some(Instant::now());
            self.save_wake.notify_all();
        }
    }

    /// Clears the dirty marker and returns the data to write, or `None`
    /// when there is nothing pending.
    fn take_for_save(&self) -> Option<BanFile> {
        {
            let mut signal = self.signal.lock().expect("ban save signal");
            signal.dirty_at.take()?;
        }
        let inner = self.inner.lock().expect("ban table lock");
        Some(BanFile {
            bans: inner.entries.values().cloned().collect(),
            offenses: inner.offenses.clone(),
        })
    }

    fn write_file(&self, file: &BanFile) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let _io = self.io_lock.lock().expect("ban file io lock");
        let bytes = bans_io::write_bans(file);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes)?;
        #[cfg(unix)]
        std::fs::set_permissions(&tmp, {
            use std::os::unix::fs::PermissionsExt;
            std::fs::Permissions::from_mode(0o600)
        })?;
        std::fs::rename(&tmp, path)?;
        self.stats.saves.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

impl Drop for BanTable {
    /// Best-effort flush of unsaved changes; explicit `flush` on shutdown
    /// is still preferred because errors are swallowed here.
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// The delayed saver: waits for the first unsaved change, sleeps
/// `save_delay`, merges everything since into one write. Exits when the
/// table is dropped (its final flush happens in `Drop`).
fn saver_loop(table: Weak<BanTable>) {
    loop {
        let Some(table) = table.upgrade() else { return };
        {
            let mut signal = table.signal.lock().expect("ban save signal");
            while signal.dirty_at.is_none() {
                signal = table.save_wake.wait(signal).expect("ban save signal");
            }
        }
        let deadline = {
            let signal = table.signal.lock().expect("ban save signal");
            let delay = table
                .inner
                .lock()
                .expect("ban table lock")
                .policy
                .save_delay;
            signal.dirty_at.map(|at| at + delay)
        };
        let Some(deadline) = deadline else { continue };
        {
            let signal = table.signal.lock().expect("ban save signal");
            let _ = table.save_wake.wait_timeout_while(
                signal,
                deadline.saturating_duration_since(Instant::now()),
                |state: &mut SaveSignal| state.dirty_at.is_some() && Instant::now() < deadline,
            );
        }
        if Instant::now() >= deadline
            && let Some(file) = table.take_for_save()
            && let Err(error) = table.write_file(&file)
        {
            table.stats.save_errors.fetch_add(1, Ordering::Relaxed);
            eprintln!("saving the bans file failed: {error}");
        }
    }
}

fn login_trusted(trust: &BTreeMap<IpAddr, SystemTime>, ip: IpAddr, now: SystemTime) -> bool {
    trust.get(&ip).is_some_and(|expires| *expires > now)
}

fn record_offense(offenses: &mut BTreeMap<BanKey, Offense>, key: BanKey, now: SystemTime) -> u32 {
    let next = match offenses.get(&key) {
        Some(offense)
            if now
                .duration_since(offense.last)
                .is_ok_and(|age| age < OFFENSE_TTL) =>
        {
            offense.count.saturating_add(1)
        }
        _ => 1,
    };
    offenses.insert(
        key,
        Offense {
            count: next,
            last: now,
        },
    );
    next
}

/// The escalated duration: double per repeat offense inside the TTL, up to
/// the policy ceiling. `count` includes the current ban, so a first ban
/// keeps the base duration.
fn escalated_duration(policy: &BanPolicy, requested: Option<Duration>, count: u32) -> Duration {
    let mut duration = requested.unwrap_or(policy.default_duration);
    if policy.increment && count > 1 {
        for _ in 1..count.min(32) {
            let doubled = duration.saturating_mul(2);
            if doubled >= policy.max_duration {
                duration = policy.max_duration;
                break;
            }
            duration = doubled;
        }
    }
    duration.min(policy.max_duration)
}

fn widen_single_v6(net: IpNet) -> IpNet {
    match net {
        IpNet::V6(v6) if v6.prefix_len() == 128 => v6_net(v6.network(), 64),
        other => other,
    }
}

/// Private, loopback or link-local (used by `ignorePrivate`).
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

fn key_covers_loopback(key: BanKey) -> bool {
    match key {
        BanKey::V4(v4) => v4.is_loopback(),
        // Overlap with the whole IPv4 loopback range: Docker bridges put
        // guests anywhere in 127/8, so banning any of it locks people out.
        BanKey::Net(IpNet::V4(net)) => {
            let low = Ipv4Addr::new(127, 0, 0, 0);
            let high = Ipv4Addr::new(127, 255, 255, 255);
            net.network() <= high && net.broadcast() >= low
        }
        BanKey::Net(IpNet::V6(net)) => net.contains(&Ipv6Addr::LOCALHOST),
    }
}

fn load_file(path: &Path, now: SystemTime) -> (BanFile, Vec<String>) {
    let Ok(bytes) = std::fs::read(path) else {
        return (BanFile::default(), Vec::new());
    };
    match bans_io::parse_bans(&bytes) {
        Some(mut file) => {
            file.bans.retain(|entry| entry.active(now));
            file.offenses.retain(|_, offense| {
                now.duration_since(offense.last)
                    .is_ok_and(|age| age < OFFENSE_TTL)
            });
            (file, Vec::new())
        }
        None => (
            BanFile::default(),
            vec!["bans file ignored (invalid format)".to_owned()],
        ),
    }
}

fn ensure_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Compact JSON codec for the bans file, written and parsed without a
/// JSON dependency. Field names match the serde shape of [`BanFile`]
/// (`bans`, `offenses`, camelCase entries); unknown object keys are
/// ignored on load and an unusable file is reported as `None` so the
/// caller warns and starts empty.
mod bans_io {
    use std::collections::BTreeMap;

    use super::{BanFile, BanKey, Entry, Offense, Source, rfc3339};

    pub fn write_bans(file: &BanFile) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + file.bans.len() * 96);
        out.extend_from_slice(b"{\"bans\":[");
        for (index, entry) in file.bans.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            out.extend_from_slice(b"{\"key\":");
            write_str(&mut out, &entry.key.to_string());
            if let Some(until) = entry.until {
                out.extend_from_slice(b",\"until\":");
                write_str(&mut out, &rfc3339::format(until));
            }
            out.extend_from_slice(b",\"created\":");
            write_str(&mut out, &rfc3339::format(entry.created));
            out.extend_from_slice(b",\"reason\":");
            write_str(&mut out, &entry.reason);
            out.extend_from_slice(b",\"source\":");
            write_str(&mut out, &entry.source.to_tag());
            out.extend_from_slice(b",\"count\":");
            out.extend_from_slice(entry.count.to_string().as_bytes());
            out.push(b'}');
        }
        out.extend_from_slice(b"],\"offenses\":{");
        for (index, (key, offense)) in file.offenses.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            write_str(&mut out, &key.to_string());
            out.extend_from_slice(b":{\"count\":");
            out.extend_from_slice(offense.count.to_string().as_bytes());
            out.extend_from_slice(b",\"last\":");
            write_str(&mut out, &rfc3339::format(offense.last));
            out.push(b'}');
        }
        out.extend_from_slice(b"}}");
        out
    }

    pub fn parse_bans(bytes: &[u8]) -> Option<BanFile> {
        let value = parse_value(&mut Parser { bytes, pos: 0 })?;
        let obj = value.as_obj()?;
        let mut bans = Vec::new();
        if let Some(items) = field(obj, "bans") {
            for item in items.as_arr()? {
                let fields = item.as_obj()?;
                let key = BanKey::parse(field(fields, "key")?.as_str()?)?;
                let until = match field(fields, "until") {
                    None | Some(Json::Null) => None,
                    Some(Json::Str(text)) => Some(rfc3339::parse(text)?),
                    Some(_) => return None,
                };
                let created = rfc3339::parse(field(fields, "created")?.as_str()?)?;
                let reason = field(fields, "reason")?.as_str()?.to_owned();
                let source = Source::parse(field(fields, "source")?.as_str()?)?;
                let count = u32::try_from(field(fields, "count")?.as_num()?).ok()?;
                bans.push(Entry {
                    key,
                    until,
                    created,
                    reason,
                    source,
                    count,
                });
            }
        }
        let mut offenses = BTreeMap::new();
        if let Some(items) = field(obj, "offenses") {
            for (key, value) in items.as_obj()? {
                let fields = value.as_obj()?;
                let key = BanKey::parse(key)?;
                let count = u32::try_from(field(fields, "count")?.as_num()?).ok()?;
                let last = rfc3339::parse(field(fields, "last")?.as_str()?)?;
                offenses.insert(key, Offense { count, last });
            }
        }
        Some(BanFile { bans, offenses })
    }

    fn field<'a>(fields: &'a [(String, Json)], name: &str) -> Option<&'a Json> {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    }

    fn write_str(out: &mut Vec<u8>, text: &str) {
        out.push(b'"');
        for character in text.chars() {
            match character {
                '"' => out.extend_from_slice(b"\\\""),
                '\\' => out.extend_from_slice(b"\\\\"),
                '\n' => out.extend_from_slice(b"\\n"),
                '\r' => out.extend_from_slice(b"\\r"),
                '\t' => out.extend_from_slice(b"\\t"),
                control if (control as u32) < 0x20 => {
                    out.extend_from_slice(format!("\\u{:04x}", control as u32).as_bytes());
                }
                other => {
                    let mut buffer = [0u8; 4];
                    out.extend_from_slice(other.encode_utf8(&mut buffer).as_bytes());
                }
            }
        }
        out.push(b'"');
    }

    enum Json {
        Null,
        Num(i64),
        Str(String),
        Arr(Vec<Json>),
        Obj(Vec<(String, Json)>),
    }

    impl Json {
        fn as_str(&self) -> Option<&str> {
            match self {
                Self::Str(text) => Some(text),
                _ => None,
            }
        }

        fn as_num(&self) -> Option<i64> {
            match self {
                Self::Num(value) => Some(*value),
                _ => None,
            }
        }

        fn as_arr(&self) -> Option<&[Json]> {
            match self {
                Self::Arr(items) => Some(items),
                _ => None,
            }
        }

        fn as_obj(&self) -> Option<&[(String, Json)]> {
            match self {
                Self::Obj(fields) => Some(fields),
                _ => None,
            }
        }
    }

    struct Parser<'a> {
        bytes: &'a [u8],
        pos: usize,
    }

    fn parse_value(parser: &mut Parser<'_>) -> Option<Json> {
        parser.skip_ws();
        match parser.peek()? {
            b'{' => parser.parse_object(),
            b'[' => parser.parse_array(),
            b'"' => parser.parse_string().map(Json::Str),
            b't' => parser.expect_literal("true").then_some(Json::Num(1)),
            b'f' => parser.expect_literal("false").then_some(Json::Null),
            b'n' => parser.expect_literal("null").then_some(Json::Null),
            b'-' | b'0'..=b'9' => parser.parse_number(),
            _ => None,
        }
    }

    impl Parser<'_> {
        fn skip_ws(&mut self) {
            while matches!(self.bytes.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
                self.pos += 1;
            }
        }

        fn peek(&mut self) -> Option<u8> {
            self.skip_ws();
            self.bytes.get(self.pos).copied()
        }

        fn expect_literal(&mut self, literal: &str) -> bool {
            if self.bytes.get(self.pos..self.pos + literal.len()) == Some(literal.as_bytes()) {
                self.pos += literal.len();
                true
            } else {
                false
            }
        }

        fn parse_object(&mut self) -> Option<Json> {
            self.pos += 1; // '{'
            let mut fields = Vec::new();
            if self.peek()? == b'}' {
                self.pos += 1;
                return Some(Json::Obj(fields));
            }
            loop {
                self.skip_ws();
                let key = self.parse_string()?;
                self.skip_ws();
                if self.bytes.get(self.pos) != Some(&b':') {
                    return None;
                }
                self.pos += 1;
                let value = parse_value(self)?;
                fields.push((key, value));
                match self.peek()? {
                    b',' => self.pos += 1,
                    b'}' => {
                        self.pos += 1;
                        return Some(Json::Obj(fields));
                    }
                    _ => return None,
                }
            }
        }

        fn parse_array(&mut self) -> Option<Json> {
            self.pos += 1; // '['
            let mut items = Vec::new();
            if self.peek()? == b']' {
                self.pos += 1;
                return Some(Json::Arr(items));
            }
            loop {
                let value = parse_value(self)?;
                items.push(value);
                match self.peek()? {
                    b',' => self.pos += 1,
                    b']' => {
                        self.pos += 1;
                        return Some(Json::Arr(items));
                    }
                    _ => return None,
                }
            }
        }

        fn parse_string(&mut self) -> Option<String> {
            if self.bytes.get(self.pos) != Some(&b'"') {
                return None;
            }
            self.pos += 1;
            let mut text = String::new();
            loop {
                let byte = *self.bytes.get(self.pos)?;
                self.pos += 1;
                match byte {
                    b'"' => return Some(text),
                    b'\\' => {
                        let escape = *self.bytes.get(self.pos)?;
                        self.pos += 1;
                        match escape {
                            b'"' => text.push('"'),
                            b'\\' => text.push('\\'),
                            b'/' => text.push('/'),
                            b'b' => text.push('\u{8}'),
                            b'f' => text.push('\u{c}'),
                            b'n' => text.push('\n'),
                            b'r' => text.push('\r'),
                            b't' => text.push('\t'),
                            b'u' => text.push(self.parse_unicode_escape()?),
                            _ => return None,
                        }
                    }
                    byte if byte < 0x20 => return None,
                    byte if byte < 0x80 => text.push(byte as char),
                    _ => {
                        // A UTF-8 continuation: collect the whole sequence.
                        let start = self.pos - 1;
                        let width = utf8_width(byte);
                        let end = start + width;
                        let slice = self.bytes.get(start..end)?;
                        if slice.iter().skip(1).any(|b| b & 0xC0 != 0x80) {
                            return None;
                        }
                        text.push_str(std::str::from_utf8(slice).ok()?);
                        self.pos = end;
                    }
                }
            }
        }

        fn parse_unicode_escape(&mut self) -> Option<char> {
            let high = self.parse_hex4()?;
            match high {
                0xD800..=0xDBFF => {
                    // High surrogate: expect \uDC00..\uDFFF next.
                    if self.bytes.get(self.pos) != Some(&b'\\')
                        || self.bytes.get(self.pos + 1) != Some(&b'u')
                    {
                        return Some('\u{FFFD}');
                    }
                    self.pos += 2;
                    let low = self.parse_hex4()?;
                    if (0xDC00..=0xDFFF).contains(&low) {
                        let combined = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
                        char::from_u32(combined)
                    } else {
                        Some('\u{FFFD}')
                    }
                }
                0xDC00..=0xDFFF => Some('\u{FFFD}'),
                value => char::from_u32(value),
            }
        }

        fn parse_hex4(&mut self) -> Option<u32> {
            let slice = self.bytes.get(self.pos..self.pos + 4)?;
            let mut value = 0u32;
            for byte in slice {
                let digit = match byte {
                    b'0'..=b'9' => u32::from(byte - b'0'),
                    b'a'..=b'f' => u32::from(byte - b'a') + 10,
                    b'A'..=b'F' => u32::from(byte - b'A') + 10,
                    _ => return None,
                };
                value = value * 16 + digit;
            }
            self.pos += 4;
            Some(value)
        }

        fn parse_number(&mut self) -> Option<Json> {
            let start = self.pos;
            if self.bytes.get(self.pos) == Some(&b'-') {
                self.pos += 1;
            }
            while self
                .bytes
                .get(self.pos)
                .is_some_and(|byte| byte.is_ascii_digit())
            {
                self.pos += 1;
            }
            if self.bytes.get(self.pos) == Some(&b'.') {
                self.pos += 1;
                while self
                    .bytes
                    .get(self.pos)
                    .is_some_and(|byte| byte.is_ascii_digit())
                {
                    self.pos += 1;
                }
            }
            let text = self.bytes.get(start..self.pos)?;
            if text.is_empty() || text == b"-" {
                return None;
            }
            // Counts are integers; the fraction part (never produced by the
            // writer) truncates harmlessly.
            let whole = std::str::from_utf8(text).ok()?;
            Some(Json::Num(whole.parse::<f64>().ok()? as i64))
        }
    }

    fn utf8_width(byte: u8) -> usize {
        match byte {
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF7 => 4,
            _ => 1,
        }
    }
}

/// RFC 3339 (UTC) storage of times, per the workspace convention.
/// Hand-rolled because fg-net has no `time` dependency: output uses second
/// precision with a `Z` offset; parsing accepts fractional seconds and
/// numeric offsets.
pub mod rfc3339 {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// Formats as `YYYY-MM-DDTHH:MM:SSZ`.
    pub fn format(time: SystemTime) -> String {
        let secs = match time.duration_since(UNIX_EPOCH) {
            Ok(delta) => delta.as_secs() as i64,
            Err(error) => -(error.duration().as_secs() as i64),
        };
        let days = secs.div_euclid(86_400);
        let second_of_day = secs.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            second_of_day / 3600,
            second_of_day % 3600 / 60,
            second_of_day % 60
        )
    }

    /// Parses `YYYY-MM-DDTHH:MM:SS(.fff…)?(Z|z|±HH:MM|±HHMM)`.
    pub fn parse(text: &str) -> Option<SystemTime> {
        let bytes = text.as_bytes();
        if bytes.len() < 20 {
            return None;
        }
        let number = |start: usize, len: usize| -> Option<i64> {
            let slice = bytes.get(start..start + len)?;
            let mut value: i64 = 0;
            for byte in slice {
                if !byte.is_ascii_digit() {
                    return None;
                }
                value = value * 10 + i64::from(byte - b'0');
            }
            Some(value)
        };
        if bytes[4] != b'-' || bytes[7] != b'-' || bytes[13] != b':' || bytes[16] != b':' {
            return None;
        }
        if !matches!(bytes[10], b'T' | b't') {
            return None;
        }
        let (year, month, day) = (number(0, 4)?, number(5, 2)?, number(8, 2)?);
        let (hour, minute, second) = (number(11, 2)?, number(14, 2)?, number(17, 2)?);
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return None;
        }
        if hour > 23 || minute > 59 || second > 60 {
            return None;
        }
        let mut index = 19;
        if bytes.get(index) == Some(&b'.') {
            index += 1;
            let start = index;
            while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
            if index == start {
                return None;
            }
        }
        let offset: i64 = match bytes.get(index) {
            Some(b'Z') | Some(b'z') => 0,
            Some(sign @ (b'+' | b'-')) => {
                index += 1;
                let (offset_hour, offset_minute) = if bytes.get(index + 2) == Some(&b':') {
                    (number(index, 2)?, number(index + 3, 2)?)
                } else {
                    (number(index, 2)?, number(index + 2, 2)?)
                };
                let magnitude = offset_hour * 3600 + offset_minute * 60;
                if *sign == b'+' { magnitude } else { -magnitude }
            }
            _ => return None,
        };
        let total = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
            - offset;
        if total >= 0 {
            Some(UNIX_EPOCH + Duration::from_secs(total as u64))
        } else {
            UNIX_EPOCH.checked_sub(Duration::from_secs(total.unsigned_abs()))
        }
    }

    /// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
    fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
        let year = if month <= 2 { year - 1 } else { year };
        let era = if year >= 0 { year } else { year - 399 } / 400;
        let year_of_era = year - era * 400;
        let month_index = if month > 2 { month - 3 } else { month + 9 };
        let day_of_year = (153 * month_index + 2) / 5 + day - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        era * 146_097 + day_of_era - 719_468
    }

    /// The civil date for days since 1970-01-01 (Howard Hinnant's
    /// algorithm).
    fn civil_from_days(days: i64) -> (i64, i64, i64) {
        let days = days + 719_468;
        let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
        let day_of_era = days - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let year = year_of_era + era * 400;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_index = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_index + 2) / 5 + 1;
        let month = if month_index < 10 {
            month_index + 3
        } else {
            month_index - 9
        };
        (if month <= 2 { year + 1 } else { year }, month, day)
    }
}

/// Serde glue for `SystemTime` fields stored as RFC 3339 strings.
mod time_serde {
    use std::time::SystemTime;

    use serde::{Deserialize, Deserializer, Serializer};

    use super::rfc3339;

    pub fn serialize<S: Serializer>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&rfc3339::format(*time))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SystemTime, D::Error> {
        let text = String::deserialize(deserializer)?;
        rfc3339::parse(&text)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid RFC 3339 time: {text}")))
    }
}

/// Serde glue for `Option<SystemTime>` fields stored as RFC 3339 strings.
mod time_option {
    use std::time::SystemTime;

    use serde::{Deserialize, Deserializer, Serializer};

    use super::rfc3339;

    pub fn serialize<S: Serializer>(
        time: &Option<SystemTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match time {
            Some(time) => serializer.serialize_str(&rfc3339::format(*time)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<SystemTime>, D::Error> {
        let text = Option::<String>::deserialize(deserializer)?;
        match text {
            None => Ok(None),
            Some(text) => rfc3339::parse(&text)
                .map(Some)
                .ok_or_else(|| serde::de::Error::custom(format!("invalid RFC 3339 time: {text}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

    fn at(secs: i64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64)
    }

    /// A shared clock the test moves forward explicitly.
    struct FakeClock(Mutex<SystemTime>);

    fn clock(secs: i64) -> (Arc<FakeClock>, Clock) {
        let fake = Arc::new(FakeClock(Mutex::new(at(secs))));
        let handle = Arc::clone(&fake);
        let clock: Clock = Arc::new(move || *handle.0.lock().expect("clock"));
        (fake, clock)
    }

    impl FakeClock {
        fn set(&self, secs: i64) {
            *self.0.lock().expect("clock") = at(secs);
        }
    }

    fn make_table(policy: BanPolicy, secs: i64) -> (Arc<BanTable>, Arc<FakeClock>) {
        let (fake, clock) = clock(secs);
        let table = BanTable::open_memory(policy, BanHooks::default(), clock);
        (table, fake)
    }

    /// Parses an IP or CIDR into a network (the test helper the whitelist
    /// and manual-ban arguments need).
    fn net(text: &str) -> IpNet {
        if let Ok(net) = text.parse::<IpNet>() {
            return net;
        }
        let ip: IpAddr = text.parse().expect("ip address");
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        IpNet::new(ip, prefix).expect("host prefix")
    }

    fn auto(table: &BanTable, ip: &str, secs: i64) -> BanOutcome {
        table.ban_auto(
            ip.parse().unwrap(),
            None,
            false,
            Source::Trap,
            "guard.reason.trap".to_owned(),
            at(secs),
        )
    }

    fn until_of(outcome: &BanOutcome) -> Option<SystemTime> {
        match outcome {
            BanOutcome::Banned { entry, .. } => entry.until,
            _ => panic!("expected Banned, got {outcome:?}"),
        }
    }

    #[test]
    fn ban_key_normalizes_v6_to_64_and_v4_mapped() {
        // A bare IPv6 address becomes its /64.
        assert_eq!(
            BanKey::from_ip("fd00::1234".parse().unwrap()).to_string(),
            "fd00::/64"
        );
        assert_eq!(
            BanKey::from_ip("fd00::ffff".parse().unwrap()),
            BanKey::from_ip("fd00::1".parse().unwrap())
        );
        // IPv4-mapped IPv6 collapses to plain IPv4.
        assert_eq!(
            BanKey::from_ip("::ffff:1.2.3.4".parse().unwrap()).to_string(),
            "1.2.3.4"
        );
        // An explicit CIDR keeps its prefix; a bare IPv4 stays a host key.
        assert_eq!(
            BanKey::parse("10.0.0.0/8").unwrap(),
            BanKey::Net("10.0.0.0/8".parse().unwrap())
        );
        assert_eq!(
            BanKey::parse("1.2.3.4").unwrap(),
            BanKey::V4("1.2.3.4".parse().unwrap())
        );
        // A bare /128 manual target aggregates to /64 as well.
        assert_eq!(
            BanKey::from_net("2001:db8::5/128".parse().unwrap()).to_string(),
            "2001:db8::/64"
        );
        assert!(BanKey::parse("not-an-address").is_none());
        // The serialized form round-trips.
        let key = BanKey::from_ip("fd00::9".parse().unwrap());
        assert_eq!(BanKey::parse(&key.to_string()), Some(key));
    }

    #[test]
    fn is_banned_matches_cidr_entries() {
        let (table, fake) = make_table(BanPolicy::default(), 1000);
        // A manual v4 network contains addresses inside it.
        table
            .ban_manual(
                "10.8.0.0/16".parse().unwrap(),
                Some(Duration::from_secs(3600)),
                false,
                at(1000),
            )
            .unwrap();
        // A manual v6 network too.
        table
            .ban_manual(
                "2001:db8::/48".parse().unwrap(),
                Some(Duration::from_secs(3600)),
                false,
                at(1000),
            )
            .unwrap();
        assert!(table.is_banned("10.8.3.4".parse().unwrap(), at(1000)));
        assert!(table.is_banned("10.8.255.255".parse().unwrap(), at(1000)));
        assert!(!table.is_banned("10.9.0.1".parse().unwrap(), at(1000)));
        assert!(table.is_banned("2001:db8::dead".parse().unwrap(), at(1000)));
        assert!(!table.is_banned("2001:db9::1".parse().unwrap(), at(1000)));
        // Auto bans of a bare v6 address cover the whole /64.
        auto(&table, "2001:db8::1", 1001);
        assert!(table.is_banned("2001:db8::abcd".parse().unwrap(), at(1002)));
        assert!(!table.is_banned("2001:db9::1".parse().unwrap(), at(1002)));
        // Expired entries read as not banned.
        fake.set(1001 + 3600 + 1);
        assert!(!table.is_banned("10.8.3.4".parse().unwrap(), at(4602)));
    }

    #[test]
    fn auto_ban_skips_whitelisted_and_private() {
        // The default whitelist covers the internal ranges.
        let (table, _fake) = make_table(BanPolicy::default(), 0);
        assert_eq!(
            auto(&table, "192.168.1.10", 0),
            BanOutcome::Rejected(RejectReason::Whitelisted)
        );
        assert_eq!(
            auto(&table, "127.0.0.1", 0),
            BanOutcome::Rejected(RejectReason::Whitelisted)
        );
        assert_eq!(
            auto(&table, "100.64.1.2", 0),
            BanOutcome::Rejected(RejectReason::Whitelisted)
        );
        assert_eq!(
            auto(&table, "fe80::1", 0),
            BanOutcome::Rejected(RejectReason::Whitelisted)
        );
        // A single whitelisted IPv6 address protects its whole /64; a
        // single IPv4 address stays exact.
        table.set_whitelist(vec![net("1.2.3.4")], vec![]);
        assert_eq!(
            auto(&table, "1.2.3.4", 1),
            BanOutcome::Rejected(RejectReason::Whitelisted)
        );
        assert!(matches!(
            auto(&table, "1.2.3.5", 1),
            BanOutcome::Banned { .. }
        ));
        table.set_whitelist(vec![net("fd00::1234")], vec![]);
        assert_eq!(
            auto(&table, "fd00::abcd", 2),
            BanOutcome::Rejected(RejectReason::Whitelisted)
        );
        assert!(matches!(
            auto(&table, "fd01::1", 2),
            BanOutcome::Banned { .. }
        ));
        // ignorePrivate guards private addresses even outside the whitelist.
        let policy = BanPolicy {
            whitelist: vec!["9.9.9.0/24".parse().unwrap()],
            ignore_private: true,
            ..BanPolicy::default()
        };
        let (table, _fake) = make_table(policy, 0);
        assert_eq!(
            auto(&table, "172.16.5.5", 0),
            BanOutcome::Rejected(RejectReason::PrivateIgnored)
        );
        assert_eq!(
            auto(&table, "169.254.9.9", 0),
            BanOutcome::Rejected(RejectReason::PrivateIgnored)
        );
        assert!(matches!(
            auto(&table, "1.1.1.1", 1),
            BanOutcome::Banned { .. }
        ));
    }

    #[test]
    fn auto_ban_doubles_duration_within_30d() {
        let (table, fake) = make_table(BanPolicy::default(), 0);
        // First ban: the default duration.
        let first = auto(&table, "1.2.3.4", 0);
        assert_eq!(until_of(&first), Some(at(3600)));
        // Second ban inside 30 days: doubled.
        let second = auto(&table, "1.2.3.4", 100);
        assert_eq!(until_of(&second), Some(at(100 + 7200)));
        // Third: quadrupled.
        let third = auto(&table, "1.2.3.4", 200);
        assert_eq!(until_of(&third), Some(at(200 + 14400)));
        // The counts keep growing with every re-ban.
        for step in 3..10 {
            auto(&table, "1.2.3.4", 200 + i64::from(step) * 100);
        }
        let count = table
            .offense(&BanKey::from_ip("1.2.3.4".parse().unwrap()))
            .unwrap()
            .count;
        assert_eq!(count, 10);
        // Unban, then re-offend: the escalation ceiling applies to the
        // fresh entry's duration (the 11th ban would double past 7 days).
        table.unban(&"1.2.3.4/32".parse().unwrap(), at(1400));
        let capped = auto(&table, "1.2.3.4", 1400);
        assert_eq!(
            until_of(&capped),
            Some(at(1400 + 7 * 24 * 3600)),
            "escalation stops at max_duration"
        );
        assert_eq!(
            table
                .offense(&BanKey::from_ip("1.2.3.4".parse().unwrap()))
                .unwrap()
                .count,
            11
        );
        // Unban (history kept), then re-offend after 30 days: restart at 1x.
        table.unban(&"1.2.3.4/32".parse().unwrap(), at(1500));
        let late = 1400 + 31 * 24 * 3600;
        fake.set(late);
        let reset = auto(&table, "1.2.3.4", late);
        assert_eq!(until_of(&reset), Some(at(late + 3600)));
        let count = table
            .offense(&BanKey::from_ip("1.2.3.4".parse().unwrap()))
            .unwrap()
            .count;
        assert_eq!(count, 1, "an offense past the TTL restarts the escalation");
    }

    #[test]
    fn auto_ban_extends_existing_temporary_entry() {
        let (table, _fake) = make_table(BanPolicy::default(), 0);
        let first = auto(&table, "5.6.7.8", 0);
        assert_eq!(until_of(&first), Some(at(3600)));
        // A later expiry wins; the count advances.
        let second = auto(&table, "5.6.7.8", 100);
        assert_eq!(until_of(&second), Some(at(100 + 7200)));
        let stored = table.list(at(200), &BanFilter::default());
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].count, 2);
        assert_eq!(stored[0].created, at(0), "created keeps the first ban time");
        // Without increment a later re-ban still extends to the later
        // expiry; repeating it inside the same second leaves the entry
        // unchanged (the offense count still advances).
        let policy = BanPolicy {
            increment: false,
            ..BanPolicy::default()
        };
        let (table2, _fake2) = make_table(policy, 0);
        auto(&table2, "9.9.9.9", 0);
        assert!(matches!(
            auto(&table2, "9.9.9.9", 10),
            BanOutcome::Banned { .. }
        ));
        assert_eq!(auto(&table2, "9.9.9.9", 10), BanOutcome::Unchanged);
        let count = table2
            .offense(&BanKey::from_ip("9.9.9.9".parse().unwrap()))
            .unwrap()
            .count;
        assert_eq!(count, 3);
    }

    #[test]
    fn permanent_entry_unchanged() {
        let (table, _fake) = make_table(BanPolicy::default(), 0);
        table.ban_auto(
            "4.4.4.4".parse().unwrap(),
            None,
            true,
            Source::Jail("ssh".to_owned()),
            "guard.reason.jail".to_owned(),
            at(0),
        );
        assert!(table.is_banned("4.4.4.4".parse().unwrap(), at(1000)));
        // Re-bans are rejected: permanent stays exactly as it is.
        assert_eq!(
            auto(&table, "4.4.4.4", 1000),
            BanOutcome::Rejected(RejectReason::AlreadyPermanent)
        );
        let stored = table.list(at(1000), &BanFilter::default());
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].count, 1);
        assert_eq!(stored[0].until, None);
    }

    #[test]
    fn table_full_evicts_expired_then_oldest_temporary() {
        let policy = BanPolicy {
            limit: 3,
            ..BanPolicy::default()
        };
        let (table, _fake) = make_table(policy, 0);
        // Permanent entry A.
        table.ban_auto(
            "1.1.1.1".parse().unwrap(),
            None,
            true,
            Source::Scan,
            "r".to_owned(),
            at(0),
        );
        // Temporary entries B and C; C expires early.
        table.ban_auto(
            "2.2.2.2".parse().unwrap(),
            Some(Duration::from_secs(100_000)),
            false,
            Source::Trap,
            "r".to_owned(),
            at(1),
        );
        table.ban_auto(
            "3.3.3.3".parse().unwrap(),
            Some(Duration::from_secs(10)),
            false,
            Source::Trap,
            "r".to_owned(),
            at(2),
        );
        // At t=100 the expired C frees a slot: D fits without eviction.
        auto(&table, "4.4.4.4", 100);
        assert!(table.is_banned("4.4.4.4".parse().unwrap(), at(101)));
        assert_eq!(table.stats().evicted, 0);
        // Full again: the oldest temporary auto ban (B) goes first.
        let outcome = auto(&table, "5.5.5.5", 101);
        let BanOutcome::Banned { evicted, .. } = outcome else {
            panic!("expected Banned, got {outcome:?}");
        };
        assert_eq!(evicted, 1);
        assert!(
            !table.is_banned("2.2.2.2".parse().unwrap(), at(101)),
            "oldest temporary evicted"
        );
        assert!(table.is_banned("4.4.4.4".parse().unwrap(), at(101)));
        assert_eq!(table.stats().evicted, 1);
        // Manual entries are never evicted: a manual ban on a full table
        // fails outright.
        let manual = table.ban_manual(
            "6.6.6.6/32".parse().unwrap(),
            Some(Duration::from_secs(3600)),
            false,
            at(102),
        );
        assert_eq!(manual.unwrap_err(), BanError::Full);
        // Make room, fill up with permanents: nothing evictable remains.
        assert_eq!(table.unban(&"4.4.4.4/32".parse().unwrap(), at(102)), 1);
        table
            .ban_manual("7.7.7.7/32".parse().unwrap(), None, true, at(103))
            .unwrap();
        // Turn the last temporary entry permanent.
        table.ban_auto(
            "5.5.5.5".parse().unwrap(),
            None,
            true,
            Source::Trap,
            "r".to_owned(),
            at(103),
        );
        assert_eq!(
            table.ban_auto(
                "8.8.8.8".parse().unwrap(),
                None,
                false,
                Source::Scan,
                "r".to_owned(),
                at(104),
            ),
            BanOutcome::Rejected(RejectReason::TableFull)
        );
        assert_eq!(table.stats().rejected, 1);
    }

    #[test]
    fn manual_ban_rejects_loopback() {
        let (table, _fake) = make_table(BanPolicy::default(), 0);
        for target in ["127.0.0.1/32", "127.0.1.0/24", "::1/128", "::/0"] {
            let error = table
                .ban_manual(
                    target.parse().unwrap(),
                    Some(Duration::from_secs(3600)),
                    false,
                    at(0),
                )
                .unwrap_err();
            assert_eq!(error, BanError::Loopback, "target {target}");
        }
        assert!(!table.is_banned("127.0.0.1".parse().unwrap(), at(1)));
        // Auto bans of loopback are prevented by the default whitelist
        // instead of being an error.
        assert_eq!(
            auto(&table, "127.0.0.2", 1),
            BanOutcome::Rejected(RejectReason::Whitelisted)
        );
    }

    #[test]
    fn manual_ban_with_duration_and_permanent() {
        let (table, _fake) = make_table(BanPolicy::default(), 0);
        let entry = table
            .ban_manual(
                "9.9.9.9/32".parse().unwrap(),
                Some(Duration::from_secs(24 * 3600)),
                false,
                at(0),
            )
            .unwrap();
        assert_eq!(entry.until, Some(at(24 * 3600)));
        assert_eq!(entry.source, Source::Manual);
        // Manual durations are not clamped by the escalation ceiling
        // (upstream allows 1..=720 hours).
        let entry = table
            .ban_manual(
                "9.9.9.10/32".parse().unwrap(),
                Some(Duration::from_secs(720 * 3600)),
                false,
                at(0),
            )
            .unwrap();
        assert_eq!(entry.until, Some(at(720 * 3600)));
        // `seconds = -1` on the interface maps to permanent: no expiry.
        let entry = table
            .ban_manual("9.9.9.11/32".parse().unwrap(), None, true, at(0))
            .unwrap();
        assert_eq!(entry.until, None);
        // Zero duration without permanence is invalid.
        assert_eq!(
            table.ban_manual("9.9.9.12/32".parse().unwrap(), None, false, at(0)),
            Err(BanError::InvalidDuration)
        );
        assert!(table.is_banned("9.9.9.11".parse().unwrap(), at(400 * 24 * 3600)));
    }

    #[test]
    fn unban_by_cidr_removes_all_inside() {
        let (table, _fake) = make_table(BanPolicy::default(), 0);
        for ip in ["203.0.113.1", "203.0.113.2", "203.0.114.9"] {
            auto(&table, ip, 0);
        }
        table
            .ban_manual(
                "203.0.113.16/28".parse().unwrap(),
                Some(Duration::from_secs(3600)),
                false,
                at(0),
            )
            .unwrap();
        let removed = table.unban(&"203.0.113.0/24".parse().unwrap(), at(10));
        assert_eq!(removed, 3, "two hosts and one /28 network fall inside");
        assert!(!table.is_banned("203.0.113.1".parse().unwrap(), at(10)));
        assert!(!table.is_banned("203.0.113.17".parse().unwrap(), at(10)));
        assert!(table.is_banned("203.0.114.9".parse().unwrap(), at(10)));
        // Unban by bare address removes exactly that key.
        let removed = table.unban(&"203.0.114.9/32".parse().unwrap(), at(11));
        assert_eq!(removed, 1);
        assert_eq!(table.counts(at(11)).bans, 0);
        // Offense history survives the unban.
        assert!(
            table
                .offense(&BanKey::from_ip("203.0.114.9".parse().unwrap()))
                .is_some()
        );
        // Nothing to remove: zero.
        assert_eq!(table.unban(&"203.0.113.0/24".parse().unwrap(), at(12)), 0);
    }

    #[test]
    fn login_trust_blocks_only_trap_and_scan() {
        let (table, _fake) = make_table(BanPolicy::default(), 0);
        table.trust_login("1.2.3.4".parse().unwrap(), at(0));
        assert!(table.is_login_trusted("1.2.3.4".parse().unwrap(), at(100)));
        assert!(!table.is_login_trusted("1.2.3.5".parse().unwrap(), at(100)));
        // The shield covers trap and scan sources only.
        assert_eq!(
            auto(&table, "1.2.3.4", 100),
            BanOutcome::Rejected(RejectReason::LoginTrusted)
        );
        assert_eq!(
            table.ban_auto(
                "1.2.3.4".parse().unwrap(),
                None,
                false,
                Source::Scan,
                "r".to_owned(),
                at(101),
            ),
            BanOutcome::Rejected(RejectReason::LoginTrusted)
        );
        assert!(
            matches!(
                table.ban_auto(
                    "1.2.3.4".parse().unwrap(),
                    None,
                    false,
                    Source::Webservice,
                    "r".to_owned(),
                    at(102),
                ),
                BanOutcome::Banned { .. }
            ),
            "other sources ignore the shield"
        );
        // And it expires after 24 hours.
        let late = 24 * 3600 + 10;
        assert!(!table.is_login_trusted("1.2.3.4".parse().unwrap(), at(late)));
        assert!(matches!(
            auto(&table, "1.2.3.4", late),
            BanOutcome::Banned { .. }
        ));
    }

    #[test]
    fn trusted_sources_exempt_from_trap_and_scan() {
        let (table, _fake) = make_table(BanPolicy::default(), 0);
        let owner = "banlist-test-trusted";
        crate::trust_src::set(
            owner,
            vec![crate::trust_src::TrustedSource {
                owner: owner.to_owned(),
                addr: "5.5.5.5".parse().unwrap(),
                until: None,
                note: "frpc".to_owned(),
            }],
        );

        assert_eq!(
            auto(&table, "5.5.5.5", 0),
            BanOutcome::Rejected(RejectReason::TrustedSource)
        );
        assert_eq!(
            table.ban_auto(
                "5.5.5.5".parse().unwrap(),
                None,
                false,
                Source::Scan,
                "r".to_owned(),
                at(1),
            ),
            BanOutcome::Rejected(RejectReason::TrustedSource)
        );
        // Non trap/scan sources still ban it.
        assert!(matches!(
            table.ban_auto(
                "5.5.5.5".parse().unwrap(),
                None,
                false,
                Source::Jail("auth".to_owned()),
                "r".to_owned(),
                at(2),
            ),
            BanOutcome::Banned { .. }
        ));
        crate::trust_src::clear(owner);
        assert!(matches!(
            auto(&table, "5.5.5.5", 3),
            BanOutcome::Banned { .. }
        ));
        // The registry is process-global; clear it so later tests in
        // this binary see a clean slate even when ordering changes.
        crate::trust_src::clear(owner);
    }

    #[test]
    fn ban_emits_event() {
        let (fake, clock) = clock(0);
        let fired: Arc<Mutex<Vec<Entry>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&fired);
        let hooks = BanHooks {
            banned: Some(Arc::new(move |entry: &Entry| {
                sink.lock().expect("sink").push(entry.clone());
            })),
            load_warning: None,
        };
        let table = BanTable::open_memory(BanPolicy::default(), hooks, clock);
        auto(&table, "7.7.7.7", 0);
        fake.set(1);
        auto(&table, "8.8.8.8", 1);
        // A rejection emits nothing.
        auto(&table, "10.0.0.1", 1);
        let fired = fired.lock().expect("sink");
        assert_eq!(fired.len(), 2);
        assert_eq!(fired[0].key.to_string(), "7.7.7.7");
        assert_eq!(fired[1].key.to_string(), "8.8.8.8");
    }

    #[test]
    fn list_filters_searches_and_paginates() {
        let (table, _fake) = make_table(BanPolicy::default(), 0);
        table.ban_auto(
            "1.1.1.1".parse().unwrap(),
            None,
            false,
            Source::Trap,
            "guard.reason.trap".to_owned(),
            at(1),
        );
        table.ban_auto(
            "2.2.2.2".parse().unwrap(),
            None,
            false,
            Source::Jail("ssh".to_owned()),
            "guard.reason.jail".to_owned(),
            at(2),
        );
        table
            .ban_manual(
                "3.3.3.3/32".parse().unwrap(),
                Some(Duration::from_secs(3600)),
                false,
                at(3),
            )
            .unwrap();
        // Newest first.
        let all = table.list(at(4), &BanFilter::default());
        let keys: Vec<String> = all.iter().map(|entry| entry.key.to_string()).collect();
        assert_eq!(keys, vec!["3.3.3.3", "2.2.2.2", "1.1.1.1"]);
        // Source filter; `jail:` covers every jail rule.
        let source_filter = |source: &str| {
            table.list(
                at(4),
                &BanFilter {
                    source: Some(source.to_owned()),
                    ..BanFilter::default()
                },
            )
        };
        assert_eq!(source_filter("manual").len(), 1);
        assert_eq!(source_filter("jail:").len(), 1);
        assert_eq!(source_filter("trap").len(), 1);
        assert_eq!(source_filter("scan").len(), 0);
        // Search matches the key or the reason, case-insensitively.
        let search = |needle: &str| {
            table.list(
                at(4),
                &BanFilter {
                    search: Some(needle.to_owned()),
                    ..BanFilter::default()
                },
            )
        };
        assert_eq!(search("2.2").len(), 1);
        assert_eq!(search("GUARD.REASON.JAIL").len(), 1);
        assert_eq!(search("no-hit").len(), 0);
        // Pagination.
        let page = table.list(
            at(4),
            &BanFilter {
                offset: 1,
                limit: 1,
                ..BanFilter::default()
            },
        );
        assert_eq!(
            page.iter()
                .map(|entry| entry.key.to_string())
                .collect::<Vec<_>>(),
            ["2.2.2.2"]
        );
        // Expiry: an expired entry is hidden unless included.
        table
            .ban_manual(
                "4.4.4.4/32".parse().unwrap(),
                Some(Duration::from_secs(10)),
                false,
                at(0),
            )
            .unwrap();
        assert_eq!(table.list(at(20), &BanFilter::default()).len(), 3);
        assert_eq!(
            table
                .list(
                    at(20),
                    &BanFilter {
                        include_expired: true,
                        ..BanFilter::default()
                    }
                )
                .len(),
            4
        );
    }

    #[test]
    fn rfc3339_format_and_parse_roundtrip() {
        let cases = [
            (0i64, "1970-01-01T00:00:00Z"),
            (1, "1970-01-01T00:00:01Z"),
            (951_868_800, "2000-03-01T00:00:00Z"),
            (1_700_000_000, "2023-11-14T22:13:20Z"),
            (4_102_444_800, "2100-01-01T00:00:00Z"),
        ];
        for (secs, text) in cases {
            assert_eq!(rfc3339::format(at(secs)), text, "format {secs}");
            assert_eq!(rfc3339::parse(text), Some(at(secs)), "parse {text}");
        }
        // Before the epoch.
        let before = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(rfc3339::format(before), "1969-12-31T23:59:59Z");
        assert_eq!(rfc3339::parse("1969-12-31T23:59:59Z"), Some(before));
        // Offsets and fractions.
        assert_eq!(
            rfc3339::parse("2023-11-15T00:13:20+02:00"),
            Some(at(1_700_000_000))
        );
        assert_eq!(
            rfc3339::parse("2023-11-14T19:13:20-03:00"),
            Some(at(1_700_000_000))
        );
        assert_eq!(
            rfc3339::parse("2023-11-14T22:13:20.123456Z"),
            Some(at(1_700_000_000))
        );
        assert_eq!(
            rfc3339::parse("2023-11-14t22:13:20z"),
            Some(at(1_700_000_000))
        );
        // Rejections.
        for bad in [
            "",
            "2023-11-14",
            "2023-11-14T22:13Z",
            "2023-13-14T22:13:20Z",
            "2023-11-14 22:13:20",
            "2023-11-14T22:13:20X",
            "2023-11-14T22:61:20Z",
        ] {
            assert_eq!(rfc3339::parse(bad), None, "parse {bad:?}");
        }
    }

    #[test]
    fn bans_file_codec_roundtrip_and_rejects_garbage() {
        let file = BanFile {
            bans: vec![
                Entry {
                    key: BanKey::from_ip("fd00::1".parse().unwrap()),
                    until: Some(at(3600)),
                    created: at(0),
                    reason: "guard.reason.trap \"quoted\"\n".to_owned(),
                    source: Source::Jail("ssh".to_owned()),
                    count: 3,
                },
                Entry {
                    key: BanKey::V4("1.2.3.4".parse().unwrap()),
                    until: None,
                    created: at(5),
                    reason: "guard.reason.manual".to_owned(),
                    source: Source::Manual,
                    count: 1,
                },
            ],
            offenses: BTreeMap::from([
                (
                    BanKey::V4("1.2.3.4".parse().unwrap()),
                    Offense {
                        count: 2,
                        last: at(100),
                    },
                ),
                (
                    BanKey::from_ip("fd00::1".parse().unwrap()),
                    Offense {
                        count: 3,
                        last: at(200),
                    },
                ),
            ]),
        };
        let bytes = bans_io::write_bans(&file);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("\"fd00::/64\""), "{text}");
        assert!(
            text.contains("1970-01-01T00:00:00Z"),
            "times are RFC 3339: {text}"
        );
        assert!(text.contains("jail:ssh"), "{text}");
        assert!(
            text.contains("\\\"quoted\\\""),
            "strings are escaped: {text}"
        );
        assert!(!text.contains("\n"), "compact output: {text}");
        let parsed = bans_io::parse_bans(text.as_bytes()).unwrap();
        assert_eq!(parsed, file);
        // Permanent entries omit the until field.
        assert!(
            !text.contains("1.2.3.4\", \"until"),
            "permanent has no until: {text}"
        );
        // Garbage is rejected so the loader warns and starts empty.
        for garbage in [
            &b""[..],
            b"{",
            b"[]",
            b"not json",
            b"{\"bans\": {}}",
            b"{\"bans\": [{\"key\": \"bogus\", \"created\": \"2023-01-01T00:00:00Z\", \"reason\": \"r\", \"source\": \"trap\", \"count\": 1}]}",
            b"{\"bans\": [{\"key\": \"1.2.3.4\"}]}",
            b"{\"bans\": [{\"key\": \"1.2.3.4\", \"created\": \"not-a-time\", \"reason\": \"r\", \"source\": \"trap\", \"count\": 1}]}",
        ] {
            assert!(bans_io::parse_bans(garbage).is_none(), "{:?} must be invalid", String::from_utf8_lossy(garbage));
        }
        // Unknown fields are tolerated on load (upstream behavior).
        assert!(bans_io::parse_bans(b"{\"bans\": [], \"bogus\": 1, \"offenses\": {}}").is_some());
    }
}
