//! WP-51 firewall sync: mirrors the shared ban table into the system
//! firewall so banned traffic is dropped in the kernel, before it reaches
//! any listener, container or forwarded host.
//!
//! Target structure (WP-51 §3.3, scoped to the intrusion-protection ban
//! sync; the redirect chain, trap / scan sets and the knock table belong
//! to WP-53 / WP-54 and are intentionally absent):
//!
//! - nftables: table `inet gately` with the timeout sets `ban4` / `ban6`
//!   (size 65536) for timed single addresses (IPv6 auto bans as /64) and
//!   the interval sets `deny4` / `deny6` for manual CIDRs and permanent
//!   bans, plus the `pre` base chain (filter, prerouting, priority -190)
//!   that drops loopback-exempted, reply-exempted, banned and denied
//!   sources. Rewrites are atomic (`table inet gately {}` +
//!   `delete table inet gately` first).
//! - iptables legacy (kernel without nf_tables): mangle `GATELY_PRE` chain
//!   jumped from `PREROUTING`, ban addresses in the ipset sets
//!   `gately_ban4` / `gately_ban6` (with the ipset timeout cap and the 24
//!   hour refresh), per-CIDR drop rules in the `GATELY_DENY` chain.
//!
//! The whitelist never reaches the firewall: the ban table already rejects
//! whitelisted and ignore-private addresses, so the mirror contains
//! exactly the entries [`fg_net::banlist::BanTable`] holds (same internal
//! ranges criteria as the application layer).
//!
//! Consume pattern (WP-51 §3.3 "钩子/消费者"):
//!
//! - startup: the first successful probe writes the whole table (full
//!   rebuild) with every active ban;
//! - incremental: every landed ban fires the table's `banned` hook, which
//!   wakes the worker; the next reconcile adds the delta only;
//! - periodic: every [`POLL_INTERVAL`] the structure check detects rules
//!   wiped by a firewall reload and rewrites them, removes unbanned /
//!   expired deny elements, and reads the packet counters (folded across
//!   rewrites into a baseline);
//! - failures: writes are retried on the next poll; after
//!   [`MAX_CONSECUTIVE_FAILURES`] the sync degrades (application layer
//!   bans keep working, [`FwStatus::degraded`] says so) and retries only
//!   after [`BACKOFF`]. Probe failures (no permission, no command, not
//!   Linux) are sticky until [`FirewallSync::reprobe`] (settings save).
//!
//! Only Linux touches the system; every other platform compiles the
//! unsupported stub reporting [`FwError::Unsupported`] — the public API is
//! identical on both. Firewall problems never block the module:
//! [`GuardService`](crate::bans::GuardService) `is_banned` always stays
//! authoritative.

mod exec;
mod render;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{
        Arc, Condvar, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime},
};

use fg_net::banlist::{BanFilter, BanTable, Clock, Entry};
pub use render::{
    Family, FwElement, GuardTable, SetName, absorb_covered, cap_per_set, chunked,
    elements_from_entries, guard_script, ipset_ban_elements, ipset_ban_member, ipset_restore_adds,
    ipset_restore_dels, ipset_restore_full, ipset_restore_setup, ipt_deny_delete_rule,
    ipt_deny_rule, ipt_pre_rules, ipt_timeout_secs, nft_add_script, nft_del_script,
    nft_element_text, nft_remove_script, parse_guard_table, split_families,
};
use serde::Serialize;

/// How often the rules and the ban delta are reconciled (upstream
/// `pollInterval`).
pub const POLL_INTERVAL: Duration = Duration::from_secs(10);
/// Upper bound for one nft / iptables / ipset invocation (upstream
/// `nftTimeout`).
pub const NFT_TIMEOUT: Duration = Duration::from_secs(15);
/// Capacity of `ban4` / `ban6` and the ipset counterparts (WP-50 §3.4:
/// upstream `nftSetSize`; overflow stays application-layer only).
pub const SET_SIZE: usize = 65536;
/// ipset timeout cap: remaining time over the cap is written at the cap
/// and refreshed before it lapses.
pub const IPT_TIMEOUT_CAP: Duration = Duration::from_secs(24 * 3600);
/// The iptables ban sets are fully refreshed at this interval (upstream
/// `iptRefresh`).
pub const IPT_REFRESH: Duration = Duration::from_secs(24 * 3600);
/// Re-push an ipset element when its capped lifetime comes within this
/// margin of lapsing (spans the degraded backoff so no active ban is lost).
pub const REFRESH_MARGIN: Duration = Duration::from_secs(600);
/// Consecutive write failures before degrading to the application layer
/// with a status notice.
pub const MAX_CONSECUTIVE_FAILURES: u32 = 3;
/// Retry cadence while degraded (application layer bans keep working).
pub const BACKOFF: Duration = Duration::from_secs(300);
/// Elements per nft / ipset invocation on the incremental path.
pub const ELEMENTS_PER_CALL: usize = 512;

/// Table and chain names (upstream names kept per WP-51 §3.4 so the
/// "view rules" output stays comparable).
pub const TABLE: &str = "gately";
pub const CHAIN_PRE: &str = "pre";
pub const IPT_CHAIN_PRE: &str = "GATELY_PRE";
pub const IPT_CHAIN_DENY: &str = "GATELY_DENY";
/// The iptables mangle table.
pub const IPT_TABLE: &str = "mangle";
pub const SET_BAN4: &str = "ban4";
pub const SET_BAN6: &str = "ban6";
pub const SET_DENY4: &str = "deny4";
pub const SET_DENY6: &str = "deny6";
pub const IPT_SET_BAN4: &str = "gately_ban4";
pub const IPT_SET_BAN6: &str = "gately_ban6";
/// /64 mask of the IPv6 ban rule (auto bans aggregate to /64).
pub const V6_MASK_64: &str = "ffff:ffff:ffff:ffff::";
/// Rule comments; the structure check and the counters both key on them.
pub const COMMENT_BAN: &str = "ban";
pub const COMMENT_DENY: &str = "deny";

/// Which firewall command family the sync drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FwBackend {
    Nftables,
    IptablesLegacy,
}

impl FwBackend {
    /// Stable identifier for status output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nftables => "nftables",
            Self::IptablesLegacy => "iptables",
        }
    }
}

impl Serialize for FwBackend {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Why the firewall mirror is unavailable. `code` is a stable reason code
/// (upstream set: `no_permission | no_nft | no_iptables | not_linux |
/// kernel_no_nf_tables`), `hint_key` the i18n key for the handling hint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FwUnavailable {
    pub code: &'static str,
    pub hint_key: &'static str,
}

impl FwUnavailable {
    pub const fn new(code: &'static str, hint_key: &'static str) -> Self {
        Self { code, hint_key }
    }

    /// Anything but Linux.
    pub const fn not_linux() -> Self {
        Self::new("not_linux", "guard.fwhint.not_linux")
    }

    /// No permission to change the firewall (root / `CAP_NET_ADMIN`).
    pub const fn no_permission() -> Self {
        Self::new("no_permission", "guard.fwhint.no_permission")
    }

    /// No usable `nft` command.
    pub const fn no_nft() -> Self {
        Self::new("no_nft", "guard.fwhint.no_nft")
    }

    /// Kernel has no nf_tables and no usable iptables legacy + ipset.
    pub const fn no_iptables() -> Self {
        Self::new("no_iptables", "guard.fwhint.no_iptables")
    }

    /// The kernel rejected nf_tables; iptables legacy is unavailable too.
    pub const fn kernel_no_nf_tables() -> Self {
        Self::new("kernel_no_nf_tables", "guard.fwhint.kernel_no_nf_tables")
    }
}

/// Error of a backend operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FwError {
    /// The platform has no firewall support.
    Unsupported,
    /// The command ran without the required privileges.
    Permission,
    /// The command failed; the payload is the trimmed stderr or the exit
    /// status.
    CommandFailed(String),
    /// Output of a firewall command could not be parsed.
    Parse(String),
}

impl fmt::Display for FwError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FwError::Unsupported => write!(f, "防火墙同步只支持 Linux"),
            FwError::Permission => write!(f, "没有修改防火墙的权限（需要 root 或 CAP_NET_ADMIN）"),
            FwError::CommandFailed(msg) => f.write_str(msg),
            FwError::Parse(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for FwError {}

/// Failure counters of the sync (status and self-check).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SyncStats {
    /// Incremental elements added.
    pub adds: u64,
    /// Incremental elements deleted.
    pub dels: u64,
    /// Full table rewrites (startup, structure loss, heal).
    pub rewrites: u64,
    /// Failed operations since start.
    pub failures: u64,
}

/// The sync status (WP-51 §3.2). `dropped` maps the rule comment to the
/// packet count with the baseline folded in (counters reset on rewrite).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FwStatus {
    pub enabled: bool,
    pub backend: Option<FwBackend>,
    pub unavailable: Option<FwUnavailable>,
    pub rules_present: bool,
    pub last_error: Option<String>,
    pub dropped: BTreeMap<String, u64>,
    /// Consecutive write failures exhausted; application layer bans keep
    /// working, the next attempt happens after [`BACKOFF`].
    pub degraded: bool,
    #[serde(skip_serializing)]
    pub last_rewrite: Option<SystemTime>,
    pub stats: SyncStats,
}

/// What the firewall currently holds for one element: the element plus
/// when the kernel-side copy lapses (`None` for the timeout-less deny
/// rules).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    pub element: FwElement,
    pub kernel_until: Option<SystemTime>,
}

/// The reconcile delta between the firewall and the ban table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Rewrite the whole table (startup, wiped structure, healing after a
    /// failed incremental write); the delta fields are unused.
    pub full: bool,
    /// Elements the firewall lacks.
    pub adds: Vec<FwElement>,
    /// Applied elements whose expiry changed: delete, then add.
    pub replaces: Vec<FwElement>,
    /// Elements the firewall still holds but the table no longer wants.
    pub dels: Vec<FwElement>,
}

/// Computes the delta. Expired timed elements are simply forgotten (the
/// kernel timeout removed them); expired deny elements still in the
/// firewall produce a delete because they carry no kernel timeout.
pub fn plan_sync(
    applied: &BTreeMap<String, Applied>,
    desired: &[FwElement],
    now: SystemTime,
    structure_ok: bool,
    force_full: bool,
) -> Plan {
    if force_full || !structure_ok {
        return Plan {
            full: true,
            ..Plan::default()
        };
    }
    let desired_keys: BTreeSet<&str> = desired.iter().map(|e| e.key.as_str()).collect();
    let mut adds = Vec::new();
    let mut replaces = Vec::new();
    for element in desired {
        match applied.get(&element.key) {
            // The ban was extended or re-landed: the kernel copy must
            // track the new expiry.
            Some(existing) if existing.element.expires != element.expires => {
                replaces.push(element.clone());
            }
            Some(_) => {}
            None => adds.push(element.clone()),
        }
    }
    let mut dels = Vec::new();
    for (key, existing) in applied {
        if desired_keys.contains(key.as_str()) {
            continue;
        }
        match existing.kernel_until {
            // Timed elements vanish in the kernel on their own; only the
            // tracking forgets them.
            Some(until) if until <= now => {}
            _ => dels.push(existing.element.clone()),
        }
    }
    Plan {
        full: false,
        adds,
        replaces,
        dels,
    }
}

/// Applied ipset elements whose capped lifetime comes within `margin` of
/// lapsing while the ban is still wanted: the iptables backend must
/// re-push them before they disappear ([`REFRESH_MARGIN`]).
pub fn refresh_due(
    applied: &BTreeMap<String, Applied>,
    desired: &[FwElement],
    now: SystemTime,
    margin: Duration,
) -> Vec<FwElement> {
    let desired_keys: BTreeSet<&str> = desired.iter().map(|e| e.key.as_str()).collect();
    applied
        .iter()
        .filter(|(key, _)| desired_keys.contains(key.as_str()))
        .filter(|(_, applied)| applied.element.timeout.is_some())
        .filter(|(_, applied)| {
            applied
                .kernel_until
                .is_some_and(|until| until.duration_since(now).unwrap_or(Duration::ZERO) <= margin)
        })
        .map(|(_, applied)| applied.element.clone())
        .collect()
}

/// Whether the periodic whole-set refresh is due (upstream `iptRefresh`).
pub fn refresh_periodic_due(last_refresh: Option<SystemTime>, now: SystemTime) -> bool {
    last_refresh
        .and_then(|last| now.duration_since(last).ok())
        .is_some_and(|age| age >= IPT_REFRESH)
}

/// Human status text (WP-51 §3.3 "生效范围"/"失败处理": the interface
/// shows the state at the top, with a reason and a remedy when
/// unavailable, and always makes clear that application layer bans keep
/// working).
pub fn status_text(status: &FwStatus) -> String {
    if !status.enabled {
        return "防火墙同步未启用".to_owned();
    }
    if let Some(unavailable) = &status.unavailable {
        let reason = match unavailable.code {
            "not_linux" => "防火墙同步只支持 Linux",
            "no_permission" => {
                "没有修改防火墙的权限（需要 root 或 CAP_NET_ADMIN；Docker 部署需要 host 网络并添加 NET_ADMIN）"
            }
            "no_nft" => "没有找到可用的 nft 命令",
            "no_iptables" => {
                "当前内核不支持 nftables，且没有可用的 iptables（legacy）与 ipset 命令"
            }
            "kernel_no_nf_tables" => "当前内核未启用 nf_tables",
            _ => "防火墙同步不可用",
        };
        return format!("{reason}；封禁仍在应用层生效");
    }
    if status.degraded {
        return format!(
            "防火墙连续写入失败，已退回应用层封禁：{}",
            status.last_error.as_deref().unwrap_or("未知错误")
        );
    }
    let Some(backend) = status.backend else {
        return "正在探测防火墙能力…".to_owned();
    };
    if !status.rules_present {
        return match &status.last_error {
            Some(error) => format!(
                "防火墙规则写入失败（{}）：{error}；封禁仍在应用层生效",
                backend.as_str()
            ),
            None => format!("正在写入防火墙规则（{}）…", backend.as_str()),
        };
    }
    let dropped: u64 = status.dropped.values().sum();
    format!(
        "防火墙同步已启用（{}，inet {TABLE} 表）；内核层已丢弃 {dropped} 个数据包",
        backend.as_str()
    )
}

/// Firewall read/write access behind the sync. The `exec` submodule
/// provides the production command backend (Linux) and the unsupported
/// stub; tests substitute fakes.
pub trait BanBackend: Send + Sync {
    /// The backend kind, or `None` when unsupported.
    fn kind(&self) -> Option<FwBackend>;
    /// Whether the table still exists and is structurally complete
    /// (missing → full rewrite).
    fn rules_present(&self) -> Result<bool, FwError>;
    /// Atomically replaces the table with `elements`.
    fn apply_full(&self, elements: &[FwElement]) -> Result<(), FwError>;
    /// Adds elements incrementally.
    fn add_elements(&self, elements: &[FwElement]) -> Result<(), FwError>;
    /// Removes elements incrementally.
    fn del_elements(&self, elements: &[FwElement]) -> Result<(), FwError>;
    /// Packet counters keyed by rule comment.
    fn read_counters(&self) -> Result<BTreeMap<String, u64>, FwError>;
    /// Removes the whole table (engine stop path).
    fn remove_all(&self) -> Result<(), FwError>;
}

/// Produces a ready backend or the reason it is unavailable.
pub type BackendFactory = Arc<dyn Fn() -> Result<Arc<dyn BanBackend>, FwUnavailable> + Send + Sync>;

/// The firewall sync engine. Constructed by
/// [`GuardService`](crate::bans::GuardService) when `settings.firewall` is
/// on; the ban hook nudges it, the module `run` stops it on shutdown.
pub struct FirewallSync {
    inner: Mutex<SyncState>,
    /// Serializes ticks so the firewall is never written concurrently.
    run: Mutex<()>,
    wake: Mutex<()>,
    wake_signal: Condvar,
    table: Arc<BanTable>,
    clock: Clock,
    factory: BackendFactory,
    /// Set when the worker finished the shutdown removal.
    cleared: Arc<AtomicBool>,
}

#[derive(Default)]
struct SyncState {
    enabled: bool,
    exiting: bool,
    needs_probe: bool,
    needs_full: bool,
    backend: Option<Arc<dyn BanBackend>>,
    unavailable: Option<FwUnavailable>,
    applied: BTreeMap<String, Applied>,
    baseline: BTreeMap<String, u64>,
    last_counters: BTreeMap<String, u64>,
    rules_present: bool,
    rules_text: Option<String>,
    last_error: Option<String>,
    degraded: bool,
    next_retry: Option<SystemTime>,
    consecutive_failures: u32,
    last_rewrite: Option<SystemTime>,
    last_refresh: Option<SystemTime>,
    stats: SyncStats,
}

impl FirewallSync {
    /// Starts the sync with the production backend and spawns the worker
    /// thread (detection and writes happen on it, never on the caller).
    /// A failed spawn only marks the sync unavailable; nothing blocks.
    pub fn start(table: Arc<BanTable>, clock: Clock) -> Arc<Self> {
        let sync = Self::with_factory(table, clock, Arc::new(exec::detect));
        let worker = Arc::clone(&sync);
        let spawned = thread::Builder::new()
            .name("fg-guard-fw".to_owned())
            .spawn(move || worker_loop(worker))
            .is_ok();
        if !spawned {
            let mut state = lock(&sync.inner);
            state.needs_probe = false;
            state.unavailable = Some(FwUnavailable::new("no_worker", "guard.fwhint.no_worker"));
        }
        sync
    }

    /// A sync without a worker thread; the owner drives `tick` manually
    /// (tests, embedding). `factory` decides the backend (Linux probe or
    /// a substitute).
    pub fn with_factory(table: Arc<BanTable>, clock: Clock, factory: BackendFactory) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(SyncState {
                enabled: true,
                needs_probe: true,
                needs_full: true,
                ..SyncState::default()
            }),
            run: Mutex::new(()),
            wake: Mutex::new(()),
            wake_signal: Condvar::new(),
            table,
            clock,
            factory,
            cleared: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The current status, counters folded with the baseline.
    pub fn status(&self) -> FwStatus {
        let state = lock(&self.inner);
        let mut dropped = state.baseline.clone();
        for (key, value) in &state.last_counters {
            *dropped.entry(key.clone()).or_default() += value;
        }
        FwStatus {
            enabled: state.enabled,
            backend: state.backend.as_ref().and_then(|backend| backend.kind()),
            unavailable: state.unavailable.clone(),
            rules_present: state.rules_present,
            last_error: state.last_error.clone(),
            dropped,
            degraded: state.degraded,
            last_rewrite: state.last_rewrite,
            stats: state.stats,
        }
    }

    /// The last fully written script ("view rules"), `None` until the
    /// first rewrite succeeded.
    pub fn rules_text(&self) -> Option<String> {
        lock(&self.inner).rules_text.clone()
    }

    /// Wakes the worker so the just-landed ban is mirrored within
    /// milliseconds instead of waiting for the next poll. Cheap and
    /// non-blocking: the reconcile diff picks the element up.
    pub fn note_banned(&self, _entry: &Entry) {
        if lock(&self.inner).backend.is_none() {
            return;
        }
        let _gate = lock(&self.wake);
        self.wake_signal.notify_all();
    }

    /// Re-runs capability detection on the next tick (settings save,
    /// operator retry).
    pub fn reprobe(&self) {
        lock(&self.inner).needs_probe = true;
        self.nudge();
    }

    /// Stops the worker: the table is removed before the thread exits
    /// (upstream: bans keep applying in the application layer until the
    /// process ends). Idempotent.
    pub fn stop(&self) {
        lock(&self.inner).exiting = true;
        self.nudge();
    }

    /// Whether the worker finished the shutdown removal.
    pub fn cleared(&self) -> bool {
        self.cleared.load(Ordering::Acquire)
    }

    fn nudge(&self) {
        let _gate = lock(&self.wake);
        self.wake_signal.notify_all();
    }

    /// One reconcile: probe if requested, compare the desired elements
    /// with what the firewall holds, write the delta (or rewrite), read
    /// the counters. Serialized against the worker; all firewall I/O
    /// happens under the `run` mutex but never while holding the state
    /// mutex, so `status` stays responsive.
    pub fn tick(&self) {
        let _run = lock(&self.run);
        let now = (self.clock)();
        {
            let state = lock(&self.inner);
            if !state.enabled || state.exiting {
                return;
            }
            if !state.needs_probe {
                if state.backend.is_none() {
                    // Sticky probe failure: only `reprobe` retries.
                    return;
                }
                if state.degraded && state.next_retry.is_some_and(|at| now < at) {
                    return;
                }
            }
        }
        if lock(&self.inner).needs_probe {
            let outcome = (self.factory)();
            let mut state = lock(&self.inner);
            state.needs_probe = false;
            match outcome {
                Ok(backend) => {
                    state.backend = Some(backend);
                    state.unavailable = None;
                    state.needs_full = true;
                    state.degraded = false;
                    state.consecutive_failures = 0;
                    state.last_error = None;
                }
                Err(unavailable) => {
                    state.backend = None;
                    state.unavailable = Some(unavailable);
                    return;
                }
            }
        }
        let Some(backend) = lock(&self.inner).backend.clone() else {
            return;
        };
        let kind = backend.kind();
        let desired =
            render::elements_from_entries(&active_entries(&self.table, now), now, SET_SIZE);
        let structure_ok = match backend.rules_present() {
            Ok(present) => present,
            Err(error) => {
                Self::record_failure_locked(&mut lock(&self.inner), error, now);
                return;
            }
        };
        let (mut applied, force_full) = {
            let state = lock(&self.inner);
            (state.applied.clone(), state.needs_full)
        };
        // Timed elements whose kernel copy lapsed are gone; forget them so
        // a still-active ban is re-added (degraded periods can outlast the
        // ipset timeout cap).
        applied
            .retain(|_, applied_entry| applied_entry.kernel_until.is_none_or(|until| until > now));
        let plan = plan_sync(&applied, &desired, now, structure_ok, force_full);
        let mut new_applied = applied.clone();
        let mut ok = true;
        let mut failure: Option<FwError> = None;
        let mut baseline_delta: Option<BTreeMap<String, u64>> = None;
        let (mut adds, mut dels, mut rewrites) = (0u64, 0u64, 0u64);
        if plan.full {
            // Counters reset with the table: fold what is on screen now
            // into the baseline before replacing it.
            baseline_delta = backend.read_counters().ok();
            match backend.apply_full(&desired) {
                Ok(()) => {
                    new_applied = desired
                        .iter()
                        .map(|element| (element.key.clone(), applied_entry(kind, element, now)))
                        .collect();
                    rewrites = 1;
                }
                Err(error) => {
                    ok = false;
                    failure = Some(error);
                }
            }
        } else {
            for chunk in chunked(&plan.dels, ELEMENTS_PER_CALL) {
                if let Err(error) = backend.del_elements(&chunk) {
                    ok = false;
                    failure = Some(error);
                    break;
                }
                for element in &chunk {
                    new_applied.remove(&element.key);
                }
                dels += chunk.len() as u64;
            }
            if ok && !plan.replaces.is_empty() {
                // Expiry changed on an applied element: swap the kernel
                // copy (an `add` alone would collide with the old one).
                if let Err(error) = backend.del_elements(&plan.replaces) {
                    ok = false;
                    failure = Some(error);
                }
            }
            if ok {
                for chunk in chunked(&plan.replaces, ELEMENTS_PER_CALL)
                    .into_iter()
                    .chain(chunked(&plan.adds, ELEMENTS_PER_CALL))
                {
                    if let Err(error) = backend.add_elements(&chunk) {
                        ok = false;
                        failure = Some(error);
                        break;
                    }
                    for element in &chunk {
                        new_applied.insert(element.key.clone(), applied_entry(kind, element, now));
                    }
                    adds += chunk.len() as u64;
                }
            }
        }
        // iptables: ipset timeouts are capped, so re-push elements whose
        // kernel copy is about to lapse, and refresh every set once per
        // refresh interval (upstream `iptRefresh`).
        let mut refreshed = 0u64;
        let mut refreshed_periodic = false;
        if ok && kind == Some(FwBackend::IptablesLegacy) {
            let last_refresh = lock(&self.inner).last_refresh;
            let periodic = refresh_periodic_due(last_refresh, now);
            let due: Vec<FwElement> = if periodic {
                refreshed_periodic = true;
                desired
                    .iter()
                    .filter(|element| element.timeout.is_some())
                    .cloned()
                    .collect()
            } else {
                refresh_due(&new_applied, &desired, now, REFRESH_MARGIN)
            };
            if due.is_empty() {
                refreshed_periodic = false;
            } else if let Err(error) = backend.add_elements(&due) {
                ok = false;
                failure = Some(error);
            } else {
                refreshed = due.len() as u64;
                for element in &due {
                    new_applied.insert(element.key.clone(), applied_entry(kind, element, now));
                }
            }
        }
        let counters = if ok {
            backend.read_counters().ok()
        } else {
            None
        };
        // Commit.
        let mut state = lock(&self.inner);
        if ok {
            state.applied = new_applied;
            state.needs_full = false;
            state.rules_present = true;
            state.consecutive_failures = 0;
            state.degraded = false;
            state.next_retry = None;
            state.last_error = None;
            state.stats.adds += adds + refreshed;
            state.stats.dels += dels;
            state.stats.rewrites += rewrites;
            if rewrites > 0 {
                state.last_rewrite = Some(now);
                state.last_refresh = Some(now);
                state.rules_text = Some(render::guard_script(&desired));
            } else if refreshed_periodic {
                state.last_refresh = Some(now);
            }
            if let Some(delta) = baseline_delta {
                for (key, value) in delta {
                    *state.baseline.entry(key).or_default() += value;
                }
                state.last_counters.clear();
            }
            if let Some(counters) = counters {
                state.last_counters = counters;
            }
        } else if let Some(failure) = failure {
            state.needs_full = true;
            Self::record_failure_locked(&mut state, failure, now);
        }
    }

    fn record_failure_locked(state: &mut SyncState, error: FwError, now: SystemTime) {
        state.last_error = Some(error.to_string());
        state.stats.failures += 1;
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
            state.degraded = true;
            state.next_retry = Some(now + BACKOFF);
        }
    }

    /// The stop path: remove the written table so nothing is left in the
    /// system firewall (best effort; never touched when nothing was ever
    /// written). Marks the worker done.
    fn shutdown_remove(&self) {
        let backend = {
            let state = lock(&self.inner);
            if state.stats.rewrites == 0 {
                return;
            }
            state.backend.clone()
        };
        if let Some(backend) = backend {
            let _ = backend.remove_all();
        }
    }
}

/// The kernel-side lifetime of a written element: exact for nftables
/// (timeout seconds), capped for ipset entries.
fn applied_entry(kind: Option<FwBackend>, element: &FwElement, now: SystemTime) -> Applied {
    let kernel_until = element.timeout.map(|secs| match kind {
        Some(FwBackend::IptablesLegacy) => {
            now + Duration::from_secs(render::ipt_timeout_secs(element.timeout))
        }
        _ => now + Duration::from_secs(secs),
    });
    Applied {
        element: element.clone(),
        kernel_until,
    }
}

/// All active entries of the ban table, paged through the public listing
/// API (the hot path read is lock-free; this runs once per tick).
fn active_entries(table: &BanTable, now: SystemTime) -> Vec<Entry> {
    let mut out = Vec::new();
    let page = fg_net::banlist::MAX_PAGE_LIMIT;
    let mut offset = 0;
    loop {
        let filter = BanFilter {
            include_expired: false,
            offset,
            limit: page,
            ..BanFilter::default()
        };
        let total = table.count(now, &filter);
        if total == 0 {
            break;
        }
        let batch = table.list(now, &filter);
        let got = batch.len();
        out.extend(batch);
        if got == 0 || offset + got >= total {
            break;
        }
        offset += got;
    }
    out
}

/// The worker: reconcile every [`POLL_INTERVAL`] (or immediately when
/// nudged), remove the table on exit.
fn worker_loop(sync: Arc<FirewallSync>) {
    loop {
        if lock(&sync.inner).exiting {
            sync.shutdown_remove();
            sync.cleared.store(true, Ordering::Release);
            return;
        }
        sync.tick();
        if lock(&sync.inner).exiting {
            continue;
        }
        let gate = lock(&sync.wake);
        let _ = sync.wake_signal.wait_timeout(gate, POLL_INTERVAL);
    }
}

/// Locks a mutex, recovering from poisoning (the guarded state is plain
/// maps and flags, so continuing is always safe).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::{
        net::IpAddr,
        sync::atomic::AtomicUsize,
        time::{Duration, UNIX_EPOCH},
    };

    use fg_net::banlist::{BanHooks, BanOutcome, BanPolicy, Source};
    use ipnet::IpNet;

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
        fn advance(&self, duration: Duration) {
            let mut now = self.0.lock().expect("clock");
            *now += duration;
        }
    }

    // -- fake backend ---------------------------------------------------

    #[derive(Default)]
    struct FakeBackendState {
        calls: Vec<String>,
        present: bool,
        fail_writes: bool,
        counters: BTreeMap<String, u64>,
        counters_reset_on_full: bool,
    }

    struct FakeBackend {
        kind: Option<FwBackend>,
        state: Mutex<FakeBackendState>,
    }

    impl FakeBackend {
        fn new(kind: Option<FwBackend>, present: bool) -> Self {
            Self {
                kind,
                state: Mutex::new(FakeBackendState {
                    present,
                    ..FakeBackendState::default()
                }),
            }
        }

        fn failing(kind: Option<FwBackend>) -> Self {
            let backend = Self::new(kind, true);
            backend.state.lock().expect("fake").fail_writes = true;
            backend
        }

        fn calls(&self) -> Vec<String> {
            self.state.lock().expect("fake").calls.clone()
        }

        fn set_counters(&self, counters: BTreeMap<String, u64>) {
            self.state.lock().expect("fake").counters = counters;
        }
    }

    impl BanBackend for FakeBackend {
        fn kind(&self) -> Option<FwBackend> {
            self.kind
        }

        fn rules_present(&self) -> Result<bool, FwError> {
            Ok(self.state.lock().expect("fake").present)
        }

        fn apply_full(&self, elements: &[FwElement]) -> Result<(), FwError> {
            let mut state = self.state.lock().expect("fake");
            // The attempt is recorded even when it fails, so the tests can
            // observe retries.
            state.calls.push(format!("full:{}", elements.len()));
            if state.fail_writes {
                return Err(FwError::CommandFailed("boom".to_owned()));
            }
            state.present = true;
            if state.counters_reset_on_full {
                state.counters.clear();
            }
            Ok(())
        }

        fn add_elements(&self, elements: &[FwElement]) -> Result<(), FwError> {
            let mut state = self.state.lock().expect("fake");
            state.calls.push(format!("add:{}", element_keys(elements)));
            if state.fail_writes {
                return Err(FwError::CommandFailed("boom".to_owned()));
            }
            Ok(())
        }

        fn del_elements(&self, elements: &[FwElement]) -> Result<(), FwError> {
            let mut state = self.state.lock().expect("fake");
            state.calls.push(format!("del:{}", element_keys(elements)));
            if state.fail_writes {
                return Err(FwError::CommandFailed("boom".to_owned()));
            }
            Ok(())
        }

        fn read_counters(&self) -> Result<BTreeMap<String, u64>, FwError> {
            Ok(self.state.lock().expect("fake").counters.clone())
        }

        fn remove_all(&self) -> Result<(), FwError> {
            self.state
                .lock()
                .expect("fake")
                .calls
                .push("remove".to_owned());
            Ok(())
        }
    }

    fn element_keys(elements: &[FwElement]) -> String {
        elements
            .iter()
            .map(|element| element.key.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn fake_factory(backend: Arc<FakeBackend>) -> BackendFactory {
        Arc::new(move || Ok(Arc::clone(&backend) as Arc<dyn BanBackend>))
    }

    fn failing_factory(unavailable: FwUnavailable) -> BackendFactory {
        Arc::new(move || Err(unavailable.clone()))
    }

    fn table(clock: &Clock) -> Arc<BanTable> {
        BanTable::open_memory(BanPolicy::default(), BanHooks::default(), Arc::clone(clock))
    }

    fn ban_v4(table: &BanTable, ip: &str, now: SystemTime) -> Entry {
        let outcome = table.ban_auto(
            ip.parse::<IpAddr>().unwrap(),
            None,
            false,
            Source::Scan,
            "guard.reason.scan".to_owned(),
            now,
        );
        let BanOutcome::Banned { entry, .. } = outcome else {
            panic!("expected Banned, got {outcome:?}");
        };
        entry
    }

    fn sync_with(table: Arc<BanTable>, clock: Clock, factory: BackendFactory) -> Arc<FirewallSync> {
        FirewallSync::with_factory(table, clock, factory)
    }

    // -- plan_sync ------------------------------------------------------

    fn element(set: SetName, value: &str, expires: Option<SystemTime>) -> FwElement {
        let net: IpNet = if value.contains('/') {
            value.parse().unwrap()
        } else {
            let prefix = match set.family() {
                Family::V4 => 32,
                Family::V6 => 128,
            };
            format!("{value}/{prefix}").parse().unwrap()
        };
        FwElement {
            key: format!("{}:{}", set.name(), value),
            set,
            value: value.to_owned(),
            net,
            timeout: expires.map(|_| 3600),
            expires,
            created: at(0),
        }
    }

    #[test]
    fn plan_sync_diffs_adds_dels_and_replaces() {
        let now = at(1000);
        let kept = element(SetName::Ban4, "203.0.113.5", Some(at(5000)));
        let extended = element(SetName::Ban4, "203.0.113.6", Some(at(9000)));
        let gone = element(SetName::Deny4, "198.51.100.0/24", None);
        let mut applied = BTreeMap::new();
        for applied_element in [
            &kept,
            &element(SetName::Ban4, "203.0.113.6", Some(at(5000))),
            &gone,
        ] {
            applied.insert(
                applied_element.key.clone(),
                Applied {
                    element: applied_element.clone(),
                    kernel_until: applied_element.expires,
                },
            );
        }
        let desired = vec![
            kept,
            extended,
            element(SetName::Ban6, "2001:db8:aa::", Some(at(6000))),
        ];
        let plan = plan_sync(&applied, &desired, now, true, false);
        assert!(!plan.full);
        assert_eq!(element_keys(&plan.adds), "ban6:2001:db8:aa::");
        assert_eq!(element_keys(&plan.replaces), "ban4:203.0.113.6");
        assert_eq!(element_keys(&plan.dels), "deny4:198.51.100.0/24");
    }

    #[test]
    fn plan_sync_requests_full_when_structure_incomplete() {
        let applied = BTreeMap::new();
        let plan = plan_sync(&applied, &[], at(0), false, false);
        assert!(plan.full);
        let plan = plan_sync(&applied, &[], at(0), true, true);
        assert!(plan.full, "forced full (heal after a failed write)");
    }

    #[test]
    fn plan_sync_forgets_expired_timed_and_deletes_expired_deny() {
        let now = at(2000);
        // Timed element whose kernel copy lapsed: silently forgotten.
        let timed = Applied {
            element: element(SetName::Ban4, "203.0.113.5", Some(at(1000))),
            kernel_until: Some(at(1000)),
        };
        // Deny element of an expired manual ban: the kernel keeps it, so a
        // delete must be issued.
        let deny = Applied {
            element: element(SetName::Deny4, "198.51.100.0/24", Some(at(1000))),
            kernel_until: None,
        };
        let mut applied = BTreeMap::new();
        applied.insert(timed.element.key.clone(), timed);
        applied.insert(deny.element.key.clone(), deny);
        let plan = plan_sync(&applied, &[], now, true, false);
        assert!(plan.adds.is_empty() && plan.replaces.is_empty());
        assert_eq!(element_keys(&plan.dels), "deny4:198.51.100.0/24");
    }

    #[test]
    fn refresh_due_repushes_elements_near_kernel_expiry() {
        let now = at(100_000);
        let cap = at(100_000 + IPT_TIMEOUT_CAP.as_secs() as i64);
        let soon = Applied {
            element: element(SetName::Ban4, "203.0.113.5", Some(at(1_000_000))),
            kernel_until: Some(now + Duration::from_secs(60)),
        };
        let far = Applied {
            element: element(SetName::Ban4, "203.0.113.6", Some(at(1_000_000))),
            kernel_until: Some(cap),
        };
        let desired = vec![soon.element.clone(), far.element.clone()];
        let mut applied = BTreeMap::new();
        applied.insert(soon.element.key.clone(), soon);
        applied.insert(far.element.key.clone(), far);
        let due = refresh_due(&applied, &desired, now, Duration::from_secs(600));
        assert_eq!(element_keys(&due), "ban4:203.0.113.5");
    }

    #[test]
    fn refresh_periodic_due_after_24h() {
        let now = at(200_000);
        assert!(!refresh_periodic_due(None, now), "nothing written yet");
        assert!(!refresh_periodic_due(Some(now), now));
        assert!(refresh_periodic_due(Some(now - IPT_REFRESH), now));
    }

    #[test]
    fn ipt_timeout_caps_long_bans_at_24h() {
        assert_eq!(ipt_timeout_secs(Some(3600)), 3600);
        assert_eq!(
            ipt_timeout_secs(Some(7 * 24 * 3600)),
            IPT_TIMEOUT_CAP.as_secs(),
            "long bans are written at the cap and refreshed"
        );
        assert_eq!(
            ipt_timeout_secs(None),
            0,
            "permanent deny entries are untouched"
        );
    }

    // -- engine ---------------------------------------------------------

    #[test]
    fn sync_startup_rebuilds_full_table_incrementally_after_bans() {
        let (_fake_clock, clock) = clock(1000);
        let table = table(&clock);
        let now = (clock)();
        ban_v4(&table, "203.0.113.5", now);
        table
            .ban_manual("198.51.100.0/24".parse::<IpNet>().unwrap(), None, true, now)
            .unwrap();
        let backend = Arc::new(FakeBackend::new(Some(FwBackend::Nftables), true));
        let sync = sync_with(
            Arc::clone(&table),
            clock.clone(),
            fake_factory(Arc::clone(&backend)),
        );
        sync.tick();
        let calls = backend.calls();
        assert_eq!(calls.len(), 1, "one full rebuild: {calls:?}");
        assert!(calls[0].starts_with("full:2"), "{calls:?}");
        let status = sync.status();
        assert_eq!(status.backend, Some(FwBackend::Nftables));
        assert!(status.rules_present);
        assert_eq!(status.stats.rewrites, 1);
        // A new ban lands: the hook nudges, the next tick adds the delta.
        let entry = ban_v4(&table, "203.0.113.6", (clock)());
        sync.note_banned(&entry);
        sync.tick();
        let calls = backend.calls();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert!(calls[1].starts_with("add:ban4:203.0.113.6"), "{calls:?}");
        assert_eq!(sync.status().stats.adds, 1);
    }

    #[test]
    fn sync_rewrites_when_structure_missing_and_replaces_extended_bans() {
        let (_fake_clock, clock) = clock(1000);
        let table = table(&clock);
        let now = (clock)();
        ban_v4(&table, "203.0.113.5", now);
        let backend = Arc::new(FakeBackend::new(Some(FwBackend::Nftables), true));
        let sync = sync_with(
            Arc::clone(&table),
            clock.clone(),
            fake_factory(Arc::clone(&backend)),
        );
        sync.tick();
        // The firewall lost the table (fw4 reload etc.): full rewrite with
        // the still-valid bans.
        backend.state.lock().expect("fake").present = false;
        sync.tick();
        assert_eq!(
            backend
                .calls()
                .iter()
                .filter(|call| call.starts_with("full:"))
                .count(),
            2,
            "{:?}",
            backend.calls()
        );
        // Extending the ban re-places the element (del + add).
        let outcome = table.ban_auto(
            "203.0.113.5".parse().unwrap(),
            Some(Duration::from_secs(7200)),
            false,
            Source::Scan,
            "guard.reason.scan".to_owned(),
            (clock)(),
        );
        assert!(matches!(outcome, BanOutcome::Banned { .. }));
        sync.tick();
        let calls = backend.calls();
        assert!(
            calls
                .iter()
                .any(|call| call.starts_with("del:ban4:203.0.113.5"))
                && calls
                    .iter()
                    .any(|call| call.starts_with("add:ban4:203.0.113.5")),
            "{calls:?}"
        );
    }

    #[test]
    fn sync_expiry_deletes_deny_element_after_ban_lapses() {
        let (fake_clock, clock) = clock(1000);
        let table = table(&clock);
        let now = (clock)();
        table
            .ban_manual(
                "198.51.100.0/24".parse::<IpNet>().unwrap(),
                Some(Duration::from_secs(10)),
                false,
                now,
            )
            .unwrap();
        let backend = Arc::new(FakeBackend::new(Some(FwBackend::Nftables), true));
        let sync = sync_with(
            Arc::clone(&table),
            clock.clone(),
            fake_factory(Arc::clone(&backend)),
        );
        sync.tick();
        fake_clock.advance(Duration::from_secs(20));
        sync.tick();
        let calls = backend.calls();
        assert!(
            calls
                .iter()
                .any(|call| call.starts_with("del:deny4:198.51.100.0/24")),
            "the timeout-less deny element is removed explicitly: {calls:?}"
        );
    }

    #[test]
    fn sync_consecutive_failures_degrade_then_retry_after_backoff() {
        let (fake_clock, clock) = clock(1000);
        let table = table(&clock);
        ban_v4(&table, "203.0.113.5", (clock)());
        let backend = Arc::new(FakeBackend::failing(Some(FwBackend::Nftables)));
        let sync = sync_with(
            Arc::clone(&table),
            clock.clone(),
            fake_factory(Arc::clone(&backend)),
        );
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            sync.tick();
        }
        let status = sync.status();
        assert!(status.degraded, "three failures degrade the sync");
        assert_eq!(status.last_error.as_deref(), Some("boom"));
        assert_eq!(status.stats.failures, u64::from(MAX_CONSECUTIVE_FAILURES));
        // While degraded, ticks park until the backoff elapses.
        let writes_before = backend.calls().len();
        fake_clock.advance(BACKOFF - Duration::from_secs(1));
        sync.tick();
        assert_eq!(backend.calls().len(), writes_before, "still parked");
        fake_clock.advance(Duration::from_secs(2));
        sync.tick();
        assert!(
            backend.calls().len() > writes_before,
            "the backoff elapsed: writes are retried"
        );
    }

    #[test]
    fn sync_failure_keeps_app_level_bans() {
        let (_fake_clock, clock) = clock(1000);
        let table = table(&clock);
        let now = (clock)();
        ban_v4(&table, "203.0.113.5", now);
        let backend = Arc::new(FakeBackend::failing(Some(FwBackend::Nftables)));
        let sync = sync_with(
            Arc::clone(&table),
            clock.clone(),
            fake_factory(Arc::clone(&backend)),
        );
        for _ in 0..(MAX_CONSECUTIVE_FAILURES + 1) {
            sync.tick();
        }
        assert!(
            table.is_banned("203.0.113.5".parse().unwrap(), (clock)()),
            "the application layer always stays authoritative"
        );
        assert!(!sync.status().rules_present);
    }

    #[test]
    fn sync_recovers_from_degraded_after_success() {
        let (_fake_clock, clock) = clock(1000);
        let table = table(&clock);
        ban_v4(&table, "203.0.113.5", (clock)());
        let backend = Arc::new(FakeBackend::failing(Some(FwBackend::Nftables)));
        let sync = sync_with(
            Arc::clone(&table),
            clock.clone(),
            fake_factory(Arc::clone(&backend)),
        );
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            sync.tick();
        }
        assert!(sync.status().degraded);
        // The environment heals (permission granted): a fresh probe and
        // write succeed.
        let good = Arc::new(FakeBackend::new(Some(FwBackend::Nftables), true));
        let healed = sync_with(
            Arc::clone(&table),
            clock.clone(),
            fake_factory(Arc::clone(&good)),
        );
        healed.tick();
        let status = healed.status();
        assert!(!status.degraded);
        assert!(status.rules_present);
    }

    #[test]
    fn sync_probe_failure_is_sticky_until_reprobe() {
        let (_fake_clock, clock) = clock(1000);
        let table = table(&clock);
        let attempted = Arc::new(AtomicUsize::new(0));
        let flag = Arc::clone(&attempted);
        let factory: BackendFactory = Arc::new(move || {
            flag.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(FwUnavailable::no_permission())
        });
        let sync = sync_with(Arc::clone(&table), clock.clone(), factory);
        sync.tick();
        assert_eq!(
            sync.status().unavailable.as_ref().unwrap().code,
            "no_permission"
        );
        assert_eq!(attempted.load(std::sync::atomic::Ordering::SeqCst), 1);
        sync.tick();
        sync.tick();
        assert_eq!(
            attempted.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "probe failures are not retried on every poll"
        );
        // Settings save / retry button re-probes.
        sync.reprobe();
        sync.tick();
        assert_eq!(attempted.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(
            sync.status().unavailable.as_ref().unwrap().code,
            "no_permission"
        );
    }

    #[test]
    fn sync_probe_reports_not_linux_on_unsupported_platforms() {
        let (_fake_clock, clock) = clock(0);
        let table = table(&clock);
        let sync = sync_with(
            Arc::clone(&table),
            clock,
            failing_factory(FwUnavailable::not_linux()),
        );
        sync.tick();
        let status = sync.status();
        assert_eq!(status.unavailable.as_ref().unwrap().code, "not_linux");
        assert_eq!(status.backend, None);
        assert!(!status.rules_present);
        assert!(status_text(&status).contains("应用层"));
    }

    #[test]
    fn sync_stop_removes_written_table_only() {
        let (_fake_clock, clock) = clock(1000);
        let table = table(&clock);
        ban_v4(&table, "203.0.113.5", (clock)());
        let backend = Arc::new(FakeBackend::new(Some(FwBackend::Nftables), true));
        let sync = sync_with(
            Arc::clone(&table),
            clock.clone(),
            fake_factory(Arc::clone(&backend)),
        );
        sync.tick();
        sync.stop();
        assert!(!sync.cleared(), "the worker (not run here) owns the flag");
        sync.shutdown_remove();
        assert!(backend.calls().iter().any(|call| call == "remove"));
        // A sync that never wrote anything must not touch the firewall.
        let untouched = Arc::new(FakeBackend::new(Some(FwBackend::Nftables), true));
        let idle = sync_with(
            Arc::clone(&table),
            clock,
            fake_factory(Arc::clone(&untouched)),
        );
        idle.stop();
        idle.shutdown_remove();
        assert!(untouched.calls().is_empty(), "{:?}", untouched.calls());
    }

    #[test]
    fn sync_folds_counters_across_rewrites() {
        let (_fake_clock, clock) = clock(1000);
        let table = table(&clock);
        ban_v4(&table, "203.0.113.5", (clock)());
        let backend = Arc::new(FakeBackend::new(Some(FwBackend::Nftables), true));
        backend.state.lock().expect("fake").counters_reset_on_full = true;
        backend.set_counters(BTreeMap::from([("ban".to_owned(), 5u64)]));
        let sync = sync_with(
            Arc::clone(&table),
            clock.clone(),
            fake_factory(Arc::clone(&backend)),
        );
        sync.tick();
        assert_eq!(
            sync.status().dropped.get("ban"),
            Some(&5),
            "the five packets dropped before the rewrite stay counted"
        );
        backend.set_counters(BTreeMap::from([("ban".to_owned(), 7u64)]));
        sync.tick();
        assert_eq!(
            sync.status().dropped.get("ban"),
            Some(&12),
            "5 baseline + 7"
        );
    }

    #[test]
    fn sync_routes_view_rules_text_after_rewrite() {
        let (_fake_clock, clock) = clock(1000);
        let table = table(&clock);
        ban_v4(&table, "203.0.113.5", (clock)());
        let backend = Arc::new(FakeBackend::new(Some(FwBackend::Nftables), true));
        let sync = sync_with(
            Arc::clone(&table),
            clock.clone(),
            fake_factory(Arc::clone(&backend)),
        );
        assert!(sync.rules_text().is_none());
        sync.tick();
        let rules = sync.rules_text().expect("rules text after rewrite");
        assert!(rules.contains("delete table inet gately"));
        assert!(rules.contains("@ban4"));
    }

    #[test]
    fn sync_refreshes_capped_ipset_entries_before_expiry() {
        let (fake_clock, clock) = clock(1000);
        let table = table(&clock);
        // A long-lived ban outlasts the ipset timeout cap.
        let outcome = table.ban_auto(
            "203.0.113.5".parse().unwrap(),
            Some(Duration::from_secs(30 * 24 * 3600)),
            false,
            Source::Scan,
            "guard.reason.scan".to_owned(),
            (clock)(),
        );
        assert!(matches!(outcome, BanOutcome::Banned { .. }));
        let backend = Arc::new(FakeBackend::new(Some(FwBackend::IptablesLegacy), true));
        let sync = sync_with(
            Arc::clone(&table),
            clock.clone(),
            fake_factory(Arc::clone(&backend)),
        );
        sync.tick();
        let full_writes = backend
            .calls()
            .iter()
            .filter(|call| call.starts_with("full:"))
            .count();
        assert_eq!(full_writes, 1);
        // Almost the whole capped lifetime passes: within the refresh
        // margin the element is re-pushed without a rewrite.
        fake_clock.advance(IPT_TIMEOUT_CAP - REFRESH_MARGIN / 2);
        sync.tick();
        let calls = backend.calls();
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.starts_with("full:"))
                .count(),
            full_writes,
            "no rewrite needed: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|call| call.starts_with("add:ban4:203.0.113.5")),
            "the capped ipset entry is refreshed: {calls:?}"
        );
    }

    // -- status text ----------------------------------------------------

    #[test]
    fn status_text_covers_enabled_unavailable_and_degraded() {
        let disabled = FwStatus::default();
        assert_eq!(status_text(&disabled), "防火墙同步未启用");

        let mut unavailable = FwStatus {
            enabled: true,
            unavailable: Some(FwUnavailable::no_permission()),
            ..FwStatus::default()
        };
        let text = status_text(&unavailable);
        assert!(text.contains("权限") && text.contains("应用层"), "{text}");
        unavailable.unavailable = Some(FwUnavailable::not_linux());
        assert!(status_text(&unavailable).contains("只支持 Linux"));

        let degraded = FwStatus {
            enabled: true,
            backend: Some(FwBackend::Nftables),
            degraded: true,
            last_error: Some("boom".to_owned()),
            ..FwStatus::default()
        };
        assert!(
            status_text(&degraded).contains("退回应用层封禁")
                && status_text(&degraded).contains("boom")
        );

        let writing = FwStatus {
            enabled: true,
            backend: Some(FwBackend::Nftables),
            ..FwStatus::default()
        };
        assert!(status_text(&writing).contains("正在写入防火墙规则"));

        let ok = FwStatus {
            enabled: true,
            backend: Some(FwBackend::Nftables),
            rules_present: true,
            dropped: BTreeMap::from([("ban".to_owned(), 3), ("deny".to_owned(), 4)]),
            ..FwStatus::default()
        };
        let text = status_text(&ok);
        assert!(
            text.contains("nftables") && text.contains("7 个数据包"),
            "{text}"
        );
    }
}
