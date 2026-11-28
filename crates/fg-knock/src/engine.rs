//! Verification pipeline and grant bookkeeping (WP-54 §3.3 steps 4–9):
//!
//! banned-source drop → prefilter → rate limit → HMAC (`KeySet`) →
//! decrypt → field checks → time window → replay → rule match → grant →
//! firewall window (injected hook) → events/logs.
//!
//! The decision logic that needs no I/O lives in pure functions
//! ([`check_message`], [`effective_timeout`], [`revokes_on_edit`]) and is
//! unit-tested against WP-54 §6; [`Engine::handle`] only orchestrates
//! shared state and calls the injected [`Hooks`]. The firewall window is
//! never touched directly: `fwopen` / WP-51 are wired in by the assembler
//! through `Deps` (conventions §3.4).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use ipnet::IpNet;
use tokio_util::sync::CancellationToken;

use fg_core::events::{Event, EventBus, Kind};
use fg_net::banlist::BanTable;

use crate::grants::{Grant, GrantSource, Grants};
use crate::limit::RateLimiter;
use crate::model::{Access, FileConfig, Rule, Settings, limits};
use crate::replay::{ReplayCache, ReplayKey};
use crate::spa::{DecodeError, KeyEntry, KeySet, MsgType};
use crate::validate::{enabled_key_entries, enabled_rule_keys, rule_credential_set};

/// Injectable wall clock (UTC); production uses the system clock.
pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// The real UTC clock.
pub fn system_clock() -> Clock {
    Arc::new(SystemTime::now)
}

/// Which channel carried the packet: the UDP listener or a TCP submission
/// via protocol routing (`submit`). Only TCP rejections publish events —
/// UDP source addresses are spoofable (§3.3 step 9, §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    Udp,
    Tcp,
}

impl Via {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

/// Opening a firewall window for one rule (injected; the assembler maps
/// `ports` onto `fwopen::Group::want` or the WP-51 `gately_knock` set).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowRequest {
    pub rule: String,
    pub ports: Vec<Access>,
}

/// Async hooks injected by the assembler (conventions §3.4). All optional.
#[derive(Clone, Default)]
pub struct Hooks {
    /// Open the firewall window for a rule with firewall blocking.
    pub open_window: Option<crate::SharedFn<WindowRequest, ()>>,
    /// Close the window again (expiry, revoke, shutdown); payload is the
    /// rule key.
    pub close_window: Option<crate::SharedFn<String, ()>>,
    /// Event bus for `knock.opened` / `knock.failed`.
    pub events: Option<EventBus>,
    /// Shared ban table: banned sources are dropped; a successful knock
    /// shields its address (24 h) against trap and scan sources.
    pub bans: Option<Arc<BanTable>>,
}

/// One compiled rule: the fields verification needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledRule {
    pub key: String,
    pub name: String,
    pub ports: Vec<Access>,
    pub firewall: bool,
    pub timeout: u32,
    pub max_timeout: u32,
    pub user: String,
    pub require_addr: bool,
    pub single_addr: bool,
    /// Valid credential fingerprints after this config edit.
    pub creds: HashSet<String>,
}

/// The immutable configuration snapshot the engine reads per packet.
#[derive(Clone, Debug, Default)]
pub struct Compiled {
    pub settings: Settings,
    pub keys: KeySet,
    pub rules: HashMap<String, CompiledRule>,
}

impl Compiled {
    /// Compiles a normalized, valid config.
    pub fn build(config: &FileConfig) -> Self {
        let mut entries = Vec::new();
        for (rule, identity, enc_b64, hmac_b64, hmac_type) in enabled_key_entries(config) {
            let Ok(key) = crate::spa::Key::from_base64(&enc_b64, &hmac_b64, hmac_type) else {
                continue;
            };
            entries.push(KeyEntry {
                cred: crate::spa::cred_fingerprint(&key.hmac, hmac_type),
                key,
                rule,
                identity,
            });
        }
        let mut rules = HashMap::new();
        for rule in config.rules.iter().filter(|rule| rule.enable) {
            rules.insert(
                rule.key.clone(),
                CompiledRule {
                    key: rule.key.clone(),
                    name: rule.name.clone(),
                    ports: rule.ports.clone(),
                    firewall: rule.firewall,
                    timeout: rule.timeout,
                    max_timeout: rule.max_timeout,
                    user: rule.user.clone(),
                    require_addr: rule.require_addr,
                    single_addr: rule.single_addr,
                    creds: rule_credential_set(rule).into_iter().collect(),
                },
            );
        }
        Self {
            settings: config.settings.clone(),
            keys: KeySet::new(entries),
            rules,
        }
    }
}

/// The result of one packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A grant was registered (and the window opened for firewall rules).
    Opened(Opened),
    /// HMAC passed but a rule check failed.
    Rejected(Reject),
    /// Banned source or not a knock packet (prefilter): counted, never
    /// logged per packet and never published.
    Ignored,
    /// Dropped by the per-source or global budget before HMAC work.
    RateLimited,
}

/// Details of a successful knock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub addr: IpAddr,
    pub rule: String,
    pub rule_name: String,
    pub identity: Option<String>,
    pub user: Option<String>,
    pub duration_secs: u32,
    pub until: SystemTime,
    pub via: &'static str,
    pub firewall: bool,
}

/// Why a packet was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// Timestamp outside the `maxAge` window.
    Expired,
    /// Timestamp predates this process start (replay after restart).
    BeforeStart,
    /// The (credential, random, timestamp) triple was already used.
    Replay,
    /// A requested port is not in the rule: the whole knock is refused.
    PortNotAllowed,
    /// The rule pins a username and the packet's differs.
    UserMismatch,
    /// The rule requires an explicit address and the packet used `-s`.
    AddrRequired,
    /// HMAC failed for every credential (invalid group: summarized).
    HmacMismatch,
    /// Decryption failed (invalid group).
    Decrypt,
    /// PKCS#7 padding invalid (invalid group).
    Padding,
    /// Plaintext malformed (invalid group).
    BadRequest,
    /// No enabled rule owns the matched credential (transient or the
    /// grant table refused).
    NoRule,
}

impl Reject {
    /// Whether this happened before authentication (invalid group:
    /// summarized per minute instead of logged per packet).
    pub fn is_invalid(self) -> bool {
        matches!(
            self,
            Self::HmacMismatch | Self::Decrypt | Self::Padding | Self::BadRequest
        )
    }

    /// Stable reason tag for logs, events and the status view.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::BeforeStart => "before-start",
            Self::Replay => "replay",
            Self::PortNotAllowed => "port-not-allowed",
            Self::UserMismatch => "user-mismatch",
            Self::AddrRequired => "addr-required",
            Self::HmacMismatch => "hmac-mismatch",
            Self::Decrypt => "decrypt",
            Self::Padding => "padding",
            Self::BadRequest => "bad-request",
            Self::NoRule => "no-rule",
        }
    }
}

impl From<DecodeError> for Reject {
    fn from(error: DecodeError) -> Self {
        match error {
            DecodeError::HmacMismatch => Self::HmacMismatch,
            DecodeError::Decrypt => Self::Decrypt,
            DecodeError::Padding => Self::Padding,
            _ => Self::BadRequest,
        }
    }
}

/// The grant plan produced by the pure checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantPlan {
    pub addr: IpAddr,
    pub duration_secs: u32,
    pub identity: Option<String>,
    pub user: Option<String>,
    pub cred: String,
    pub single_addr: bool,
}

/// Everything the pure checks need, gathered by the engine per packet.
pub struct CheckContext<'a> {
    pub rule: &'a CompiledRule,
    pub max_age: u32,
    /// The packet's source address (the `-s` fallback for the grant).
    pub peer: IpAddr,
    pub now: SystemTime,
    pub started: SystemTime,
    pub replay_hit: bool,
    /// The matched credential fingerprint and its identity.
    pub credential: (&'a str, Option<&'a str>),
}

/// The pure state machine (WP-54 §3.3 step 6): time window, restart
/// guard, replay, rule match, username and address requirements.
/// Decoupled from [`Engine`] so the §6 table is testable directly.
pub fn check_message(
    message: &crate::spa::Message,
    ctx: CheckContext<'_>,
) -> Result<GrantPlan, Reject> {
    // Only Access / ClientTimeoutAccess packets decode at all (the spa
    // layer rejects the rest); assert the invariant defensively.
    debug_assert!(matches!(
        message.msg_type,
        MsgType::Access | MsgType::ClientTimeoutAccess
    ));
    let rule = ctx.rule;
    // Time window: the packet timestamp must be within maxAge of now.
    // A future timestamp beyond the window is treated the same (skew).
    let delta = (unix_secs(ctx.now) - message.timestamp).abs();
    if delta > i64::from(ctx.max_age) {
        return Err(Reject::Expired);
    }
    // Restart guard: replay records do not survive a restart, so packets
    // older than this process are refused outright.
    if message.timestamp < unix_secs(ctx.started) {
        return Err(Reject::BeforeStart);
    }
    if ctx.replay_hit {
        return Err(Reject::Replay);
    }
    // Every requested port must be protected by the rule.
    for access in &message.access {
        if !rule.ports.contains(access) {
            return Err(Reject::PortNotAllowed);
        }
    }
    // Pinned username.
    if !rule.user.is_empty() && message.user != rule.user {
        return Err(Reject::UserMismatch);
    }
    // `-s` packets may be refused when the rule demands an address.
    if rule.require_addr && message.addr.is_none() {
        return Err(Reject::AddrRequired);
    }
    Ok(GrantPlan {
        addr: message.addr.unwrap_or(ctx.peer),
        duration_secs: effective_timeout(rule.timeout, rule.max_timeout, message.client_timeout),
        identity: ctx.credential.1.map(str::to_owned),
        user: (!message.user.is_empty()).then_some(message.user.clone()),
        cred: ctx.credential.0.to_owned(),
        single_addr: rule.single_addr,
    })
}

/// Grant duration: the rule's `timeout`, unless the client requested one
/// (`-f`) and the rule honors requests (`maxTimeout > 0`), in which case
/// the request capped at `maxTimeout` applies; shorter requests always
/// win.
pub fn effective_timeout(rule_timeout: u32, rule_max_timeout: u32, requested: Option<u32>) -> u32 {
    match requested {
        Some(request) if rule_max_timeout > 0 => request.min(rule_max_timeout),
        _ => rule_timeout,
    }
}

/// Which grants a rule edit revokes (WP-54 §3.3 table):
/// - port list, firewall flag, timeout, pinned user or address requirement
///   changed → every knock grant of the rule;
/// - name / group / remark / identities / single-address only → just the
///   grants whose credential no longer exists;
/// - web-login grants are never revoked here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revoke {
    All,
    Stale,
}

pub fn revokes_on_edit(old: &Rule, new: &Rule) -> Revoke {
    if old.ports != new.ports
        || old.firewall != new.firewall
        || old.timeout != new.timeout
        || old.user != new.user
        || old.require_addr != new.require_addr
    {
        return Revoke::All;
    }
    Revoke::Stale
}

/// Counters for the status endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub opened: u64,
    pub rejected: u64,
    pub invalid: u64,
    pub ignored: u64,
    pub rate_limited: u64,
    pub failed_events: u64,
    pub grants: usize,
    pub replay_cache: usize,
    pub rate_sources: usize,
}

#[derive(Default)]
struct Counters {
    opened: std::sync::atomic::AtomicU64,
    rejected: std::sync::atomic::AtomicU64,
    invalid: std::sync::atomic::AtomicU64,
    ignored: std::sync::atomic::AtomicU64,
    rate_limited: std::sync::atomic::AtomicU64,
    failed_events: std::sync::atomic::AtomicU64,
}

macro_rules! bump {
    ($counters:expr, $field:ident) => {
        $counters
            .$field
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    };
}

/// Per-minute summary of pre-authentication failures.
#[derive(Default)]
struct InvalidWindow {
    started: Option<std::time::Instant>,
    sources: HashSet<IpNet>,
    count: u64,
}

/// One per-minute invalid summary (upstream: "N 个来源的 M 个报文认证失败").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidSummary {
    pub sources: usize,
    pub count: u64,
}

impl InvalidSummary {
    pub fn message(&self) -> String {
        format!("{} 个来源的 {} 个报文认证失败", self.sources, self.count)
    }
}

/// The knock engine. Share it (`Arc`) between the listener, the routes
/// and the close-window timers.
pub struct Engine {
    compiled: ArcSwap<Compiled>,
    grants: Arc<Grants>,
    replay: ReplayCache,
    limiter: RateLimiter,
    hooks: Hooks,
    clock: Clock,
    started: SystemTime,
    counters: Counters,
    invalid: Mutex<InvalidWindow>,
    failed_throttle: Mutex<HashMap<IpAddr, SystemTime>>,
    /// Per-rule close-window timers (firewall rules only).
    timers: Mutex<HashMap<String, CancellationToken>>,
    root_token: CancellationToken,
}

impl Engine {
    /// Assembles an engine over the shared grant registry.
    pub fn new(
        grants: Arc<Grants>,
        replay: ReplayCache,
        limiter: RateLimiter,
        hooks: Hooks,
        clock: Clock,
    ) -> Arc<Self> {
        let started = (clock)();
        Arc::new(Self {
            compiled: ArcSwap::from_pointee(Compiled::default()),
            grants,
            replay,
            limiter,
            hooks,
            clock,
            started,
            counters: Counters::default(),
            invalid: Mutex::new(InvalidWindow::default()),
            failed_throttle: Mutex::new(HashMap::new()),
            timers: Mutex::new(HashMap::new()),
            root_token: CancellationToken::new(),
        })
    }

    pub fn started(&self) -> SystemTime {
        self.started
    }

    /// The engine's current time (the injected clock; grants, replay and
    /// events evaluate against it).
    pub fn now(&self) -> SystemTime {
        (self.clock)()
    }

    pub fn grants(&self) -> &Arc<Grants> {
        &self.grants
    }

    pub fn replay(&self) -> &ReplayCache {
        &self.replay
    }

    pub fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }

    pub fn snapshot(&self) -> Arc<Compiled> {
        self.compiled.load_full()
    }

    /// Installs a fresh config (already normalized and valid): rebuilds
    /// the key set and rule map, updates the registry's rule list and
    /// applies the edit-revocation table. `old` is the previously applied
    /// config, if any.
    pub fn apply_config(self: &Arc<Self>, old: Option<&FileConfig>, new: &FileConfig) {
        let compiled = Compiled::build(new);
        self.compiled.store(Arc::new(compiled));
        self.grants.set_rules(enabled_rule_keys(new));
        let old_rules: HashMap<&str, &Rule> = old
            .map(|config| {
                config
                    .rules
                    .iter()
                    .map(|rule| (rule.key.as_str(), rule))
                    .collect()
            })
            .unwrap_or_default();
        for rule in &new.rules {
            let Some(previous) = old_rules.get(rule.key.as_str()) else {
                continue;
            };
            if !rule.enable {
                // Disabled rules lose every grant and any open window.
                self.grants.revoke_rule(&rule.key);
                self.cancel_window(&rule.key);
                continue;
            }
            match revokes_on_edit(previous, rule) {
                Revoke::All => {
                    self.grants.revoke_rule(&rule.key);
                }
                Revoke::Stale => {
                    let valid: HashSet<String> = rule_credential_set(rule).into_iter().collect();
                    self.grants.revoke_stale_in_rule(&rule.key, &valid);
                }
            }
        }
        // Rules removed from the config entirely.
        let removed: Vec<String> = old_rules
            .keys()
            .filter(|key| !new.rules.iter().any(|rule| &rule.key == *key))
            .map(|key| (*key).to_owned())
            .collect();
        for key in removed {
            self.grants.revoke_rule(&key);
            self.cancel_window(&key);
        }
        // Rules that lost firewall blocking close their window now.
        let live_windows: HashSet<String> = self
            .compiled
            .load()
            .rules
            .values()
            .filter(|rule| rule.firewall)
            .map(|rule| rule.key.clone())
            .collect();
        let orphaned: Vec<String> = self
            .timers
            .lock()
            .expect("window timers")
            .keys()
            .filter(|key| !live_windows.contains(*key))
            .cloned()
            .collect();
        for key in orphaned {
            self.cancel_window(&key);
        }
    }

    /// Cancels one rule's close timer and closes its window. Safe outside
    /// a runtime: the close hook then runs on the next runtime context
    /// (startup has no windows open anyway).
    pub fn cancel_window(self: &Arc<Self>, rule: &str) {
        if let Some(token) = self.timers.lock().expect("window timers").remove(rule) {
            token.cancel();
        }
        if tokio::runtime::Handle::try_current().is_ok() {
            let hooks = self.hooks.clone();
            let rule = rule.to_owned();
            tokio::spawn(async move {
                close_window(&hooks, &rule).await;
            });
        }
    }

    /// Processes one packet from `peer` that arrived over `via`.
    pub async fn handle(self: &Arc<Self>, packet: &[u8], peer: SocketAddr, via: Via) -> Outcome {
        let now = (self.clock)();
        let snapshot = self.compiled.load();

        // 1. Banned sources are dropped before anything else.
        if let Some(bans) = &self.hooks.bans
            && bans.is_banned(peer.ip(), now)
        {
            bump!(self.counters, ignored);
            return Outcome::Ignored;
        }

        // 2. Prefilter: length and charset, before any HMAC work.
        if crate::spa::prefilter(packet).is_err() {
            bump!(self.counters, ignored);
            return Outcome::Ignored;
        }

        // 3. Rate limit: per source network and global HMAC budget.
        let cost = RateLimiter::packet_cost(packet.len(), snapshot.keys.len());
        if !self
            .limiter
            .allow(peer.ip(), cost, std::time::Instant::now())
        {
            bump!(self.counters, rate_limited);
            return Outcome::RateLimited;
        }

        // 4. HMAC authentication against every configured credential; a
        //    mismatching packet never reaches decryption (spa layer).
        let (index, message) = match snapshot.keys.decode(packet) {
            Ok(found) => found,
            Err(error) => {
                let reject = Reject::from(error);
                bump!(self.counters, invalid);
                self.record_invalid(peer.ip());
                self.reject(peer.ip(), via, reject, None, now);
                return Outcome::Rejected(reject);
            }
        };
        let entry = &snapshot.keys.entries()[index];
        let Some(rule) = snapshot.rules.get(&entry.rule) else {
            bump!(self.counters, invalid);
            self.reject(peer.ip(), via, Reject::NoRule, None, now);
            return Outcome::Rejected(Reject::NoRule);
        };

        // 5–6. Field checks: time window, replay, rule match.
        let replay_key =
            ReplayKey::new(entry.cred.clone(), message.rand.clone(), message.timestamp);
        let replay_hit = self.replay.contains(&replay_key);
        let plan = match check_message(
            &message,
            CheckContext {
                rule,
                max_age: snapshot.settings.max_age,
                peer: peer.ip(),
                now,
                started: self.started,
                replay_hit,
                credential: (&entry.cred, entry.identity.as_deref()),
            },
        ) {
            Ok(plan) => plan,
            Err(reject) => {
                bump!(self.counters, rejected);
                self.reject(peer.ip(), via, reject, Some(&rule.name), now);
                return Outcome::Rejected(reject);
            }
        };

        // 7. Register the grant (single-address rules revoke first).
        let until = now + Duration::from_secs(u64::from(plan.duration_secs));
        let grant = Grant {
            addr: plan.addr,
            rule: rule.key.clone(),
            until,
            source: GrantSource::Knock,
            identity: plan.identity.clone(),
            user: plan.user.clone(),
            cred: plan.cred.clone(),
        };
        let Some(stored) = self.grants.grant(grant, plan.single_addr, now) else {
            bump!(self.counters, rejected);
            self.reject(peer.ip(), via, Reject::NoRule, Some(&rule.name), now);
            return Outcome::Rejected(Reject::NoRule);
        };
        self.replay.record(replay_key);
        bump!(self.counters, opened);

        // A successful knock shields its address against trap/scan bans
        // for the ban table's trust TTL (the intruder-protection surface).
        if let Some(bans) = &self.hooks.bans {
            bans.trust_login(plan.addr, now);
        }

        // 8. Firewall window for rules with firewall blocking: open now,
        //    close on a per-rule timer (repeat knocks reschedule it).
        if rule.firewall {
            self.schedule_window(&rule.key, &rule.ports, stored.until, now)
                .await;
        }

        // 9. Log and publish the success.
        let opened = Opened {
            addr: plan.addr,
            rule: rule.key.clone(),
            rule_name: rule.name.clone(),
            identity: plan.identity.clone(),
            user: plan.user.clone(),
            duration_secs: plan.duration_secs,
            until: stored.until,
            via: via.tag(),
            firewall: rule.firewall,
        };
        tracing::info!(
            target: "fg_knock",
            source = %rule.name,
            rule = %rule.key,
            addr = %plan.addr,
            via = via.tag(),
            seconds = plan.duration_secs,
            identity = plan.identity.as_deref().unwrap_or("shared"),
            "敲门验证通过，已放行"
        );
        if let Some(events) = &self.hooks.events {
            events.publish_with(|| {
                let mut event = Event::new(Kind::KnockOpened, "knock");
                event.args = vec![
                    ("rule", rule.name.clone()),
                    ("addr", plan.addr.to_string()),
                    ("via", via.tag().to_owned()),
                ];
                event.fields = vec![(
                    "identity",
                    plan.identity.clone().unwrap_or_else(|| "shared".to_owned()),
                )];
                event
            });
        }
        Outcome::Opened(opened)
    }

    /// Protocol-routing submission entry (`knockgate.submit`): TCP knocks
    /// come through an authenticated channel, so rejections publish
    /// events.
    pub async fn submit(self: &Arc<Self>, packet: &[u8], peer: SocketAddr) -> Outcome {
        self.handle(packet, peer, Via::Tcp).await
    }

    /// One rejected knock: UDP never publishes (spoofable sources, §8);
    /// TCP publishes throttled per source — including pre-authentication
    /// failures, because the TCP channel's source is authenticated. Invalid
    /// packets are additionally counted for the per-minute summary.
    fn reject(
        &self,
        peer: IpAddr,
        via: Via,
        reject: Reject,
        rule_name: Option<&str>,
        now: SystemTime,
    ) {
        if via == Via::Udp {
            // Counted (invalid → summary) and logged, never published.
            if !reject.is_invalid() {
                tracing::warn!(
                    target: "fg_knock",
                    source = rule_name.unwrap_or("knock"),
                    addr = %peer,
                    via = via.tag(),
                    reason = reject.tag(),
                    "敲门被拒绝"
                );
            }
            return;
        }
        if !reject.is_invalid() {
            tracing::warn!(
                target: "fg_knock",
                source = rule_name.unwrap_or("knock"),
                addr = %peer,
                via = via.tag(),
                reason = reject.tag(),
                "敲门被拒绝"
            );
        }
        if !self.allow_failed_event(peer, now) {
            return;
        }
        bump!(self.counters, failed_events);
        if let Some(events) = &self.hooks.events {
            events.publish_with(|| {
                let mut event = Event::new(Kind::KnockFailed, "knock");
                event.args = vec![
                    ("addr", peer.to_string()),
                    ("reason", reject.tag().to_owned()),
                ];
                event.fields = vec![("via", "tcp".to_owned())];
                event
            });
        }
    }

    /// The 5-second per-source throttle for `knock.failed` events.
    fn allow_failed_event(&self, peer: IpAddr, now: SystemTime) -> bool {
        let mut throttle = self.failed_throttle.lock().expect("failed throttle");
        throttle.retain(|_, last| {
            now.duration_since(*last)
                .is_ok_and(|age| age < limits::FAILED_EVENT_THROTTLE)
        });
        if throttle.len() >= limits::FAILED_THROTTLE_MAX {
            throttle.clear();
        }
        throttle.insert(peer, now).is_none()
    }

    /// Counts one pre-authentication failure for the per-minute summary.
    fn record_invalid(&self, peer: IpAddr) {
        let mut window = self.invalid.lock().expect("invalid window");
        window.count += 1;
        window.sources.insert(RateLimiter::source_net(peer));
        if window.started.is_none() {
            window.started = Some(std::time::Instant::now());
        }
    }

    /// Emits the summary once the minute elapsed; the listener loop calls
    /// this periodically and logs the result.
    pub fn take_invalid_summary(&self, now: std::time::Instant) -> Option<InvalidSummary> {
        let mut window = self.invalid.lock().expect("invalid window");
        let started = window.started?;
        if now.saturating_duration_since(started) < limits::FAILED_SUMMARY_INTERVAL {
            return None;
        }
        let summary = InvalidSummary {
            sources: window.sources.len(),
            count: window.count,
        };
        *window = InvalidWindow::default();
        Some(summary)
    }

    /// Opens (or reschedules) the firewall window of one firewall rule.
    async fn schedule_window(
        self: &Arc<Self>,
        rule_key: &str,
        ports: &[Access],
        until: SystemTime,
        now: SystemTime,
    ) {
        let hooks = self.hooks.clone();
        let request = WindowRequest {
            rule: rule_key.to_owned(),
            ports: ports.to_vec(),
        };
        if let Some(open) = &hooks.open_window {
            match open(request).await {
                Ok(()) => tracing::debug!(target: "fg_knock", rule = %rule_key, "已开窗"),
                Err(error) => {
                    tracing::warn!(target: "fg_knock", rule = %rule_key, %error, "开窗失败")
                }
            }
        }
        // Reschedule the close timer: cancel the previous one so the
        // window stays open until the newest grant expires.
        let token = self.root_token.child_token();
        self.timers
            .lock()
            .expect("window timers")
            .insert(rule_key.to_owned(), token.clone());
        let delay = until.duration_since(now).unwrap_or(Duration::ZERO);
        let engine = Arc::clone(self);
        let rule = rule_key.to_owned();
        tokio::spawn(async move {
            tokio::select! {
                _ = token.cancelled() => {}
                _ = tokio::time::sleep(delay) => {
                    close_window(&hooks, &rule).await;
                    engine.timers.lock().expect("window timers").remove(&rule);
                }
            }
        });
    }

    /// Cancels every close timer and closes every open window (shutdown).
    pub async fn shutdown(self: &Arc<Self>) {
        self.root_token.cancel();
        let rules: Vec<String> = self
            .timers
            .lock()
            .expect("window timers")
            .drain()
            .map(|(rule, _)| rule)
            .collect();
        for rule in rules {
            close_window(&self.hooks.clone(), &rule).await;
        }
    }

    /// Counters for the status endpoint.
    pub fn stats(&self, now: SystemTime) -> Stats {
        let load =
            |value: &std::sync::atomic::AtomicU64| value.load(std::sync::atomic::Ordering::Relaxed);
        Stats {
            opened: load(&self.counters.opened),
            rejected: load(&self.counters.rejected),
            invalid: load(&self.counters.invalid),
            ignored: load(&self.counters.ignored),
            rate_limited: load(&self.counters.rate_limited),
            failed_events: load(&self.counters.failed_events),
            grants: self.grants.active_count(now),
            replay_cache: self.replay.len(),
            rate_sources: self.limiter.tracked_sources(),
        }
    }
}

async fn close_window(hooks: &Hooks, rule: &str) {
    let Some(close) = &hooks.close_window else {
        return;
    };
    if let Err(error) = close(rule.to_owned()).await {
        tracing::warn!(target: "fg_knock", rule = %rule, %error, "关窗失败");
    }
}

fn unix_secs(time: SystemTime) -> i64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limit::RateLimiter;
    use crate::replay::ReplayCache;
    use crate::spa::test_support::{b64, sample_message};
    use crate::spa::{Access, Proto};

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn rule() -> CompiledRule {
        CompiledRule {
            key: "r1".into(),
            name: "ssh".into(),
            ports: vec![Access::new(Proto::Tcp, 22)],
            firewall: true,
            timeout: 30,
            max_timeout: 300,
            user: String::new(),
            require_addr: false,
            single_addr: false,
            creds: HashSet::new(),
        }
    }

    fn model_rule() -> crate::model::Rule {
        crate::model::Rule {
            key: "r1".into(),
            name: "ssh".into(),
            ports: vec![Access::new(Proto::Tcp, 22)],
            firewall: true,
            timeout: 30,
            max_timeout: 300,
            ..crate::model::Rule::default()
        }
    }

    fn context<'a>(
        rule: &'a CompiledRule,
        started: SystemTime,
        replay_hit: bool,
    ) -> CheckContext<'a> {
        CheckContext {
            rule,
            max_age: 120,
            peer: "203.0.113.9".parse().unwrap(),
            now: at(1_000_000),
            started,
            replay_hit,
            credential: ("cred1", Some("alice")),
        }
    }

    fn check(
        message: &crate::spa::Message,
        rule: &CompiledRule,
        replay_hit: bool,
    ) -> Result<GrantPlan, Reject> {
        check_message(message, context(rule, at(999_000), replay_hit))
    }

    #[test]
    fn expired_timestamp_rejected() {
        let mut message = sample_message();
        message.timestamp = 999_800; // 200 s old, maxAge 120
        assert_eq!(check(&message, &rule(), false), Err(Reject::Expired));
        // Inside the window (also for a small future skew).
        message.timestamp = 999_900;
        assert!(check(&message, &rule(), false).is_ok());
        message.timestamp = 1_000_100;
        assert!(check(&message, &rule(), false).is_ok());
        message.timestamp = 1_000_121;
        assert_eq!(check(&message, &rule(), false), Err(Reject::Expired));
    }

    #[test]
    fn timestamp_before_start_rejected_engine() {
        let mut message = sample_message();
        // Inside the 120 s window but before this process started.
        message.timestamp = 999_950;
        assert_eq!(
            check_message(&message, context(&rule(), at(999_990), false)),
            Err(Reject::BeforeStart)
        );
        // The shared helper's start (999_000) accepts the same packet.
        assert!(check(&message, &rule(), false).is_ok());
    }

    #[test]
    fn replay_rejected_by_engine_check() {
        let mut message = sample_message();
        message.timestamp = 1_000_000;
        assert!(check(&message, &rule(), false).is_ok());
        assert_eq!(check(&message, &rule(), true), Err(Reject::Replay));
    }

    #[test]
    fn port_not_in_rule_rejects_whole_knock() {
        let mut message = sample_message();
        message.timestamp = 1_000_000;
        message.access = vec![Access::new(Proto::Tcp, 22), Access::new(Proto::Udp, 8080)];
        assert_eq!(check(&message, &rule(), false), Err(Reject::PortNotAllowed));
        message.access = vec![Access::new(Proto::Tcp, 22)];
        assert!(check(&message, &rule(), false).is_ok());
    }

    #[test]
    fn username_must_match_when_configured() {
        let mut pinned = rule();
        pinned.user = "alice".into();
        let mut message = sample_message();
        message.timestamp = 1_000_000;
        message.user = "bob".into();
        assert_eq!(check(&message, &pinned, false), Err(Reject::UserMismatch));
        message.user = "alice".into();
        let plan = check(&message, &pinned, false).unwrap();
        assert_eq!(plan.user.as_deref(), Some("alice"));
    }

    #[test]
    fn require_addr_rejects_source_address_knocks() {
        let mut pinned = rule();
        pinned.require_addr = true;
        let mut message = sample_message(); // addr: None (-s)
        message.timestamp = 1_000_000;
        assert_eq!(check(&message, &pinned, false), Err(Reject::AddrRequired));
        message.addr = Some("203.0.113.9".parse().unwrap());
        assert!(check(&message, &pinned, false).is_ok());
    }

    #[test]
    fn plan_uses_source_address_when_unset() {
        let mut message = sample_message();
        message.timestamp = 1_000_000;
        let plan = check(&message, &rule(), false).unwrap();
        assert_eq!(plan.addr.to_string(), "203.0.113.9");
        assert_eq!(plan.identity.as_deref(), Some("alice"));
        assert_eq!(plan.cred, "cred1");
    }

    #[test]
    fn grant_uses_requested_or_client_timeout() {
        // Default: the rule's 30 s.
        assert_eq!(effective_timeout(30, 300, None), 30);
        // `-f 600` caps at maxTimeout 300.
        assert_eq!(effective_timeout(30, 300, Some(600)), 300);
        // `-f 10` shorter than the rule timeout is honored.
        assert_eq!(effective_timeout(30, 300, Some(10)), 10);
        // maxTimeout 0 ignores client requests entirely.
        assert_eq!(effective_timeout(30, 0, Some(600)), 30);
    }

    #[test]
    fn edit_rule_revokes_knock_grants_only_pure() {
        let old = model_rule();
        // Only name / remark / single-address change → stale revocation.
        let mut cosmetic = old.clone();
        cosmetic.name = "ssh2".into();
        assert_eq!(revokes_on_edit(&old, &cosmetic), Revoke::Stale);
        cosmetic = old.clone();
        cosmetic.single_addr = true;
        assert_eq!(revokes_on_edit(&old, &cosmetic), Revoke::Stale);
        // Ports / firewall / timeout / user / requireAddr → everything.
        let mut changed = old.clone();
        changed.ports = vec![Access::new(Proto::Udp, 53)];
        assert_eq!(revokes_on_edit(&old, &changed), Revoke::All);
        changed = old.clone();
        changed.firewall = false;
        assert_eq!(revokes_on_edit(&old, &changed), Revoke::All);
        changed = old.clone();
        changed.timeout = 60;
        assert_eq!(revokes_on_edit(&old, &changed), Revoke::All);
        changed = old.clone();
        changed.user = "alice".into();
        assert_eq!(revokes_on_edit(&old, &changed), Revoke::All);
        changed = old.clone();
        changed.require_addr = true;
        assert_eq!(revokes_on_edit(&old, &changed), Revoke::All);
    }

    #[test]
    fn identity_identified_by_key() {
        let key16 = b64(&[7u8; 16]);
        let key32 = b64(&[9u8; 32]);
        let config = FileConfig {
            settings: Settings::default(),
            rules: vec![Rule {
                key: "r1".into(),
                name: "ssh".into(),
                enable: true,
                ports: vec![Access::new(Proto::Tcp, 22)],
                enc_key: key16.clone(),
                hmac_key: key32.clone(),
                identities: vec![crate::model::Identity {
                    id: "alice".into(),
                    name: "Alice".into(),
                    enable: true,
                    enc_key: b64(&[11u8; 16]),
                    hmac_key: b64(&[13u8; 32]),
                    ..crate::model::Identity::default()
                }],
                ..Rule::default()
            }],
        };
        let compiled = Compiled::build(&config);
        assert_eq!(compiled.keys.len(), 2, "shared key + identity");
        // The shared key maps to no identity.
        let shared = crate::spa::Key::from_base64(&key16, &key32, crate::spa::HmacType::Sha256)
            .expect("valid keys");
        let packet = crate::spa::encode(&sample_message(), &shared, &[5u8; 16]).unwrap();
        let (index, _) = compiled.keys.decode(&packet).unwrap();
        assert!(compiled.keys.entries()[index].identity.is_none());
        assert_eq!(compiled.keys.entries()[index].rule, "r1");
        // The identity key identifies Alice: rebuild the Key from the
        // compiled entry's raw material.
        let entry = &compiled.keys.entries()[1];
        let alice = crate::spa::Key {
            enc: entry.key.enc.clone(),
            hmac: entry.key.hmac.clone(),
            hmac_type: crate::spa::HmacType::Sha256,
        };
        let packet = crate::spa::encode(&sample_message(), &alice, &[6u8; 16]).unwrap();
        let (index, _) = compiled.keys.decode(&packet).unwrap();
        assert_eq!(
            compiled.keys.entries()[index].identity.as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn compiled_snapshot_filters_disabled_rules() {
        let mut config = FileConfig::default();
        config.rules.push(Rule {
            key: "off".into(),
            enable: false,
            name: "off".into(),
            enc_key: b64(&[7u8; 16]),
            hmac_key: b64(&[9u8; 32]),
            ..Rule::default()
        });
        let compiled = Compiled::build(&config);
        assert!(compiled.keys.is_empty());
        assert!(compiled.rules.is_empty());
    }

    #[test]
    fn engine_uses_injected_clock_for_grants() {
        let fixed = at(1_700_000_000);
        let clock: Clock = Arc::new(move || fixed);
        let engine = Engine::new(
            Arc::new(Grants::new()),
            ReplayCache::new(fixed),
            RateLimiter::new(),
            Hooks::default(),
            clock,
        );
        assert_eq!(engine.started(), fixed);
        assert_eq!(engine.stats(fixed).opened, 0);
    }
}
