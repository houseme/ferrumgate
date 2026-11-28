//! Jails (WP-52): the generic "window count → threshold → ban" engine and
//! the `<HOST>` filter semantics. Sources feed matches into
//! [`JailEngine::on_line`] (log lines), [`JailEngine::on_event`] (WP-16
//! events), and the web probe calls ([`JailEngine::on_web_hit`] /
//! [`JailEngine::on_tls_fail`], see [`crate::webprobe`]); the engine
//! counts per source inside the rule's `findTime` window and registers
//! automatic bans through the shared service with the `jail:<key>`
//! source, so the WP-51 firewall mirror picks them up like every other
//! ban.

pub mod command_source;
pub mod count;
pub mod docker_source;
pub mod event_source;
pub mod file_source;
pub mod journal;
pub mod model;
pub mod tail;
pub mod validate;

use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::Result;
use arc_swap::ArcSwap;
use fg_net::banlist::{BanKey, BanOutcome, Source, default_whitelist};
use ipnet::IpNet;
use regex::Regex;

use crate::bans::GuardService;
use crate::model::{FileConfig, Settings};
use crate::webprobe::{PathRule, TlsFail, TlsFailKind, path_rule, rule_match, tls as tls_probe};

pub use count::{Hit, WindowCounter};
pub use model::{Jail, MAX_TRACKED, Source as JailSource};

/// The injectable clock: jails compare hits against the wall clock, tests
/// replace it.
pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// The source address placeholder in filter lines.
pub const HOST_PLACEHOLDER: &str = "<HOST>";

/// Matches IPv4, bracketed IPv6, bare IPv6 and IPv4-mapped forms
/// (`::ffff:1.2.3.4`). Every candidate is parsed and canonicalized
/// before it counts, so a capture that does not parse never bans.
const HOST_PATTERN: &str = r"(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:.]{2,46}\]|(?:[0-9A-Fa-f]{0,4}:){1,7}\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){1,7})";

/// Splits a multi-line jail field into trimmed, non-empty lines.
pub fn split_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// One compiled filter line: the regex with every `<HOST>` replaced by a
/// named capture group over the host pattern.
#[derive(Clone, Debug)]
pub struct LineMatcher {
    regex: Regex,
    host_groups: Vec<usize>,
}

impl LineMatcher {
    /// Whether the line matches at all (ignore rules use plain regexes
    /// instead).
    pub fn is_match(&self, line: &str) -> bool {
        self.regex.is_match(line)
    }

    /// The first captured address that parses and canonicalizes; a line
    /// whose host capture does not parse is not counted.
    pub fn match_host(&self, line: &str) -> Option<IpAddr> {
        let captures = self.regex.captures(line)?;
        for index in &self.host_groups {
            if let Some(matched) = captures.get(*index)
                && let Some(ip) = parse_host(matched.as_str())
            {
                return Some(ip);
            }
        }
        None
    }
}

/// Compiles one filter line. Lines without `<HOST>` compile too (the
/// validation rejects them for log jails); every occurrence becomes one
/// named capture group.
pub fn compile_line(line: &str) -> Result<LineMatcher, Vec<String>> {
    let occurrences = line.matches(HOST_PLACEHOLDER).count();
    let mut pattern = String::with_capacity(line.len() + occurrences * 64);
    let mut rest = line;
    let mut built = 0;
    while let Some(position) = rest.find(HOST_PLACEHOLDER) {
        pattern.push_str(&rest[..position]);
        pattern.push_str(&format!("(?P<host_{built}>{HOST_PATTERN})"));
        built += 1;
        rest = &rest[position + HOST_PLACEHOLDER.len()..];
    }
    pattern.push_str(rest);
    let regex = Regex::new(&pattern).map_err(|error| vec![error.to_string()])?;
    let host_groups = regex
        .capture_names()
        .enumerate()
        .filter(|(_, name)| name.is_some_and(|name| name.starts_with("host_")))
        .map(|(index, _)| index)
        .collect();
    Ok(LineMatcher { regex, host_groups })
}

/// Compiles every filter line of a log jail.
pub fn compile_filter(filter: &str) -> Result<Vec<LineMatcher>, Vec<String>> {
    let mut matchers = Vec::new();
    let mut errors = Vec::new();
    for line in split_lines(filter) {
        match compile_line(&line) {
            Ok(matcher) => matchers.push(matcher),
            Err(mut line_errors) => errors.append(&mut line_errors),
        }
    }
    if errors.is_empty() {
        Ok(matchers)
    } else {
        Err(errors)
    }
}

/// Compiles the ignore lines (plain regexes, no `<HOST>` semantics).
pub fn compile_ignore(ignore: &str) -> Result<Vec<Regex>, Vec<String>> {
    let mut regexes = Vec::new();
    let mut errors = Vec::new();
    for line in split_lines(ignore) {
        match Regex::new(&line) {
            Ok(regex) => regexes.push(regex),
            Err(error) => errors.push(error.to_string()),
        }
    }
    if errors.is_empty() {
        Ok(regexes)
    } else {
        Err(errors)
    }
}

/// Parses and canonicalizes a captured host text: brackets stripped,
/// IPv4-mapped IPv6 collapsed to IPv4.
pub fn parse_host(text: &str) -> Option<IpAddr> {
    let trimmed = text.trim().trim_start_matches('[').trim_end_matches(']');
    trimmed.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

/// Never auto-banned sources: the shared whitelist (internal ranges, the
/// user's `ignoreList`) plus, when `ignorePrivate` is on, every private,
/// loopback or link-local address. Published with the snapshot so the
/// hot path reads it lock-free.
#[derive(Clone, Debug, Default)]
pub struct IgnoreSet {
    nets: Vec<IpNet>,
    ignore_private: bool,
}

impl IgnoreSet {
    pub fn from_settings(settings: &Settings) -> Self {
        let mut nets = default_whitelist();
        for entry in &settings.ignore_list {
            if let Some(net) = crate::validate::parse_net(entry) {
                nets.push(net);
            }
        }
        Self {
            nets,
            ignore_private: settings.ignore_private,
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        if self.ignore_private && is_private(ip) {
            return true;
        }
        self.nets.iter().any(|net| net.contains(&ip))
    }
}

/// The private / loopback / link-local check, mirroring the table's
/// `ignorePrivate` semantics.
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

/// A compiled, enabled log / event jail with its live window counter.
pub struct CompiledLog {
    jail: Jail,
    /// Log sources match lines; event jails have no matchers.
    matchers: Vec<LineMatcher>,
    ignores: Vec<Regex>,
    counter: WindowCounter,
}

impl CompiledLog {
    /// Whether the line hits the rule: no ignore line matched and one
    /// filter line extracted a source address.
    fn match_line(&self, line: &str) -> Option<IpAddr> {
        if self.ignores.iter().any(|regex| regex.is_match(line)) {
            return None;
        }
        self.matchers
            .iter()
            .find_map(|matcher| matcher.match_host(line))
    }
}

/// A compiled, enabled web jail.
pub struct CompiledWeb {
    jail: Jail,
    rules: Vec<PathRule>,
    ignores: Vec<PathRule>,
    counter: WindowCounter,
}

/// A compiled, enabled TLS jail.
pub struct CompiledTls {
    jail: Jail,
    kinds: Vec<TlsFailKind>,
    counter: WindowCounter,
}

/// The immutable rules snapshot: replaced as a whole on every save; the
/// hot paths load it once and never take the configuration lock.
pub struct Snapshot {
    log_index: HashMap<String, usize>,
    /// Event jails grouped by their target kind name.
    event_index: HashMap<String, Vec<usize>>,
    log_jails: Vec<CompiledLog>,
    web_jails: Vec<CompiledWeb>,
    tls_jails: Vec<CompiledTls>,
    ignore: IgnoreSet,
}

impl Snapshot {
    /// An empty snapshot (no rules, default ignore set).
    pub fn empty(settings: &Settings) -> Self {
        Self {
            log_index: HashMap::new(),
            event_index: HashMap::new(),
            log_jails: Vec::new(),
            web_jails: Vec::new(),
            tls_jails: Vec::new(),
            ignore: IgnoreSet::from_settings(settings),
        }
    }
}

/// Live counters for status pages and tests.
#[derive(Debug, Default)]
pub struct JailStats {
    /// Automatic bans landed by any jail.
    pub bans: AtomicU64,
    /// Log lines that counted.
    pub lines_matched: AtomicU64,
    /// Events that counted.
    pub events_matched: AtomicU64,
}

/// One running source task identity: restarting only happens when the
/// source itself (kind, target) changes — filter edits are picked up by
/// the next snapshot without restarting the reader.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TaskKey {
    jail: String,
    kind: &'static str,
    spec: String,
}

/// The jail engine: owns the compiled snapshot, the source tasks and the
/// event subscription. Cheap to share (`Arc`), hot paths take no locks
/// beyond the snapshot load and the per-rule counters of matched hits.
pub struct JailEngine {
    service: Arc<GuardService>,
    snapshot: ArcSwap<Snapshot>,
    clock: Clock,
    stats: JailStats,
    tasks: Mutex<HashMap<TaskKey, tokio::task::AbortHandle>>,
    fileauth_seen: Mutex<BTreeMap<(String, BanKey), SystemTime>>,
    docker: Mutex<Option<Arc<dyn docker_source::DockerFollow>>>,
    subscription: Mutex<Option<fg_core::events::Subscription>>,
}

impl JailEngine {
    /// Creates an engine over the shared ban service. Rules arrive via
    /// [`JailEngine::reload`]; source tasks start with
    /// [`JailEngine::reconcile_sources`], the event subscription with
    /// [`event_source::attach`].
    pub fn new(service: Arc<GuardService>, clock: Clock) -> Self {
        let snapshot = Snapshot::empty(&service.settings());
        Self {
            service,
            snapshot: ArcSwap::from_pointee(snapshot),
            clock,
            stats: JailStats::default(),
            tasks: Mutex::new(HashMap::new()),
            fileauth_seen: Mutex::new(BTreeMap::new()),
            docker: Mutex::new(None),
            subscription: Mutex::new(None),
        }
    }

    pub fn stats(&self) -> &JailStats {
        &self.stats
    }

    pub fn clock(&self) -> SystemTime {
        (self.clock)()
    }

    /// The shared ban service (the assembly layer re-exports the table
    /// for `is_banned` consumers).
    pub fn service(&self) -> &Arc<GuardService> {
        &self.service
    }

    /// Installs the docker follow handle (WP-60 provides the
    /// implementation). Without one, `docker` jails are refused at save
    /// time.
    pub fn set_docker(&self, follow: Option<Arc<dyn docker_source::DockerFollow>>) {
        *self.docker.lock().expect("guard docker slot") = follow;
    }

    pub fn docker(&self) -> Option<Arc<dyn docker_source::DockerFollow>> {
        self.docker.lock().expect("guard docker slot").clone()
    }

    /// Holds the event-bus subscription alive (dropping the engine
    /// unregisters it).
    pub fn set_subscription(&self, subscription: fg_core::events::Subscription) {
        *self.subscription.lock().expect("guard subscription") = Some(subscription);
    }

    /// Compiles every enabled jail and publishes the snapshot as a whole.
    /// Compile problems (they should have been caught by validation) skip
    /// the affected jail and log a warning — the engine never runs a
    /// half-compiled rule.
    pub fn reload(&self, config: &FileConfig) -> Result<()> {
        let mut snapshot = Snapshot::empty(&config.settings);
        for raw in &config.jails {
            let jail = validate::normalize_jail(raw.clone());
            if !jail.enable {
                continue;
            }
            let window = Duration::from_secs(u64::from(jail.window()));
            let counter = WindowCounter::new(jail.retries(), window);
            match jail.source {
                JailSource::File
                | JailSource::Journal
                | JailSource::Command
                | JailSource::Docker => {
                    let (Some(matchers), Ok(ignores)) = (
                        compile_filter(&jail.filter).ok(),
                        compile_ignore(&jail.ignore),
                    ) else {
                        tracing::warn!(
                            module = "guard",
                            jail = %jail.key,
                            "jail filter or ignore failed to compile; rule disabled"
                        );
                        continue;
                    };
                    let index = snapshot.log_jails.len();
                    snapshot.log_index.insert(jail.key.clone(), index);
                    snapshot.log_jails.push(CompiledLog {
                        counter,
                        matchers,
                        ignores,
                        jail,
                    });
                }
                JailSource::Event => {
                    let ignores = compile_ignore(&jail.ignore).unwrap_or_default();
                    let index = snapshot.log_jails.len();
                    snapshot
                        .event_index
                        .entry(jail.target.clone())
                        .or_default()
                        .push(index);
                    snapshot.log_jails.push(CompiledLog {
                        counter,
                        matchers: Vec::new(),
                        ignores,
                        jail,
                    });
                }
                JailSource::Web => {
                    let (Ok(rules), Ok(ignores)) = (
                        path_rule::compile_paths(&jail.filter),
                        path_rule::compile_paths(&jail.ignore),
                    ) else {
                        tracing::warn!(module = "guard", jail = %jail.key, "jail path rules failed to compile; rule disabled");
                        continue;
                    };
                    snapshot.web_jails.push(CompiledWeb {
                        counter,
                        rules,
                        ignores,
                        jail,
                    });
                }
                JailSource::Tls => {
                    let kinds = split_lines(&jail.filter)
                        .into_iter()
                        .filter_map(|line| TlsFailKind::from_tag(&line))
                        .collect();
                    snapshot.tls_jails.push(CompiledTls {
                        counter,
                        kinds,
                        jail,
                    });
                }
            }
        }
        self.snapshot.store(Arc::new(snapshot));
        Ok(())
    }

    /// Aligns the running source tasks with the snapshot: file, journal,
    /// command and docker jails get one reader task per target line;
    /// removed, disabled or retargeted jails are stopped.
    pub fn reconcile_sources(self: &Arc<Self>) {
        let mut desired: HashMap<TaskKey, ()> = HashMap::new();
        let snapshot = self.snapshot.load();
        for compiled in &snapshot.log_jails {
            let jail = &compiled.jail;
            match jail.source {
                JailSource::File => {
                    for path in split_lines(&jail.target) {
                        desired.insert(
                            TaskKey {
                                jail: jail.key.clone(),
                                kind: "file",
                                spec: path,
                            },
                            (),
                        );
                    }
                }
                JailSource::Journal => {
                    desired.insert(
                        TaskKey {
                            jail: jail.key.clone(),
                            kind: "journal",
                            spec: split_lines(&jail.target).join("\n"),
                        },
                        (),
                    );
                }
                JailSource::Command => {
                    desired.insert(
                        TaskKey {
                            jail: jail.key.clone(),
                            kind: "command",
                            spec: jail.target.clone(),
                        },
                        (),
                    );
                }
                JailSource::Docker => {
                    for container in split_lines(&jail.target) {
                        desired.insert(
                            TaskKey {
                                jail: jail.key.clone(),
                                kind: "docker",
                                spec: container,
                            },
                            (),
                        );
                    }
                }
                JailSource::Event | JailSource::Web | JailSource::Tls => {}
            }
        }
        drop(snapshot);
        let mut tasks = self.tasks.lock().expect("guard jail tasks");
        tasks.retain(|key, handle| {
            if desired.contains_key(key) {
                true
            } else {
                handle.abort();
                tracing::info!(module = "guard", jail = %key.jail, source = key.kind, "jail source stopped");
                false
            }
        });
        for key in desired.into_keys() {
            if tasks.contains_key(&key) {
                continue;
            }
            let handle = match key.kind {
                "file" => file_source::spawn(Arc::clone(self), &key.jail, &key.spec),
                "journal" => journal::spawn(Arc::clone(self), &key.jail, &key.spec),
                "command" => command_source::spawn(Arc::clone(self), &key.jail, &key.spec),
                "docker" => match self.docker() {
                    Some(follow) => {
                        docker_source::spawn(Arc::clone(self), &key.jail, &key.spec, follow)
                    }
                    None => {
                        tracing::warn!(module = "guard", jail = %key.jail, "docker module not included; jail stays idle");
                        continue;
                    }
                },
                _ => continue,
            };
            tracing::info!(module = "guard", jail = %key.jail, source = key.kind, "jail source started");
            tasks.insert(key, handle);
        }
    }

    /// Stops every source task (shutdown path).
    pub fn stop_sources(&self) {
        let mut tasks = self.tasks.lock().expect("guard jail tasks");
        for (_, handle) in tasks.drain() {
            handle.abort();
        }
    }

    /// One log line from a file / journal / command / docker source.
    pub fn on_line(&self, jail_key: &str, line: &str) {
        let snapshot = self.snapshot.load();
        let Some(&index) = snapshot.log_index.get(jail_key) else {
            return;
        };
        let compiled = &snapshot.log_jails[index];
        let Some(ip) = compiled.match_line(line) else {
            return;
        };
        self.count_hit(
            &compiled.jail,
            &compiled.counter,
            ip,
            line_reason(line),
            &snapshot.ignore,
        );
    }

    /// One published event. Event jails match by their target kind; the
    /// event carries the source address itself (no filter involved).
    pub fn on_event(&self, kind: &str, ip: IpAddr, at: SystemTime) {
        let snapshot = self.snapshot.load();
        let Some(indices) = snapshot.event_index.get(kind) else {
            return;
        };
        for index in indices {
            let compiled = &snapshot.log_jails[*index];
            if compiled.ignores.iter().any(|regex| regex.is_match(kind)) {
                continue;
            }
            // File-service logins: the same source counts at most once
            // per 5 seconds (clients retrying bad passwords in parallel
            // stay one offense). The publishers guarantee this for their
            // own events; the engine enforces it defensively.
            if compiled.jail.target == "fileauth.failed"
                && !self.fileauth_allow(&compiled.jail.key, ip, at)
            {
                continue;
            }
            self.count_hit(
                &compiled.jail,
                &compiled.counter,
                ip,
                format!("{} ({kind})", compiled.jail.name),
                &snapshot.ignore,
            );
        }
    }

    /// One finished web request (hot path: one snapshot load, no locks
    /// for non-matching probes).
    pub fn on_web_hit(&self, request: &rule_match::WebRequestSummary<'_>) {
        let snapshot = self.snapshot.load();
        if snapshot.web_jails.is_empty() {
            return;
        }
        for compiled in &snapshot.web_jails {
            let jail = &compiled.jail;
            if !rule_match::web_jail_counts(
                &jail.target,
                &compiled.rules,
                &compiled.ignores,
                jail.any_status,
                jail.unknown_host,
                request,
            ) {
                continue;
            }
            self.count_hit(
                jail,
                &compiled.counter,
                request.ip,
                format!("{} ({})", jail.name, request.path),
                &snapshot.ignore,
            );
        }
    }

    /// One TLS handshake failure.
    pub fn on_tls_fail(&self, fail: &TlsFail<'_>) {
        let snapshot = self.snapshot.load();
        if snapshot.tls_jails.is_empty() {
            return;
        }
        for compiled in &snapshot.tls_jails {
            let jail = &compiled.jail;
            if !tls_probe::tls_jail_counts(
                &jail.target,
                &compiled.kinds,
                fail,
                snapshot.ignore.contains(fail.ip),
                self.service.is_banned(fail.ip),
            ) {
                continue;
            }
            self.count_hit(
                jail,
                &compiled.counter,
                fail.ip,
                format!("{} ({}: {})", jail.name, fail.kind.tag(), fail.reason),
                &snapshot.ignore,
            );
        }
    }

    /// The fileauth 5-second per-source dedup; expired entries are
    /// dropped as the map grows.
    fn fileauth_allow(&self, jail_key: &str, ip: IpAddr, at: SystemTime) -> bool {
        const WINDOW: Duration = Duration::from_secs(5);
        const CAP: usize = 32768;
        let key = (jail_key.to_owned(), BanKey::from_ip(ip));
        let mut seen = self.fileauth_seen.lock().expect("guard fileauth dedup");
        if seen.len() >= CAP {
            seen.retain(|_, last| at.duration_since(*last).is_ok_and(|age| age <= WINDOW));
            if seen.len() >= CAP {
                seen.clear();
            }
        }
        let allowed = seen
            .get(&key)
            .is_none_or(|last| at.duration_since(*last).is_ok_and(|age| age > WINDOW));
        if allowed {
            seen.insert(key, at);
        }
        allowed
    }

    /// Counts one match and bans when the window threshold is reached.
    /// Whitelisted, ignore-private and already banned addresses never
    /// accumulate.
    fn count_hit(
        &self,
        jail: &Jail,
        counter: &WindowCounter,
        ip: IpAddr,
        reason: String,
        ignore: &IgnoreSet,
    ) {
        let ip = ip.to_canonical();
        if ignore.contains(ip) || self.service.is_banned(ip) {
            return;
        }
        let outcome = counter.hit(ip, self.clock());
        if matches!(outcome, Hit::Counted(_) | Hit::Triggered) {
            if jail.source.is_log() {
                self.stats.lines_matched.fetch_add(1, Ordering::Relaxed);
            } else if matches!(jail.source, JailSource::Event) {
                self.stats.events_matched.fetch_add(1, Ordering::Relaxed);
            }
        }
        if matches!(outcome, Hit::Triggered) {
            self.ban(jail, ip, reason);
        }
    }

    /// Registers the automatic ban: `banTime` 0 uses the module default,
    /// -1 is permanent, a positive value carries its own seconds; the
    /// source is always `jail:<key>`.
    fn ban(&self, jail: &Jail, ip: IpAddr, reason: String) {
        let (duration, permanent) = validate::ban_duration(jail.ban_time);
        let outcome = self.service.ban_auto(
            ip,
            duration,
            permanent,
            Source::Jail(jail.key.clone()),
            reason,
            self.clock(),
        );
        if matches!(outcome, BanOutcome::Banned { .. }) {
            self.stats.bans.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Trims a log line for a ban reason and keeps it on one line, bounded.
fn line_reason(line: &str) -> String {
    const MAX_REASON_BYTES: usize = 200;
    let flat: String = line
        .trim()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    flat.chars().take(MAX_REASON_BYTES).collect()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::model::Settings;
    use fg_core::events::EventBus;
    use fg_net::banlist::system_clock;

    fn engine() -> Arc<JailEngine> {
        let service = GuardService::open_memory(&Settings::default(), EventBus::default());
        Arc::new(JailEngine::new(service, system_clock()))
    }

    fn file_jail(filter: &str, ignore: &str, retries: u32) -> Jail {
        validate::normalize_jail(Jail {
            key: "aabbccddeeff".to_owned(),
            name: "ssh".to_owned(),
            enable: true,
            source: JailSource::File,
            target: "/var/log/auth.log".to_owned(),
            filter: filter.to_owned(),
            ignore: ignore.to_owned(),
            max_retry: retries,
            find_time: 600,
            ban_time: 0,
            ..Jail::default()
        })
    }

    fn config_with(jails: Vec<Jail>) -> FileConfig {
        FileConfig {
            settings: Settings::default(),
            jails,
        }
    }

    #[test]
    fn filter_extracts_v4_v6_bracketed_mapped() {
        let matcher = compile_line("Failed password for .* from <HOST> port").expect("compile");
        assert_eq!(
            matcher.match_host("Failed password for root from 203.0.113.4 port 22 ssh2"),
            Some("203.0.113.4".parse().unwrap())
        );
        assert_eq!(
            matcher.match_host("Failed password for x from 2001:db8::1 port 22 ssh2"),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            matcher.match_host("Failed password for x from [2001:db8::2] port 22 ssh2"),
            Some("2001:db8::2".parse().unwrap())
        );
        assert_eq!(
            matcher.match_host("Failed password for x from ::ffff:203.0.113.5 port 22"),
            Some("203.0.113.5".parse().unwrap()),
            "mapped addresses collapse to IPv4"
        );
        assert_eq!(
            matcher.match_host("Failed password for root from nowhere port 22"),
            None,
            "unparseable captures never count"
        );
        assert!(!matcher.is_match("session opened for user root"));
    }

    #[test]
    fn filter_supports_multiple_hosts_and_ignores() {
        let matcher = compile_line("<HOST> -> <HOST>").expect("compile");
        assert_eq!(
            matcher.match_host("203.0.113.1 -> 203.0.113.2"),
            Some("203.0.113.1".parse().unwrap()),
            "the first parseable capture wins"
        );
        let ignore = compile_ignore(".* healthcheck\nnoisy .*").expect("compile");
        assert!(
            ignore
                .iter()
                .any(|re| re.is_match("192.0.2.1 healthcheck ok"))
        );
        assert!(ignore.iter().any(|re| re.is_match("noisy probe")));
    }

    #[tokio::test]
    async fn ignore_rules_skip_lines() {
        let engine = engine();
        let jail = file_jail("Failed password for .* from <HOST>", "healthcheck .*", 2);
        engine.reload(&config_with(vec![jail])).expect("reload");
        engine.on_line(
            "aabbccddeeff",
            "healthcheck Failed password for a from 198.51.100.9",
        );
        engine.on_line("aabbccddeeff", "Failed password for a from 198.51.100.9");
        let bans = engine.service().list(&fg_net::banlist::BanFilter {
            source: Some("jail:aabbccddeeff".to_owned()),
            ..Default::default()
        });
        assert_eq!(bans.len(), 0, "first counted hit only (threshold 2)");
        engine.on_line("aabbccddeeff", "Failed password for a from 198.51.100.9");
        let bans = engine.service().list(&fg_net::banlist::BanFilter {
            source: Some("jail:aabbccddeeff".to_owned()),
            ..Default::default()
        });
        assert_eq!(bans.len(), 1, "threshold reached");
        assert_eq!(bans[0].source.to_tag(), "jail:aabbccddeeff");
        assert_eq!(
            bans[0].key.to_string(),
            "198.51.100.9",
            "IPv4 bans carry the bare address"
        );
    }

    #[tokio::test]
    async fn engine_counts_within_window_and_bans() {
        let engine = engine();
        let jail = file_jail("from <HOST>", "", 3);
        engine.reload(&config_with(vec![jail])).expect("reload");
        for _ in 0..2 {
            engine.on_line("aabbccddeeff", "bad from 198.51.100.4");
        }
        assert!(!engine.service().is_banned("198.51.100.4".parse().unwrap()));
        engine.on_line("aabbccddeeff", "bad from 198.51.100.4");
        assert!(engine.service().is_banned("198.51.100.4".parse().unwrap()));
        assert_eq!(engine.stats().bans.load(Ordering::SeqCst), 1);
        assert_eq!(engine.stats().lines_matched.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn engine_skips_whitelisted_private_and_banned_sources() {
        let engine = engine();
        let settings = Settings {
            ignore_list: vec!["198.51.100.0/24".to_owned()],
            ignore_private: true,
            ..Settings::default()
        };
        let jail = file_jail("from <HOST>", "", 1);
        let config = FileConfig {
            settings,
            jails: vec![jail],
        };
        engine.reload(&config).expect("reload");
        // The user's ignoreList never counts.
        engine.on_line("aabbccddeeff", "from 198.51.100.7");
        assert!(!engine.service().is_banned("198.51.100.7".parse().unwrap()));
        // Private sources never count when ignorePrivate is on.
        engine.on_line("aabbccddeeff", "from 192.168.1.5");
        assert!(!engine.service().is_banned("192.168.1.5".parse().unwrap()));
        // A real ban stops further accumulation for that address.
        engine.on_line("aabbccddeeff", "from 203.0.113.99");
        assert!(engine.service().is_banned("203.0.113.99".parse().unwrap()));
        let bans = engine.stats().bans.load(Ordering::SeqCst);
        engine.on_line("aabbccddeeff", "from 203.0.113.99");
        assert_eq!(engine.stats().bans.load(Ordering::SeqCst), bans);
    }

    #[tokio::test]
    async fn engine_ban_time_semantics_apply() {
        // A custom banTime carries its own duration; -1 is permanent.
        let engine = engine();
        let temporary = file_jail("from <HOST>", "", 1);
        let permanent = validate::normalize_jail(Jail {
            key: "bbccddeeffaa".to_owned(),
            name: "perm".to_owned(),
            enable: true,
            source: JailSource::File,
            target: "/var/log/auth.log".to_owned(),
            filter: "from <HOST>".to_owned(),
            max_retry: 1,
            ban_time: -1,
            ..Jail::default()
        });
        engine
            .reload(&config_with(vec![temporary, permanent]))
            .expect("reload");
        engine.on_line("aabbccddeeff", "from 203.0.113.10");
        engine.on_line("bbccddeeffaa", "from 203.0.113.11");
        let banned = engine.service().list(&Default::default());
        let temp = banned
            .iter()
            .find(|entry| entry.key.to_string() == "203.0.113.10")
            .expect("temporary ban");
        let perm = banned
            .iter()
            .find(|entry| entry.key.to_string() == "203.0.113.11")
            .expect("permanent ban");
        assert!(temp.until.is_some());
        assert_eq!(perm.until, None);
    }

    #[tokio::test]
    async fn engine_events_ban_by_kind() {
        let engine = engine();
        let jail = validate::normalize_jail(Jail {
            key: "cceeffaabbcc".to_owned(),
            name: "admin".to_owned(),
            enable: true,
            source: JailSource::Event,
            target: "auth.failed".to_owned(),
            max_retry: 3,
            ..Jail::default()
        });
        engine.reload(&config_with(vec![jail])).expect("reload");
        let at = || SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        for _ in 0..2 {
            engine.on_event("auth.failed", "203.0.113.20".parse().unwrap(), at());
        }
        assert!(!engine.service().is_banned("203.0.113.20".parse().unwrap()));
        engine.on_event("auth.failed", "203.0.113.20".parse().unwrap(), at());
        assert!(engine.service().is_banned("203.0.113.20".parse().unwrap()));
        assert_eq!(engine.stats().events_matched.load(Ordering::SeqCst), 3);
        // Other kinds do not feed this jail.
        engine.on_event("waf.blocked", "203.0.113.21".parse().unwrap(), at());
        assert!(!engine.service().is_banned("203.0.113.21".parse().unwrap()));
    }

    #[tokio::test]
    async fn engine_fileauth_dedups_per_five_seconds() {
        let engine = engine();
        let jail = validate::normalize_jail(Jail {
            key: "ddeeffaabbcc".to_owned(),
            name: "files".to_owned(),
            enable: true,
            source: JailSource::Event,
            target: "fileauth.failed".to_owned(),
            max_retry: 3,
            ..Jail::default()
        });
        engine.reload(&config_with(vec![jail])).expect("reload");
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(5000);
        let ip: IpAddr = Ipv4Addr::new(203, 0, 113, 30).into();
        for _ in 0..3 {
            engine.on_event("fileauth.failed", ip, t0);
        }
        assert!(
            !engine.service().is_banned(ip),
            "parallel retries within 5 s count once"
        );
        engine.on_event("fileauth.failed", ip, t0 + Duration::from_secs(6));
        engine.on_event("fileauth.failed", ip, t0 + Duration::from_secs(12));
        assert!(
            engine.service().is_banned(ip),
            "bursts more than 5 s apart count again"
        );
    }

    #[tokio::test]
    async fn engine_web_and_tls_paths_count() {
        let engine = engine();
        let web = validate::normalize_jail(Jail {
            key: "eeffaabbccdd".to_owned(),
            name: "decoy".to_owned(),
            enable: true,
            source: JailSource::Web,
            filter: "*/.env".to_owned(),
            any_status: true,
            max_retry: 2,
            ..Jail::default()
        });
        let tls = validate::normalize_jail(Jail {
            key: "effaabbccdde".to_owned(),
            name: "probe".to_owned(),
            enable: true,
            source: JailSource::Tls,
            filter: "not_tls\nno_shared_params".to_owned(),
            max_retry: 2,
            ..Jail::default()
        });
        engine.reload(&config_with(vec![web, tls])).expect("reload");
        let summary = |path: &'static str, status: u16| rule_match::WebRequestSummary {
            listener: "web",
            path,
            host: "example.test",
            status,
            ip: Ipv4Addr::new(203, 0, 113, 40).into(),
            unknown_host: false,
            default_site: false,
            trusted_user: false,
            access_denied: false,
        };
        engine.on_web_hit(&summary("//.env", 200));
        assert!(!engine.service().is_banned("203.0.113.40".parse().unwrap()));
        engine.on_web_hit(&summary("/a/../.env", 404));
        assert!(engine.service().is_banned("203.0.113.40".parse().unwrap()));
        let ip: IpAddr = Ipv4Addr::new(203, 0, 113, 41).into();
        let fail = |reason: &'static str| TlsFail {
            listener: "web",
            ip,
            kind: tls_probe::classify(reason),
            reason,
            trusted_proxy: false,
        };
        engine.on_tls_fail(&fail("received plaintext HTTP request"));
        engine.on_tls_fail(&fail("no shared cipher suites"));
        assert!(engine.service().is_banned(ip));
    }

    #[tokio::test]
    async fn engine_reload_replaces_snapshot_and_stops_orphans() {
        let engine = engine();
        engine
            .reload(&config_with(vec![file_jail("from <HOST>", "", 1)]))
            .expect("reload");
        engine.on_line("aabbccddeeff", "from 203.0.113.50");
        assert!(engine.service().is_banned("203.0.113.50".parse().unwrap()));
        // Replacing the jails clears the old rule entirely.
        engine.reload(&config_with(vec![])).expect("reload");
        engine.on_line("aabbccddeeff", "from 203.0.113.51");
        assert!(!engine.service().is_banned("203.0.113.51".parse().unwrap()));
    }

    #[test]
    fn line_reasons_are_single_line_and_bounded() {
        let long = format!("bad {}\nsecond line", "x".repeat(400));
        let reason = line_reason(&long);
        assert!(!reason.contains('\n'));
        assert!(reason.chars().count() <= 200);
    }
}
