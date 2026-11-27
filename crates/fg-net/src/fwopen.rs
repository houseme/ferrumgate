//! WP-37: automatic firewall opening for ports the gateway itself listens
//! on (web listener, port forwarding, protocol routing; STUN and frps call
//! in through their own work packages).
//!
//! Tagged accept rules are inserted at the top of every existing chain that
//! can drop inbound traffic (nftables filter base chains on the `input`
//! hook, iptables/ip6tables `INPUT`), so they win over the system
//! firewall's own drop rules. Each rule opens a single port or a
//! contiguous port range, optionally limited to one address family or a
//! bound destination address — never a whole zone. A reconcile pass every
//! 30 seconds restores rules lost to a firewall reload and removes rules
//! left behind by a previous run. Only Linux is supported; every other
//! platform compiles to [`UnsupportedBackend`], which reports
//! [`FwError::Unsupported`] instead of touching the system.
//!
//! See docs/plan/WP-37-fw-open.md. Wiring point: the host process calls
//! [`setup`] once at startup with the config directory, creates one
//! [`Group`] per module (`web`, `pf`, `protoroute`, `stun`, …) and
//! registers the ports that actually listen via [`Group::want`].

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, Once, OnceLock, RwLock};
use std::thread;
use std::time::Duration;

pub use crate::openports::Proto;

/// Tag identifying rules inserted by this program; only rules whose
/// comment carries this prefix are ever deleted.
pub const COMMENT_PREFIX: &str = "ferrumgate-open:";

/// Prefix of the dedicated iptables chain used when the kernel has no
/// nf_tables (e.g. Synology DSM); the instance id is appended.
pub const CHAIN_PREFIX: &str = "GTLY_OPEN_";

/// Synology's name for the real builtin INPUT chain: its modified iptables
/// rewrites `INPUT` to a chain placed after the Synology firewall, so the
/// jump has to target `PRIMITIVE_INPUT` instead.
pub const SYNO_INPUT: &str = "PRIMITIVE_INPUT";

/// Note shown when a listener only binds a loopback address and therefore
/// needs no firewall opening.
pub const LOOPBACK_NOTE: &str = "只监听本机回环地址，无需放行防火墙";

/// How often the desired state is reconciled with the firewall.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

/// Status shown while a registration has not been written yet.
pub const STATUS_PENDING: &str = "正在放行防火墙端口";

/// Upper bound for a single nft / iptables invocation.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Instance identity and startup cleanup
// ---------------------------------------------------------------------------

/// Instance id, derived from the config directory by [`set_instance`].
static INSTANCE: Mutex<Option<String>> = Mutex::new(None);

/// Guarantees [`setup`] runs at most once per process.
static SETUP: Once = Once::new();

/// Lazily created process-wide manager behind every [`Group`].
static MANAGER: OnceLock<Manager> = OnceLock::new();

/// Sets the instance identity from the config directory (short hash of the
/// absolute path) so that several instances on one host never delete each
/// other's rules. Call before the first opening; defaults to `default`.
pub fn set_instance(dir: &Path) {
    let path = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    let id = short_hash(&path.to_string_lossy(), 4);
    *lock(&INSTANCE) = Some(id);
}

/// The current instance id (`default` until [`set_instance`] runs).
pub fn instance_id() -> String {
    lock(&INSTANCE)
        .clone()
        .unwrap_or_else(|| "default".to_string())
}

/// Comment prefix of this instance's rules:
/// `ferrumgate-open:<instance>:<owner>:<port>`.
fn own_prefix() -> String {
    format!("{COMMENT_PREFIX}{}:", instance_id())
}

/// Name of this instance's dedicated legacy iptables chain.
#[cfg(target_os = "linux")]
fn chain_name() -> String {
    format!("{CHAIN_PREFIX}{}", instance_id())
}

/// Sets the instance identity and cleans up rules left over from a
/// previous run (e.g. after the process was killed). Modules call this
/// from `init`; only the first call takes effect. The sweep runs in the
/// background and stays silent when no firewall or no permission is
/// available.
pub fn setup(config_dir: &Path) {
    SETUP.call_once(|| {
        set_instance(config_dir);
        thread::Builder::new()
            .name("fwopen-sweep".into())
            .spawn(|| global_manager().sweep())
            .ok();
    });
}

// ---------------------------------------------------------------------------
// Public data types
// ---------------------------------------------------------------------------

/// Address family a rule should be limited to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    /// Only IPv4.
    V4,
    /// Only IPv6.
    V6,
    /// Both families.
    Both,
}

/// A port or a contiguous port range that should be opened in the
/// firewall.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Port {
    /// Transport protocol.
    pub proto: Proto,
    /// Address family; forced to the family of `addr` when set.
    pub family: Family,
    /// When set, only traffic addressed to this IP is opened.
    pub addr: Option<IpAddr>,
    /// First port of the range.
    pub first: u16,
    /// Last port of the range (clamped up to `first`).
    pub last: u16,
}

impl Port {
    /// A single port.
    pub fn single(proto: Proto, family: Family, port: u16) -> Self {
        Self {
            proto,
            family,
            addr: None,
            first: port,
            last: port,
        }
    }

    /// A contiguous port range.
    pub fn range(proto: Proto, family: Family, first: u16, last: u16) -> Self {
        Self {
            proto,
            family,
            addr: None,
            first,
            last,
        }
    }

    /// Restricts the rule to connections addressed to `addr`.
    pub fn to_addr(mut self, addr: IpAddr) -> Self {
        self.addr = Some(addr);
        self
    }

    /// The last port of the range; never below `first`.
    pub fn last(&self) -> u16 {
        self.last.max(self.first)
    }

    /// Port or range as text, e.g. `443` or `8000-8010`.
    pub fn port_text(&self) -> String {
        if self.last() > self.first {
            format!("{}-{}", self.first, self.last())
        } else {
            self.first.to_string()
        }
    }

    /// Whether the IPv4 family should be opened.
    fn v4(&self) -> bool {
        self.family != Family::V6
    }

    /// Whether the IPv6 family should be opened.
    fn v6(&self) -> bool {
        self.family != Family::V4
    }

    fn family_char(&self) -> &'static str {
        match self.family {
            Family::V4 => "4",
            Family::V6 => "6",
            Family::Both => "",
        }
    }

    /// Identifier embedded in the rule comment: protocol + family + ports
    /// + address digest. Contains no colon so the owner can be split off.
    fn key(&self) -> String {
        let mut k = format!(
            "{}{}-{}",
            text::proto_text(self.proto),
            self.family_char(),
            self.port_text()
        );
        if let Some(addr) = self.addr {
            k.push('-');
            k.push_str(&short_hash(&addr.to_string(), 4));
        }
        k
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let proto = match self.proto {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
        };
        write!(f, "{proto} ")?;
        match self.addr {
            Some(addr) if addr.is_ipv6() => write!(f, "[{addr}]:{}", self.port_text()),
            Some(addr) => write!(f, "{addr}:{}", self.port_text()),
            None => {
                write!(f, "{}", self.port_text())?;
                match self.family {
                    Family::V4 => write!(f, " (IPv4)"),
                    Family::V6 => write!(f, " (IPv6)"),
                    Family::Both => Ok(()),
                }
            }
        }
    }
}

/// A chain that rules may be inserted into.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A base chain of type `filter` on the `input` hook in an nftables
    /// `ip` / `ip6` / `inet` table.
    Nft {
        table: String,
        family: String,
        chain: String,
        /// Enumerated chains always sit on the input hook.
        hook_input: bool,
        /// Chain policy, lower-case (`drop` / `accept`); `None` when the
        /// chain has none.
        policy: Option<String>,
        /// The chain holds rules other than tagged ones.
        busy: bool,
    },
    /// The builtin `INPUT` chain of iptables or ip6tables.
    Iptables {
        /// `true` for ip6tables.
        v6: bool,
        policy: Option<String>,
        busy: bool,
    },
}

impl Target {
    /// Backend kind, as used in diagnostics: `nft`, `iptables` or
    /// `ip6tables`.
    pub fn kind(&self) -> &'static str {
        match self {
            Target::Nft { .. } => "nft",
            Target::Iptables { v6: true, .. } => "ip6tables",
            Target::Iptables { v6: false, .. } => "iptables",
        }
    }

    /// Stable identifier used as the key of the rules map.
    pub fn key(&self) -> String {
        match self {
            Target::Nft {
                family,
                table,
                chain,
                ..
            } => format!("nftables {family} {table} {chain}"),
            Target::Iptables { v6: true, .. } => "ip6tables INPUT".to_string(),
            Target::Iptables { v6: false, .. } => "iptables INPUT".to_string(),
        }
    }

    /// Whether `p` belongs on this chain: IPv4-only chains skip IPv6-only
    /// ports and vice versa.
    pub fn accepts(&self, p: &Port) -> bool {
        match self {
            Target::Nft { family, .. } => match family.as_str() {
                "ip" => p.v4(),
                "ip6" => p.v6(),
                _ => true,
            },
            Target::Iptables { v6, .. } => {
                if *v6 {
                    p.v6()
                } else {
                    p.v4()
                }
            }
        }
    }

    /// Whether this chain can drop inbound traffic and therefore needs our
    /// rules: policy `drop` or rules besides the tagged ones.
    pub fn needed(&self) -> bool {
        let drops = match self {
            Target::Nft { policy, busy, .. } | Target::Iptables { policy, busy, .. } => {
                *busy || policy.as_deref() == Some("drop")
            }
        };
        match self {
            Target::Nft { hook_input, .. } => drops && *hook_input,
            Target::Iptables { .. } => drops,
        }
    }
}

/// One tagged rule found in the firewall: `reference` is the nft handle or
/// the iptables rule arguments used to delete it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub comment: String,
    pub reference: String,
}

/// Which firewall commands are available on the host.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Detect {
    pub nft: bool,
    pub iptables: bool,
    pub ip6tables: bool,
}

/// Rules grouped by the chain they were found in.
pub type TargetRules = Vec<(Target, Vec<Rule>)>;

/// Error reported by backend operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FwError {
    /// The platform has no firewall support (anything but Linux).
    Unsupported,
    /// Neither `nft` nor `iptables` was found on the host.
    NoFirewallCommand,
    /// The command ran without the required privileges (root or
    /// `NET_ADMIN`).
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
            FwError::Unsupported => write!(f, "自动放行防火墙只支持 Linux"),
            FwError::NoFirewallCommand => {
                write!(f, "没有找到 nft 或 iptables 命令，无法放行防火墙")
            }
            FwError::Permission => write!(
                f,
                "没有修改防火墙的权限（需要 root；Docker 部署需要 host 网络与 cap_add: NET_ADMIN）"
            ),
            FwError::CommandFailed(msg) => write!(f, "{msg}"),
            FwError::Parse(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for FwError {}

/// Firewall read/write access. Implementations must be callable from any
/// thread; [`CmdBackend`] is the production implementation, and
/// [`UnsupportedBackend`] stands in for unsupported platforms.
pub trait Backend: Send + Sync {
    /// Probes which firewall commands are available.
    fn detect(&self) -> Detect;
    /// Enumerates the chains rules may be inserted into.
    fn targets(&self) -> Result<Vec<Target>, FwError>;
    /// Lists tagged rules grouped by chain.
    fn existing(&self) -> Result<TargetRules, FwError>;
    /// Inserts one accept rule at the top of the chain.
    fn add(&self, target: &Target, comment: &str, port: &Port) -> Result<(), FwError>;
    /// Removes a previously listed rule.
    fn del(&self, target: &Target, rule: &Rule) -> Result<(), FwError>;
}

// ---------------------------------------------------------------------------
// Port computation (pure, every platform)
// ---------------------------------------------------------------------------

/// Computes what to open for one listener. `network` is one of
/// `tcp`, `tcp4`, `tcp6`, `udp`, `udp4`, `udp6`; `host` is the bound
/// address (`None` or an unspecified address opens both families);
/// `ports` are the ports that actually listen; `extra` opens the same
/// ports on the counterpart protocol (e.g. HTTP/3's UDP next to TCP).
/// Returns one [`Port`] per merged range; empty when nothing should be
/// opened (loopback-only listener, unknown network or no ports).
pub fn for_listen(network: &str, host: Option<IpAddr>, ports: &[u16], extra: &[u16]) -> Vec<Port> {
    let network = network.to_ascii_lowercase();
    let proto_name = network.trim_end_matches(['4', '6']);
    let proto = match proto_name {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        _ => return Vec::new(),
    };
    let suffix_family = match &network[proto_name.len()..] {
        "4" => Family::V4,
        "6" => Family::V6,
        _ => Family::Both,
    };
    let addr = match host {
        Some(ip) if ip.is_loopback() => return Vec::new(),
        // Unspecified addresses open without a destination restriction,
        // matching the dual-stack behaviour of a wildcard listener.
        Some(ip) if ip.is_unspecified() => None,
        Some(ip) => Some(ip),
        None => None,
    };
    // A bound address decides the family.
    let family = match addr {
        Some(addr) => {
            if addr.is_ipv4() {
                Family::V4
            } else {
                Family::V6
            }
        }
        None => suffix_family,
    };
    let mut out = Vec::new();
    for (first, last) in collapse_ports(ports) {
        out.push(Port {
            proto,
            family,
            addr,
            first,
            last,
        });
    }
    let other = if proto == Proto::Tcp {
        Proto::Udp
    } else {
        Proto::Tcp
    };
    for (first, last) in collapse_ports(extra) {
        out.push(Port {
            proto: other,
            family,
            addr,
            first,
            last,
        });
    }
    out
}

/// Whether the bound address is a loopback address (127.0.0.0/8, ::1);
/// such listeners are unreachable from the outside and need no opening.
pub fn is_loopback(host: Option<IpAddr>) -> bool {
    matches!(host, Some(ip) if ip.is_loopback())
}

/// Drops port 0 and merges the rest into sorted, deduplicated ranges.
fn collapse_ports(ports: &[u16]) -> Vec<(u16, u16)> {
    let valid: Vec<u16> = ports.iter().copied().filter(|&p| p != 0).collect();
    crate::ports::collapse(&valid)
}

/// Validates, deduplicates and sorts registered ports; a bound address
/// forces its family, and `last` is clamped up to `first`.
fn normalize(ports: Vec<Port>) -> Vec<Port> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(ports.len());
    for mut p in ports {
        if p.first == 0 {
            continue;
        }
        if p.last < p.first {
            p.last = p.first;
        }
        if let Some(addr) = p.addr {
            p.family = if addr.is_ipv4() {
                Family::V4
            } else {
                Family::V6
            };
        }
        if !seen.insert(p.clone()) {
            continue;
        }
        out.push(p);
    }
    out.sort_by(|a, b| a.first.cmp(&b.first).then_with(|| a.key().cmp(&b.key())));
    out
}

/// Restricts an owner name to characters that are safe inside a rule
/// comment; anything else (or too long) becomes a digest so a hostile key
/// cannot break the nft / iptables commands.
fn safe_owner(owner: &str) -> String {
    let safe = !owner.is_empty()
        && owner.chars().count() <= 48
        && owner
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'));
    if safe {
        owner.to_string()
    } else {
        format!("h-{}", short_hash(owner, 8))
    }
}

/// Comment of one rule: `prefix + owner + ":" + port key`.
fn comment(prefix: &str, owner: &str, p: &Port) -> String {
    format!("{prefix}{owner}:{}", p.key())
}

/// Recovers the owner from a rule comment; `None` for comments of other
/// programs or other instances, which must never be touched.
fn owner_of(prefix: &str, c: &str) -> Option<String> {
    let rest = c.strip_prefix(prefix)?;
    let idx = rest.rfind(':')?;
    Some(rest[..idx].to_string())
}

/// Whether the comment belongs to one of `ports` on this chain.
fn has_comment(prefix: &str, owner: &str, ports: &[Port], target: &Target, c: &str) -> bool {
    ports
        .iter()
        .any(|p| target.accepts(p) && comment(prefix, owner, p) == c)
}

// ---------------------------------------------------------------------------
// Manager: desired state, reconcile and status
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Manager {
    inner: Arc<ManagerInner>,
}

struct ManagerInner {
    backend: RwLock<Arc<dyn Backend>>,
    state: Mutex<ManagerState>,
    /// Serializes reconciles so the firewall is never written concurrently.
    run: Mutex<()>,
    interval: Duration,
    /// Fixed comment prefix; `None` reads the live instance prefix. Tests
    /// pin it so they stay deterministic.
    prefix: Option<String>,
}

#[derive(Default)]
struct ManagerState {
    owners: HashMap<String, OwnerState>,
    /// Whether the periodic reconcile loop is running.
    looping: bool,
}

#[derive(Clone)]
struct OwnerState {
    ports: Vec<Port>,
    status: String,
    ok: bool,
}

#[derive(Default)]
struct OwnerResult {
    ports: Vec<Port>,
    targets: Vec<String>,
    fail: Vec<String>,
}

impl Manager {
    fn with_backend(
        backend: Arc<dyn Backend>,
        interval: Duration,
        prefix: Option<String>,
        looping: bool,
    ) -> Self {
        Self {
            inner: Arc::new(ManagerInner {
                backend: RwLock::new(backend),
                state: Mutex::new(ManagerState {
                    owners: HashMap::new(),
                    looping,
                }),
                run: Mutex::new(()),
                interval,
                prefix,
            }),
        }
    }

    /// Registers `owner`'s desired ports and reconciles immediately. An
    /// empty list revokes the owner. Returns the status text and whether
    /// every port was opened.
    fn set(&self, owner: &str, ports: Vec<Port>) -> (String, bool) {
        let ports = normalize(ports);
        if ports.is_empty() {
            self.clear(owner);
            return (String::new(), true);
        }
        let start = {
            let mut st = lock(&self.inner.state);
            st.owners.insert(
                owner.to_string(),
                OwnerState {
                    ports: ports.clone(),
                    status: String::new(),
                    ok: false,
                },
            );
            let start = !st.looping;
            st.looping = true;
            start
        };
        if start {
            let inner = Arc::clone(&self.inner);
            let spawned = thread::Builder::new()
                .name("fwopen-reconcile".into())
                .spawn(move || reconcile_loop(inner));
            if spawned.is_err() {
                // Fall back to per-set reconciles only.
                let mut st = lock(&self.inner.state);
                st.looping = false;
            }
        }
        self.inner.reconcile();
        let st = lock(&self.inner.state);
        match st.owners.get(owner) {
            Some(o) => (o.status.clone(), o.ok),
            None => (String::new(), false),
        }
    }

    /// Revokes an owner and removes its rules.
    fn clear(&self, owner: &str) {
        let existed = lock(&self.inner.state).owners.remove(owner).is_some();
        if existed {
            self.inner.reconcile();
        }
    }

    fn status(&self, owner: &str) -> String {
        lock(&self.inner.state)
            .owners
            .get(owner)
            .map(|o| o.status.clone())
            .unwrap_or_default()
    }

    fn failed(&self, owner: &str) -> bool {
        lock(&self.inner.state)
            .owners
            .get(owner)
            .is_some_and(|o| !o.status.is_empty() && !o.ok)
    }

    /// One reconcile with no registrations: removes leftover rules of this
    /// instance from a previous run.
    fn sweep(&self) {
        self.inner.reconcile();
    }
}

/// Periodic reconcile; exits once no ports are registered.
fn reconcile_loop(inner: Arc<ManagerInner>) {
    loop {
        thread::sleep(inner.interval);
        let empty = {
            let mut st = lock(&inner.state);
            if st.owners.is_empty() {
                st.looping = false;
                true
            } else {
                false
            }
        };
        if empty {
            return;
        }
        inner.reconcile();
    }
}

impl ManagerInner {
    fn prefix(&self) -> String {
        self.prefix.clone().unwrap_or_else(own_prefix)
    }

    /// Brings the tagged rules in line with the registered ports: adds the
    /// missing ones, removes the stale ones, and updates every owner's
    /// status text.
    fn reconcile(&self) {
        let _run = lock(&self.run);
        let prefix = self.prefix();
        let want: HashMap<String, Vec<Port>> = {
            let st = lock(&self.state);
            st.owners
                .iter()
                .map(|(k, o)| (k.clone(), o.ports.clone()))
                .collect()
        };
        let mut results: HashMap<String, OwnerResult> = want
            .keys()
            .map(|k| {
                (
                    k.clone(),
                    OwnerResult {
                        ports: want[k].clone(),
                        ..Default::default()
                    },
                )
            })
            .collect();
        let be = Arc::clone(
            &*self
                .backend
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        match be.existing() {
            Err(e) => {
                let msg = e.to_string();
                for r in results.values_mut() {
                    r.fail.push(msg.clone());
                }
            }
            Ok(pairs) => {
                for (target, rules) in &pairs {
                    let key = target.key();
                    let mut present: HashSet<String> = HashSet::new();
                    for rule in rules {
                        let Some(owner) = owner_of(&prefix, &rule.comment) else {
                            // Rules of other programs or other instances are
                            // not ours to touch.
                            present.insert(rule.comment.clone());
                            continue;
                        };
                        let keep = want.get(&owner).is_some_and(|ports| {
                            target.needed()
                                && has_comment(&prefix, &owner, ports, target, &rule.comment)
                        }) && !present.contains(&rule.comment);
                        if keep {
                            present.insert(rule.comment.clone());
                            continue;
                        }
                        if let Err(e) = be.del(target, rule)
                            && let Some(r) = results.get_mut(&owner)
                        {
                            r.fail.push(format!("{key}: {e}"));
                        }
                    }
                    if !target.needed() {
                        // The chain accepts everything already.
                        continue;
                    }
                    for (owner, ports) in &want {
                        let Some(r) = results.get_mut(owner) else {
                            continue;
                        };
                        let mut ok_all = true;
                        let mut used = false;
                        for p in ports {
                            if !target.accepts(p) {
                                continue;
                            }
                            used = true;
                            let c = comment(&prefix, owner, p);
                            if present.contains(&c) {
                                continue;
                            }
                            if let Err(e) = be.add(target, &c, p) {
                                ok_all = false;
                                r.fail.push(format!("{key}: {e}"));
                            }
                        }
                        if ok_all && used {
                            r.targets.push(key.clone());
                        }
                    }
                }
            }
        }
        self.publish(&results);
    }

    fn publish(&self, results: &HashMap<String, OwnerResult>) {
        let mut st = lock(&self.state);
        for (owner, r) in results {
            let Some(o) = st.owners.get_mut(owner) else {
                continue;
            };
            let (status, ok) = describe(r, in_container());
            o.status = status;
            o.ok = ok;
        }
    }
}

/// Status text for one owner plus whether the ports are open.
fn describe(r: &OwnerResult, container: bool) -> (String, bool) {
    let port_text = r
        .ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join("、");
    if !r.fail.is_empty() {
        return (
            format!("放行防火墙端口 {port_text} 失败：{}", r.fail.join("；")),
            false,
        );
    }
    if r.targets.is_empty() {
        if container {
            return (
                "容器内没有发现会拦截入站连接的防火墙规则，无需放行；Docker bridge 网络的映射端口需要在宿主机或路由器的防火墙中放行"
                    .to_string(),
                true,
            );
        }
        return (
            "没有发现会拦截入站连接的防火墙规则（nftables / iptables），无需放行".to_string(),
            true,
        );
    }
    (
        format!("已在防火墙放行 {port_text}（{}）", r.targets.join("、")),
        true,
    )
}

/// Whether we are running inside a container (bridge networks need the
/// port opened on the host instead).
fn in_container() -> bool {
    ["/.dockerenv", "/run/.containerenv"]
        .iter()
        .any(|p| Path::new(p).exists())
}

fn default_backend() -> Arc<dyn Backend> {
    #[cfg(target_os = "linux")]
    {
        Arc::new(CmdBackend::new())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Arc::new(UnsupportedBackend)
    }
}

fn global_manager() -> Manager {
    MANAGER
        .get_or_init(|| Manager::with_backend(default_backend(), RECONCILE_INTERVAL, None, false))
        .clone()
}

// ---------------------------------------------------------------------------
// Group: per-module registrations, serialized background writes
// ---------------------------------------------------------------------------

/// Registers the desired openings of one module (web listener, port
/// forwarding rules, …). [`Group::want`] returns immediately; a background
/// worker writes the firewall serially in registration order, so module
/// APIs are never blocked by an nft / iptables invocation and concurrent
/// registrations cannot reorder the writes.
pub struct Group {
    shared: Arc<GroupShared>,
}

struct GroupShared {
    /// Module prefix (`web`, `pf`, …) used in the rule owner.
    prefix: &'static str,
    manager: Manager,
    state: Mutex<GroupState>,
    /// Serializes one pending key at a time; `clear_all` waits for the
    /// in-flight write before revoking everything.
    op: Mutex<()>,
}

#[derive(Default)]
struct GroupState {
    want: HashMap<String, Vec<Port>>,
    applied: HashMap<String, Vec<Port>>,
    pending: Vec<String>,
    running: bool,
}

impl GroupShared {
    fn owner(&self, key: &str) -> String {
        safe_owner(&format!("{}:{}", self.prefix, key))
    }
}

impl Group {
    /// Creates a group; `prefix` namespaces the rule owners of the module.
    pub fn new(prefix: &'static str) -> Arc<Self> {
        Arc::new(Self {
            shared: Arc::new(GroupShared {
                prefix,
                manager: global_manager(),
                state: Mutex::new(GroupState::default()),
                op: Mutex::new(()),
            }),
        })
    }

    /// Registers `key`'s desired ports; an empty list revokes. Returns
    /// immediately, the worker applies the change in the background.
    pub fn want(&self, key: &str, ports: Vec<Port>) {
        let ports = normalize(ports);
        let start = {
            let mut st = lock(&self.shared.state);
            if ports.is_empty() {
                if !st.want.contains_key(key) && !st.applied.contains_key(key) {
                    return;
                }
                st.want.remove(key);
            } else {
                st.want.insert(key.to_string(), ports);
            }
            if !st.pending.iter().any(|k| k == key) {
                st.pending.push(key.to_string());
            }
            let start = !st.running;
            st.running = true;
            start
        };
        if start {
            let shared = Arc::clone(&self.shared);
            let spawned = thread::Builder::new()
                .name("fwopen-group".into())
                .spawn(move || group_worker(shared));
            if spawned.is_err() {
                let mut st = lock(&self.shared.state);
                st.running = false;
            }
        }
    }

    /// Status text for `key`: pending while not yet written, otherwise the
    /// last reconcile result; empty when never registered.
    pub fn status(&self, key: &str) -> String {
        let (wanted, pending) = {
            let st = lock(&self.shared.state);
            (
                st.want.contains_key(key),
                st.pending.iter().any(|k| k == key),
            )
        };
        if !wanted {
            return String::new();
        }
        if !pending {
            let s = self.shared.manager.status(&self.shared.owner(key));
            if !s.is_empty() {
                return s;
            }
        }
        STATUS_PENDING.to_string()
    }

    /// Whether the most recent opening of `key` failed; false while
    /// pending or unregistered.
    pub fn failed(&self, key: &str) -> bool {
        let (wanted, pending) = {
            let st = lock(&self.shared.state);
            (
                st.want.contains_key(key),
                st.pending.iter().any(|k| k == key),
            )
        };
        wanted && !pending && self.shared.manager.failed(&self.shared.owner(key))
    }

    /// Synchronously revokes every registration of this group, including
    /// one applied by the worker while this call waited for it. Modules
    /// call this when they stop: after shutdown the ports may be taken by
    /// other programs.
    pub fn clear_all(&self) {
        let mut keys: Vec<String> = {
            let mut st = lock(&self.shared.state);
            let keys: Vec<String> = st
                .want
                .keys()
                .cloned()
                .chain(st.applied.keys().cloned())
                .collect();
            st.want.clear();
            st.pending.clear();
            keys
        };
        let _op = lock(&self.shared.op);
        {
            let mut st = lock(&self.shared.state);
            keys.extend(st.applied.keys().cloned());
            st.applied.clear();
        }
        keys.sort_unstable();
        keys.dedup();
        for key in keys {
            self.shared.manager.clear(&self.shared.owner(&key));
        }
    }
}

/// Applies pending registrations one at a time until none remain.
fn group_worker(shared: Arc<GroupShared>) {
    loop {
        let key = {
            let st = lock(&shared.state);
            st.pending.first().cloned()
        };
        let Some(key) = key else {
            lock(&shared.state).running = false;
            return;
        };
        let _op = lock(&shared.op);
        {
            let st = lock(&shared.state);
            if !st.pending.iter().any(|k| k == &key) {
                // clear_all revoked everything while we waited for the op
                // lock; the next loop iteration finds nothing to do.
                continue;
            }
        }
        let (wanted, prev) = {
            let st = lock(&shared.state);
            (st.want.get(&key).cloned(), st.applied.get(&key).cloned())
        };
        let owner = shared.owner(&key);
        match &wanted {
            None => shared.manager.clear(&owner),
            Some(ports) => {
                // Ports unchanged and maintained by the periodic reconcile:
                // skip the redundant write.
                let maintained =
                    prev.as_ref() == Some(ports) && !shared.manager.status(&owner).is_empty();
                if !maintained {
                    let (_status, _ok) = shared.manager.set(&owner, ports.clone());
                }
            }
        }
        {
            let mut st = lock(&shared.state);
            match &wanted {
                Some(ports) => {
                    st.applied.insert(key.clone(), ports.clone());
                }
                None => {
                    st.applied.remove(&key);
                }
            }
            // Keep the key pending when it was re-registered while the
            // write was in flight; the next round applies the newest state.
            if st.want.get(&key).cloned() == wanted {
                st.pending.retain(|k| *k != key);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pure firewall-text helpers (compiled everywhere so their snapshot tests
// run on every platform; the command backend that uses them is Linux-only)
// ---------------------------------------------------------------------------

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod text {
    use super::{COMMENT_PREFIX, Port, Rule, Target};

    /// Lower-case protocol name.
    pub(super) fn proto_text(proto: crate::openports::Proto) -> &'static str {
        match proto {
            crate::openports::Proto::Tcp => "tcp",
            crate::openports::Proto::Udp => "udp",
        }
    }

    /// Restricts table and chain names read back from nft to characters
    /// that cannot break the generated statements.
    pub(super) fn is_safe_name(s: &str) -> bool {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    }

    /// Match expressions of one nft rule: destination address, protocol
    /// restriction on inet chains, and the port or port range.
    pub(super) fn nft_match(t: &Target, p: &Port) -> String {
        let mut parts: Vec<String> = Vec::new();
        match p.addr {
            Some(addr) if addr.is_ipv6() => parts.push(format!("ip6 daddr {addr}")),
            Some(addr) => parts.push(format!("ip daddr {addr}")),
            None => {
                if let Target::Nft { family, .. } = t
                    && family == "inet"
                {
                    match p.family {
                        super::Family::V4 => parts.push("meta nfproto ipv4".to_string()),
                        super::Family::V6 => parts.push("meta nfproto ipv6".to_string()),
                        super::Family::Both => {}
                    }
                }
            }
        }
        parts.push(format!("{} dport {}", proto_text(p.proto), p.port_text()));
        parts.join(" ")
    }

    /// Match arguments of an iptables / ip6tables rule.
    pub(super) fn ipt_args(p: &Port) -> Vec<String> {
        let mut port = p.first.to_string();
        if p.last() > p.first {
            port.push(':');
            port.push_str(&p.last().to_string());
        }
        let mut args = vec![
            "-p".to_string(),
            proto_text(p.proto).to_string(),
            "--dport".to_string(),
            port,
        ];
        if let Some(addr) = p.addr {
            args.push("-d".to_string());
            args.push(addr.to_string());
        }
        args
    }

    /// Keys a rule by family + protocol + port + address, stripping the
    /// normalizations of `iptables-save` (`-m tcp`, `/32`, `/128`).
    pub(super) fn rule_key(v6: bool, args: &str) -> String {
        let f: Vec<&str> = args.split_whitespace().collect();
        let (mut proto, mut port, mut addr) = ("", "", "");
        let mut i = 0;
        while i + 1 < f.len() {
            match f[i] {
                "-p" => proto = f[i + 1],
                "--dport" => port = f[i + 1],
                "-d" => {
                    let mut a = f[i + 1];
                    if let Some(s) = a.strip_suffix("/32") {
                        a = s;
                    }
                    if let Some(s) = a.strip_suffix("/128") {
                        a = s;
                    }
                    addr = a;
                }
                _ => {}
            }
            i += 1;
        }
        format!("{}|{}|{}|{}", if v6 { "6" } else { "4" }, proto, port, addr)
    }

    /// The rule key a registered port produces.
    pub(super) fn port_key(v6: bool, p: &Port) -> String {
        rule_key(v6, &ipt_args(p).join(" "))
    }

    /// Whether an nft error means the kernel has no nf_tables (missing
    /// netlink support reports EINVAL / EPROTONOSUPPORT-like errors);
    /// permission errors deliberately do not match, so they are reported
    /// instead of falling back to legacy iptables.
    pub(super) fn kernel_no_nft(msg: &str) -> bool {
        let low = msg.to_lowercase();
        [
            "invalid argument",
            "protocol not supported",
            "address family not supported",
            "operation not supported",
        ]
        .iter()
        .any(|s| low.contains(s))
    }

    /// Turns command failures into an error, giving permission problems a
    /// deployment hint and truncating everything else.
    pub(super) fn classify(msg: &str) -> super::FwError {
        let low = msg.to_lowercase();
        if low.contains("operation not permitted") || low.contains("permission denied") {
            return super::FwError::Permission;
        }
        let mut bounded = msg.to_string();
        if bounded.chars().count() > 300 {
            bounded = bounded.chars().take(300).collect();
        }
        super::FwError::CommandFailed(bounded)
    }

    #[derive(serde::Deserialize)]
    struct NftDoc {
        #[serde(default)]
        nftables: Vec<NftObject>,
    }

    #[derive(serde::Deserialize)]
    struct NftObject {
        #[serde(default)]
        chain: Option<NftChain>,
        #[serde(default)]
        rule: Option<NftRule>,
    }

    #[derive(serde::Deserialize)]
    struct NftChain {
        #[serde(default)]
        family: String,
        #[serde(default)]
        table: String,
        #[serde(default)]
        name: String,
        #[serde(rename = "type", default)]
        chain_type: Option<String>,
        #[serde(default)]
        hook: Option<String>,
        #[serde(default)]
        policy: Option<String>,
    }

    #[derive(serde::Deserialize)]
    struct NftRule {
        #[serde(default)]
        handle: i64,
        #[serde(default)]
        comment: Option<String>,
    }

    /// Parses `nft -j list chains` into the filter base chains on the
    /// input hook of the ip / ip6 / inet families. The inet `gately` table
    /// (used by intrusion protection) is skipped, as are chains with
    /// unsafe names.
    pub(super) fn parse_nft_chains(raw: &str) -> Result<Vec<Target>, super::FwError> {
        let doc: NftDoc = serde_json::from_str(raw)
            .map_err(|e| super::FwError::Parse(format!("解析 nft 输出失败: {e}")))?;
        let mut out = Vec::new();
        for obj in doc.nftables {
            let Some(c) = obj.chain else { continue };
            if c.hook.as_deref() != Some("input") || c.chain_type.as_deref() != Some("filter") {
                continue;
            }
            if !matches!(c.family.as_str(), "ip" | "ip6" | "inet") {
                continue;
            }
            if c.family == "inet" && c.table == "gately" {
                continue;
            }
            if !is_safe_name(&c.table) || !is_safe_name(&c.name) {
                continue;
            }
            out.push(Target::Nft {
                table: c.table,
                family: c.family,
                chain: c.name,
                hook_input: true,
                policy: c.policy.map(|p| p.to_lowercase()),
                busy: false,
            });
        }
        Ok(out)
    }

    /// Parses `nft -j -a list chain`: the tagged rules (with handle) plus
    /// whether the chain also holds untagged rules.
    pub(super) fn parse_nft_rules(raw: &str) -> Result<(bool, Vec<Rule>), super::FwError> {
        let doc: NftDoc = serde_json::from_str(raw)
            .map_err(|e| super::FwError::Parse(format!("解析 nft 输出失败: {e}")))?;
        let mut busy = false;
        let mut rules = Vec::new();
        for obj in doc.nftables {
            let Some(r) = obj.rule else { continue };
            match r.comment {
                Some(c) if c.starts_with(COMMENT_PREFIX) => {
                    rules.push(Rule {
                        comment: c,
                        reference: r.handle.to_string(),
                    });
                }
                _ => busy = true,
            }
        }
        Ok((busy, rules))
    }

    /// Parses `iptables -S INPUT` / `ip6tables -S INPUT`: tagged rules keep
    /// their arguments as the deletion reference, everything else marks the
    /// chain busy.
    pub(super) fn parse_iptables(out: &str) -> (Target, Vec<Rule>) {
        let (mut policy, mut busy) = (None, false);
        let mut rules = Vec::new();
        for line in out.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 2 || f[1] != "INPUT" {
                continue;
            }
            match f[0] {
                "-P" => policy = f.get(2).map(|p| p.to_lowercase()),
                "-A" => {
                    let mut c = String::new();
                    let mut i = 2;
                    while i + 1 < f.len() {
                        if f[i] == "--comment" {
                            c = f[i + 1].trim_matches('"').to_string();
                        }
                        i += 1;
                    }
                    if c.starts_with(COMMENT_PREFIX) {
                        // Match by the original arguments when deleting;
                        // quotes are stripped to mirror how we wrote it.
                        let reference = f[2..]
                            .iter()
                            .map(|s| s.trim_matches('"'))
                            .collect::<Vec<_>>()
                            .join(" ");
                        rules.push(Rule {
                            comment: c,
                            reference,
                        });
                        continue;
                    }
                    busy = true;
                }
                _ => {}
            }
        }
        (
            Target::Iptables {
                v6: false,
                policy,
                busy,
            },
            rules,
        )
    }

    /// The parsed `iptables-save -t filter` view of one address family.
    pub(super) struct SavedTable {
        pub policy: Option<String>,
        /// Arguments of the INPUT rules (without `-A INPUT`), in order.
        pub input: Vec<String>,
        /// Arguments of the dedicated chain's rules.
        pub own: Vec<String>,
        pub has_own: bool,
        /// Position of our jump rule inside INPUT, if present.
        pub jump_pos: Option<usize>,
        pub jumps: usize,
    }

    impl SavedTable {
        /// The jump is unique and only other instances' chain jumps may sit
        /// before it (otherwise instances would keep fighting for the top
        /// position on every reconcile).
        pub fn jump_ok(&self) -> bool {
            if self.jumps != 1 {
                return false;
            }
            let Some(pos) = self.jump_pos else {
                return false;
            };
            self.input[..pos].iter().all(|r| {
                let mut f = r.split_whitespace();
                match (f.next(), f.next(), f.next()) {
                    (Some("-j"), Some(name), None) => name.starts_with(super::CHAIN_PREFIX),
                    _ => false,
                }
            })
        }

        /// Whether INPUT holds rules besides our jump (those may drop
        /// traffic, so our chain is needed).
        pub fn busy(&self, own: &str) -> bool {
            let jump = format!("-j {own}");
            self.input.iter().any(|r| *r != jump)
        }
    }

    /// Parses `iptables-save -t filter` output for the dedicated chain
    /// `own`.
    pub(super) fn parse_saved_filter(out: &str, own: &str) -> SavedTable {
        let jump = format!("-j {own}");
        let own_chain = format!(":{own} ");
        let own_rule = format!("-A {own} ");
        let mut st = SavedTable {
            policy: None,
            input: Vec::new(),
            own: Vec::new(),
            has_own: false,
            jump_pos: None,
            jumps: 0,
        };
        for raw in out.lines() {
            let l = raw.trim();
            if let Some(rest) = l.strip_prefix(":INPUT ") {
                if let Some(p) = rest.split_whitespace().next() {
                    st.policy = Some(p.to_lowercase());
                }
            } else if l.starts_with(&own_chain) {
                st.has_own = true;
            } else if let Some(args) = l.strip_prefix("-A INPUT ") {
                if args == jump {
                    if st.jump_pos.is_none() {
                        st.jump_pos = Some(st.input.len());
                    }
                    st.jumps += 1;
                }
                st.input.push(args.to_string());
            } else if let Some(args) = l.strip_prefix(&own_rule) {
                st.own.push(args.to_string());
            }
        }
        st
    }
}

// ---------------------------------------------------------------------------
// Linux command backend
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::Mutex;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{
        Detect, FwError, Port, Rule, SYNO_INPUT, Target, TargetRules, as_v6, lock,
        text::{
            classify, ipt_args, nft_match, parse_iptables, parse_nft_chains, parse_nft_rules,
            parse_saved_filter, port_key, rule_key,
        },
    };

    /// One address family of the legacy-iptables chain mode.
    #[derive(Clone)]
    pub(super) struct ChainFam {
        v6: bool,
        bin: PathBuf,
        save: PathBuf,
        /// Name the command uses for the builtin INPUT chain (Synology
        /// rewrites `INPUT`).
        input: String,
    }

    impl ChainFam {
        fn kind(&self) -> &'static str {
            if self.v6 { "ip6tables" } else { "iptables" }
        }

        fn builtin(&self) -> &str {
            if self.input.is_empty() {
                "INPUT"
            } else {
                &self.input
            }
        }
    }

    /// State of the legacy chain mode: which family commands exist, and the
    /// comment each in-chain rule was written for (several owners may claim
    /// the same port, so one key maps to several comments).
    struct ChainState {
        fams: Vec<ChainFam>,
        known: HashMap<String, Vec<String>>,
    }

    #[derive(Default)]
    struct CmdState {
        nft: Option<PathBuf>,
        iptables: Option<PathBuf>,
        ip6tables: Option<PathBuf>,
        ipt_nft: bool,
        ip6t_nft: bool,
        chain: Option<ChainState>,
    }

    /// Backend that drives nft / iptables / ip6tables by executing the
    /// binaries (decision D7: no netlink in the first pass).
    pub(super) struct CmdBackend {
        state: Mutex<CmdState>,
    }

    impl CmdBackend {
        pub(super) fn new() -> Self {
            Self {
                state: Mutex::new(CmdState::default()),
            }
        }

        fn detect_locked(st: &mut CmdState) {
            st.nft = look_path("nft");
            st.iptables = look_path("iptables");
            st.ip6tables = look_path("ip6tables");
            st.ipt_nft = false;
            st.ip6t_nft = false;
            if let Some(p) = st.iptables.clone()
                && let Ok(v) = run(None, &p, &["-V"])
            {
                st.ipt_nft = v.contains("nf_tables");
            }
            if let Some(p) = st.ip6tables.clone()
                && let Ok(v) = run(None, &p, &["-V"])
            {
                st.ip6t_nft = v.contains("nf_tables");
            }
        }

        /// Targets and tagged rules of the legacy chain mode.
        fn chain_targets(st: &mut CmdState) -> Result<TargetRules, FwError> {
            let fams = st
                .chain
                .as_ref()
                .ok_or_else(|| FwError::CommandFailed("专用链模式未初始化".to_string()))?
                .fams
                .clone();
            let own = super::chain_name();
            let mut list: TargetRules = Vec::new();
            for (i, f) in fams.iter().enumerate() {
                let out = match run(None, &f.save, &["-t", "filter"]) {
                    Ok(out) => out,
                    Err(e) => {
                        // The kernel may lack IPv6; keep IPv4 working.
                        if f.v6 && i > 0 {
                            continue;
                        }
                        return Err(e);
                    }
                };
                let sv = parse_saved_filter(&out, &own);
                let t = Target::Iptables {
                    v6: f.v6,
                    policy: sv.policy.clone(),
                    busy: sv.busy(&own),
                };
                // When the chain has rules but our jump was pushed down,
                // move it back to the first position.
                if !sv.own.is_empty() && !sv.jump_ok() {
                    fix_chain_jump(f, &own, sv.jumps)?;
                }
                let mut rules = Vec::new();
                let mut used: HashMap<String, usize> = HashMap::new();
                for args in &sv.own {
                    let key = rule_key(f.v6, args);
                    let n = used.entry(key.clone()).or_insert(0);
                    let cm = st
                        .chain
                        .as_ref()
                        .and_then(|c| c.known.get(&key))
                        .and_then(|list| list.get(*n))
                        .cloned()
                        // Rules written by a previous process are claimed
                        // with a comment that matches no registration, so
                        // the reconcile deletes and re-adds them.
                        .unwrap_or_else(|| format!("{}?:{key}", super::own_prefix()));
                    *n += 1;
                    rules.push(Rule {
                        comment: cm,
                        reference: args.clone(),
                    });
                }
                list.push((t, rules));
            }
            Ok(list)
        }

        fn chain_add(st: &mut CmdState, t: &Target, cm: &str, p: &Port) -> Result<(), FwError> {
            let fams = st
                .chain
                .as_ref()
                .ok_or_else(|| FwError::CommandFailed("专用链模式未初始化".to_string()))?
                .fams
                .clone();
            let kind = t.kind();
            let f = fams
                .iter()
                .find(|f| f.kind() == kind)
                .cloned()
                .ok_or_else(|| FwError::CommandFailed(format!("没有 {kind} 命令")))?;
            let own = super::chain_name();
            let out = run(None, &f.save, &["-t", "filter"])?;
            let sv = parse_saved_filter(&out, &own);
            if !sv.has_own {
                run(None, &f.bin, &["-w", "-N", &own])?;
            }
            if !sv.jump_ok() {
                fix_chain_jump(&f, &own, sv.jumps)?;
            }
            let mut args: Vec<String> = vec!["-w".to_string(), "-A".to_string(), own.clone()];
            args.extend(ipt_args(p));
            args.push("-j".to_string());
            args.push("ACCEPT".to_string());
            run(None, &f.bin, &args)?;
            let key = port_key(f.v6, p);
            if let Some(cs) = st.chain.as_mut() {
                cs.known.entry(key).or_default().push(cm.to_string());
            }
            Ok(())
        }

        fn chain_del(st: &mut CmdState, t: &Target, rule: &Rule) -> Result<(), FwError> {
            let fams = st
                .chain
                .as_ref()
                .ok_or_else(|| FwError::CommandFailed("专用链模式未初始化".to_string()))?
                .fams
                .clone();
            let kind = t.kind();
            let f = fams
                .iter()
                .find(|f| f.kind() == kind)
                .cloned()
                .ok_or_else(|| FwError::CommandFailed(format!("没有 {kind} 命令")))?;
            let own = super::chain_name();
            let mut args: Vec<String> = vec!["-w".to_string(), "-D".to_string(), own.clone()];
            args.extend(rule.reference.split_whitespace().map(str::to_string));
            run(None, &f.bin, &args)?;
            // Drop only this rule's claim; other claims on the same port
            // keep their rules.
            let key = rule_key(f.v6, &rule.reference);
            if let Some(cs) = st.chain.as_mut()
                && let Some(list) = cs.known.get_mut(&key)
            {
                if let Some(i) = list.iter().position(|c| *c == rule.comment) {
                    list.remove(i);
                } else if !list.is_empty() {
                    list.remove(0);
                }
                if list.is_empty() {
                    cs.known.remove(&key);
                }
            }
            drop_empty_chain(&f);
            Ok(())
        }

        /// Enumerates chains and tagged rules: nftables base chains first,
        /// then the iptables / ip6tables INPUT chains. Falls back to the
        /// dedicated-chain mode when the kernel has no nf_tables or the
        /// installed iptables cannot tag rules.
        fn targets_locked(st: &mut CmdState) -> Result<TargetRules, FwError> {
            if st.chain.is_some() {
                return Self::chain_targets(st);
            }
            Self::detect_locked(st);
            if st.nft.is_none() && st.iptables.is_none() {
                return Err(FwError::NoFirewallCommand);
            }
            // Whether the iptables-nft / ip6tables-nft filter INPUT chains
            // exist in nft (they are written via iptables then).
            let mut has_ip_filter = false;
            let mut has_ip6_filter = false;
            let mut chains_out = String::new();
            if let Some(nft) = st.nft.clone() {
                match run(None, &nft, &["-j", "list", "chains"]) {
                    Ok(out) => chains_out = out,
                    Err(e) => {
                        if super::text::kernel_no_nft(&e.to_string()) {
                            let fams = find_chain_fams();
                            if !fams.is_empty() {
                                st.chain = Some(ChainState {
                                    fams,
                                    known: HashMap::new(),
                                });
                                return Self::chain_targets(st);
                            }
                            return Err(FwError::CommandFailed(format!(
                                "当前系统内核不支持 nftables，且没有 iptables（legacy）命令，无法放行防火墙: {e}"
                            )));
                        }
                        return Err(e);
                    }
                }
            }
            let mut list: TargetRules = Vec::new();
            if let Some(nft) = st.nft.clone() {
                for cand in parse_nft_chains(&chains_out)? {
                    let managed_by_ipt = match &cand {
                        Target::Nft {
                            family,
                            table,
                            chain,
                            ..
                        } => {
                            (family == "ip" && table == "filter" && chain == "INPUT" && st.ipt_nft)
                                || (family == "ip6"
                                    && table == "filter"
                                    && chain == "INPUT"
                                    && st.ip6t_nft)
                        }
                        _ => false,
                    };
                    if managed_by_ipt {
                        let Target::Nft { family, .. } = &cand else {
                            continue;
                        };
                        if family == "ip" {
                            has_ip_filter = true;
                        } else {
                            has_ip6_filter = true;
                        }
                        continue;
                    }
                    let Target::Nft {
                        family,
                        table,
                        chain,
                        ..
                    } = &cand
                    else {
                        continue;
                    };
                    let out = run(
                        None,
                        &nft,
                        &["-j", "-a", "list", "chain", family, table, chain],
                    )?;
                    let (busy, rules) = parse_nft_rules(&out)?;
                    let mut t = cand;
                    if let Target::Nft { busy: b, .. } = &mut t {
                        *b = busy;
                    }
                    list.push((t, rules));
                }
            }
            // iptables-legacy rules are invisible to nft: always check.
            // iptables-nft is only used when its filter table already
            // exists, so we never create a table out of thin air.
            if let Some(ipt) = st.iptables.clone()
                && (!st.ipt_nft || has_ip_filter || st.nft.is_none())
            {
                // Some trimmed systems (Synology) ship an iptables without
                // the comment module; fall back to the dedicated chain mode.
                if st.nft.is_none() && !st.ipt_nft && !ipt_has_comment(&ipt) {
                    let fams = find_chain_fams();
                    if !fams.is_empty() {
                        st.chain = Some(ChainState {
                            fams,
                            known: HashMap::new(),
                        });
                        return Self::chain_targets(st);
                    }
                }
                let out = run(None, &ipt, &["-w", "-S", "INPUT"])?;
                list.push(parse_iptables(&out));
            }
            if let Some(ip6t) = st.ip6tables.clone()
                && (!st.ip6t_nft || has_ip6_filter || st.nft.is_none())
            {
                match run(None, &ip6t, &["-w", "-S", "INPUT"]) {
                    Ok(out) => {
                        let (t, rules) = parse_iptables(&out);
                        list.push((as_v6(t), rules));
                    }
                    Err(e) => {
                        // A kernel without IPv6 makes ip6tables fail; that
                        // must not block IPv4 openings.
                        if st.iptables.is_some() || st.nft.is_some() {
                            return Ok(list);
                        }
                        return Err(e);
                    }
                }
            }
            Ok(list)
        }
    }

    impl super::Backend for CmdBackend {
        fn detect(&self) -> Detect {
            let mut st = lock(&self.state);
            Self::detect_locked(&mut st);
            Detect {
                nft: st.nft.is_some(),
                iptables: st.iptables.is_some(),
                ip6tables: st.ip6tables.is_some(),
            }
        }

        fn targets(&self) -> Result<Vec<Target>, FwError> {
            self.existing()
                .map(|pairs| pairs.into_iter().map(|(t, _)| t).collect())
        }

        fn existing(&self) -> Result<TargetRules, FwError> {
            let mut st = lock(&self.state);
            Self::targets_locked(&mut st)
        }

        fn add(&self, t: &Target, comment: &str, p: &Port) -> Result<(), FwError> {
            let mut st = lock(&self.state);
            if st.chain.is_some() {
                return Self::chain_add(&mut st, t, comment, p);
            }
            match t {
                Target::Iptables { v6, .. } => {
                    let bin = if *v6 { &st.ip6tables } else { &st.iptables }
                        .clone()
                        .ok_or_else(|| FwError::CommandFailed(format!("没有 {} 命令", t.kind())))?;
                    let mut args: Vec<String> = vec![
                        "-w".to_string(),
                        "-I".to_string(),
                        "INPUT".to_string(),
                        "1".to_string(),
                    ];
                    args.extend(ipt_args(p));
                    args.push("-m".to_string());
                    args.push("comment".to_string());
                    args.push("--comment".to_string());
                    args.push(comment.to_string());
                    args.push("-j".to_string());
                    args.push("ACCEPT".to_string());
                    run(None, &bin, &args).map(|_| ())
                }
                Target::Nft {
                    family,
                    table,
                    chain,
                    ..
                } => {
                    let nft = st
                        .nft
                        .clone()
                        .ok_or_else(|| FwError::CommandFailed("没有 nft 命令".to_string()))?;
                    let stmt = format!(
                        "insert rule {family} {table} {chain} {} counter accept comment \"{comment}\"\n",
                        nft_match(t, p)
                    );
                    run(Some(&stmt), &nft, &["-f", "-"]).map(|_| ())
                }
            }
        }

        fn del(&self, t: &Target, rule: &Rule) -> Result<(), FwError> {
            let mut st = lock(&self.state);
            if st.chain.is_some() {
                return Self::chain_del(&mut st, t, rule);
            }
            match t {
                Target::Iptables { v6, .. } => {
                    let bin = if *v6 { &st.ip6tables } else { &st.iptables }
                        .clone()
                        .ok_or_else(|| FwError::CommandFailed(format!("没有 {} 命令", t.kind())))?;
                    let mut args: Vec<String> =
                        vec!["-w".to_string(), "-D".to_string(), "INPUT".to_string()];
                    args.extend(rule.reference.split_whitespace().map(str::to_string));
                    run(None, &bin, &args).map(|_| ())
                }
                Target::Nft {
                    family,
                    table,
                    chain,
                    ..
                } => {
                    let nft = st
                        .nft
                        .clone()
                        .ok_or_else(|| FwError::CommandFailed("没有 nft 命令".to_string()))?;
                    let stmt = format!(
                        "delete rule {family} {table} {chain} handle {}\n",
                        rule.reference
                    );
                    run(Some(&stmt), &nft, &["-f", "-"]).map(|_| ())
                }
            }
        }
    }

    /// Removes every jump to the dedicated chain, then inserts a fresh one
    /// at the top.
    fn fix_chain_jump(f: &ChainFam, own: &str, jumps: usize) -> Result<(), FwError> {
        for _ in 0..jumps {
            run(None, &f.bin, &["-w", "-D", f.builtin(), "-j", own]).map(|_| ())?;
        }
        run(None, &f.bin, &["-w", "-I", f.builtin(), "1", "-j", own]).map(|_| ())
    }

    /// Deletes the jump and the dedicated chain once it holds no rules, so
    /// nothing is left behind in the system firewall. Failures are
    /// ignored: an empty chain is harmless.
    fn drop_empty_chain(f: &ChainFam) {
        let own = super::chain_name();
        let Ok(out) = run(None, &f.save, &["-t", "filter"]) else {
            return;
        };
        let sv = parse_saved_filter(&out, &own);
        if !sv.has_own || !sv.own.is_empty() {
            return;
        }
        for _ in 0..sv.jumps {
            if run(None, &f.bin, &["-w", "-D", f.builtin(), "-j", &own]).is_err() {
                return;
            }
        }
        let _ = run(None, &f.bin, &["-w", "-X", &own]);
    }

    /// Finds iptables (legacy) and its save command for both families.
    /// An nf_tables variant of the plain binary is rejected, so only real
    /// legacy tooling reaches chain mode.
    fn find_chain_fams() -> Vec<ChainFam> {
        let mut out = Vec::new();
        for v6 in [false, true] {
            let name = if v6 { "ip6tables" } else { "iptables" };
            let mut f = ChainFam {
                v6,
                bin: PathBuf::new(),
                save: PathBuf::new(),
                input: String::new(),
            };
            if let Some(p) = look_path(&format!("{name}-legacy")) {
                f.bin = p;
                f.save = look_path(&format!("{name}-legacy-save")).unwrap_or_default();
            } else if let Some(p) = look_path(name)
                && let Ok(v) = run(None, &p, &["-V"])
                && !v.contains("nf_tables")
            {
                f.bin = p;
                f.save = look_path(&format!("{name}-save")).unwrap_or_default();
            }
            if !f.bin.as_os_str().is_empty() && !f.save.as_os_str().is_empty() {
                f.input = "INPUT".to_string();
                // Only Synology's iptables knows PRIMITIVE_INPUT; on other
                // systems the query fails and INPUT stays.
                if run(None, &f.bin, &["-w", "-S", SYNO_INPUT]).is_ok() {
                    f.input = SYNO_INPUT.to_string();
                }
                out.push(f);
            }
        }
        out
    }

    /// Whether iptables can load the comment match module (trimmed systems
    /// such as Synology cannot, so rules there cannot be tagged).
    fn ipt_has_comment(bin: &Path) -> bool {
        match run(None, bin, &["-m", "comment", "-h"]) {
            Ok(_) => true,
            Err(e) => !e.to_string().contains("comment"),
        }
    }

    /// Looks `name` up in PATH and then the usual sbin directories
    /// (`/usr/sbin` and friends are frequently missing from PATH when
    /// running as a service).
    fn look_path(name: &str) -> Option<PathBuf> {
        let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|v| std::env::split_paths(&v).collect())
            .unwrap_or_default();
        dirs.extend(["/usr/sbin", "/sbin", "/usr/bin"].iter().map(PathBuf::from));
        look_path_in(&dirs, name)
    }

    pub(super) fn look_path_in(dirs: &[PathBuf], name: &str) -> Option<PathBuf> {
        dirs.iter().map(|d| d.join(name)).find(|p| is_executable(p))
    }

    fn is_executable(path: &Path) -> bool {
        match path.metadata() {
            Ok(m) => m.is_file() && m.permissions().mode() & 0o111 != 0,
            Err(_) => false,
        }
    }

    /// Runs `bin` with an argument array (never a shell) and an optional
    /// stdin payload, with a hard timeout. Output is captured; failures
    /// are classified for status display and the legacy fallback.
    pub(super) fn run<S: AsRef<std::ffi::OsStr>>(
        stdin: Option<&str>,
        bin: &Path,
        args: &[S],
    ) -> Result<String, FwError> {
        use std::io::Read as _;

        let mut cmd = Command::new(bin);
        cmd.args(args);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        cmd.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => return Err(classify(&e.to_string())),
        };
        if let Some((input, mut pipe)) = stdin.zip(child.stdin.take()) {
            let _ = pipe.write_all(input.as_bytes());
        }
        let stdout_t = child.stdout.take().map(|mut pipe| {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = pipe.read_to_end(&mut buf);
                buf
            })
        });
        let stderr_t = child.stderr.take().map(|mut pipe| {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = pipe.read_to_end(&mut buf);
                buf
            })
        });
        let deadline = Instant::now() + super::COMMAND_TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(FwError::CommandFailed(format!(
                        "{} 执行超时",
                        bin.display()
                    )));
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(e) => return Err(classify(&e.to_string())),
            }
        };
        let stdout = stdout_t.and_then(|t| t.join().ok()).unwrap_or_default();
        let stderr = stderr_t.and_then(|t| t.join().ok()).unwrap_or_default();
        if !status.success() {
            let mut msg = String::from_utf8_lossy(&stderr).trim().to_string();
            if msg.is_empty() {
                msg = status.to_string();
            }
            return Err(classify(&msg));
        }
        Ok(String::from_utf8_lossy(&stdout).into_owned())
    }
}

#[cfg(target_os = "linux")]
use linux::CmdBackend;

/// Flips a parsed iptables target to the ip6tables variant.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn as_v6(t: Target) -> Target {
    match t {
        Target::Iptables { policy, busy, .. } => Target::Iptables {
            v6: true,
            policy,
            busy,
        },
        other => other,
    }
}

/// Placeholder backend for platforms without firewall support. Every
/// operation reports [`FwError::Unsupported`]; nothing touches the system.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedBackend;

impl Backend for UnsupportedBackend {
    fn detect(&self) -> Detect {
        Detect::default()
    }

    fn targets(&self) -> Result<Vec<Target>, FwError> {
        Err(FwError::Unsupported)
    }

    fn existing(&self) -> Result<TargetRules, FwError> {
        Err(FwError::Unsupported)
    }

    fn add(&self, _target: &Target, _comment: &str, _port: &Port) -> Result<(), FwError> {
        Err(FwError::Unsupported)
    }

    fn del(&self, _target: &Target, _rule: &Rule) -> Result<(), FwError> {
        Err(FwError::Unsupported)
    }
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

/// Locks a mutex, recovering from poisoning (the guarded invariants are
/// plain maps, so continuing is always safe).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// SHA-256 (FIPS 180-4). Used for the instance identity and owner digests;
/// the FIPS test vectors below pin the implementation, so no external
/// crate is needed for this.
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The first `n` bytes of the SHA-256 digest of `s`, hex encoded.
fn short_hash(s: &str, n: usize) -> String {
    hex(&sha256(s.as_bytes())[..n])
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, Instant};

    use super::*;
    use text::{
        classify, ipt_args, kernel_no_nft, nft_match, parse_iptables, parse_nft_chains,
        parse_nft_rules, parse_saved_filter, port_key, rule_key,
    };

    const TEST_PREFIX: &str = "ferrumgate-open:testinst:";

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn ip4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }

    fn ip6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    fn nft_target(
        family: &str,
        table: &str,
        chain: &str,
        policy: Option<&str>,
        busy: bool,
    ) -> Target {
        Target::Nft {
            table: table.to_string(),
            family: family.to_string(),
            chain: chain.to_string(),
            hook_input: true,
            policy: policy.map(str::to_string),
            busy,
        }
    }

    /// The busy fw4 input chain used by most tests.
    fn fw4() -> Target {
        nft_target("inet", "fw4", "input", Some("accept"), true)
    }

    /// An accept-policy chain without other rules: nothing to open.
    fn idle_chain() -> Target {
        nft_target("ip", "other", "input", Some("accept"), false)
    }

    fn ipt_input(policy: Option<&str>, v6: bool) -> Target {
        Target::Iptables {
            v6,
            policy: policy.map(str::to_string),
            busy: false,
        }
    }

    // ------------------------------------------------------------------
    // Port computation
    // ------------------------------------------------------------------

    #[test]
    fn for_listen_dual_stack_opens_both_families() {
        let got = for_listen("tcp", None, &[443, 8001, 8000, 8002, 443], &[]);
        assert_eq!(
            got,
            vec![
                Port::single(Proto::Tcp, Family::Both, 443),
                Port::range(Proto::Tcp, Family::Both, 8000, 8002),
            ]
        );
        assert_eq!(
            for_listen("UDP", Some(ip4("0.0.0.0")), &[5353], &[]),
            vec![Port::single(Proto::Udp, Family::Both, 5353)]
        );
        // A wildcard IPv6 listener stays unrestricted too.
        assert_eq!(
            for_listen("tcp6", Some(ip6("::")), &[50663], &[]),
            vec![Port::single(Proto::Tcp, Family::V6, 50663)]
        );
    }

    #[test]
    fn for_listen_v4_or_v6_only() {
        assert_eq!(
            for_listen("udp4", None, &[3478], &[]),
            vec![Port::single(Proto::Udp, Family::V4, 3478)]
        );
        assert_eq!(
            for_listen("udp6", None, &[3478], &[]),
            vec![Port::single(Proto::Udp, Family::V6, 3478)]
        );
        assert_eq!(
            for_listen("tcp4", Some(ip4("192.168.1.1")), &[443], &[]),
            vec![Port::single(Proto::Tcp, Family::V4, 443).to_addr(ip4("192.168.1.1"))]
        );
    }

    #[test]
    fn for_listen_bound_address_limits_daddr() {
        let got = for_listen("tcp", Some(ip4("192.168.1.1")), &[1, 2, 3], &[]);
        assert_eq!(
            got,
            vec![Port::range(Proto::Tcp, Family::V4, 1, 3).to_addr(ip4("192.168.1.1"))]
        );
        // A bound IPv6 address forces the v6 family and is rendered
        // canonically.
        let got = for_listen("tcp4", Some(ip6("2001:db8::1")), &[443], &[]);
        assert_eq!(
            got,
            vec![Port::single(Proto::Tcp, Family::V6, 443).to_addr(ip6("2001:db8::1"))]
        );
        assert_eq!(got[0].to_string(), "TCP [2001:db8::1]:443");
    }

    #[test]
    fn for_listen_loopback_opens_nothing() {
        assert!(for_listen("tcp", Some(ip4("127.0.0.1")), &[80], &[]).is_empty());
        assert!(for_listen("tcp6", Some(ip6("::1")), &[80], &[]).is_empty());
        assert!(for_listen("udp", Some(ip4("127.9.9.9")), &[5353], &[]).is_empty());
        assert!(is_loopback(Some(ip4("127.1.2.3"))));
        assert!(is_loopback(Some(ip6("::1"))));
        assert!(!is_loopback(None));
        assert!(!is_loopback(Some(ip4("0.0.0.0"))));
        assert!(!is_loopback(Some(ip6("::"))));
        assert!(!is_loopback(Some(ip4("192.168.1.1"))));
        // The caller distinguishes "loopback" from other empty results via
        // the exported note.
        assert!(!LOOPBACK_NOTE.is_empty());
    }

    #[test]
    fn for_listen_http3_adds_udp() {
        let got = for_listen("tcp", None, &[443], &[443]);
        assert_eq!(
            got,
            vec![
                Port::single(Proto::Tcp, Family::Both, 443),
                Port::single(Proto::Udp, Family::Both, 443),
            ]
        );
        // And the other way around: a UDP listener opens TCP extras.
        let got = for_listen("udp", Some(ip6("2001:db8::5")), &[3478], &[3478]);
        assert_eq!(
            got,
            vec![
                Port::single(Proto::Udp, Family::V6, 3478).to_addr(ip6("2001:db8::5")),
                Port::single(Proto::Tcp, Family::V6, 3478).to_addr(ip6("2001:db8::5")),
            ]
        );
    }

    #[test]
    fn for_listen_invalid_input_opens_nothing() {
        assert!(for_listen("unix", None, &[80], &[]).is_empty());
        assert!(for_listen("tcp", None, &[], &[]).is_empty());
        // Port 0 means a kernel-assigned port; nothing to open.
        assert!(for_listen("tcp", None, &[0], &[]).is_empty());
        assert!(
            for_listen("tcp", None, &[0, 80], &[])
                .first()
                .unwrap()
                .first
                == 80
        );
    }

    #[test]
    fn ports_collapsed_into_ranges() {
        let got = for_listen("tcp", None, &[65535, 65535, 1, 3, 4, 5, 8000, 8001], &[]);
        assert_eq!(
            got,
            vec![
                Port::single(Proto::Tcp, Family::Both, 1),
                Port::range(Proto::Tcp, Family::Both, 3, 5),
                Port::range(Proto::Tcp, Family::Both, 8000, 8001),
                Port::single(Proto::Tcp, Family::Both, 65535),
            ]
        );
    }

    // ------------------------------------------------------------------
    // Registration normalization and rule comments
    // ------------------------------------------------------------------

    #[test]
    fn normalize_validates_sorts_and_dedups_ports() {
        let got = normalize(vec![
            Port::single(Proto::Tcp, Family::Both, 443),
            Port::single(Proto::Tcp, Family::Both, 0),
            Port::range(Proto::Tcp, Family::Both, 80, 70),
            Port::single(Proto::Tcp, Family::V6, 443).to_addr(ip4("192.168.1.1")),
            Port::single(Proto::Tcp, Family::V4, 443).to_addr(ip6("2001:db8::1")),
            Port::single(Proto::Tcp, Family::Both, 443),
        ]);
        assert_eq!(
            got,
            vec![
                Port::single(Proto::Tcp, Family::Both, 80),
                // The three 443 variants differ (family or address), so all
                // survive dedup; keys sort family-free before "4" and "6".
                Port::single(Proto::Tcp, Family::Both, 443),
                Port::single(Proto::Tcp, Family::V4, 443).to_addr(ip4("192.168.1.1")),
                Port::single(Proto::Tcp, Family::V6, 443).to_addr(ip6("2001:db8::1")),
            ]
        );
        // The port key is embeddable in comments: no colons.
        for p in &got {
            assert!(!p.key().contains(':'));
        }
    }

    #[test]
    fn rules_tagged_with_instance_and_owner() {
        let p = Port::single(Proto::Tcp, Family::V4, 34811);
        let c = comment(TEST_PREFIX, "stun:k", &p);
        assert_eq!(c, format!("{TEST_PREFIX}stun:k:{}", p.key()));
        assert_eq!(c, format!("{TEST_PREFIX}stun:k:tcp4-34811"));
        assert_eq!(owner_of(TEST_PREFIX, &c).as_deref(), Some("stun:k"));
        // A foreign instance's comments never resolve on this instance.
        assert_eq!(
            owner_of(TEST_PREFIX, "ferrumgate-open:otherinst:stun:k:tcp4-34811"),
            None
        );
        assert_eq!(owner_of(TEST_PREFIX, "!fw4: something"), None);
        assert_eq!(owner_of(TEST_PREFIX, TEST_PREFIX), None);
    }

    #[test]
    fn safe_owner_hashes_unsafe_input() {
        assert_eq!(safe_owner("web:listener-1"), "web:listener-1");
        let hashed = safe_owner("web:a\" accept; flush ruleset; \"");
        assert!(hashed.starts_with("h-"));
        assert!(!hashed.contains(['"', ';', ' ']));
        // Overlong and empty names are hashed too.
        assert!(safe_owner(&"a".repeat(49)).starts_with("h-"));
        assert!(safe_owner("").starts_with("h-"));
    }

    // ------------------------------------------------------------------
    // Target behaviour and status text
    // ------------------------------------------------------------------

    #[test]
    fn target_accepts_filters_family() {
        let both = Port::single(Proto::Tcp, Family::Both, 443);
        let v4 = Port::single(Proto::Udp, Family::V4, 3478);
        let v6 = Port::single(Proto::Tcp, Family::V6, 50663);
        let ip = nft_target("ip", "a", "input", Some("drop"), false);
        let ip6 = nft_target("ip6", "b", "input", Some("drop"), false);
        let inet = nft_target("inet", "fw4", "input", None, true);
        assert!(ip.accepts(&both) && ip.accepts(&v4) && !ip.accepts(&v6));
        assert!(ip6.accepts(&both) && ip6.accepts(&v6) && !ip6.accepts(&v4));
        assert!(inet.accepts(&v4) && inet.accepts(&v6) && inet.accepts(&both));
        assert!(ipt_input(Some("drop"), false).accepts(&both));
        assert!(!ipt_input(Some("drop"), false).accepts(&v6));
        assert!(ipt_input(Some("drop"), true).accepts(&v6));
        assert!(!ipt_input(Some("drop"), true).accepts(&v4));
    }

    #[test]
    fn target_needed_when_drop_busy_or_input() {
        assert!(fw4().needed());
        assert!(nft_target("inet", "t", "input", Some("drop"), false).needed());
        assert!(!idle_chain().needed());
        assert!(ipt_input(Some("drop"), false).needed());
        assert!(!ipt_input(Some("accept"), false).needed());
        // A chain that is not on the input hook is never written.
        let mut not_input = fw4();
        if let Target::Nft { hook_input, .. } = &mut not_input {
            *hook_input = false;
        }
        assert!(!not_input.needed());
    }

    #[test]
    fn describe_reports_idle_success_and_failure() {
        let r = OwnerResult {
            ports: vec![Port::single(Proto::Tcp, Family::Both, 443)],
            targets: vec!["iptables INPUT".to_string()],
            fail: vec![],
        };
        let (s, ok) = describe(&r, false);
        assert_eq!(s, "已在防火墙放行 TCP 443（iptables INPUT）");
        assert!(ok);

        let idle = OwnerResult {
            ports: vec![Port::single(Proto::Udp, Family::V4, 5000)],
            ..Default::default()
        };
        let (s, ok) = describe(&idle, false);
        assert!(s.contains("无需放行"));
        assert!(ok);

        let mut r = OwnerResult {
            ports: vec![Port::single(Proto::Tcp, Family::Both, 443)],
            targets: vec!["iptables INPUT".to_string()],
            ..Default::default()
        };
        r.fail.push("iptables INPUT: boom".to_string());
        let (s, ok) = describe(&r, false);
        assert!(s.contains("失败") && s.contains("TCP 443") && s.contains("boom"));
        assert!(!ok);
    }

    // ------------------------------------------------------------------
    // Reconcile against a fake backend
    // ------------------------------------------------------------------

    #[derive(Default)]
    struct FakeState {
        chains: Vec<Target>,
        rules: HashMap<String, Vec<Rule>>,
        add_err: Option<String>,
        delay: Option<Duration>,
        add_calls: usize,
        del_calls: usize,
        existing_calls: usize,
        next: usize,
    }

    struct FakeBackend {
        st: Mutex<FakeState>,
    }

    impl FakeBackend {
        fn new(chains: Vec<Target>) -> Arc<Self> {
            Arc::new(Self {
                st: Mutex::new(FakeState {
                    chains,
                    ..Default::default()
                }),
            })
        }

        fn lock(&self) -> MutexGuard<'_, FakeState> {
            lock(&self.st)
        }

        fn comments(&self, t: &Target) -> Vec<String> {
            self.lock()
                .rules
                .get(&t.key())
                .map(|rs| rs.iter().map(|r| r.comment.clone()).collect())
                .unwrap_or_default()
        }

        fn set_chains(&self, chains: Vec<Target>) {
            self.lock().chains = chains;
        }

        fn clear_rules(&self) {
            self.lock().rules.clear();
        }

        fn set_add_err(&self, msg: &str) {
            self.lock().add_err = Some(msg.to_string());
        }

        fn clear_add_err(&self) {
            self.lock().add_err = None;
        }

        fn set_delay(&self, d: Duration) {
            self.lock().delay = Some(d);
        }
    }

    impl Backend for FakeBackend {
        fn detect(&self) -> Detect {
            Detect::default()
        }

        fn targets(&self) -> Result<Vec<Target>, FwError> {
            Ok(self.lock().chains.clone())
        }

        fn existing(&self) -> Result<TargetRules, FwError> {
            let mut st = self.lock();
            st.existing_calls += 1;
            if let Some(d) = st.delay {
                drop(st);
                thread::sleep(d);
                st = self.lock();
            }
            Ok(st
                .chains
                .iter()
                .map(|t| {
                    let key = t.key();
                    let rules = st.rules.get(&key).cloned().unwrap_or_default();
                    (t.clone(), rules)
                })
                .collect())
        }

        fn add(&self, t: &Target, comment: &str, _p: &Port) -> Result<(), FwError> {
            let mut st = self.lock();
            if let Some(d) = st.delay {
                drop(st);
                thread::sleep(d);
                st = self.lock();
            }
            st.add_calls += 1;
            if let Some(e) = st.add_err.clone() {
                return Err(FwError::CommandFailed(e));
            }
            st.next += 1;
            let reference = format!("h{}", st.next);
            st.rules.entry(t.key()).or_default().push(Rule {
                comment: comment.to_string(),
                reference,
            });
            Ok(())
        }

        fn del(&self, t: &Target, rule: &Rule) -> Result<(), FwError> {
            let mut st = self.lock();
            st.del_calls += 1;
            let rules = st.rules.entry(t.key()).or_default();
            match rules.iter().position(|r| r.reference == rule.reference) {
                Some(i) => {
                    rules.remove(i);
                    Ok(())
                }
                None => Err(FwError::CommandFailed("not found".to_string())),
            }
        }
    }

    fn test_manager(be: Arc<dyn Backend>) -> Manager {
        // `looping = true` keeps the periodic thread out of the test.
        Manager::with_backend(
            be,
            Duration::from_secs(3600),
            Some(TEST_PREFIX.to_string()),
            true,
        )
    }

    fn test_group(prefix: &'static str, manager: Manager) -> Arc<Group> {
        Arc::new(Group {
            shared: Arc::new(GroupShared {
                prefix,
                manager,
                state: Mutex::new(GroupState::default()),
                op: Mutex::new(()),
            }),
        })
    }

    fn wait_idle(group: &Group) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let st = lock(&group.shared.state);
            if !st.running && st.pending.is_empty() {
                return;
            }
            drop(st);
            thread::sleep(Duration::from_millis(5));
        }
        panic!("group worker did not settle within 5s");
    }

    #[test]
    fn reconcile_adds_missing_and_removes_stale() {
        let fw4 = fw4();
        let idle = idle_chain();
        let be = FakeBackend::new(vec![fw4.clone(), idle.clone()]);
        // Leftover rule of an owner that is no longer registered.
        {
            let mut st = be.lock();
            st.rules.insert(
                fw4.key(),
                vec![Rule {
                    comment: comment(
                        TEST_PREFIX,
                        "stun:old",
                        &Port::single(Proto::Tcp, Family::Both, 1000),
                    ),
                    reference: "z".to_string(),
                }],
            );
        }
        let m = test_manager(be.clone());

        let (status, ok) = m.set(
            "stun:k1",
            vec![Port::single(Proto::Tcp, Family::Both, 34811)],
        );
        assert!(ok, "{status}");
        assert!(
            status.contains("TCP 34811") && status.contains("nftables inet fw4 input"),
            "{status}"
        );
        assert_eq!(
            be.comments(&fw4),
            vec![format!("{TEST_PREFIX}stun:k1:tcp-34811")]
        );
        // An idle accept-policy chain is never written.
        assert!(be.comments(&idle).is_empty());

        // Registering the same ports again does not duplicate rules.
        m.set(
            "stun:k1",
            vec![Port::single(Proto::Tcp, Family::Both, 34811)],
        );
        assert_eq!(be.comments(&fw4).len(), 1);

        // Rules flushed by a firewall reload are restored by the next
        // reconcile.
        be.clear_rules();
        m.inner.reconcile();
        assert_eq!(
            be.comments(&fw4),
            vec![format!("{TEST_PREFIX}stun:k1:tcp-34811")]
        );

        m.clear("stun:k1");
        assert!(be.comments(&fw4).is_empty());
        assert_eq!(m.status("stun:k1"), "");
    }

    #[test]
    fn reconcile_reports_failure_and_idle_firewall() {
        let be = FakeBackend::new(vec![]);
        let m = test_manager(be.clone());
        // No chains at all: nothing needs opening.
        let (s, ok) = m.set("a", vec![Port::single(Proto::Udp, Family::Both, 5000)]);
        assert!(ok && s.contains("无需放行"), "{s}");

        be.set_chains(vec![ipt_input(Some("drop"), false)]);
        be.set_add_err("boom");
        let (s, ok) = m.set("a", vec![Port::single(Proto::Udp, Family::Both, 5000)]);
        assert!(!ok);
        assert!(s.contains("失败") && s.contains("boom"), "{s}");
    }

    #[test]
    fn reconcile_keeps_other_instances() {
        let fw4 = Target::Nft {
            table: "fw4".to_string(),
            family: "inet".to_string(),
            chain: "input".to_string(),
            hook_input: true,
            policy: Some("drop".to_string()),
            busy: false,
        };
        let foreign = comment(
            "ferrumgate-open:otherinst:",
            "stun:x",
            &Port::single(Proto::Udp, Family::Both, 2000),
        );
        let be = FakeBackend::new(vec![fw4.clone()]);
        {
            let mut st = be.lock();
            st.rules.insert(
                fw4.key(),
                vec![Rule {
                    comment: foreign.clone(),
                    reference: "f".to_string(),
                }],
            );
        }
        let m = test_manager(be.clone());
        m.set("stun:k", vec![Port::single(Proto::Tcp, Family::Both, 3000)]);
        m.clear("stun:k");
        // A sweep-style reconcile without registrations must not touch the
        // foreign rule either.
        m.inner.reconcile();
        assert_eq!(be.comments(&fw4), vec![foreign]);
    }

    #[test]
    fn reconcile_migrates_legacy_comments() {
        let fw4 = fw4();
        let be = FakeBackend::new(vec![fw4.clone()]);
        {
            let mut st = be.lock();
            st.rules.insert(
                fw4.key(),
                vec![Rule {
                    comment: format!("{TEST_PREFIX}stun:k:tcp:34811"),
                    reference: "old".to_string(),
                }],
            );
        }
        let m = test_manager(be.clone());
        m.set("stun:k", vec![Port::single(Proto::Tcp, Family::V4, 34811)]);
        assert_eq!(
            be.comments(&fw4),
            vec![format!("{TEST_PREFIX}stun:k:tcp4-34811")]
        );
    }

    #[test]
    fn reconcile_writes_each_family_to_matching_chains() {
        let inet = fw4();
        let ip = nft_target("ip", "a", "input", Some("drop"), false);
        let ip6 = nft_target("ip6", "b", "input", Some("drop"), false);
        let ipt = ipt_input(Some("drop"), false);
        let ip6t = ipt_input(Some("drop"), true);
        let be = FakeBackend::new(vec![
            inet.clone(),
            ip.clone(),
            ip6.clone(),
            ipt.clone(),
            ip6t.clone(),
        ]);
        let m = test_manager(be.clone());
        let ports = vec![
            Port::single(Proto::Tcp, Family::V6, 50663),
            Port::single(Proto::Udp, Family::V4, 3478),
            Port::range(Proto::Tcp, Family::Both, 8000, 8010),
        ];
        let (status, ok) = m.set("web:k", ports);
        assert!(ok, "{status}");
        // The inet chain carries all three; the single-family chains two
        // (the range plus their own family's port).
        assert_eq!(be.comments(&inet).len(), 3);
        for t in [&ip, &ip6, &ipt, &ip6t] {
            assert_eq!(be.comments(t).len(), 2, "{}", t.key());
        }
        // IPv6-only ports never land on IPv4 chains.
        for c in be.comments(&ip) {
            assert!(!c.contains("tcp6-"), "{c}");
        }
        assert!(
            status.contains("TCP 8000-8010")
                && status.contains("TCP 50663 (IPv6)")
                && status.contains("UDP 3478 (IPv4)")
        );

        // Down to a single IPv6 port: the IPv4 chains lose every rule.
        m.set("web:k", vec![Port::single(Proto::Tcp, Family::V6, 50663)]);
        assert!(be.comments(&ip).is_empty() && be.comments(&ipt).is_empty());
        assert_eq!(be.comments(&ip6).len(), 1);
        assert_eq!(be.comments(&inet).len(), 1);

        // Only IPv4 chains available: an IPv6-only registration has
        // nothing to open.
        let ip_only = nft_target("ip", "a", "input", Some("drop"), false);
        let be2 = FakeBackend::new(vec![ip_only.clone()]);
        let m2 = test_manager(be2.clone());
        let (s, ok) = m2.set("web:k", vec![Port::single(Proto::Tcp, Family::V6, 50663)]);
        assert!(ok && s.contains("无需放行"), "{s}");
        assert!(be2.comments(&ip_only).is_empty());
    }

    #[test]
    fn manager_set_empty_ports_revokes_owner() {
        let fw4 = fw4();
        let be = FakeBackend::new(vec![fw4.clone()]);
        let m = test_manager(be.clone());
        let owner = safe_owner("web:a\" accept; flush ruleset; \"");
        assert!(owner.starts_with("h-"));
        m.set(
            owner.clone().as_str(),
            vec![Port::single(Proto::Tcp, Family::Both, 1)],
        );
        let comments = be.comments(&fw4);
        assert_eq!(comments.len(), 1);
        assert!(!comments[0].contains(['"', ';', ' ']));
        // An empty port list revokes the owner entirely.
        m.set(&owner, vec![]);
        assert!(be.comments(&fw4).is_empty());
        assert_eq!(m.status(&owner), "");
    }

    #[test]
    fn want_returns_immediately_and_runs_in_order() {
        let fw4 = fw4();
        let be = FakeBackend::new(vec![fw4.clone()]);
        be.set_delay(Duration::from_millis(30));
        let g = test_group("web", test_manager(be.clone()));
        let start = Instant::now();
        g.want("a", vec![Port::single(Proto::Tcp, Family::Both, 443)]);
        g.want("b", vec![Port::single(Proto::Tcp, Family::Both, 8443)]);
        // Both writes take ~120ms in the worker; want() returned at once.
        assert!(
            start.elapsed() < Duration::from_millis(10),
            "{:?}",
            start.elapsed()
        );
        wait_idle(&g);
        let comments = be.comments(&fw4);
        assert_eq!(comments.len(), 2);
        assert!(
            comments[0].contains(":a:") && comments[1].contains(":b:"),
            "{comments:?}"
        );
    }

    #[test]
    fn group_want_replaces_ports_and_revokes() {
        let fw4 = fw4();
        let be = FakeBackend::new(vec![fw4.clone()]);
        let g = test_group("web", test_manager(be.clone()));

        g.want("a", vec![Port::single(Proto::Tcp, Family::V6, 50663)]);
        g.want("b", vec![Port::single(Proto::Tcp, Family::Both, 443)]);
        wait_idle(&g);
        assert_eq!(be.comments(&fw4).len(), 2);
        assert!(
            g.status("a").contains("TCP 50663 (IPv6)"),
            "{}",
            g.status("a")
        );

        // Changing the ports replaces the rules.
        g.want("a", vec![Port::single(Proto::Tcp, Family::V6, 50664)]);
        wait_idle(&g);
        let joined = be.comments(&fw4).join(",");
        assert!(
            !joined.contains("50663") && joined.contains("tcp6-50664"),
            "{joined}"
        );

        // Revoking clears the rules and the status; revoking an unknown
        // key does nothing.
        g.want("a", vec![]);
        g.want("never", vec![]);
        wait_idle(&g);
        assert_eq!(g.status("a"), "");
        assert_eq!(g.status("never"), "");
        assert_eq!(be.comments(&fw4).len(), 1);

        // Rapid toggles converge on the last registration.
        for _ in 0..20 {
            g.want("b", vec![]);
            g.want("b", vec![Port::single(Proto::Tcp, Family::Both, 8443)]);
        }
        wait_idle(&g);
        let joined = be.comments(&fw4).join(",");
        assert_eq!(joined.matches("web:b:").count(), 1, "{joined}");
        assert!(joined.contains("tcp-8443"), "{joined}");
    }

    #[test]
    fn clear_all_revokes_everything_on_stop() {
        let fw4 = fw4();
        let be = FakeBackend::new(vec![fw4.clone()]);
        let g = test_group("pf", test_manager(be.clone()));
        // clear_all races with the worker on purpose: it must wait for the
        // in-flight write and revoke it too.
        g.want("a", vec![Port::range(Proto::Udp, Family::Both, 5000, 5010)]);
        g.want("b", vec![Port::single(Proto::Tcp, Family::Both, 22)]);
        g.clear_all();
        wait_idle(&g);
        assert!(be.comments(&fw4).is_empty());
        assert_eq!(g.status("a"), "");
        assert_eq!(g.status("b"), "");
    }

    #[test]
    fn group_failed_status_reports_reason() {
        let ipt = ipt_input(Some("drop"), false);
        let be = FakeBackend::new(vec![ipt.clone()]);
        be.set_add_err("没有修改防火墙的权限");
        let g = test_group("web", test_manager(be.clone()));
        g.want("a", vec![Port::single(Proto::Tcp, Family::Both, 443)]);
        wait_idle(&g);
        assert!(g.failed("a"));
        assert!(g.status("a").contains("失败"), "{}", g.status("a"));
        assert!(!g.failed("never"));

        // Recovering: the next registration succeeds and clears the flag.
        be.clear_add_err();
        g.want("a", vec![Port::single(Proto::Tcp, Family::Both, 8443)]);
        wait_idle(&g);
        assert!(!g.failed("a"));
        assert!(!g.failed("never"));
    }

    #[test]
    fn reconcile_runs_every_30s() {
        assert_eq!(RECONCILE_INTERVAL, Duration::from_secs(30));
        let fw4 = fw4();
        let be = FakeBackend::new(vec![fw4.clone()]);
        // A short interval stands in for the 30s ticker; the loop flag is
        // left off so the periodic thread actually starts.
        let m = Manager::with_backend(
            be.clone(),
            Duration::from_millis(20),
            Some(TEST_PREFIX.to_string()),
            false,
        );
        m.set("a", vec![Port::single(Proto::Tcp, Family::Both, 443)]);
        let deadline = Instant::now() + Duration::from_secs(5);
        while be.lock().existing_calls < 3 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            be.lock().existing_calls >= 3,
            "periodic reconcile did not run"
        );
        m.clear("a"); // lets the loop thread retire
    }

    #[test]
    fn unsupported_reports_not_linux() {
        let be = Arc::new(UnsupportedBackend);
        let m = test_manager(be.clone());
        let (s, ok) = m.set("web:x", vec![Port::single(Proto::Tcp, Family::Both, 443)]);
        assert!(!ok);
        assert!(s.contains("只支持 Linux"), "{s}");
        assert_eq!(be.detect(), Detect::default());
        assert_eq!(be.targets(), Err(FwError::Unsupported));
        assert_eq!(be.existing(), Err(FwError::Unsupported));
    }

    // ------------------------------------------------------------------
    // Digest primitive
    // ------------------------------------------------------------------

    #[test]
    fn sha256_matches_fips_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // 56 bytes: forces the extra padding block.
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    // ------------------------------------------------------------------
    // Command-backend text generation and parsing (pure, every platform)
    // ------------------------------------------------------------------

    fn nft_t(family: &str) -> Target {
        Target::Nft {
            table: "t".to_string(),
            family: family.to_string(),
            chain: "input".to_string(),
            hook_input: true,
            policy: None,
            busy: true,
        }
    }

    #[test]
    fn nft_match_renders_family_addr_and_ports() {
        let both = Port::single(Proto::Tcp, Family::Both, 443);
        let v4 = Port::single(Proto::Udp, Family::V4, 3478);
        let v6 = Port::single(Proto::Tcp, Family::V6, 50663);
        assert_eq!(nft_match(&nft_t("inet"), &both), "tcp dport 443");
        assert_eq!(
            nft_match(&nft_t("inet"), &v4),
            "meta nfproto ipv4 udp dport 3478"
        );
        assert_eq!(
            nft_match(&nft_t("inet"), &v6),
            "meta nfproto ipv6 tcp dport 50663"
        );
        // A dedicated ip6 chain only ever sees v6: no nfproto needed.
        assert_eq!(nft_match(&nft_t("ip6"), &v6), "tcp dport 50663");
        let ranged = Port::range(Proto::Tcp, Family::V6, 8000, 8010).to_addr(ip6("2001:db8::1"));
        assert_eq!(
            nft_match(&nft_t("inet"), &ranged),
            "ip6 daddr 2001:db8::1 tcp dport 8000-8010"
        );
        let bound = Port::single(Proto::Tcp, Family::V4, 80).to_addr(ip4("192.168.1.1"));
        assert_eq!(
            nft_match(&nft_t("inet"), &bound),
            "ip daddr 192.168.1.1 tcp dport 80"
        );
    }

    #[test]
    fn ipt_args_render_range_and_addr() {
        let p = Port::range(Proto::Tcp, Family::V4, 8000, 8010).to_addr(ip4("10.0.0.1"));
        assert_eq!(
            ipt_args(&p).join(" "),
            "-p tcp --dport 8000:8010 -d 10.0.0.1"
        );
        let single = Port::single(Proto::Udp, Family::Both, 3478);
        assert_eq!(ipt_args(&single).join(" "), "-p udp --dport 3478");
    }

    #[test]
    fn parse_nft_chains_filters_input_chains() {
        let raw = r#"{"nftables":[{"metainfo":{"version":"1.0.6"}},
            {"chain":{"family":"inet","table":"fw4","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"accept"}},
            {"chain":{"family":"inet","table":"fw4","name":"input_wan","handle":2}},
            {"chain":{"family":"inet","table":"gately","name":"input","type":"filter","hook":"input","prio":-10,"policy":"accept"}},
            {"chain":{"family":"ip6","table":"x","name":"input","type":"filter","hook":"input","policy":"drop"}},
            {"chain":{"family":"inet","table":"firewalld","name":"filter_INPUT","type":"filter","hook":"input","policy":"accept"}},
            {"chain":{"family":"ip","table":"nat","name":"PREROUTING","type":"nat","hook":"prerouting","policy":"accept"}}]}"#;
        let list = parse_nft_chains(raw).unwrap();
        assert_eq!(list.len(), 3);
        let mut it = list.into_iter();
        let Target::Nft {
            table,
            family,
            policy,
            ..
        } = it.next().unwrap()
        else {
            unreachable!()
        };
        assert_eq!(
            (table.as_str(), family.as_str(), policy.as_deref()),
            ("fw4", "inet", Some("accept"))
        );
        let Target::Nft { family, policy, .. } = it.next().unwrap() else {
            unreachable!()
        };
        assert_eq!((family.as_str(), policy.as_deref()), ("ip6", Some("drop")));
        let Target::Nft { chain, .. } = it.next().unwrap() else {
            unreachable!()
        };
        assert_eq!(chain, "filter_INPUT");
        // Unparseable output is an explicit parse error.
        assert!(parse_nft_chains("not json").is_err());
    }

    #[test]
    fn parse_nft_rules_extracts_tagged_handles() {
        let raw = r#"{"nftables":[{"metainfo":{}},
            {"rule":{"family":"inet","table":"fw4","chain":"input","handle":7,"comment":"ferrumgate-open:stun:k:tcp:1","expr":[]}},
            {"rule":{"family":"inet","table":"fw4","chain":"input","handle":8,"comment":"!fw4: Handle wan IPv4/IPv6 input traffic","expr":[]}}]}"#;
        let (busy, rules) = parse_nft_rules(raw).unwrap();
        assert!(busy);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].reference, "7");
        assert!(rules[0].comment.starts_with(COMMENT_PREFIX));
        assert!(matches!(parse_nft_rules("{"), Err(FwError::Parse(_))));
    }

    #[test]
    fn parse_iptables_extracts_rules_and_busy() {
        let out = "-P INPUT DROP\n\
            -A INPUT -p tcp -m tcp --dport 34811 -m comment --comment \"ferrumgate-open:testinst:stun:k:tcp4-34811\" -j ACCEPT\n\
            -A INPUT -i lo -j ACCEPT\n";
        let (t, rules) = parse_iptables(out);
        let Target::Iptables {
            v6: false,
            policy,
            busy,
        } = &t
        else {
            unreachable!()
        };
        assert_eq!(policy.as_deref(), Some("drop"));
        assert!(*busy);
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].reference,
            "-p tcp -m tcp --dport 34811 -m comment --comment ferrumgate-open:testinst:stun:k:tcp4-34811 -j ACCEPT"
        );
    }

    #[test]
    fn parse_saved_filter_tracks_jump_position() {
        let own = "GTLY_OPEN_0123abcd";
        let base = format!(
            "*filter\n:INPUT DROP [0:0]\n:{own} - [0:0]\n-A INPUT -j {own}\n-A {own} -p tcp -m tcp --dport 443 -j ACCEPT\nCOMMIT\n"
        );
        let sv = parse_saved_filter(&base, own);
        assert_eq!(sv.policy.as_deref(), Some("drop"));
        assert!(sv.has_own);
        assert_eq!(
            sv.own,
            vec!["-p tcp -m tcp --dport 443 -j ACCEPT".to_string()]
        );
        assert_eq!(sv.jumps, 1);
        assert_eq!(sv.jump_pos, Some(0));
        assert!(sv.jump_ok());
        assert!(!sv.busy(own));

        // A foreign rule ahead of the jump breaks the position.
        let with_foreign = format!(
            "*filter\n:INPUT DROP [0:0]\n-A INPUT -j INPUT_FIREWALL\n-A INPUT -j {own}\n-A {own} -p tcp -m tcp --dport 443 -j ACCEPT\nCOMMIT\n"
        );
        let sv = parse_saved_filter(&with_foreign, own);
        assert!(!sv.jump_ok());
        assert!(sv.busy(own));

        // Another instance's chain jump ahead of ours is tolerated.
        let other_ahead = format!(
            "*filter\n:INPUT DROP [0:0]\n:GTLY_OPEN_deadbeef - [0:0]\n-A INPUT -j GTLY_OPEN_deadbeef\n-A INPUT -j {own}\n-A {own} -p tcp -m tcp --dport 443 -j ACCEPT\nCOMMIT\n"
        );
        let sv = parse_saved_filter(&other_ahead, own);
        assert!(sv.jump_ok());
        assert!(sv.busy(own));
    }

    #[test]
    fn rule_key_normalizes_saved_forms() {
        let p = Port::single(Proto::Tcp, Family::V4, 443).to_addr(ip4("192.168.1.2"));
        assert_eq!(
            rule_key(
                false,
                "-d 192.168.1.2/32 -p tcp -m tcp --dport 443 -j ACCEPT"
            ),
            port_key(false, &p)
        );
        let p6 = Port::range(Proto::Udp, Family::V6, 3478, 3480).to_addr(ip6("2001:db8::1"));
        assert_eq!(
            rule_key(
                true,
                "-d 2001:db8::1/128 -p udp -m udp --dport 3478:3480 -j ACCEPT"
            ),
            port_key(true, &p6)
        );
        assert_ne!(
            rule_key(false, "-p tcp -m tcp --dport 443 -j ACCEPT"),
            rule_key(true, "-p tcp -m tcp --dport 443 -j ACCEPT")
        );
    }

    #[test]
    fn kernel_no_nft_ignores_permission_errors() {
        assert!(kernel_no_nft(
            "netlink: Error: cache initialization failed: Invalid argument"
        ));
        assert!(kernel_no_nft(
            "ip: Address family not supported by protocol"
        ));
        // Permission problems must not look like a missing nf_tables: they
        // are reported instead of falling back to legacy iptables.
        assert!(!kernel_no_nft("Operation not permitted"));
        assert!(!kernel_no_nft("syntax error"));
    }

    #[test]
    fn classify_maps_permission_errors() {
        assert_eq!(
            classify("Permission denied (os error 13)"),
            FwError::Permission
        );
        assert_eq!(classify("Operation not permitted"), FwError::Permission);
        assert_eq!(classify("boom"), FwError::CommandFailed("boom".to_string()));
        let long = "x".repeat(400);
        assert_eq!(
            classify(&long),
            FwError::CommandFailed("x".repeat(300)),
            "overlong output is truncated"
        );
    }

    // ------------------------------------------------------------------
    // Linux-only: real command execution probes
    // ------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    mod linux_probes {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicUsize, Ordering};

        static SCRATCH: AtomicUsize = AtomicUsize::new(0);

        fn scratch_dir(tag: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "fg-net-fwopen-{}-{}-{}",
                std::process::id(),
                tag,
                SCRATCH.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).unwrap();
            dir
        }

        #[test]
        fn detect_reports_missing_binaries() {
            let dir = scratch_dir("detect");
            let dirs = vec![dir.clone()];
            assert_eq!(crate::fwopen::linux::look_path_in(&dirs, "nft"), None);
            // Present but not executable: not a candidate.
            let fake = dir.join("nft");
            fs::write(&fake, b"").unwrap();
            fs::set_permissions(&fake, fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(crate::fwopen::linux::look_path_in(&dirs, "nft"), None);
            // Executable: found.
            fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(crate::fwopen::linux::look_path_in(&dirs, "nft"), Some(fake));
            fs::remove_dir_all(&dir).ok();
        }

        #[test]
        fn commands_run_as_argument_arrays() {
            // Probes only: no firewall state is touched. Uses the argument
            // array path with plain coreutils.
            if !Path::new("/bin/echo").is_file() {
                return;
            }
            let out =
                crate::fwopen::linux::run(None, Path::new("/bin/echo"), &["fwopen-probe"]).unwrap();
            assert_eq!(out, "fwopen-probe\n");
            if !Path::new("/bin/cat").is_file() {
                return;
            }
            let out =
                crate::fwopen::linux::run(Some("hello"), Path::new("/bin/cat"), &[] as &[&str])
                    .unwrap();
            assert_eq!(out, "hello");
        }
    }
}
