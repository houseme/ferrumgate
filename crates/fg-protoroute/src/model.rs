//! The `protoroute.json` model (WP-35 §3.2): module settings, one routing
//! rule per shared public port and its ordered routes. JSON field names
//! follow upstream (camelCase); every struct denies unknown fields and
//! fills defaults so a partially written file still loads.

use serde::{Deserialize, Serialize};

/// Shared ceilings and defaults for the module (conventions §2: every
/// listener, queue and buffer limit lives here).
pub mod limits {
    use std::time::Duration;

    /// Regular protocols are decided within this many sniffed bytes
    /// (upstream: 16 KiB).
    pub const SNIFF_BUFFER_MAX: usize = 16 * 1024;
    /// HTTP request headers scanned for `Host` (upstream: 32 KiB).
    pub const HTTP_HEAD_MAX: usize = 32 * 1024;
    /// One sniff read from the client (upstream: 4096).
    pub const READ_CHUNK: usize = 4096;
    /// A ClientHello may span records up to this size (upstream: 64 KiB).
    pub const CLIENT_HELLO_MAX: usize = 64 * 1024;
    /// HTTP request line cap (upstream: 8 KiB).
    pub const REQUEST_LINE_MAX: usize = 8 * 1024;
    /// A Minecraft handshake packet is between these sizes (upstream).
    pub const MINECRAFT_MIN: usize = 7;
    pub const MINECRAFT_MAX: usize = 2048;
    /// SPA packets are a single base64-ish line of bounded length
    /// (FerrumGate values; upstream reads the same bounded line shape).
    pub const SPA_MIN: usize = 64;
    pub const SPA_MAX: usize = 4096;
    /// `sniffTimeout` seconds: `0` reads as this default (upstream: 5).
    pub const SNIFF_TIMEOUT_DEFAULT_SECS: f32 = 5.0;
    /// `sniffTimeout` range in seconds (upstream: 0.1 - 60, one decimal).
    pub const SNIFF_TIMEOUT_MIN_SECS: f32 = 0.1;
    pub const SNIFF_TIMEOUT_MAX_SECS: f32 = 60.0;
    /// `defaultMaxConnections` (upstream: 256).
    pub const DEFAULT_MAX_CONNECTIONS: u32 = 256;
    /// `dialTimeout` seconds: `0` reads as this default (upstream: 5).
    pub const DIAL_TIMEOUT_DEFAULT_SECS: u32 = 5;
    /// Per-rule route count (FerrumGate protection).
    pub const ROUTES_MAX: usize = 128;
    /// Rules per file (FerrumGate protection, same as the other modules).
    pub const RULES_MAX: usize = 64;
    /// Targets of one route or of the default target (FerrumGate
    /// protection).
    pub const TARGETS_MAX: usize = 16;
    /// Listening ports per rule (FerrumGate protection).
    pub const PORTS_MAX: usize = 64;
    /// Source access entries per list (FerrumGate protection).
    pub const ACCESS_MAX: usize = 256;
    /// Rule name length (FerrumGate protection).
    pub const NAME_MAX_CHARS: usize = 128;
    /// Route name length (FerrumGate protection).
    pub const ROUTE_NAME_MAX_CHARS: usize = 128;
    /// Group name length (FerrumGate protection).
    pub const GROUP_MAX_CHARS: usize = 64;
    /// Remark length (FerrumGate protection).
    pub const REMARK_MAX_CHARS: usize = 512;
    /// One target address entry length (FerrumGate protection).
    pub const TARGET_MAX_CHARS: usize = 255;
    /// Domains per route (FerrumGate protection).
    pub const DOMAINS_MAX: usize = 64;
    /// ALPN ids per route (FerrumGate protection).
    pub const ALPN_MAX: usize = 16;
    /// Grace period for in-flight connections when the module drains.
    pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(15);
    /// Pause between accept-error retries before a listener is declared
    /// failed.
    pub const ACCEPT_RETRY: Duration = Duration::from_millis(200);
    /// Extra time granted to reading the rest of a SPA packet after
    /// detection (the client is expected to send it in one go and close).
    pub const SPA_READ_TIMEOUT: Duration = Duration::from_secs(2);
}

/// `protoroute.json`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct FileConfig {
    pub settings: Settings,
    pub rules: Vec<Rule>,
}

/// Module settings: the shared defaults rules inherit when they leave a
/// limit unset.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Settings {
    /// Module switch: disabled rules never listen.
    pub enable: bool,
    /// Connection cap used when a rule leaves `maxConnections` at 0
    /// (`0` normalizes to [`limits::DEFAULT_MAX_CONNECTIONS`]).
    pub default_max_connections: u32,
    /// Per-source cap used when a rule leaves `maxConnsPerSource` at 0
    /// (`0` reads as half the rule's connection cap).
    pub default_max_conns_per_source: u32,
    /// Sources exempt from the per-source cap (IP / CIDR); loopback and
    /// private ranges are always exempt.
    pub per_source_exempt: Vec<String>,
    /// Outbound dial timeout in seconds (`0` normalizes to
    /// [`limits::DIAL_TIMEOUT_DEFAULT_SECS`]).
    pub dial_timeout: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enable: true,
            default_max_connections: 0,
            default_max_conns_per_source: 0,
            per_source_exempt: Vec::new(),
            dial_timeout: 0,
        }
    }
}

/// Address family a rule listens on (TCP only; upstream supports no UDP).
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Net {
    /// Dual stack.
    #[default]
    Tcp,
    /// IPv4 only.
    Tcp4,
    /// IPv6 only.
    Tcp6,
}

impl Net {
    /// `tcp` / `tcp4` / `tcp6`, the spelling used in status views.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Tcp4 => "tcp4",
            Self::Tcp6 => "tcp6",
        }
    }
}

/// PROXY protocol announced to a target before the passthrough stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
    /// Announce nothing.
    #[default]
    None,
    /// PROXY protocol version 1 (text).
    V1,
    /// PROXY protocol version 2 (binary).
    V2,
}

/// One routable application protocol. 21 identifiers (upstream), including
/// `spa` (port-knock packets) and `timeout` (server-speaks-first
/// protocols, matched when the client sends nothing).
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Tls,
    Http,
    Ssh,
    Rdp,
    Socks,
    OpenVpn,
    Xmpp,
    Mqtt,
    #[serde(alias = "postgresql")]
    Postgres,
    Rtsp,
    Sip,
    Minecraft,
    Redis,
    Amqp,
    Smb,
    Git,
    BitTorrent,
    Adb,
    Irc,
    Spa,
    Timeout,
}

impl Protocol {
    /// Lower-case wire name (`tls`, `postgres`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Http => "http",
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::Socks => "socks",
            Self::OpenVpn => "openvpn",
            Self::Xmpp => "xmpp",
            Self::Mqtt => "mqtt",
            Self::Postgres => "postgres",
            Self::Rtsp => "rtsp",
            Self::Sip => "sip",
            Self::Minecraft => "minecraft",
            Self::Redis => "redis",
            Self::Amqp => "amqp",
            Self::Smb => "smb",
            Self::Git => "git",
            Self::BitTorrent => "bittorrent",
            Self::Adb => "adb",
            Self::Irc => "irc",
            Self::Spa => "spa",
            Self::Timeout => "timeout",
        }
    }

    /// Protocols routed by domain (SNI / Host / Minecraft server address).
    /// Every other protocol has at most one enabled route per rule.
    pub fn is_domain_routed(self) -> bool {
        matches!(self, Self::Tls | Self::Http | Self::Minecraft)
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Source access control of a rule (checked before sniffing; a denied
/// connection is closed without reading a byte).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct AccessConfig {
    /// Enforce the lists.
    pub enable: bool,
    /// Allowed sources (IP / CIDR); empty with `enable` allows all.
    pub whitelist: Vec<String>,
    /// Denied sources (IP / CIDR); deny wins over allow.
    pub blacklist: Vec<String>,
}

/// One route of a rule: a match condition plus the passthrough target.
/// Order is display order only; matching priority is defined by
/// [`crate::router`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Route {
    pub name: String,
    /// Disabled routes keep their configuration but never match and never
    /// take part in conflict checks.
    pub disabled: bool,
    pub protocol: Protocol,
    /// Domains (TLS SNI / HTTP Host / Minecraft server address); empty
    /// matches every connection of the protocol, including ones without a
    /// domain. `*` matches any carried domain.
    pub domains: Vec<String>,
    /// ALPN ids (TLS only): more specific than the same route without
    /// ALPN.
    pub alpn: Vec<String>,
    /// Passthrough targets in failover order (`host` or `host:port`; a
    /// bare host uses `targetPort`).
    pub target_addresses: Vec<String>,
    /// Target port (`0` = same port the client connected to).
    pub target_port: u16,
    pub proxy_protocol: ProxyProtocol,
    /// Port-knock rule key that must have a live grant for this source
    /// before the route applies. `spa` routes cannot require a knock.
    pub knock: Option<String>,
}

/// One rule: listeners on a shared public port plus its routes and the
/// default target for connections that match no route.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Rule {
    pub key: String,
    pub name: String,
    pub enable: bool,
    pub group: String,
    /// Address families to listen on (TCP only).
    pub protocols: Vec<Net>,
    /// Bind address (`""` = all interfaces).
    pub listen_address: String,
    /// Comma-separated ports / ranges, e.g. `443,8443` or `8000-8010`.
    pub listen_ports: String,
    /// Register the listening ports with the automatic firewall opener
    /// (WP-37).
    pub auto_firewall: bool,
    /// Routes in display order; matching priority is [`crate::router`]'s.
    pub routes: Vec<Route>,
    /// Default target: addresses in failover order; empty = connections
    /// with no matching route are dropped.
    pub target_addresses: Vec<String>,
    /// Default-target ports (comma separated), filled from legacy
    /// `host:port` entries by normalization.
    pub target_ports: String,
    /// PROXY protocol announced to the default target.
    pub proxy_protocol: ProxyProtocol,
    /// Sniff window in seconds (`0` → 5, range 0.1 - 60, one decimal).
    pub sniff_timeout: f32,
    /// Connection cap (`0` = settings default, itself 256).
    pub max_connections: u32,
    /// Per-source cap (`0` = half of the effective connection cap).
    pub max_conns_per_source: u32,
    /// Port-knock rule key gating the whole rule (checked before sniff).
    pub knock: Option<String>,
    pub access: AccessConfig,
    pub remark: String,
}
