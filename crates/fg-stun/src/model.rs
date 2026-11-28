//! The `stun.json` model (WP-42): module settings and the traversal rule
//! collection. JSON field names follow upstream (camelCase); every struct
//! denies unknown fields and fills defaults so a partially written file
//! still loads. The UPnP / NAT-PMP mapping, built-in forwarding and
//! webhook / script notification knobs are carried here so the file
//! round-trips; their engines land with the remaining WP-42 steps.

use serde::{Deserialize, Serialize};

/// Shared ceilings and defaults for the module (conventions §2: every
/// background limit lives here).
pub mod limits {
    use std::time::Duration;

    /// STUN wire ceiling (RFC 5389 / upstream `stun.go`).
    pub const MAX_MESSAGE_SIZE: usize = 2048;
    /// Binding transaction retransmits inside one `stunTimeout` window.
    pub const TRANSMIT_ATTEMPTS: u32 = 2;
    /// Reachability check failures tolerated before a channel gives up.
    pub const CHECK_FAILURES_BEFORE_LOST: u32 = 3;
    /// Default for `heartbeatInterval` / `stunTimeout` / `retryInterval`
    /// (milliseconds; `0` normalizes to this).
    pub const INTERVAL_DEFAULT_MS: u32 = 3000;
    /// Floor for the three interval knobs in milliseconds.
    pub const INTERVAL_MIN_MS: u32 = 500;
    /// Re-query period for the public address in seconds (default).
    pub const ADDR_CHECK_INTERVAL_DEFAULT_SECS: u32 = 60;
    /// Values below this normalize to the default.
    pub const ADDR_CHECK_INTERVAL_MIN_SECS: u32 = 10;
    /// TCP keep-alive targets without a port default to 80.
    pub const KEEP_ALIVE_DEFAULT_PORT: u16 = 80;
    /// STUN servers without a port default to 3478.
    pub const STUN_DEFAULT_PORT: u16 = 3478;
    /// Upstream default STUN servers (visible, editable and switchable in
    /// the settings; an empty list normalizes to these).
    pub const DEFAULT_STUN_SERVERS: [&str; 5] = [
        "stun.nextcloud.com:3478",
        "stun.hot-chilli.net:3478",
        "stun.voip.blackberry.com:3478",
        "stun.radiojar.com:3478",
        "stun.freeswitch.org:3478",
    ];
    /// Upstream default TCP keep-alive targets (port defaults to 80).
    pub const DEFAULT_KEEP_ALIVE_SERVERS: [&str; 2] = ["www.baidu.com:80", "www.qq.com:80"];
    /// FerrumGate protection: number of rules per file.
    pub const RULES_MAX: usize = 64;
    /// FerrumGate protection: server / target list length.
    pub const SERVERS_MAX: usize = 16;
    /// FerrumGate protection: rule name length.
    pub const NAME_MAX_CHARS: usize = 128;
    /// FerrumGate protection: group name length.
    pub const GROUP_MAX_CHARS: usize = 64;
    /// FerrumGate protection: remark length.
    pub const REMARK_MAX_CHARS: usize = 512;
    /// FerrumGate protection: one server / target entry length.
    pub const SERVER_MAX_CHARS: usize = 255;
    /// FerrumGate protection: user script length.
    pub const SCRIPT_MAX_CHARS: usize = 8192;
    /// Cap on the built-in forward's failover target list.
    pub const FORWARD_TARGETS_MAX: usize = 16;
    /// Webhook timeout default / ceiling in seconds (FerrumGate values;
    /// upstream field semantics are carried but the delivery step lands
    /// with the notification work).
    pub const WEBHOOK_TIMEOUT_DEFAULT_SECS: u32 = 30;
    /// Webhook timeout ceiling in seconds.
    pub const WEBHOOK_TIMEOUT_MAX_SECS: u32 = 600;
    /// Idle UDP session timeout default in seconds (carried for the
    /// built-in forward).
    pub const UDP_SESSION_TIMEOUT_DEFAULT_SECS: u32 = 300;
    /// Grace period for in-flight binding / check operations when the
    /// module drains.
    pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);
    /// Keep-alive TCP connections: reconnect delay after a drop.
    pub const KEEP_ALIVE_RECONNECT_DELAY: Duration = Duration::from_secs(2);
    /// Keep-alive TCP connect timeout.
    pub const KEEP_ALIVE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    /// Keep-alive TCP connections held per rule.
    pub const KEEP_ALIVE_CONNECTIONS_MAX: usize = 8;
    /// User script execution ceiling (WP-42 §8: scripts have a timeout).
    pub const SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);
    /// Script output (stdout + stderr) truncation in characters.
    pub const SCRIPT_OUTPUT_MAX_CHARS: usize = 4000;
    /// UPnP lease requested before the refresh cycle re-adds it.
    pub const UPNP_LEASE_SECS: u32 = 3600;
}

/// `stun.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct FileConfig {
    pub settings: Settings,
    pub rules: Vec<Rule>,
}

/// Module settings: the shared server lists and webhook used when a rule
/// sets `useGlobalServers` / `useGlobalWebhook`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Settings {
    /// Module switch: disabled rules never start a channel.
    pub enable: bool,
    /// STUN servers (`host:port`) used by rules with `useGlobalServers`.
    pub stun_servers: Vec<String>,
    /// TCP keep-alive targets (`host:port`, port defaults to 80).
    pub keep_alive_servers: Vec<String>,
    /// Webhook used by rules with `useGlobalWebhook`.
    pub webhook: WebhookConfig,
    /// Re-query period for the public address in seconds; `< 10` reads as
    /// 60.
    pub addr_check_interval: u32,
}

/// Transport protocol of a rule channel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    #[default]
    Tcp,
    Udp,
}

impl Proto {
    /// Lower-case wire name (`tcp` / `udp`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// How the channel picks its local bind address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BindMode {
    /// First non-loopback address (or `0.0.0.0` as a fallback).
    #[default]
    Auto,
    /// The configured local IP.
    Ip,
    /// The configured interface name.
    Interface,
    /// Interfaces whose name matches the configured regex.
    Regex,
}

/// Local bind selection of a rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Bind {
    pub mode: BindMode,
    /// Address for `mode: ip`.
    pub ip: String,
    /// Interface name for `mode: interface`.
    pub interface: String,
    /// Interface-name regex for `mode: regex`.
    pub regex: String,
}

/// Webhook delivery settings (module level and per rule).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct WebhookConfig {
    /// `http(s)://` URL; empty disables delivery.
    pub url: String,
    /// One of GET | POST | PUT | PATCH | DELETE.
    pub method: String,
    /// Raw `Key: Value` header lines.
    pub headers: Vec<String>,
    /// Request body sent as-is (`{ip}` / `{port}` placeholders stay for the
    /// notification step).
    pub body: String,
    /// Send through the global outbound proxy.
    pub proxy: bool,
    /// Request timeout in seconds; 0 normalizes to the default.
    pub timeout: u32,
}

/// Source access control of the built-in forward (carried for WP-42 step 9;
/// only shape and length are validated here).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct AccessConfig {
    /// Enforce the lists before connecting to the target.
    pub enable: bool,
    /// Allowed sources (IP / CIDR); empty with `enable` allows all.
    pub whitelist: Vec<String>,
    /// Denied sources (IP / CIDR); checked after the whitelist.
    pub blacklist: Vec<String>,
}

/// One traversal rule: a local channel socket whose NAT mapping is kept
/// alive with periodic STUN bindings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Rule {
    pub key: String,
    pub name: String,
    pub group: String,
    pub enable: bool,
    /// Channel transport.
    pub protocol: Proto,
    /// Local bind selection.
    pub bind: Bind,
    /// Channel local port; `0` = random.
    pub local_port: u16,
    /// Use the module's `stunServers` instead of the rule's own list.
    pub use_global_servers: bool,
    /// Rule-private STUN servers (`host:port`).
    pub stun_servers: Vec<String>,
    /// TCP-only keep-alive targets (`host:port`, port defaults to 80).
    pub keep_alive_servers: Vec<String>,
    /// Disable the built-in forward (traffic goes to the router instead).
    pub disable_forward: bool,
    /// Forward targets in failover order (`host` or `host:port`).
    pub target_addresses: Vec<String>,
    /// Forward target port.
    pub target_port: u16,
    /// Add a UPnP IGD mapping for the channel port.
    pub upnp: bool,
    /// UPnP gateway address (empty = SSDP discovery).
    pub upnp_gateway: String,
    /// Internal host announced to the gateway (empty = the address used to
    /// reach it).
    pub upnp_local_host: String,
    /// UPnP control URL (skips discovery).
    pub upnp_control_url: String,
    /// Internal port for the UPnP mapping; `0` = the channel port.
    pub upnp_internal_port: u16,
    /// Add a NAT-PMP mapping for the channel port.
    pub natpmp: bool,
    /// NAT-PMP gateway address.
    pub natpmp_gateway: String,
    /// Open the channel port in the system firewall (WP-37 handles the
    /// mechanics).
    pub auto_firewall: bool,
    /// Binding heartbeat in milliseconds; `0` → 3000, floor 500.
    pub heartbeat_interval: u32,
    /// Single binding timeout in milliseconds; `0` → 3000, floor 500.
    pub stun_timeout: u32,
    /// Retry interval after a failed round in milliseconds; `0` → 3000,
    /// floor 500.
    pub retry_interval: u32,
    /// Keep retrying failed rounds; off requires a manual restart.
    pub auto_retry: bool,
    /// Skip the reachability check (hairpin NAT escape hatch).
    pub disable_check: bool,
    /// Use the module webhook instead of the rule's own.
    pub use_global_webhook: bool,
    /// Rule-private webhook.
    pub webhook: WebhookConfig,
    /// Fire the webhook only when the mapping changed (otherwise on every
    /// successful round).
    pub webhook_only_on_change: bool,
    /// Run `script` on mapping success / change.
    pub script_enable: bool,
    /// Shell script; variables arrive via the environment.
    pub script: String,
    /// Built-in forward connection cap (`0` = unbounded).
    pub max_connections: u32,
    /// Idle UDP session timeout in seconds (`0` = default).
    pub udp_session_timeout: u32,
    /// Source access control of the built-in forward.
    pub access: AccessConfig,
    pub remark: String,
}
