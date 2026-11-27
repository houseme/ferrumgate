//! The portforward.json model (WP-34): settings and rules with upstream
//! defaults applied at normalization.

use serde::{Deserialize, Serialize};

/// Per-rule proxy protocol; TCP only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
    #[default]
    None,
    V1,
    V2,
}

/// Transport protocols a rule forwards; both may be set at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    pub settings: Settings,
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// Module switch; rules default to disabled regardless.
    pub enable: bool,
    /// Per-TCP-port connection limit; 0 normalizes to 256.
    pub default_max_connections: u32,
    /// Per-source limit; 0 normalizes to half of the port's max.
    pub default_max_conns_per_source: u32,
    /// Sources never subject to the per-source limit (IP or CIDR).
    pub per_source_exempt: Vec<String>,
    /// Idle UDP session lifetime in seconds; 0 normalizes to 60.
    pub default_udp_session_timeout: u32,
    /// Process-wide UDP session budget; 0 normalizes to 1024.
    pub max_udp_sessions: u32,
    /// Outbound dial timeout in seconds; 0 normalizes to 5.
    pub dial_timeout: u32,
    /// First-data timeout in seconds; 0 normalizes to 60, clamped to 3600.
    pub first_data_timeout: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enable: true,
            default_max_connections: 0,
            default_max_conns_per_source: 0,
            per_source_exempt: Vec::new(),
            default_udp_session_timeout: 0,
            max_udp_sessions: 0,
            dial_timeout: 0,
            first_data_timeout: 0,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rule {
    pub key: String,
    pub name: String,
    /// Rules default to disabled (verified against upstream defaults).
    pub enable: bool,
    pub group: String,
    /// tcp | udp, one or both.
    pub protocols: Vec<Protocol>,
    /// Empty = all addresses.
    pub listen_address: String,
    /// `443`, `443,8443` or `8000-8010`.
    pub listen_ports: String,
    pub auto_firewall: bool,
    /// Tried in order; sequential failover.
    pub target_addresses: Vec<String>,
    /// One port (reused by every listener) or one per listen port.
    pub target_ports: String,
    /// Per TCP port; 0 → the global default.
    pub max_connections: u32,
    /// Per source; 0 → the global default. Loopback/internal never limited.
    pub max_conns_per_source: u32,
    /// Seconds; 0 → the global default.
    pub udp_session_timeout: u32,
    pub proxy_protocol: ProxyProtocol,
    /// Source access lists (WP-36 minimal shape: allow / deny).
    #[serde(flatten)]
    pub access: RawAccess,
    pub remark: String,
}

/// The rule-level source lists (WP-36 `RawSourceRule` shape flattened into
/// the rule; ban and knock hooks integrate above this layer).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawAccess {
    #[serde(rename = "allow", skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    #[serde(rename = "deny", skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}
