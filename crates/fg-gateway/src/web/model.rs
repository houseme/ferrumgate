//! The webservice.json serde model (WP-20 step 2): listeners carrying
//! sites, settings, and the shared site field groups. Field names follow
//! the upstream model (camelCase).

use serde::{Deserialize, Serialize};

/// webservice.json top level.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct FileConfig {
    pub settings: Settings,
    pub listeners: Vec<Listener>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    /// Module switch; false stops all listeners.
    pub enable: bool,
    /// Default response header timeout milliseconds for proxy sites.
    pub response_header_timeout_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enable: false,
            response_header_timeout_ms: 30_000,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Listener {
    pub key: String,
    pub name: String,
    pub enable: bool,
    /// `tcp` (dual-stack) for now; upstream also knows `udp` variants.
    pub network: String,
    /// Empty = all addresses.
    pub listen_ip: String,
    pub port: u16,
    pub tls: bool,
    /// Minimum TLS version: "" | "1.2" | "1.3".
    pub min_tls: String,
    /// Serve plain HTTP on the same port alongside TLS.
    pub plain_http: bool,
    /// Extra plain HTTP port ("" disables).
    pub http_port: String,
    pub accept_proxy_protocol: bool,
    /// Access scheme the interface uses to build links: "" | http | https.
    pub access_scheme: String,
    /// Access port for interface links (0 = the listener port).
    pub access_port: u16,
    pub auto_firewall: bool,
    pub sites: Vec<Site>,
    /// This listener is the default site target.
    pub default: bool,
    pub remark: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Site {
    pub key: String,
    pub name: String,
    pub enable: bool,
    pub group: String,
    /// Domain rules; at most one `*` per entry.
    pub domains: Vec<String>,
    /// proxy | redirect | static | text.
    pub site_type: String,
    /// Reverse-proxy fields (site_type = proxy).
    pub targets: Vec<String>,
    pub upstream_h2c: bool,
    /// Redirect fields (site_type = redirect).
    pub redirect_to: String,
    pub redirect_code: u16,
    /// Static-file fields (site_type = static).
    pub root: String,
    /// Fixed-text fields (site_type = text).
    pub text_body: String,
    pub text_content_type: String,
    /// Health check (proxy sites): mode "" | http | tcp.
    pub health_mode: String,
    pub health_path: String,
    pub health_interval_secs: u32,
    pub health_timeout_secs: u32,
    pub health_fails: u32,
    pub health_passes: u32,
    /// Source access lists (WP-36 shape, validated in WP-24/26).
    pub access_allow: Vec<String>,
    pub access_deny: Vec<String>,
    pub remark: String,
}
