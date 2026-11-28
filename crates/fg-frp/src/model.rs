//! The `frp.json` model (WP-44 §3.2): module settings, the online-install
//! knobs, the frpc / frps instance collections and the proxy collection.
//! JSON field names follow upstream (camelCase); the frpc / frps settings
//! are flattened onto each instance entry.
//!
//! References verified against the frp source tree (`pkg/config/v1`):
//! client `serverAddr` / `serverPort` / `auth.token` / `user` /
//! `transport.protocol` / `transport.tls.enable` / `transport.quic.*`;
//! server `bindAddr` / `bindPort` / `kcpBindPort` / `quicBindPort` /
//! `proxyBindAddr` / `vhostHTTPPort` / `vhostHTTPSPort` / `subDomainHost` /
//! `allowPorts` / `webServer.*` / `httpPlugins`. Only the fields Gately
//! manages appear here.

use serde::{Deserialize, Serialize};

/// Shared ceilings and defaults for the module (conventions §2: every
/// background limit lives here).
pub mod limits {
    use std::time::Duration;

    /// Generated `frp/<instance>.toml` files live in this config-store data
    /// directory, mode 0600 (WP-44 §3.3).
    pub const CONFIG_DIR: &str = "frp";
    /// Permissions of the rendered instance config files (the token is
    /// inside the file, never on the command line).
    pub const CONFIG_FILE_MODE: u32 = 0o600;

    /// frp QUIC defaults (WP-44 §3.4): keepalive 10 s, idle timeout 30 s,
    /// 100000 incoming streams. 0 in the model means "use the frp default".
    pub const QUIC_KEEPALIVE_DEFAULT_SECS: u32 = 10;
    /// frp QUIC default idle timeout in seconds.
    pub const QUIC_IDLE_DEFAULT_SECS: u32 = 30;
    /// frp QUIC default incoming-stream budget.
    pub const QUIC_STREAMS_DEFAULT: u32 = 100_000;
    /// QUIC tuning ceiling: the stream budget may not exceed this.
    pub const QUIC_STREAMS_CAP: u32 = 1_000_000;

    /// A logged-in frpc stays a trusted source for 10 minutes after its
    /// last observed login activity; every subsequent Login / NewProxy on
    /// the live connection refreshes the window.
    pub const TRUST_TTL: Duration = Duration::from_secs(10 * 60);
    /// Trusted-source addresses retained per frps instance.
    pub const TRUSTED_ADDR_CAP: usize = 32;
    /// TCP remote ports registered as open per frps instance; cleared when
    /// the instance stops.
    pub const OPEN_PORTS_CAP: usize = 4096;
    /// Ports learned into the firewall per instance (`maxLearnedPorts` in
    /// upstream `frp/ports.go`; keeps a misbehaving client from bloating
    /// the firewall set). Upstream's exact figure is not in the WP table;
    /// it shares the 4096 ceiling here.
    pub const FIREWALL_PORTS_CAP: usize = 4096;

    /// Bounded stop deadline when the module drains; the per-process grace
    /// (5 s SIGTERM + 2 s kill) applies inside it.
    pub const DRAIN_STOP: Duration = Duration::from_secs(15);

    /// FerrumGate protection: instance / proxy name length.
    pub const NAME_MAX_CHARS: usize = 128;
    /// FerrumGate protection: group name length.
    pub const GROUP_MAX_CHARS: usize = 64;
    /// FerrumGate protection: remark length.
    pub const REMARK_MAX_CHARS: usize = 512;
    /// FerrumGate protection: token length (frp has no limit; `ps` can read
    /// tokens on a command line, ours lives in a 0600 file).
    pub const TOKEN_MAX_CHARS: usize = 256;
    /// FerrumGate protection: entries per IP list (allow / deny / sets).
    pub const IP_ENTRIES_MAX: usize = 512;
    /// FerrumGate protection: allow-ports text length.
    pub const ALLOW_PORTS_MAX_CHARS: usize = 1024;
    /// FerrumGate protection: custom domains per proxy.
    pub const DOMAINS_MAX: usize = 64;
}

/// Mask used for secret fields in every listing / read response; submitting
/// it (or an empty value) keeps the stored secret (conventions §3.3).
pub const SECRET_MASK: &str = "********";

/// frp.json.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct FileConfig {
    pub settings: Settings,
    pub install: InstallConfig,
    pub clients: Vec<Client>,
    pub servers: Vec<Server>,
    pub proxies: Vec<Proxy>,
}

/// Module settings (WP-44 §3.2): explicit program paths; empty means
/// "look in the config directory's `bin/` first, then in `PATH`" (WP-43).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Settings {
    pub frpc_path: String,
    pub frps_path: String,
}

/// Online-install knobs for the frp programs (WP-43). The WP-44 table
/// leaves the block's fields open; upstream keeps a per-module download
/// proxy and a module-scoped update switch, so those two are modeled here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct InstallConfig {
    /// Check for new frp releases every 12 h (WP-43 `AutoChecker`); the
    /// global "close update checks" setting gates it at the assembler.
    pub auto_check: bool,
    /// Per-module download proxy override (`http(s)://` or `socks5://`).
    pub proxy: String,
}

impl Default for InstallConfig {
    fn default() -> Self {
        Self {
            auto_check: true,
            proxy: String::new(),
        }
    }
}

/// Transport protocol between frpc and frps (WP-44 §3.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Tcp,
    Kcp,
    Quic,
    Websocket,
    Wss,
}

impl Protocol {
    /// The frp TOML wire value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Kcp => "kcp",
            Self::Quic => "quic",
            Self::Websocket => "websocket",
            Self::Wss => "wss",
        }
    }
}

/// Proxy type (WP-44 §3.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyType {
    #[default]
    Tcp,
    Udp,
    Http,
    Https,
    Stcp,
    Xtcp,
}

impl ProxyType {
    /// The frp TOML wire value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Http => "http",
            Self::Https => "https",
            Self::Stcp => "stcp",
            Self::Xtcp => "xtcp",
        }
    }

    /// Whether the proxy registers a `remotePort` on the server.
    pub fn has_remote_port(&self) -> bool {
        matches!(self, Self::Tcp | Self::Udp)
    }

    /// Whether the proxy is a vhost (HTTP / HTTPS) proxy.
    pub fn is_vhost(&self) -> bool {
        matches!(self, Self::Http | Self::Https)
    }

    /// Whether the proxy needs a shared secret (`secretKey`).
    pub fn needs_secret(&self) -> bool {
        matches!(self, Self::Stcp | Self::Xtcp)
    }
}

/// QUIC tuning shared by frpc (`transport.quic.*`, protocol `quic`) and
/// frps (`transport.quic.*` with a QUIC port set). 0 means "use the frp
/// default" (10 s / 30 s / 100000).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct QuicTuning {
    /// Keepalive interval in seconds; must be below `quic_max_idle_timeout`
    /// when both are non-zero.
    pub quic_keepalive_period: u32,
    /// Idle timeout in seconds.
    pub quic_max_idle_timeout: u32,
    /// Incoming-stream budget; at most [`limits::QUIC_STREAMS_CAP`].
    pub quic_max_incoming_streams: u32,
}

/// One frpc instance: identity plus the flattened `ClientSettings`, the
/// QUIC tuning and the "access" block used only for building visitor URLs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Client {
    pub key: String,
    pub name: String,
    pub group: String,
    pub enable: bool,
    pub remark: String,
    // ClientSettings (flattened).
    pub server_addr: String,
    pub server_port: u16,
    pub token: String,
    pub user: String,
    pub protocol: Protocol,
    /// TLS transport; None keeps the frp default (on since frp 0.50).
    pub tls: Option<bool>,
    #[serde(flatten)]
    pub quic: QuicTuning,
    // ClientAccess: only used to render visitor links; changing it never
    // restarts frpc (WP-44 §3.3).
    pub access: ClientAccess,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            key: String::new(),
            name: String::new(),
            group: String::new(),
            enable: false,
            remark: String::new(),
            server_addr: String::new(),
            server_port: 7000,
            token: String::new(),
            user: String::new(),
            protocol: Protocol::Tcp,
            tls: None,
            quic: QuicTuning::default(),
            access: ClientAccess::default(),
        }
    }
}

impl Client {
    /// The secret fields, for masking and the plaintext secrets endpoint.
    pub fn secret_fields(&self) -> [(&'static str, &str); 1] {
        [("token", self.token.as_str())]
    }

    /// Applies `merge_secrets` semantics for this entry.
    pub fn merge_secret(&mut self, field: &str, incoming: &str) {
        if field == "token" && secret_unchanged(incoming, &self.token) {
            return;
        }
        if field == "token" {
            self.token = incoming.to_owned();
        }
    }
}

/// The visitor-facing access block of a frpc instance (WP-44 §3.3): frpc
/// does not know the frps HTTP / HTTPS ports or the subdomain root, so the
/// visitor's real scheme / ports / domain are kept here to build links.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct ClientAccess {
    /// `http` or `https`; empty means "infer from the proxy type".
    pub http_scheme: String,
    /// Visitor-facing HTTP port; 0 = scheme default (80).
    pub http_port: u16,
    /// Visitor-facing HTTPS port; 0 = scheme default (443).
    pub https_port: u16,
    /// Subdomain root for building full domains from `subdomain` entries.
    pub subdomain_host: String,
}

/// One frps instance: identity plus the flattened `ServerSettings`, QUIC
/// tuning, dashboard and the frpc login source access control.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Server {
    pub key: String,
    pub name: String,
    pub group: String,
    pub enable: bool,
    pub remark: String,
    // ServerSettings (flattened).
    /// Listen address for the frpc connection port; empty = all addresses.
    pub bind_addr: String,
    pub bind_port: u16,
    /// UDP ports; 0 = disabled. They may differ from `bind_port`, but not
    /// from each other. The KCP port may equal the bind port.
    pub kcp_bind_port: u16,
    pub quic_bind_port: u16,
    #[serde(flatten)]
    pub quic: QuicTuning,
    pub token: String,
    /// Open the connection / KCP / QUIC / vhost ports in the firewall for
    /// the instance's lifetime (WP-37 wiring at the assembler).
    pub auto_firewall: bool,
    /// Address the HTTP / HTTPS ports and tcp / udp remote ports bind to;
    /// empty = all addresses.
    pub proxy_bind_addr: String,
    pub vhost_http_port: u16,
    pub vhost_https_port: u16,
    /// Subdomain root used for server-side validation.
    pub subdomain_host: String,
    /// Port whitelist text (`443,8000-9000`); empty = all ports.
    pub allow_ports: String,
    // Dashboard (`webServer.*`).
    pub dashboard_port: u16,
    pub dashboard_addr: String,
    pub dashboard_user: String,
    pub dashboard_pwd: String,
    // frpc login source access control, evaluated before the token check
    // happens inside frps itself (WP-44 §3.3).
    /// `""` off, `white` allow-list, `black` deny-list (normalized).
    pub ip_mode: String,
    /// Hand-entered IPs / CIDRs of the allow list.
    pub ip_list: Vec<String>,
    /// Subscribed IP-set keys (from the web service IP lists) of the allow
    /// list; refreshed lists apply without restarting frps.
    pub ip_sets: Vec<String>,
    /// Priority deny list: a hit is always rejected, before any other rule.
    pub ip_deny_list: Vec<String>,
    /// Priority deny IP-set keys.
    pub ip_deny_sets: Vec<String>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            key: String::new(),
            name: String::new(),
            group: String::new(),
            enable: false,
            remark: String::new(),
            bind_addr: String::new(),
            bind_port: 7000,
            kcp_bind_port: 0,
            quic_bind_port: 0,
            quic: QuicTuning::default(),
            token: String::new(),
            auto_firewall: true,
            proxy_bind_addr: String::new(),
            vhost_http_port: 0,
            vhost_https_port: 0,
            subdomain_host: String::new(),
            allow_ports: String::new(),
            dashboard_port: 0,
            dashboard_addr: String::new(),
            dashboard_user: String::new(),
            dashboard_pwd: String::new(),
            ip_mode: String::new(),
            ip_list: Vec::new(),
            ip_sets: Vec::new(),
            ip_deny_list: Vec::new(),
            ip_deny_sets: Vec::new(),
        }
    }
}

impl Server {
    /// The secret fields, for masking and the plaintext secrets endpoint.
    pub fn secret_fields(&self) -> [(&'static str, &str); 2] {
        [
            ("token", self.token.as_str()),
            ("dashboardPwd", self.dashboard_pwd.as_str()),
        ]
    }

    /// Applies `merge_secrets` semantics for this entry.
    pub fn merge_secret(&mut self, field: &str, incoming: &str) {
        match field {
            "token" if secret_unchanged(incoming, &self.token) => {}
            "token" => self.token = incoming.to_owned(),
            "dashboardPwd" if secret_unchanged(incoming, &self.dashboard_pwd) => {}
            "dashboardPwd" => self.dashboard_pwd = incoming.to_owned(),
            _ => {}
        }
    }
}

/// One proxy. Proxies belong to a frpc instance (`client` holds its key);
/// editing one restarts only that instance.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Proxy {
    pub key: String,
    pub name: String,
    pub group: String,
    #[serde(rename = "type")]
    pub typ: ProxyType,
    pub enable: bool,
    /// Backend address; empty normalizes to 127.0.0.1 (frp default).
    pub local_ip: String,
    pub local_port: u16,
    /// tcp / udp only.
    pub remote_port: u16,
    /// http / https only.
    pub custom_domains: Vec<String>,
    pub subdomain: String,
    /// stcp / xtcp only.
    pub secret_key: String,
    pub remark: String,
    /// Key of the owning frpc instance.
    pub client: String,
}

/// `********` or an empty incoming value means "keep the stored secret"
/// (conventions §3.3).
pub fn secret_unchanged(incoming: &str, _stored: &str) -> bool {
    incoming == SECRET_MASK || incoming.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_config_roundtrips_camel_case_and_rejects_unknown() {
        let config = FileConfig {
            settings: Settings {
                frpc_path: "/usr/bin/frpc".into(),
                frps_path: String::new(),
            },
            install: InstallConfig {
                auto_check: false,
                proxy: "http://127.0.0.1:7890".into(),
            },
            clients: vec![Client {
                key: "abc123".into(),
                name: "home".into(),
                enable: true,
                server_addr: "frps.example.com".into(),
                server_port: 7000,
                token: "t".into(),
                protocol: Protocol::Quic,
                tls: Some(true),
                quic: QuicTuning {
                    quic_keepalive_period: 5,
                    quic_max_idle_timeout: 60,
                    quic_max_incoming_streams: 1000,
                },
                access: ClientAccess {
                    http_scheme: "https".into(),
                    http_port: 8080,
                    https_port: 8443,
                    subdomain_host: "example.com".into(),
                },
                ..Client::default()
            }],
            ..FileConfig::default()
        };
        let json = serde_json::to_string(&config).expect("serialize");
        assert!(json.contains("\"frpcPath\":\"/usr/bin/frpc\""), "{json}");
        assert!(json.contains("\"autoCheck\":false"), "{json}");
        assert!(
            json.contains("\"serverAddr\":\"frps.example.com\""),
            "{json}"
        );
        assert!(json.contains("\"quicKeepalivePeriod\":5"), "{json}");
        assert!(json.contains("\"httpScheme\":\"https\""), "{json}");
        let back: FileConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, config);
        assert!(serde_json::from_str::<FileConfig>("{\"nope\":1}").is_err());
    }

    #[test]
    fn enums_serialize_to_frp_wire_values() {
        assert_eq!(serde_json::to_string(&Protocol::Wss).unwrap(), "\"wss\"");
        assert_eq!(serde_json::to_string(&ProxyType::Stcp).unwrap(), "\"stcp\"");
        assert_eq!(ProxyType::Http.as_str(), "http");
        assert!(ProxyType::Udp.has_remote_port());
        assert!(!ProxyType::Http.has_remote_port());
        assert!(ProxyType::Http.is_vhost());
        assert!(ProxyType::Xtcp.needs_secret());
        assert!(!ProxyType::Tcp.needs_secret());
    }

    #[test]
    fn secret_mask_keeps_stored_value() {
        let mut client = Client {
            token: "real".into(),
            ..Client::default()
        };
        client.merge_secret("token", SECRET_MASK);
        assert_eq!(client.token, "real");
        client.merge_secret("token", "");
        assert_eq!(client.token, "real");
        client.merge_secret("token", "next");
        assert_eq!(client.token, "next");

        let mut server = Server {
            token: "t".into(),
            dashboard_pwd: "d".into(),
            ..Server::default()
        };
        server.merge_secret("dashboardPwd", SECRET_MASK);
        assert_eq!(server.dashboard_pwd, "d");
        server.merge_secret("dashboardPwd", "new");
        assert_eq!(server.dashboard_pwd, "new");
        server.merge_secret("token", "x");
        assert_eq!(server.token, "x");
        assert_eq!(Client::default().secret_fields().len(), 1);
        assert_eq!(Server::default().secret_fields().len(), 2);
    }
}
