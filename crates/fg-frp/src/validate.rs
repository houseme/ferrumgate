//! Normalization, validation and frp TOML rendering for the frp model
//! (WP-44 §3, steps 1–3): pure functions over plain data. `normalize`
//! applies defaults and drops stray text; `validate` collects every
//! problem; `render_client_toml` / `render_server_toml` write the frp
//! 0.52+ TOML with the exact field names from the frp source tree
//! (`pkg/config/v1`): `serverAddr`, `auth.token`, `transport.tls.enable`,
//! `transport.quic.keepalivePeriod`, `bindAddr`, `kcpBindPort`,
//! `quicBindPort`, `proxyBindAddr`, `vhostHTTPPort`, `allowPorts`,
//! `webServer.*`, `httpPlugins`, `localIP`, `customDomains`, `secretKey`.
//!
//! The token is only ever written into the rendered file (mode 0600 at the
//! call site) — never into process arguments, which `ps` can read.

use std::net::IpAddr;

use anyhow::{Error, Result, anyhow};
use ipnet::IpNet;

use crate::model::{
    Client, ClientAccess, FileConfig, Protocol, Proxy, ProxyType, QuicTuning, Server, limits,
};

/// A collected validation problem: the offending field path and reason.
#[derive(Debug, PartialEq, Eq)]
pub struct Problem {
    pub field: String,
    pub reason: String,
}

impl Problem {
    fn new(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

/// Render failure (TOML serialization); values are plain data, so only
/// backend errors can surface.
pub type RenderError = Error;

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/// Applies defaults and trims user-entered text: names / addresses / tokens
/// are trimmed, the login-source mode normalizes to `off` / `white` /
/// `black`, empty IP entries and malformed custom domains are dropped, and
/// an empty proxy `localIp` becomes the frp default `127.0.0.1`.
pub fn normalize(mut config: FileConfig) -> FileConfig {
    for client in &mut config.clients {
        client.key = client.key.trim().to_owned();
        client.name = client.name.trim().to_owned();
        client.group = client.group.trim().to_owned();
        client.remark = client.remark.trim().to_owned();
        client.server_addr = client.server_addr.trim().to_owned();
        client.token = client.token.trim().to_owned();
        client.user = client.user.trim().to_owned();
        normalize_access(&mut client.access);
        normalize_quic(&mut client.quic);
    }
    for server in &mut config.servers {
        server.key = server.key.trim().to_owned();
        server.name = server.name.trim().to_owned();
        server.group = server.group.trim().to_owned();
        server.remark = server.remark.trim().to_owned();
        server.bind_addr = server.bind_addr.trim().to_owned();
        server.proxy_bind_addr = server.proxy_bind_addr.trim().to_owned();
        server.subdomain_host = server.subdomain_host.trim().to_owned();
        server.token = server.token.trim().to_owned();
        server.allow_ports = server.allow_ports.trim().to_owned();
        server.dashboard_addr = server.dashboard_addr.trim().to_owned();
        server.dashboard_user = server.dashboard_user.trim().to_owned();
        server.dashboard_pwd = server.dashboard_pwd.trim().to_owned();
        server.ip_mode = normalize_ip_mode(&server.ip_mode);
        normalize_entries(&mut server.ip_list);
        normalize_entries(&mut server.ip_sets);
        normalize_entries(&mut server.ip_deny_list);
        normalize_entries(&mut server.ip_deny_sets);
        normalize_quic(&mut server.quic);
    }
    for proxy in &mut config.proxies {
        proxy.key = proxy.key.trim().to_owned();
        proxy.name = proxy.name.trim().to_owned();
        proxy.group = proxy.group.trim().to_owned();
        proxy.remark = proxy.remark.trim().to_owned();
        proxy.local_ip = proxy.local_ip.trim().to_owned();
        if proxy.local_ip.is_empty() {
            proxy.local_ip = "127.0.0.1".to_owned();
        }
        proxy.subdomain = proxy.subdomain.trim().to_owned();
        proxy.secret_key = proxy.secret_key.trim().to_owned();
        proxy.client = proxy.client.trim().to_owned();
        proxy.custom_domains = proxy
            .custom_domains
            .iter()
            .map(|domain| domain.trim().to_ascii_lowercase())
            .filter(|domain| valid_domain(domain))
            .take(limits::DOMAINS_MAX)
            .collect();
    }
    config.settings.frpc_path = config.settings.frpc_path.trim().to_owned();
    config.settings.frps_path = config.settings.frps_path.trim().to_owned();
    config.install.proxy = config.install.proxy.trim().to_owned();
    config
}

/// The visitor scheme accepts `http` / `https` only.
fn normalize_access(access: &mut ClientAccess) {
    let scheme = access.http_scheme.trim().to_ascii_lowercase();
    access.http_scheme = match scheme.as_str() {
        "http" | "https" => scheme,
        // An unusable scheme normalizes to "unset" (default inference).
        _ => String::new(),
    };
    access.subdomain_host = access
        .subdomain_host
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
}

/// The login-source mode accepts several upstream spellings; the stored
/// form is `off`, `white` or `black`.
fn normalize_ip_mode(mode: &str) -> String {
    match mode.trim().to_ascii_lowercase().as_str() {
        "white" | "allow" | "allowlist" | "whitelist" => "white".to_owned(),
        "black" | "deny" | "denylist" | "blacklist" => "black".to_owned(),
        _ => String::new(),
    }
}

fn normalize_entries(entries: &mut Vec<String>) {
    entries.retain(|entry| {
        let trimmed = entry.trim();
        !trimmed.is_empty() && parse_ip_entry(trimmed).is_some()
    });
    for entry in entries.iter_mut() {
        *entry = entry.trim().to_owned();
    }
    if entries.len() > limits::IP_ENTRIES_MAX {
        entries.truncate(limits::IP_ENTRIES_MAX);
    }
}

/// QUIC stream budget above the frp ceiling clamps to the ceiling; a zero
/// keepalive / idle stays zero (= frp default).
fn normalize_quic(quic: &mut QuicTuning) {
    quic.quic_max_incoming_streams = quic.quic_max_incoming_streams.min(limits::QUIC_STREAMS_CAP);
}

/// A custom domain must be a bare hostname: no scheme, no path, no port.
pub fn valid_domain(domain: &str) -> bool {
    let domain = domain.trim();
    !domain.is_empty()
        && !domain.contains(['/', ':', '@', '?', '#', ' '])
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
        && domain.bytes().all(|byte| byte.is_ascii())
}

/// Parses one IP-list entry: a bare IP or a CIDR.
pub fn parse_ip_entry(entry: &str) -> Option<IpNet> {
    let entry = entry.trim();
    if let Ok(net) = entry.parse::<IpNet>() {
        return Some(net);
    }
    entry.parse::<IpAddr>().ok().map(IpNet::from)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validates a normalized config, collecting every problem (WP-44 step 1:
/// QUIC constraints, KCP / QUIC ports, proxy-type field mapping, proxy
/// ownership).
pub fn validate(config: &FileConfig) -> Vec<Problem> {
    let mut problems = Vec::new();
    let clients: std::collections::BTreeSet<&str> = config
        .clients
        .iter()
        .map(|client| client.key.as_str())
        .collect();
    let mut client_keys = std::collections::BTreeSet::new();
    for client in &config.clients {
        let prefix = format!(
            "clients.{}",
            label(client.key.as_str(), client.name.as_str())
        );
        check_identity(
            &prefix,
            client.key.as_str(),
            client.name.as_str(),
            client.remark.as_str(),
            &mut client_keys,
            &mut problems,
        );
        if client.server_addr.is_empty() {
            problems.push(Problem::new(
                format!("{prefix}.serverAddr"),
                "服务器地址不能为空",
            ));
        }
        if client.server_port == 0 {
            problems.push(Problem::new(
                format!("{prefix}.serverPort"),
                "服务器端口不能为 0",
            ));
        }
        check_quic(&prefix, &client.quic, &mut problems);
        check_access(&prefix, &client.access, &mut problems);
    }
    let mut server_keys = std::collections::BTreeSet::new();
    for server in &config.servers {
        let prefix = format!(
            "servers.{}",
            label(server.key.as_str(), server.name.as_str())
        );
        check_identity(
            &prefix,
            server.key.as_str(),
            server.name.as_str(),
            server.remark.as_str(),
            &mut server_keys,
            &mut problems,
        );
        if server.bind_port == 0 {
            problems.push(Problem::new(
                format!("{prefix}.bindPort"),
                "绑定端口不能为 0",
            ));
        }
        if server.kcp_bind_port != 0
            && server.quic_bind_port != 0
            && server.kcp_bind_port == server.quic_bind_port
        {
            problems.push(Problem::new(
                format!("{prefix}.quicBindPort"),
                "KCP 端口与 QUIC 端口不能相同",
            ));
        }
        check_quic(&prefix, &server.quic, &mut problems);
        check_ports_text(&prefix, &server.allow_ports, &mut problems);
        for (field, entries) in [
            ("ipList", &server.ip_list),
            ("ipSets", &server.ip_sets),
            ("ipDenyList", &server.ip_deny_list),
            ("ipDenySets", &server.ip_deny_sets),
        ] {
            if entries.len() > limits::IP_ENTRIES_MAX {
                problems.push(Problem::new(
                    format!("{prefix}.{field}"),
                    format!("最多 {} 条", limits::IP_ENTRIES_MAX),
                ));
            }
        }
    }
    let mut proxy_keys = std::collections::BTreeSet::new();
    for proxy in &config.proxies {
        let prefix = format!("proxies.{}", label(proxy.key.as_str(), proxy.name.as_str()));
        check_identity(
            &prefix,
            proxy.key.as_str(),
            proxy.name.as_str(),
            proxy.remark.as_str(),
            &mut proxy_keys,
            &mut problems,
        );
        if proxy.client.is_empty() || !clients.contains(proxy.client.as_str()) {
            problems.push(Problem::new(
                format!("{prefix}.client"),
                format!("所属 frpc 实例不存在：{}", proxy.client),
            ));
        }
        if proxy.local_port == 0 {
            problems.push(Problem::new(
                format!("{prefix}.localPort"),
                "本地端口不能为 0",
            ));
        }
        match proxy.typ {
            ProxyType::Tcp | ProxyType::Udp => {
                if proxy.remote_port == 0 {
                    problems.push(Problem::new(
                        format!("{prefix}.remotePort"),
                        "tcp / udp 代理需要远程端口",
                    ));
                }
            }
            ProxyType::Http | ProxyType::Https => {
                if proxy.custom_domains.is_empty() && proxy.subdomain.is_empty() {
                    problems.push(Problem::new(
                        format!("{prefix}.customDomains"),
                        "http / https 代理需要自定义域名或子域名",
                    ));
                }
            }
            ProxyType::Stcp | ProxyType::Xtcp => {
                if proxy.secret_key.is_empty() {
                    problems.push(Problem::new(
                        format!("{prefix}.secretKey"),
                        "stcp / xtcp 代理需要密钥",
                    ));
                }
            }
        }
    }
    problems
}

fn label(key: &str, name: &str) -> String {
    if key.is_empty() {
        name.to_owned()
    } else {
        key.to_owned()
    }
}

fn check_identity<'a>(
    prefix: &str,
    key: &'a str,
    name: &str,
    remark: &str,
    keys: &mut std::collections::BTreeSet<&'a str>,
    problems: &mut Vec<Problem>,
) {
    if key.is_empty() {
        problems.push(Problem::new("key", "key 不能为空"));
    } else if !keys.insert(key) {
        problems.push(Problem::new("key", format!("重复的 key {key}")));
    }
    if name.is_empty() {
        problems.push(Problem::new(format!("{prefix}.name"), "名称不能为空"));
    } else if name.chars().count() > limits::NAME_MAX_CHARS {
        problems.push(Problem::new(
            format!("{prefix}.name"),
            format!("名称最多 {} 个字符", limits::NAME_MAX_CHARS),
        ));
    }
    if remark.chars().count() > limits::REMARK_MAX_CHARS {
        problems.push(Problem::new(
            format!("{prefix}.remark"),
            format!("备注最多 {} 个字符", limits::REMARK_MAX_CHARS),
        ));
    }
}

fn check_quic(prefix: &str, quic: &QuicTuning, problems: &mut Vec<Problem>) {
    // Both non-zero: the keepalive must stay below the idle timeout; with
    // either at zero the frp defaults (10 s / 30 s) keep the invariant.
    if quic.quic_keepalive_period != 0
        && quic.quic_max_idle_timeout != 0
        && quic.quic_keepalive_period >= quic.quic_max_idle_timeout
    {
        problems.push(Problem::new(
            format!("{prefix}.quicKeepalivePeriod"),
            "保活间隔必须小于空闲断开时间",
        ));
    }
    if quic.quic_max_incoming_streams > limits::QUIC_STREAMS_CAP {
        problems.push(Problem::new(
            format!("{prefix}.quicMaxIncomingStreams"),
            format!("最大并发流不超过 {}", limits::QUIC_STREAMS_CAP),
        ));
    }
}

fn check_access(prefix: &str, access: &ClientAccess, problems: &mut Vec<Problem>) {
    if !access.http_scheme.is_empty()
        && access.http_scheme != "http"
        && access.http_scheme != "https"
    {
        problems.push(Problem::new(
            format!("{prefix}.access.httpScheme"),
            "协议只支持 http / https",
        ));
    }
    if !access.subdomain_host.is_empty() && !valid_domain(&access.subdomain_host) {
        problems.push(Problem::new(
            format!("{prefix}.access.subdomainHost"),
            "子域名根域名需为合法域名",
        ));
    }
}

fn check_ports_text(prefix: &str, text: &str, problems: &mut Vec<Problem>) {
    if text.chars().count() > limits::ALLOW_PORTS_MAX_CHARS {
        problems.push(Problem::new(
            format!("{prefix}.allowPorts"),
            format!("端口白名单最多 {} 个字符", limits::ALLOW_PORTS_MAX_CHARS),
        ));
        return;
    }
    if text.is_empty() {
        return;
    }
    if let Err(error) = parse_allow_ports(text) {
        problems.push(Problem::new(format!("{prefix}.allowPorts"), error));
    }
}

/// Parses the allow-ports whitelist into collapsed inclusive ranges
/// (frp's `allowPorts`): `443`, `443,8000-8010`, full-width commas and
/// spaces accepted. Unlike the firewall-oriented `fg_net::ports` parser
/// (whose 64-entry expansion cap fits target mapping, not whitelists),
/// ranges stay collapsed and the range count is capped instead.
pub fn parse_allow_ports(text: &str) -> Result<Vec<(u16, u16)>, String> {
    const MAX_RANGES: usize = 1024;
    let mut ranges: Vec<(u16, u16)> = Vec::new();
    for part in text.trim().split([',', '，', ' ']) {
        let part = part.trim();
        if part.is_empty() {
            return Err("端口白名单有空条目".to_owned());
        }
        let (start, end) = match part.split_once('-') {
            Some((start, end)) => {
                let start: u16 = start
                    .trim()
                    .parse()
                    .map_err(|_| format!("端口白名单条目无效：{part}"))?;
                let end: u16 = end
                    .trim()
                    .parse()
                    .map_err(|_| format!("端口白名单条目无效：{part}"))?;
                (start, end)
            }
            None => {
                let port: u16 = part
                    .parse()
                    .map_err(|_| format!("端口白名单条目无效：{part}"))?;
                (port, port)
            }
        };
        if start == 0 {
            return Err("端口白名单不能包含 0".to_owned());
        }
        if start > end {
            return Err(format!("端口白名单区间倒置：{part}"));
        }
        ranges.push((start, end));
        if ranges.len() > MAX_RANGES {
            return Err(format!("端口白名单最多 {} 条", MAX_RANGES));
        }
    }
    if ranges.is_empty() {
        return Err("端口白名单为空".to_owned());
    }
    ranges.sort_unstable();
    let mut merged: Vec<(u16, u16)> = Vec::new();
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1.saturating_add(1) => {
                last.1 = last.1.max(end);
            }
            _ => merged.push((start, end)),
        }
    }
    Ok(merged)
}

// ---------------------------------------------------------------------------
// frp TOML rendering
// ---------------------------------------------------------------------------

/// The frps login-check plugin endpoint wired into the rendered server
/// config (`httpPlugins`): the loopback gate served by [`crate::login_check`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginEndpoint {
    pub name: String,
    pub addr: String,
    pub path: String,
    pub ops: &'static [&'static str],
}

impl PluginEndpoint {
    /// The gate endpoint of one frps instance: base address of the running
    /// login-check listener plus its per-instance path.
    pub fn gate(base_addr: String, path: String) -> Self {
        Self {
            name: "ferrumgate-frp".to_owned(),
            addr: base_addr,
            path,
            ops: &["Login", "NewProxy"],
        }
    }
}

// The render structs use frp's JSON/TOML field names verbatim, so Rust
// names differ where frp uses camelCase (`serverAddr`).
mod wire {
    use serde::Serialize;

    use crate::model::QuicTuning;

    #[derive(Serialize)]
    pub struct ClientToml<'a> {
        #[serde(rename = "serverAddr")]
        pub server_addr: &'a str,
        #[serde(rename = "serverPort")]
        pub server_port: u16,
        #[serde(rename = "auth", skip_serializing_if = "Option::is_none")]
        pub auth: Option<Auth<'a>>,
        #[serde(rename = "user", skip_serializing_if = "Option::is_none")]
        pub user: Option<&'a str>,
        pub transport: ClientTransport<'a>,
        #[serde(rename = "proxies", skip_serializing_if = "Vec::is_empty")]
        pub proxies: Vec<ProxyToml<'a>>,
    }

    #[derive(Serialize)]
    pub struct Auth<'a> {
        pub token: &'a str,
    }

    #[derive(Serialize)]
    pub struct ClientTransport<'a> {
        pub protocol: &'a str,
        #[serde(rename = "tls", skip_serializing_if = "Option::is_none")]
        pub tls: Option<TlsEnable>,
        #[serde(rename = "quic", skip_serializing_if = "Option::is_none")]
        pub quic: Option<QuicWire>,
    }

    #[derive(Serialize)]
    pub struct TlsEnable {
        pub enable: bool,
    }

    /// Only non-zero values are emitted; zero keeps the frp defaults.
    #[derive(Serialize)]
    pub struct QuicWire {
        #[serde(rename = "keepalivePeriod", skip_serializing_if = "is_zero")]
        pub keepalive_period: u32,
        #[serde(rename = "maxIdleTimeout", skip_serializing_if = "is_zero")]
        pub max_idle_timeout: u32,
        #[serde(rename = "maxIncomingStreams", skip_serializing_if = "is_zero")]
        pub max_incoming_streams: u32,
    }

    impl QuicWire {
        pub fn from_quic(quic: &QuicTuning) -> Self {
            Self {
                keepalive_period: quic.quic_keepalive_period,
                max_idle_timeout: quic.quic_max_idle_timeout,
                max_incoming_streams: quic.quic_max_incoming_streams,
            }
        }
    }

    #[derive(Serialize)]
    pub struct ProxyToml<'a> {
        pub name: &'a str,
        #[serde(rename = "type")]
        pub typ: &'static str,
        #[serde(rename = "localIP")]
        pub local_ip: &'a str,
        #[serde(rename = "localPort")]
        pub local_port: u16,
        #[serde(rename = "remotePort", skip_serializing_if = "is_zero_u16")]
        pub remote_port: u16,
        #[serde(rename = "customDomains", skip_serializing_if = "Vec::is_empty")]
        pub custom_domains: Vec<String>,
        #[serde(rename = "subdomain", skip_serializing_if = "Option::is_none")]
        pub subdomain: Option<&'a str>,
        #[serde(rename = "secretKey", skip_serializing_if = "Option::is_none")]
        pub secret_key: Option<&'a str>,
    }

    #[derive(Serialize)]
    pub struct ServerToml<'a> {
        #[serde(rename = "bindAddr", skip_serializing_if = "Option::is_none")]
        pub bind_addr: Option<&'a str>,
        #[serde(rename = "bindPort")]
        pub bind_port: u16,
        #[serde(rename = "kcpBindPort", skip_serializing_if = "is_zero_u16")]
        pub kcp_bind_port: u16,
        #[serde(rename = "quicBindPort", skip_serializing_if = "is_zero_u16")]
        pub quic_bind_port: u16,
        #[serde(rename = "auth", skip_serializing_if = "Option::is_none")]
        pub auth: Option<Auth<'a>>,
        pub transport: ServerTransport,
        #[serde(rename = "proxyBindAddr", skip_serializing_if = "Option::is_none")]
        pub proxy_bind_addr: Option<&'a str>,
        #[serde(rename = "vhostHTTPPort", skip_serializing_if = "is_zero_u16")]
        pub vhost_http_port: u16,
        #[serde(rename = "vhostHTTPSPort", skip_serializing_if = "is_zero_u16")]
        pub vhost_https_port: u16,
        #[serde(rename = "subDomainHost", skip_serializing_if = "Option::is_none")]
        pub subdomain_host: Option<&'a str>,
        #[serde(rename = "allowPorts", skip_serializing_if = "Vec::is_empty")]
        pub allow_ports: Vec<PortsRangeWire>,
        #[serde(rename = "webServer", skip_serializing_if = "Option::is_none")]
        pub web_server: Option<WebServer<'a>>,
        #[serde(rename = "httpPlugins", skip_serializing_if = "Vec::is_empty")]
        pub http_plugins: Vec<PluginToml<'a>>,
    }

    #[derive(Serialize)]
    pub struct ServerTransport {
        #[serde(rename = "quic", skip_serializing_if = "Option::is_none")]
        pub quic: Option<QuicWire>,
    }

    #[derive(Serialize)]
    pub struct PortsRangeWire {
        #[serde(skip_serializing_if = "is_zero_u16")]
        pub start: u16,
        #[serde(skip_serializing_if = "is_zero_u16")]
        pub end: u16,
        #[serde(skip_serializing_if = "is_zero_u16")]
        pub single: u16,
    }

    #[derive(Serialize)]
    pub struct WebServer<'a> {
        #[serde(rename = "addr", skip_serializing_if = "Option::is_none")]
        pub addr: Option<&'a str>,
        pub port: u16,
        #[serde(rename = "user", skip_serializing_if = "Option::is_none")]
        pub user: Option<&'a str>,
        #[serde(rename = "password", skip_serializing_if = "Option::is_none")]
        pub password: Option<&'a str>,
    }

    #[derive(Serialize)]
    pub struct PluginToml<'a> {
        pub name: &'a str,
        pub addr: &'a str,
        pub path: &'a str,
        pub ops: &'a [&'a str],
    }

    fn is_zero(value: &u32) -> bool {
        *value == 0
    }

    fn is_zero_u16(value: &u16) -> bool {
        *value == 0
    }
}

/// Renders one frpc instance's TOML: the enabled proxies owned by the
/// instance follow the root settings. The token lands in `auth.token`
/// inside the file; process arguments only ever carry `-c <file>`.
pub fn render_client_toml(client: &Client, proxies: &[Proxy]) -> Result<String, RenderError> {
    let owned: Vec<wire::ProxyToml<'_>> = proxies
        .iter()
        .filter(|proxy| proxy.enable && proxy.client == client.key)
        .map(|proxy| wire::ProxyToml {
            name: proxy.name.as_str(),
            typ: proxy.typ.as_str(),
            local_ip: proxy.local_ip.as_str(),
            local_port: proxy.local_port,
            remote_port: if proxy.typ.has_remote_port() {
                proxy.remote_port
            } else {
                0
            },
            custom_domains: if proxy.typ.is_vhost() {
                proxy.custom_domains.clone()
            } else {
                Vec::new()
            },
            subdomain: (!proxy.subdomain.is_empty()).then_some(proxy.subdomain.as_str()),
            secret_key: (!proxy.secret_key.is_empty()).then_some(proxy.secret_key.as_str()),
        })
        .collect();
    let document = wire::ClientToml {
        server_addr: client.server_addr.as_str(),
        server_port: client.server_port,
        auth: (!client.token.is_empty()).then_some(wire::Auth {
            token: client.token.as_str(),
        }),
        user: (!client.user.is_empty()).then_some(client.user.as_str()),
        transport: wire::ClientTransport {
            protocol: client.protocol.as_str(),
            tls: client.tls.map(|enable| wire::TlsEnable { enable }),
            quic: (client.protocol == Protocol::Quic)
                .then(|| wire::QuicWire::from_quic(&client.quic)),
        },
        proxies: owned,
    };
    toml::to_string(&document).map_err(|error| anyhow!("生成 frpc 配置失败：{error}"))
}

/// Renders one frps instance's TOML. `gate` (the loopback login-check
/// endpoint) becomes the `httpPlugins` entry when the listener is up;
/// without it frps still runs, just without the source access control.
pub fn render_server_toml(
    server: &Server,
    gate: Option<&PluginEndpoint>,
) -> Result<String, RenderError> {
    let allow_ports: Vec<wire::PortsRangeWire> = if server.allow_ports.is_empty() {
        Vec::new()
    } else {
        // Validation rejects bad text earlier; rendering stays total.
        parse_allow_ports(&server.allow_ports)
            .unwrap_or_default()
            .into_iter()
            .map(|(start, end)| {
                if start == end {
                    wire::PortsRangeWire {
                        start: 0,
                        end: 0,
                        single: start,
                    }
                } else {
                    wire::PortsRangeWire {
                        start,
                        end,
                        single: 0,
                    }
                }
            })
            .collect()
    };
    let document = wire::ServerToml {
        bind_addr: (!server.bind_addr.is_empty()).then_some(server.bind_addr.as_str()),
        bind_port: server.bind_port,
        kcp_bind_port: server.kcp_bind_port,
        quic_bind_port: server.quic_bind_port,
        auth: (!server.token.is_empty()).then_some(wire::Auth {
            token: server.token.as_str(),
        }),
        transport: wire::ServerTransport {
            quic: (server.quic_bind_port > 0).then(|| wire::QuicWire::from_quic(&server.quic)),
        },
        proxy_bind_addr: (!server.proxy_bind_addr.is_empty())
            .then_some(server.proxy_bind_addr.as_str()),
        vhost_http_port: server.vhost_http_port,
        vhost_https_port: server.vhost_https_port,
        subdomain_host: (!server.subdomain_host.is_empty())
            .then_some(server.subdomain_host.as_str()),
        allow_ports,
        web_server: (server.dashboard_port > 0).then_some(wire::WebServer {
            addr: (!server.dashboard_addr.is_empty()).then_some(server.dashboard_addr.as_str()),
            port: server.dashboard_port,
            user: (!server.dashboard_user.is_empty()).then_some(server.dashboard_user.as_str()),
            password: (!server.dashboard_pwd.is_empty()).then_some(server.dashboard_pwd.as_str()),
        }),
        http_plugins: gate
            .map(|gate| {
                vec![wire::PluginToml {
                    name: gate.name.as_str(),
                    addr: gate.addr.as_str(),
                    path: gate.path.as_str(),
                    ops: gate.ops,
                }]
            })
            .unwrap_or_default(),
    };
    toml::to_string(&document).map_err(|error| anyhow!("生成 frps 配置失败：{error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ClientAccess;

    fn base_client() -> Client {
        Client {
            key: "c1".into(),
            name: "home".into(),
            enable: true,
            server_addr: "frps.example.com".into(),
            server_port: 7000,
            token: "secret-token".into(),
            user: "u".into(),
            ..Client::default()
        }
    }

    fn tcp_proxy() -> Proxy {
        Proxy {
            key: "p1".into(),
            name: "ssh".into(),
            enable: true,
            local_ip: "127.0.0.1".into(),
            local_port: 22,
            remote_port: 6022,
            client: "c1".into(),
            ..Proxy::default()
        }
    }

    // -- validation ---------------------------------------------------------

    #[test]
    fn validate_quic_keepalive_less_than_idle() {
        let mut client = base_client();
        client.quic = QuicTuning {
            quic_keepalive_period: 30,
            quic_max_idle_timeout: 10,
            quic_max_incoming_streams: 0,
        };
        let config = normalize(FileConfig {
            clients: vec![client],
            ..FileConfig::default()
        });
        let problems = validate(&config);
        assert!(
            problems
                .iter()
                .any(|problem| problem.field.ends_with("quicKeepalivePeriod")
                    && problem.reason.contains("小于")),
            "{problems:?}"
        );
        // Equal values are also rejected; keepalive below idle passes.
        let mut client = base_client();
        client.quic = QuicTuning {
            quic_keepalive_period: 10,
            quic_max_idle_timeout: 10,
            quic_max_incoming_streams: 0,
        };
        let config = normalize(FileConfig {
            clients: vec![client],
            ..FileConfig::default()
        });
        assert!(
            validate(&config)
                .iter()
                .any(|problem| problem.field.ends_with("quicKeepalivePeriod"))
        );
        // frp defaults cover the zero case: no problem.
        let mut client = base_client();
        client.quic = QuicTuning {
            quic_keepalive_period: 0,
            quic_max_idle_timeout: 0,
            quic_max_incoming_streams: 0,
        };
        let config = normalize(FileConfig {
            clients: vec![client],
            ..FileConfig::default()
        });
        assert!(validate(&config).is_empty());
    }

    #[test]
    fn validate_quic_streams_cap() {
        let mut client = base_client();
        client.protocol = Protocol::Quic;
        client.quic = QuicTuning {
            quic_keepalive_period: 0,
            quic_max_idle_timeout: 0,
            quic_max_incoming_streams: limits::QUIC_STREAMS_CAP + 1,
        };
        let config = normalize(FileConfig {
            clients: vec![client],
            ..FileConfig::default()
        });
        // normalize clamps before validation can even see the overflow.
        assert!(validate(&config).is_empty());
        assert_eq!(
            config.clients[0].quic.quic_max_incoming_streams,
            limits::QUIC_STREAMS_CAP
        );
    }

    #[test]
    fn validate_kcp_quic_ports_differ() {
        let mut server = Server {
            key: "s1".into(),
            name: "main".into(),
            bind_port: 7000,
            kcp_bind_port: 7001,
            quic_bind_port: 7001,
            ..Server::default()
        };
        let config = normalize(FileConfig {
            servers: vec![server.clone()],
            ..FileConfig::default()
        });
        let problems = validate(&config);
        assert!(
            problems
                .iter()
                .any(|problem| problem.field.ends_with("quicBindPort")
                    && problem.reason.contains("不能相同")),
            "{problems:?}"
        );
        // The KCP port may equal the bind port.
        server.kcp_bind_port = 7000;
        server.quic_bind_port = 7002;
        let config = normalize(FileConfig {
            servers: vec![server],
            ..FileConfig::default()
        });
        assert!(validate(&config).is_empty());
    }

    #[test]
    fn validate_proxy_fields_match_type() {
        let mut proxy = tcp_proxy();
        proxy.remote_port = 0;
        let config = FileConfig {
            clients: vec![base_client()],
            proxies: vec![proxy],
            ..FileConfig::default()
        };
        assert!(
            validate(&config)
                .iter()
                .any(|problem| problem.field.ends_with("remotePort"))
        );
        let mut proxy = tcp_proxy();
        proxy.typ = ProxyType::Http;
        let config = FileConfig {
            clients: vec![base_client()],
            proxies: vec![proxy],
            ..FileConfig::default()
        };
        assert!(
            validate(&config)
                .iter()
                .any(|problem| problem.field.ends_with("customDomains"))
        );
        let mut proxy = tcp_proxy();
        proxy.typ = ProxyType::Stcp;
        proxy.remote_port = 0;
        let config = FileConfig {
            clients: vec![base_client()],
            proxies: vec![proxy],
            ..FileConfig::default()
        };
        assert!(
            validate(&config)
                .iter()
                .any(|problem| problem.field.ends_with("secretKey"))
        );
        // A filled http proxy with subdomain passes.
        let proxy = Proxy {
            typ: ProxyType::Http,
            local_port: 80,
            subdomain: "web".into(),
            client: "c1".into(),
            ..tcp_proxy()
        };
        let config = FileConfig {
            clients: vec![base_client()],
            proxies: vec![proxy],
            ..FileConfig::default()
        };
        assert!(validate(&config).is_empty());
    }

    #[test]
    fn validate_proxy_client_exists() {
        let config = FileConfig {
            clients: vec![base_client()],
            proxies: vec![tcp_proxy()],
            ..FileConfig::default()
        };
        assert!(validate(&config).is_empty());
        let mut orphan = tcp_proxy();
        orphan.client = "ghost".into();
        let config = FileConfig {
            clients: vec![base_client()],
            proxies: vec![orphan],
            ..FileConfig::default()
        };
        let problems = validate(&config);
        assert!(
            problems
                .iter()
                .any(|problem| problem.field.ends_with(".client")
                    && problem.reason.contains("不存在")),
            "{problems:?}"
        );
    }

    #[test]
    fn validate_client_access_and_domains() {
        let mut client = base_client();
        client.access = ClientAccess {
            http_scheme: "gopher".into(),
            http_port: 0,
            https_port: 0,
            subdomain_host: "bad host".into(),
        };
        let config = normalize(FileConfig {
            clients: vec![client],
            ..FileConfig::default()
        });
        // An unusable scheme normalizes to "unset" (defaults apply), but a
        // malformed subdomain root stays visible as a problem.
        assert_eq!(config.clients[0].access.http_scheme, "");
        let problems = validate(&config);
        assert!(
            problems
                .iter()
                .any(|problem| problem.field.ends_with("access.subdomainHost")),
            "{problems:?}"
        );
        // A proper scheme survives normalization.
        let mut client = base_client();
        client.access = ClientAccess {
            http_scheme: "HTTPS".into(),
            http_port: 0,
            https_port: 0,
            subdomain_host: "Tunnel.Example.com/".into(),
        };
        let config = normalize(FileConfig {
            clients: vec![client],
            ..FileConfig::default()
        });
        assert_eq!(config.clients[0].access.http_scheme, "https");
        assert_eq!(
            config.clients[0].access.subdomain_host,
            "tunnel.example.com"
        );
        assert!(validate(&config).is_empty());
    }

    #[test]
    fn normalize_trims_and_cleans_collections() {
        let mut server = Server {
            key: " s1 ".into(),
            name: " main ".into(),
            ip_mode: "whitelist".into(),
            ip_list: vec![" 10.0.0.1 ".into(), "bad-entry".into(), "".into()],
            allow_ports: " 8000-9000 ".into(),
            ..Server::default()
        };
        server.ip_deny_list = vec!["203.0.113.0/24".into()];
        let mut proxy = tcp_proxy();
        proxy.local_ip = "  ".into();
        proxy.custom_domains = vec![" My.Example.com ".into(), "https://bad".into()];
        let config = normalize(FileConfig {
            servers: vec![server],
            proxies: vec![proxy],
            ..FileConfig::default()
        });
        let server = &config.servers[0];
        assert_eq!(server.key, "s1");
        assert_eq!(server.ip_mode, "white");
        assert_eq!(server.ip_list, ["10.0.0.1"]);
        assert_eq!(server.ip_deny_list, ["203.0.113.0/24"]);
        assert_eq!(server.allow_ports, "8000-9000");
        let proxy = &config.proxies[0];
        assert_eq!(proxy.local_ip, "127.0.0.1");
        assert_eq!(proxy.custom_domains, ["my.example.com"]);
    }

    #[test]
    fn parse_ip_entry_accepts_ip_and_cidr_only() {
        assert!(parse_ip_entry("10.0.0.1").is_some());
        assert!(parse_ip_entry("203.0.113.0/24").is_some());
        assert!(parse_ip_entry("::1").is_some());
        assert!(parse_ip_entry("not-an-ip").is_none());
        assert!(parse_ip_entry("10.0.0.5/99").is_none());
        assert!(valid_domain("a.example.com"));
        assert!(!valid_domain("bad host"));
        assert!(!valid_domain("host:8080"));
    }

    // -- rendering ----------------------------------------------------------

    #[test]
    fn render_client_toml_snapshot() {
        let client = Client {
            quic: QuicTuning {
                quic_keepalive_period: 5,
                quic_max_idle_timeout: 60,
                quic_max_incoming_streams: 1000,
            },
            tls: Some(false),
            protocol: Protocol::Quic,
            ..base_client()
        };
        let http = Proxy {
            key: "p2".into(),
            name: "web".into(),
            enable: true,
            typ: ProxyType::Http,
            local_ip: "127.0.0.1".into(),
            local_port: 80,
            subdomain: "web".into(),
            custom_domains: vec!["app.example.com".into()],
            client: "c1".into(),
            ..Proxy::default()
        };
        let disabled = Proxy {
            key: "p3".into(),
            name: "off".into(),
            enable: false,
            client: "c1".into(),
            ..tcp_proxy()
        };
        let other = Proxy {
            key: "p4".into(),
            name: "elsewhere".into(),
            client: "c2".into(),
            ..tcp_proxy()
        };
        let rendered =
            render_client_toml(&client, &[tcp_proxy(), http, disabled, other]).expect("render");
        let expected = r#"serverAddr = "frps.example.com"
serverPort = 7000
user = "u"

[auth]
token = "secret-token"

[transport]
protocol = "quic"

[transport.tls]
enable = false

[transport.quic]
keepalivePeriod = 5
maxIdleTimeout = 60
maxIncomingStreams = 1000

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6022

[[proxies]]
name = "web"
type = "http"
localIP = "127.0.0.1"
localPort = 80
customDomains = ["app.example.com"]
subdomain = "web"
"#;
        assert_eq!(rendered, expected, "\n--- rendered ---\n{rendered}");
        // The output is valid TOML that round-trips into the expected keys.
        let value: toml::Value = toml::from_str(&rendered).expect("parse");
        assert_eq!(value["serverAddr"], toml::Value::from("frps.example.com"));
        assert_eq!(
            value["transport"]["tls"]["enable"],
            toml::Value::Boolean(false)
        );
        assert_eq!(
            value["transport"]["quic"]["keepalivePeriod"],
            toml::Value::Integer(5)
        );
        assert_eq!(
            value["proxies"][0]["remotePort"],
            toml::Value::Integer(6022)
        );
        assert_eq!(value["proxies"][1]["subdomain"], toml::Value::from("web"));
    }

    #[test]
    fn render_server_toml_snapshot() {
        let server = Server {
            key: "s1".into(),
            name: "main".into(),
            bind_addr: "0.0.0.0".into(),
            bind_port: 7000,
            kcp_bind_port: 7000,
            quic_bind_port: 7002,
            quic: QuicTuning {
                quic_keepalive_period: 10,
                quic_max_idle_timeout: 30,
                quic_max_incoming_streams: 100000,
            },
            token: "srv-token".into(),
            proxy_bind_addr: "127.0.0.1".into(),
            vhost_http_port: 8080,
            vhost_https_port: 8443,
            subdomain_host: "frps.example.com".into(),
            allow_ports: "6000-6100,7000".into(),
            dashboard_port: 7500,
            dashboard_addr: "127.0.0.1".into(),
            dashboard_user: "admin".into(),
            dashboard_pwd: "admin-pwd".into(),
            ..Server::default()
        };
        let gate = PluginEndpoint::gate("http://127.0.0.1:19555".into(), "/frp/login".into());
        let rendered = render_server_toml(&server, Some(&gate)).expect("render");
        let expected = r#"bindAddr = "0.0.0.0"
bindPort = 7000
kcpBindPort = 7000
quicBindPort = 7002
proxyBindAddr = "127.0.0.1"
vhostHTTPPort = 8080
vhostHTTPSPort = 8443
subDomainHost = "frps.example.com"

[auth]
token = "srv-token"

[transport.quic]
keepalivePeriod = 10
maxIdleTimeout = 30
maxIncomingStreams = 100000

[[allowPorts]]
start = 6000
end = 6100

[[allowPorts]]
single = 7000

[webServer]
addr = "127.0.0.1"
port = 7500
user = "admin"
password = "admin-pwd"

[[httpPlugins]]
name = "ferrumgate-frp"
addr = "http://127.0.0.1:19555"
path = "/frp/login"
ops = ["Login", "NewProxy"]
"#;
        assert_eq!(rendered, expected, "\n--- rendered ---\n{rendered}");
        let value: toml::Value = toml::from_str(&rendered).expect("parse");
        assert_eq!(
            value["httpPlugins"][0]["ops"][0],
            toml::Value::from("Login")
        );
        assert_eq!(value["allowPorts"][0]["start"], toml::Value::Integer(6000));
        assert_eq!(value["allowPorts"][1]["single"], toml::Value::Integer(7000));
    }

    #[test]
    fn render_server_toml_without_gate_and_defaults() {
        let server = Server {
            key: "s1".into(),
            name: "bare".into(),
            bind_port: 7000,
            ..Server::default()
        };
        let rendered = render_server_toml(&server, None).expect("render");
        assert!(!rendered.contains("httpPlugins"));
        assert!(!rendered.contains("auth"));
        assert!(!rendered.contains("webServer"));
        assert!(rendered.contains("bindPort = 7000"));
    }

    #[test]
    fn render_token_in_file_not_on_command_line() {
        let client = base_client();
        let rendered = render_client_toml(&client, &[tcp_proxy()]).expect("render");
        assert!(rendered.contains("secret-token"), "token lives in the file");
        // The spawn arguments the runtime builds carry only `-c <path>`.
        let args = [
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from("/cfg/frp/c1.toml"),
        ];
        let joined = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!joined.contains("secret-token"));
    }
}
