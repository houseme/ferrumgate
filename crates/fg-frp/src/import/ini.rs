//! The legacy INI importer (WP-44 step 9): `frpc.ini` / `frps.ini` with a
//! `[common]` section. Comments (`#`, `;`), `key = value` pairs, one
//! section per proxy on the client side. Unmapped keys are reported in the
//! preview's `ignored` list, never silently dropped.

use super::{ImportError, ImportPreview};
use crate::model::{Client, Protocol, Proxy, ProxyType, Server};

/// Parses INI content and detects the role from the `[common]` keys
/// (`server_addr` → frpc, `bind_port` → frps).
pub fn parse(content: &str) -> Result<ImportPreview, ImportError> {
    let sections = parse_sections(content);
    let Some(common) = sections.iter().find(|(name, _)| name == "common") else {
        return Err("INI 缺少 [common] 段".to_owned());
    };
    let keys = keys_of(&common.1);
    if keys.contains_key("server_addr") {
        Ok(parse_client(&sections))
    } else if keys.contains_key("bind_port") {
        parse_server(&sections)
    } else {
        Err("无法从 [common] 段识别角色（需要 server_addr 或 bind_port）".to_owned())
    }
}

/// Sections in file order: `[(section, [(key, value)])]`.
fn parse_sections(content: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut sections: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            sections.push((name.trim().to_owned(), Vec::new()));
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let entry = (key.trim().to_owned(), value.trim().to_owned());
        match sections.last_mut() {
            Some((_, entries)) => entries.push(entry),
            // Keys before any section header land in an implicit common.
            None => sections.push(("common".to_owned(), vec![entry])),
        }
    }
    sections
}

fn keys_of(entries: &[(String, String)]) -> std::collections::BTreeMap<&str, &str> {
    entries
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect()
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

fn parse_u16(value: &str) -> Option<u16> {
    value.trim().parse::<u16>().ok()
}

fn parse_protocol(value: &str) -> Option<Protocol> {
    match value.trim().to_ascii_lowercase().as_str() {
        "tcp" => Some(Protocol::Tcp),
        "kcp" => Some(Protocol::Kcp),
        "quic" => Some(Protocol::Quic),
        "websocket" => Some(Protocol::Websocket),
        "wss" => Some(Protocol::Wss),
        _ => None,
    }
}

fn parse_proxy_type(value: &str) -> Option<ProxyType> {
    match value.trim().to_ascii_lowercase().as_str() {
        "tcp" => Some(ProxyType::Tcp),
        "udp" => Some(ProxyType::Udp),
        "http" => Some(ProxyType::Http),
        "https" => Some(ProxyType::Https),
        "stcp" => Some(ProxyType::Stcp),
        "xtcp" => Some(ProxyType::Xtcp),
        _ => None,
    }
}

fn parse_client(sections: &[(String, Vec<(String, String)>)]) -> ImportPreview {
    let mut preview = ImportPreview::default();
    let mut client = Client {
        name: "imported".to_string(),
        enable: false,
        ..Client::default()
    };
    let common = sections
        .iter()
        .find(|(name, _)| name == "common")
        .map(|(_, entries)| keys_of(entries))
        .unwrap_or_default();
    let mut ignore = |key: &str, value: &str| {
        preview.ignored.push(format!("common.{key}: {value}"));
    };
    for (key, value) in &common {
        match *key {
            "server_addr" => client.server_addr = value.to_string(),
            "server_port" => {
                if let Some(port) = parse_u16(value) {
                    client.server_port = port;
                } else {
                    ignore(key, value);
                }
            }
            "token" => client.token = value.to_string(),
            "user" => client.user = value.to_string(),
            "protocol" => match parse_protocol(value) {
                Some(protocol) => client.protocol = protocol,
                None => ignore(key, value),
            },
            "tls_enable" | "tls" => match parse_bool(value) {
                Some(enable) => client.tls = Some(enable),
                None => ignore(key, value),
            },
            "quic_keepalive_period" => {
                client.quic.quic_keepalive_period = value.parse().unwrap_or(0);
            }
            "quic_max_idle_timeout" => {
                client.quic.quic_max_idle_timeout = value.parse().unwrap_or(0);
            }
            "quic_max_incoming_streams" => {
                client.quic.quic_max_incoming_streams = value.parse().unwrap_or(0);
            }
            _ => ignore(key, value),
        }
    }
    // Visitor access block from the common section when present.
    if let Some(scheme) = common.get("vhost_http_scheme") {
        client.access.http_scheme = (*scheme).to_owned();
    } else if common.contains_key("vhost_https_port") {
        client.access.http_scheme = "https".to_owned();
    }
    if let Some(port) = common.get("vhost_http_port").and_then(|v| parse_u16(v)) {
        client.access.http_port = port;
    }
    if let Some(port) = common.get("vhost_https_port").and_then(|v| parse_u16(v)) {
        client.access.https_port = port;
    }
    if let Some(host) = common.get("subdomain_host") {
        client.access.subdomain_host = (*host).to_owned();
    }
    if client.quic.quic_max_incoming_streams > crate::model::limits::QUIC_STREAMS_CAP {
        client.quic.quic_max_incoming_streams = crate::model::limits::QUIC_STREAMS_CAP;
    }
    preview.clients.push(client);
    for (name, entries) in sections.iter().filter(|(name, _)| name != "common") {
        let keys = keys_of(entries);
        let typ = keys
            .get("type")
            .and_then(|value| parse_proxy_type(value))
            .unwrap_or(ProxyType::Tcp);
        let mut proxy = Proxy {
            name: name.clone(),
            typ,
            enable: true,
            local_ip: keys
                .get("local_ip")
                .map(|value| value.to_string())
                .unwrap_or_else(|| "127.0.0.1".to_owned()),
            client: String::new(),
            ..Proxy::default()
        };
        for (key, value) in &keys {
            match *key {
                "type" | "local_ip" => {}
                "local_port" => proxy.local_port = parse_u16(value).unwrap_or(0),
                "remote_port" => proxy.remote_port = parse_u16(value).unwrap_or(0),
                "custom_domains" => {
                    proxy.custom_domains = value
                        .split([',', '，'])
                        .map(|domain| domain.trim().to_owned())
                        .filter(|domain| !domain.is_empty())
                        .collect();
                }
                "subdomain" => proxy.subdomain = value.to_string(),
                "secret_key" | "sk" => proxy.secret_key = value.to_string(),
                // Everything the model does not carry is reported as
                // ignored, never silently dropped.
                _ => preview.ignored.push(format!("{name}.{key}: {value}")),
            }
        }
        if proxy.typ.needs_secret()
            && proxy.secret_key.is_empty()
            && let Some(sk) = keys.get("sk")
        {
            proxy.secret_key = (*sk).to_owned();
        }
        preview.proxies.push(proxy);
    }
    // Proxies belong to the (single) imported instance.
    for proxy in &mut preview.proxies {
        proxy.client = preview.clients[0].key.clone();
    }
    preview
}

fn parse_server(
    sections: &[(String, Vec<(String, String)>)],
) -> Result<ImportPreview, ImportError> {
    let mut preview = ImportPreview::default();
    let mut server = Server {
        name: "imported".to_string(),
        enable: false,
        ..Server::default()
    };
    let common = sections
        .iter()
        .find(|(name, _)| name == "common")
        .map(|(_, entries)| keys_of(entries))
        .unwrap_or_default();
    for (key, value) in &common {
        match *key {
            "bind_addr" => server.bind_addr = value.to_string(),
            "bind_port" => server.bind_port = parse_u16(value).unwrap_or(7000),
            "kcp_bind_port" => server.kcp_bind_port = parse_u16(value).unwrap_or(0),
            "quic_bind_port" => server.quic_bind_port = parse_u16(value).unwrap_or(0),
            "token" => server.token = value.to_string(),
            "proxy_bind_addr" => server.proxy_bind_addr = value.to_string(),
            "vhost_http_port" => server.vhost_http_port = parse_u16(value).unwrap_or(0),
            "vhost_https_port" => server.vhost_https_port = parse_u16(value).unwrap_or(0),
            "subdomain_host" => server.subdomain_host = value.to_string(),
            "allow_ports" => server.allow_ports = value.replace('，', ","),
            "dashboard_port" => server.dashboard_port = parse_u16(value).unwrap_or(0),
            "dashboard_addr" => server.dashboard_addr = value.to_string(),
            "dashboard_user" => server.dashboard_user = value.to_string(),
            "dashboard_pwd" => server.dashboard_pwd = value.to_string(),
            "quic_keepalive_period" => {
                server.quic.quic_keepalive_period = value.parse().unwrap_or(0);
            }
            "quic_max_idle_timeout" => {
                server.quic.quic_max_idle_timeout = value.parse().unwrap_or(0);
            }
            "quic_max_incoming_streams" => {
                server.quic.quic_max_incoming_streams = value.parse().unwrap_or(0);
            }
            _ => preview.ignored.push(format!("common.{key}: {value}")),
        }
    }
    if server.quic.quic_max_incoming_streams > crate::model::limits::QUIC_STREAMS_CAP {
        server.quic.quic_max_incoming_streams = crate::model::limits::QUIC_STREAMS_CAP;
    }
    // Bind-address-only legacy files (Gately upstream TestImportServerBindAddr):
    // a missing bind_port keeps the frp default 7000.
    preview.servers.push(server);
    Ok(preview)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_INI: &str = r#"
# a comment
[common]
server_addr = frps.example.com
server_port = 7000
token = legacy-token
user = home
protocol = kcp
tls_enable = true
websocket_pool_count = 5

[ssh]
type = tcp
local_ip = 10.0.0.3
local_port = 22
remote_port = 6022
use_encryption = true

[web]
type = http
local_port = 80
custom_domains = app.example.com, web.example.com
subdomain = web

[secret]
type = stcp
local_port = 3389
secret_key = rdp-sk
"#;

    #[test]
    fn import_ini_with_common_section() {
        let preview = parse(CLIENT_INI).expect("parse");
        assert_eq!(preview.clients.len(), 1);
        let client = &preview.clients[0];
        assert_eq!(client.server_addr, "frps.example.com");
        assert_eq!(client.server_port, 7000);
        assert_eq!(client.token, "legacy-token");
        assert_eq!(client.user, "home");
        assert_eq!(client.protocol, Protocol::Kcp);
        assert_eq!(client.tls, Some(true));
        // New instances from an import are disabled by default.
        assert!(!client.enable);

        assert_eq!(preview.proxies.len(), 3);
        let ssh = &preview.proxies[0];
        assert_eq!(ssh.name, "ssh");
        assert_eq!(ssh.typ, ProxyType::Tcp);
        assert_eq!(ssh.local_ip, "10.0.0.3");
        assert_eq!(ssh.remote_port, 6022);
        assert!(ssh.enable, "导入的代理保持可用");
        let web = &preview.proxies[1];
        assert_eq!(web.custom_domains, ["app.example.com", "web.example.com"]);
        assert_eq!(web.subdomain, "web");
        let secret = &preview.proxies[2];
        assert_eq!(secret.typ, ProxyType::Stcp);
        assert_eq!(secret.secret_key, "rdp-sk");
        // Proxies point at the imported instance.
        assert_eq!(preview.proxies[0].client, preview.clients[0].key);

        // Unmapped fields are reported, per section.
        assert!(
            preview
                .ignored
                .iter()
                .any(|line| line == "common.websocket_pool_count: 5"),
            "{:?}",
            preview.ignored
        );
        assert!(
            preview
                .ignored
                .iter()
                .any(|line| line.starts_with("ssh.use_encryption"))
        );
    }

    #[test]
    fn import_ini_server_maps_common() {
        let content = r#"
[common]
bind_addr = 0.0.0.0
bind_port = 7000
kcp_bind_port = 7001
token = srv
vhost_http_port = 8080
subdomain_host = frps.example.com
allow_ports = 6000-6100，7000
dashboard_port = 7500
dashboard_user = admin
dashboard_pwd = pw
max_ports_per_client = 10
"#;
        let preview = parse(content).expect("parse");
        assert!(preview.clients.is_empty());
        let server = &preview.servers[0];
        assert_eq!(server.bind_addr, "0.0.0.0");
        assert_eq!(server.bind_port, 7000);
        assert_eq!(server.kcp_bind_port, 7001);
        assert_eq!(server.token, "srv");
        assert_eq!(server.vhost_http_port, 8080);
        assert_eq!(server.subdomain_host, "frps.example.com");
        assert_eq!(server.allow_ports, "6000-6100,7000");
        assert_eq!(server.dashboard_port, 7500);
        assert_eq!(server.dashboard_user, "admin");
        assert_eq!(server.dashboard_pwd, "pw");
        assert!(
            preview
                .ignored
                .iter()
                .any(|line| line.starts_with("common.max_ports_per_client"))
        );
    }

    #[test]
    fn import_ini_rejects_missing_common_or_unknown_role() {
        assert!(parse("[ssh]\ntype = tcp\n").is_err(), "no [common]");
        assert!(
            parse("[common]\nuser = u\n").is_err(),
            "no server_addr / bind_port in [common]"
        );
    }
}
