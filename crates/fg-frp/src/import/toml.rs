//! The frp 0.52+ TOML importer (WP-44 step 10): maps the documented
//! surface of the frpc / frps TOML onto the model; unknown keys and
//! unknown per-proxy keys land in the preview's `ignored` list. Role
//! detection: `serverAddr` or `[[proxies]]` → frpc, `bindPort` → frps.

use toml::Value;

use super::{ImportError, ImportPreview};
use crate::model::{Client, Protocol, Proxy, ProxyType, QuicTuning, Server, limits};

/// Parses TOML content and detects the role.
pub fn parse(content: &str) -> Result<ImportPreview, ImportError> {
    let table: toml::Table = content
        .parse::<toml::Table>()
        .map_err(|error| format!("TOML 解析失败：{error}"))?;
    let is_client = table.contains_key("serverAddr") || table.contains_key("proxies");
    let is_server = table.contains_key("bindPort");
    match (is_client, is_server) {
        (true, _) => Ok(parse_client(&table)),
        (false, true) => Ok(parse_server(&table)),
        (false, false) => Err("无法识别角色（需要 serverAddr 或 bindPort）".to_owned()),
    }
}

fn as_str(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}

fn as_u16(value: Option<&Value>) -> Option<u16> {
    value
        .and_then(Value::as_integer)
        .and_then(|int| u16::try_from(int).ok())
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

fn parse_quic(table: &toml::Table, quic: &mut QuicTuning, ignored: &mut Vec<String>, place: &str) {
    for (key, value) in table {
        match key.as_str() {
            "keepalivePeriod" => {
                quic.quic_keepalive_period = as_u16(Some(value)).unwrap_or(0) as u32
            }
            "maxIdleTimeout" => {
                quic.quic_max_idle_timeout = as_u16(Some(value)).unwrap_or(0) as u32
            }
            "maxIncomingStreams" => {
                quic.quic_max_incoming_streams = value
                    .as_integer()
                    .and_then(|int| u32::try_from(int).ok())
                    .unwrap_or(0);
            }
            _ => ignored.push(format!("{place}.{key}: {value}")),
        }
    }
    quic.quic_max_incoming_streams = quic.quic_max_incoming_streams.min(limits::QUIC_STREAMS_CAP);
}

fn parse_client(table: &toml::Table) -> ImportPreview {
    let mut preview = ImportPreview::default();
    let mut ignored: Vec<String> = Vec::new();
    let mut client = Client {
        name: "imported".to_owned(),
        enable: false,
        ..Client::default()
    };
    for (key, value) in table {
        match key.as_str() {
            "serverAddr" => {
                client.server_addr = as_str(Some(value)).unwrap_or_default();
            }
            "serverPort" => client.server_port = as_u16(Some(value)).unwrap_or(7000),
            "user" => client.user = as_str(Some(value)).unwrap_or_default(),
            "auth" => {
                if let Some(token) = value.as_table().and_then(|auth| auth.get("token")) {
                    client.token = as_str(Some(token)).unwrap_or_default();
                }
                if let Some(auth) = value.as_table() {
                    for (sub, sub_value) in auth {
                        if sub != "token" {
                            ignored.push(format!("auth.{sub}: {sub_value}"));
                        }
                    }
                }
            }
            "transport" => {
                if let Some(transport) = value.as_table() {
                    for (sub, sub_value) in transport {
                        match sub.as_str() {
                            "protocol" => {
                                let text = as_str(Some(sub_value)).unwrap_or_default();
                                match parse_protocol(&text) {
                                    Some(protocol) => client.protocol = protocol,
                                    None => ignored.push(format!("transport.protocol: {text}")),
                                }
                            }
                            "tls" => {
                                // frp: transport.tls.enable
                                let enable = sub_value
                                    .as_table()
                                    .and_then(|tls| tls.get("enable"))
                                    .and_then(as_bool_from);
                                match enable {
                                    Some(enable) => client.tls = Some(enable),
                                    None => ignored.push(format!("transport.tls: {sub_value}")),
                                }
                                if let Some(tls) = sub_value.as_table() {
                                    for (tls_key, tls_value) in tls {
                                        if tls_key != "enable" {
                                            ignored.push(format!(
                                                "transport.tls.{tls_key}: {tls_value}"
                                            ));
                                        }
                                    }
                                }
                            }
                            "quic" => {
                                if let Some(quic_table) = sub_value.as_table() {
                                    parse_quic(
                                        quic_table,
                                        &mut client.quic,
                                        &mut ignored,
                                        "transport.quic",
                                    );
                                }
                            }
                            _ => ignored.push(format!("transport.{sub}: {sub_value}")),
                        }
                    }
                }
            }
            "proxies" => {} // handled below
            _ => ignored.push(format!("{key}: {value}")),
        }
    }
    if let Some(proxies) = table.get("proxies").and_then(Value::as_array) {
        for entry in proxies {
            let Some(proxy_table) = entry.as_table() else {
                ignored.push(format!("proxies: {entry}"));
                continue;
            };
            let mut proxy = Proxy {
                name: as_str(proxy_table.get("name")).unwrap_or_default(),
                typ: as_str(proxy_table.get("type"))
                    .and_then(|text| parse_proxy_type(&text))
                    .unwrap_or(ProxyType::Tcp),
                enable: true,
                local_ip: as_str(proxy_table.get("localIP")).unwrap_or_else(|| "127.0.0.1".into()),
                client: String::new(),
                ..Proxy::default()
            };
            for (key, value) in proxy_table {
                match key.as_str() {
                    "name" | "type" | "localIP" => {}
                    "localPort" => proxy.local_port = as_u16(Some(value)).unwrap_or(0),
                    "remotePort" => proxy.remote_port = as_u16(Some(value)).unwrap_or(0),
                    "customDomains" => {
                        proxy.custom_domains = value
                            .as_array()
                            .map(|domains| {
                                domains
                                    .iter()
                                    .filter_map(|domain| as_str(Some(domain)))
                                    .filter(|domain| crate::validate::valid_domain(domain))
                                    .collect()
                            })
                            .unwrap_or_default();
                    }
                    "subdomain" => proxy.subdomain = as_str(Some(value)).unwrap_or_default(),
                    "secretKey" => proxy.secret_key = as_str(Some(value)).unwrap_or_default(),
                    _ => ignored.push(format!("proxies.{}.{}: {}", proxy.name, key, value)),
                }
            }
            preview.proxies.push(proxy);
        }
    }
    preview.clients.push(client);
    for proxy in &mut preview.proxies {
        proxy.client = preview.clients[0].key.clone();
    }
    preview.ignored = ignored;
    preview
}

fn as_bool_from(value: &Value) -> Option<bool> {
    value.as_bool()
}

fn parse_server(table: &toml::Table) -> ImportPreview {
    let mut preview = ImportPreview::default();
    let mut server = Server {
        name: "imported".to_owned(),
        enable: false,
        ..Server::default()
    };
    for (key, value) in table {
        match key.as_str() {
            "bindAddr" => server.bind_addr = as_str(Some(value)).unwrap_or_default(),
            "bindPort" => server.bind_port = as_u16(Some(value)).unwrap_or(7000),
            "kcpBindPort" => server.kcp_bind_port = as_u16(Some(value)).unwrap_or(0),
            "quicBindPort" => server.quic_bind_port = as_u16(Some(value)).unwrap_or(0),
            "proxyBindAddr" => server.proxy_bind_addr = as_str(Some(value)).unwrap_or_default(),
            "vhostHTTPPort" => server.vhost_http_port = as_u16(Some(value)).unwrap_or(0),
            "vhostHTTPSPort" => server.vhost_https_port = as_u16(Some(value)).unwrap_or(0),
            "subDomainHost" => server.subdomain_host = as_str(Some(value)).unwrap_or_default(),
            "auth" => {
                server.token = value
                    .as_table()
                    .and_then(|auth| auth.get("token"))
                    .and_then(|token| as_str(Some(token)))
                    .unwrap_or_default();
            }
            "transport" => {
                if let Some(quic) = value.as_table().and_then(|transport| transport.get("quic"))
                    && let Some(quic_table) = quic.as_table()
                {
                    parse_quic(
                        quic_table,
                        &mut server.quic,
                        &mut preview.ignored,
                        "transport.quic",
                    );
                }
            }
            "allowPorts" => {
                server.allow_ports = allow_ports_text(value);
            }
            "webServer" => {
                if let Some(web) = value.as_table() {
                    for (sub, sub_value) in web {
                        match sub.as_str() {
                            "port" => server.dashboard_port = as_u16(Some(sub_value)).unwrap_or(0),
                            "addr" => {
                                server.dashboard_addr = as_str(Some(sub_value)).unwrap_or_default()
                            }
                            "user" => {
                                server.dashboard_user = as_str(Some(sub_value)).unwrap_or_default()
                            }
                            "password" => {
                                server.dashboard_pwd = as_str(Some(sub_value)).unwrap_or_default()
                            }
                            _ => preview
                                .ignored
                                .push(format!("webServer.{sub}: {sub_value}")),
                        }
                    }
                }
            }
            _ => preview.ignored.push(format!("{key}: {value}")),
        }
    }
    preview.servers.push(server);
    preview
}

/// `allowPorts` array of `{start, end}` / `{single}` tables → the model's
/// port text (`"6000-6100,7000"`).
fn allow_ports_text(value: &Value) -> String {
    let Some(ranges) = value.as_array() else {
        return String::new();
    };
    let mut parts = Vec::new();
    for range in ranges {
        let Some(table) = range.as_table() else {
            continue;
        };
        let start = as_u16(table.get("start"));
        let end = as_u16(table.get("end"));
        let single = as_u16(table.get("single"));
        if let Some(single) = single {
            parts.push(single.to_string());
        } else if let Some(start) = start {
            match end {
                Some(end) if end > start => parts.push(format!("{start}-{end}")),
                _ => parts.push(start.to_string()),
            }
        }
    }
    parts.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_TOML: &str = r#"
serverAddr = "frps.example.com"
serverPort = 7000
user = "me"

[auth]
token = "tok"

[transport]
protocol = "quic"

[transport.tls]
enable = true

[transport.quic]
keepalivePeriod = 5
maxIdleTimeout = 60
metas = "unused"

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "10.0.0.3"
localPort = 22
remotePort = 6022

[[proxies]]
name = "web"
type = "http"
localPort = 80
customDomains = ["app.example.com"]
subdomain = "web"
httpUser = "u"
"#;

    #[test]
    fn import_toml_maps_client_fields() {
        let preview = parse(CLIENT_TOML).expect("parse");
        assert_eq!(preview.clients.len(), 1);
        assert_eq!(preview.servers.len(), 0);
        let client = &preview.clients[0];
        assert_eq!(client.server_addr, "frps.example.com");
        assert_eq!(client.server_port, 7000);
        assert_eq!(client.token, "tok");
        assert_eq!(client.protocol, Protocol::Quic);
        assert_eq!(client.tls, Some(true));
        assert_eq!(client.quic.quic_keepalive_period, 5);
        assert_eq!(preview.proxies.len(), 2);
        assert_eq!(preview.proxies[0].remote_port, 6022);
        assert_eq!(preview.proxies[0].local_ip, "10.0.0.3");
        assert_eq!(preview.proxies[1].custom_domains, ["app.example.com"]);
        assert_eq!(preview.proxies[1].subdomain, "web");
        // Unmapped keys are reported: transport.quic.metas, proxies.web.httpUser.
        assert!(
            preview
                .ignored
                .iter()
                .any(|line| line.starts_with("transport.quic.metas")),
            "{:?}",
            preview.ignored
        );
        assert!(preview.ignored.iter().any(|line| line.contains("httpUser")));
        // The proxies point at the imported instance.
        assert_eq!(preview.proxies[0].client, preview.clients[0].key);
    }

    #[test]
    fn import_toml_maps_server_fields_and_allow_ports() {
        let content = r#"
bindAddr = "0.0.0.0"
bindPort = 7000
kcpBindPort = 7001
quicBindPort = 7002
subDomainHost = "frps.example.com"
allowPorts = [
  { start = 6000, end = 6100 },
  { single = 7000 },
]

[auth]
token = "srv"

[webServer]
port = 7500
user = "admin"
password = "pw"
maxPorts = 1
"#;
        let preview = parse(content).expect("parse");
        let server = &preview.servers[0];
        assert_eq!(server.bind_addr, "0.0.0.0");
        assert_eq!(server.bind_port, 7000);
        assert_eq!(server.kcp_bind_port, 7001);
        assert_eq!(server.quic_bind_port, 7002);
        assert_eq!(server.token, "srv");
        assert_eq!(server.allow_ports, "6000-6100,7000");
        assert_eq!(server.dashboard_port, 7500);
        assert_eq!(server.dashboard_pwd, "pw");
        assert!(
            preview
                .ignored
                .iter()
                .any(|line| line.starts_with("webServer.maxPorts")),
            "{:?}",
            preview.ignored
        );
    }

    #[test]
    fn import_toml_rejects_unknown_role_and_broken_text() {
        assert!(parse("unrelated = 1").is_err());
        assert!(parse("not toml ][").is_err());
        // An empty document has no role marker.
        assert!(parse("").is_err());
    }
}
