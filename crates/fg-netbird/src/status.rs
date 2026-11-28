//! Instance status parsed from `netbird status --json` (WP-45 §5 step
//! 11): management connection state, the local peer address, and the
//! peers list with direct / relayed path, handshake and traffic. Parsing
//! is whitelist-only with tolerances for the field names seen across
//! NetBird versions; unknown fields are ignored. It also contains the
//! version helpers for the pre-0.75 SOCKS5 warning (WP-45 §3.3: 0.75
//! 之前的版本在用户态网络下忽略设置的 SOCKS5 地址、总是监听全部地址).

use serde::Serialize;
use serde_json::Value;

/// One peer from the status payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerInfo {
    pub ip: String,
    pub fqdn: String,
    pub connected: bool,
    /// Direct path when true; relayed otherwise.
    pub direct: bool,
    pub relay: String,
    pub last_handshake: String,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
}

/// The parsed status (whitelisted fields only).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusInfo {
    /// Management URL the daemon reports.
    pub management_url: String,
    /// True when the daemon is connected to the management plane (i.e.
    /// authenticated and joined).
    pub management_connected: bool,
    /// This peer's NetBird IP.
    pub local_ip: String,
    pub peers: Vec<PeerInfo>,
}

impl StatusInfo {
    /// The node is joined and usable.
    pub fn connected(&self) -> bool {
        self.management_connected
    }
}

fn text(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        match value.get(*key) {
            Some(Value::String(text)) if !text.is_empty() => return Some(text.clone()),
            Some(Value::Number(number)) => return Some(number.to_string()),
            _ => {}
        }
    }
    None
}

fn boolean(value: &Value, keys: &[&str]) -> Option<bool> {
    for key in keys {
        if let Some(found) = value.get(*key) {
            if let Some(parsed) = found.as_bool() {
                return Some(parsed);
            }
            // "status": "Connected"
            if let Some(status) = found.as_str() {
                return Some(status.eq_ignore_ascii_case("connected"));
            }
        }
    }
    None
}

fn number(value: &Value, keys: &[&str]) -> Option<u64> {
    for key in keys {
        if let Some(found) = value.get(*key)
            && let Some(parsed) = found.as_u64().or_else(|| found.as_f64().map(|f| f as u64))
        {
            return Some(parsed);
        }
    }
    None
}

fn parse_peer(value: &Value) -> Option<PeerInfo> {
    Some(PeerInfo {
        ip: text(value, &["ip", "IP"]).unwrap_or_default(),
        fqdn: text(value, &["fqdn", "FQDN", "dns", "DNS"]).unwrap_or_default(),
        connected: boolean(value, &["connected", "Connected", "status", "Status"]).unwrap_or(false),
        direct: value
            .get("direct")
            .or_else(|| value.get("Direct"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        relay: text(value, &["relay", "Relay"]).unwrap_or_default(),
        last_handshake: text(
            value,
            &[
                "lastWireguardHandshake",
                "LastWireguardHandshake",
                "lastHandshake",
            ],
        )
        .unwrap_or_default(),
        rx_bytes: number(value, &["transferReceived", "TransferReceived", "rxBytes"]),
        tx_bytes: number(value, &["transferSent", "TransferSent", "txBytes"]),
    })
}

/// Parses the full status payload.
pub fn parse_status(body: &Value) -> StatusInfo {
    let management = body
        .get("managementState")
        .or_else(|| body.get("management"))
        .cloned()
        .unwrap_or(Value::Null);
    let local = body
        .get("localPeerState")
        .or_else(|| body.get("local"))
        .cloned()
        .unwrap_or(Value::Null);
    let peers = match body.get("peers").or_else(|| body.get("Peers")) {
        Some(Value::Array(items)) => items.iter().filter_map(parse_peer).collect(),
        Some(Value::Object(map)) => map.values().filter_map(parse_peer).collect(),
        _ => Vec::new(),
    };
    StatusInfo {
        management_url: text(&management, &["url", "URL"]).unwrap_or_default(),
        management_connected: boolean(&management, &["connected", "Connected"]).unwrap_or(false),
        local_ip: text(&local, &["ip", "IP"]).unwrap_or_default(),
        peers,
    }
}

/// Parses the first `x.y.z` version in `netbird version` output.
pub fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = Vec::new();
    let mut current = String::new();
    for c in text.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_digit() {
            current.push(c);
        } else if c == '.' && !current.is_empty() {
            parts.push(current.clone());
            current.clear();
        } else {
            if !current.is_empty() {
                parts.push(current.clone());
            }
            current.clear();
            if parts.len() >= 3 {
                break;
            }
            parts.clear();
        }
    }
    if parts.len() < 3 {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ))
}

/// NetBird before 0.75 runs the userspace SOCKS5 proxy on all interfaces
/// regardless of the configured address — warn loudly (WP-45 §3.3).
pub fn old_version_warns_public_socks(version: Option<(u32, u32, u32)>) -> bool {
    match version {
        // Unknown version: no claim, no warning from this check.
        None => false,
        Some(version) => version < (0, 75, 0),
    }
}

/// Scans CLI output for the login link (device-code login). Returns the
/// first http(s) URL, if any.
pub fn parse_login_link(lines: &[String]) -> Option<String> {
    lines
        .iter()
        .filter_map(|line| {
            let start = line.find("http://").or_else(|| line.find("https://"))?;
            let rest = &line[start..];
            let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
            Some(rest[..end].to_owned())
        })
        .next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Value {
        json!({
            "managementState": {"url": "https://api.netbird.io:443", "connected": true, "extra": 1},
            "signalState": {"connected": true},
            "localPeerState": {"IP": "100.90.0.5", "kernelWireguard": false},
            "peers": [
                {
                    "ip": "100.90.0.2",
                    "fqdn": "alpha.corp.example",
                    "connected": true,
                    "direct": true,
                    "relay": "",
                    "lastWireguardHandshake": "2025-06-01T12:00:00Z",
                    "transferReceived": 1024,
                    "transferSent": 2048,
                    "unknownFuture": {"deep": [1]}
                },
                {
                    "ip": "100.90.0.3",
                    "fqdn": "beta.corp.example",
                    "status": "Connected",
                    "direct": false,
                    "relay": "relay-1",
                    "transferReceived": 1,
                    "transferSent": 2
                }
            ]
        })
    }

    #[test]
    fn netbird_status_parsed_from_cli_json() {
        let status = parse_status(&fixture());
        assert!(status.connected());
        assert_eq!(status.management_url, "https://api.netbird.io:443");
        assert_eq!(status.local_ip, "100.90.0.5");
        assert_eq!(status.peers.len(), 2);
        assert_eq!(status.peers[0].fqdn, "alpha.corp.example");
        assert_eq!(status.peers[0].last_handshake, "2025-06-01T12:00:00Z");
        assert_eq!(status.peers[0].rx_bytes, Some(1024));
        assert!(status.peers[0].direct, "direct 路径");
        assert!(!status.peers[1].direct, "经中继");
        assert_eq!(status.peers[1].relay, "relay-1");
        assert!(status.peers[1].connected, "status: Connected 也算已连接");
        // Degenerate payloads.
        assert_eq!(parse_status(&Value::Null), StatusInfo::default());
        let disconnected = json!({"managementState": {"connected": false}});
        assert!(!parse_status(&disconnected).connected());
    }

    #[test]
    fn netbird_old_version_socks5_warning() {
        assert_eq!(parse_version("0.74.3"), Some((0, 74, 3)));
        assert_eq!(parse_version("netbird version 0.75.2"), Some((0, 75, 2)));
        assert_eq!(parse_version("1.2.3-rc1"), Some((1, 2, 3)));
        assert_eq!(parse_version("garbage"), None);
        assert!(old_version_warns_public_socks(Some((0, 74, 3))));
        assert!(old_version_warns_public_socks(Some((0, 74, 0))));
        assert!(!old_version_warns_public_socks(Some((0, 75, 0))));
        assert!(!old_version_warns_public_socks(Some((1, 0, 0))));
        assert!(!old_version_warns_public_socks(None), "未知版本不告警");
    }

    #[test]
    fn netbird_parse_auth_line_extracts_login_link() {
        let lines = vec![
            "connecting to the daemon".to_owned(),
            "Please open the following link in your browser to authenticate:".to_owned(),
            "    https://login.netbird.io/realms/netbird/login-actions/authenticate?client_id=xyz"
                .to_owned(),
            "another line".to_owned(),
        ];
        assert_eq!(
            parse_login_link(&lines).as_deref(),
            Some(
                "https://login.netbird.io/realms/netbird/login-actions/authenticate?client_id=xyz"
            )
        );
        assert_eq!(parse_login_link(&["no link".to_owned()]), None);
        // The link stops at whitespace.
        let lines = vec!["visit https://a.example/x then press enter".to_owned()];
        assert_eq!(
            parse_login_link(&lines).as_deref(),
            Some("https://a.example/x")
        );
    }
}
