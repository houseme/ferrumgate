//! Instance status parsed from `tailscale status --json` (WP-45 §5 step
//! 8): the peers list (direct or relayed, latency-relevant handshake and
//! traffic counters), the login link while authentication is pending, and
//! the self addresses. Parsing is whitelist-only: node keys, user data and
//! other configuration fields in the payload are never read, so they can
//! not leak into the API, logs or snapshot consumers.

use serde::Serialize;
use serde_json::Value;

/// One peer from the status payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerInfo {
    pub hostname: String,
    pub dns_name: String,
    pub ips: Vec<String>,
    pub online: bool,
    /// Relay name when the path is relayed; empty on a direct path.
    pub relay: String,
    /// Direct endpoint (`ip:port`) when connected directly.
    pub direct_addr: String,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub last_handshake: String,
}

/// The parsed status (whitelisted fields only).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusInfo {
    /// Backend state: `Running`, `NeedsLogin`, `NoState`, …
    pub backend_state: String,
    /// Login link while authentication is pending (`AuthURL`). Contains a
    /// one-time token; the log path masking in fg-proc keeps it out of
    /// logs, this field is the UI surface.
    pub login_url: Option<String>,
    pub version: Option<String>,
    pub self_hostname: String,
    pub self_ips: Vec<String>,
    pub tailnet_name: Option<String>,
    pub peers: Vec<PeerInfo>,
}

impl StatusInfo {
    /// The daemon answered and the node is part of a tailnet.
    pub fn connected(&self) -> bool {
        self.backend_state == "Running"
    }
}

fn text(value: &Value, key: &str) -> Option<String> {
    match value.get(key) {
        Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
        _ => None,
    }
}

fn string_list(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn parse_peer(value: &Value) -> Option<PeerInfo> {
    Some(PeerInfo {
        hostname: text(value, "HostName").unwrap_or_default(),
        dns_name: text(value, "DNSName").unwrap_or_default(),
        ips: string_list(value, "TailscaleIPs"),
        online: value
            .get("Online")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        relay: text(value, "Relay").unwrap_or_default(),
        // `CurAddr` is present on a direct path, empty on relays.
        direct_addr: text(value, "CurAddr").unwrap_or_default(),
        rx_bytes: value.get("RxBytes").and_then(Value::as_u64),
        tx_bytes: value.get("TxBytes").and_then(Value::as_u64),
        last_handshake: text(value, "LastHandshake").unwrap_or_default(),
    })
}

/// Parses the full status payload.
pub fn parse_status(body: &Value) -> StatusInfo {
    let self_value = body.get("Self").cloned().unwrap_or(Value::Null);
    let peers = body
        .get("Peer")
        .and_then(Value::as_object)
        .map(|map| map.values().filter_map(parse_peer).collect())
        .unwrap_or_default();
    StatusInfo {
        backend_state: text(body, "BackendState").unwrap_or_default(),
        login_url: text(body, "AuthURL"),
        version: text(body, "Version"),
        self_hostname: text(&self_value, "HostName").unwrap_or_default(),
        self_ips: string_list(&self_value, "TailscaleIPs"),
        tailnet_name: body
            .get("CurrentTailnet")
            .and_then(|tailnet| text(tailnet, "Name")),
        peers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NODE_KEY: &str = "nodekey:0f1e2d3c4b5aSECRET9a8b7c6d";

    fn fixture() -> Value {
        json!({
            "Version": "1.80.0",
            "BackendState": "Running",
            "AuthURL": "",
            "TailscaleIPs": ["100.64.0.1", "fd7a:115c:a1e0::1"],
            "Self": {
                "HostName": "host-a",
                "TailscaleIPs": ["100.64.0.1", "fd7a:115c:a1e0::1"],
                "Online": true,
                "CapMap": {"somecap": [1, 2]}
            },
            "CurrentTailnet": {"Name": "example.ts.net", "MagicDNSSuffix": "example.ts.net."},
            "Health": [],
            "Peer": {
                NODE_KEY: {
                    "HostName": "host-b",
                    "DNSName": "host-b.example.ts.net.",
                    "TailscaleIPs": ["100.64.0.2"],
                    "Online": true,
                    "Relay": "",
                    "CurAddr": "203.0.113.5:4242",
                    "RxBytes": 1024,
                    "TxBytes": 2048,
                    "LastHandshake": "2025-06-01T12:00:00Z",
                    "ShareeNode": false,
                    "Tags": ["tag:server"]
                },
                "nodekey:another": {
                    "HostName": "host-c",
                    "DNSName": "",
                    "TailscaleIPs": ["100.64.0.3"],
                    "Online": false,
                    "Relay": "torelay",
                    "RxBytes": 1,
                    "TxBytes": 2
                }
            },
            "User": {"123": {"LoginName": "admin@example.ts.net"}}
        })
    }

    #[test]
    fn tailscale_status_parsed_from_cli_json() {
        let status = parse_status(&fixture());
        assert_eq!(status.backend_state, "Running");
        assert!(status.connected());
        assert_eq!(status.version.as_deref(), Some("1.80.0"));
        assert_eq!(status.self_hostname, "host-a");
        assert_eq!(status.self_ips.len(), 2);
        assert_eq!(status.tailnet_name.as_deref(), Some("example.ts.net"));
        assert_eq!(status.login_url, None);
        assert_eq!(status.peers.len(), 2);
        let direct = &status.peers[0];
        assert_eq!(direct.hostname, "host-b");
        assert_eq!(direct.dns_name, "host-b.example.ts.net.");
        assert!(direct.online);
        assert!(direct.relay.is_empty(), "CurAddr 存在即直连");
        assert_eq!(direct.direct_addr, "203.0.113.5:4242");
        assert_eq!(direct.rx_bytes, Some(1024));
        assert_eq!(direct.tx_bytes, Some(2048));
        let relayed = &status.peers[1];
        assert_eq!(relayed.relay, "torelay");
        assert!(relayed.direct_addr.is_empty());
        assert!(!relayed.online);
        // Pending login: the link is surfaced for the UI.
        let mut pending = fixture();
        pending["BackendState"] = "NeedsLogin".into();
        pending["AuthURL"] = "https://login.example/xyz".into();
        let status = parse_status(&pending);
        assert!(!status.connected());
        assert_eq!(
            status.login_url.as_deref(),
            Some("https://login.example/xyz")
        );
        // Empty / broken payloads degrade to an empty status.
        assert_eq!(parse_status(&Value::Null), StatusInfo::default());
    }

    #[test]
    fn tailscale_status_output_contains_no_secret() {
        let status = parse_status(&fixture());
        let rendered = serde_json::to_string(&status).expect("serialize");
        assert!(
            !rendered.contains("SECRET"),
            "节点密钥等配置字段不得出现在状态输出: {rendered}"
        );
        assert!(!rendered.contains("nodekey"));
        // Login names and capability maps are not forwarded either.
        assert!(!rendered.contains("LoginName"));
        assert!(!rendered.contains("somecap"));
    }
}
