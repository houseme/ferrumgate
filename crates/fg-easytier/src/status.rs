//! Instance status parsed from the `easytier-cli` JSON output (WP-45 §5
//! step 4). Parsing is whitelist-only: `easytier-cli node` includes the
//! network configuration (the network secret among it, WP-45 §3.3) — those
//! fields are never read, so they cannot leak into the API, logs or any
//! consumer of the status snapshot. Unknown fields are ignored so newer
//! program versions keep working.

use serde::Serialize;
use serde_json::Value;

/// Node-level status from `easytier-cli node` (whitelisted fields only).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    pub version: String,
    pub hostname: String,
    pub listeners: Vec<String>,
    pub virtual_ip: Option<String>,
    pub nat_type: Option<String>,
    pub public_ip: Option<String>,
}

/// One peer from `easytier-cli peer` (whitelisted fields only): address,
/// direct or relayed path, latency, loss and traffic counters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerInfo {
    pub peer_id: String,
    pub virtual_ip: Option<String>,
    pub hostname: String,
    pub latency_ms: Option<u64>,
    /// Loss rate in percent (0..=100), rounded.
    pub loss_rate: Option<u64>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub transport: String,
    pub direct: bool,
}

/// The whole instance status: node info plus peers. Serialized into the
/// status endpoint and reusable as a read-only snapshot.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceStatus {
    pub node: Option<NodeInfo>,
    pub peers: Vec<PeerInfo>,
    /// Why the status is incomplete (program missing, CLI failed…).
    pub error: Option<String>,
}

fn text(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(found) = value.get(*key) {
            match found {
                Value::String(text) => {
                    if !text.is_empty() {
                        return Some(text.clone());
                    }
                }
                Value::Number(number) => return Some(number.to_string()),
                _ => {}
            }
        }
    }
    None
}

fn number(value: &Value, keys: &[&str]) -> Option<u64> {
    for key in keys {
        if let Some(found) = value.get(*key)
            && let Some(parsed) = scalar_u64(found)
        {
            return Some(parsed);
        }
    }
    None
}

/// Numbers may arrive as JSON numbers or as strings like `"12ms"`.
fn scalar_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .or_else(|| number.as_f64().map(|f| f as u64)),
        Value::String(text) => parse_leading_f64(text).map(|f| f as u64),
        _ => None,
    }
}

fn scalar_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => parse_leading_f64(text),
        _ => None,
    }
}

fn parse_leading_f64(text: &str) -> Option<f64> {
    let digits: String = text
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
        .collect();
    digits.parse::<f64>().ok()
}

fn ip_prefix(value: &Value, keys: &[&str]) -> Option<String> {
    text(value, keys).map(|mut ip| {
        // EasyTier formats virtual IPs as `10.126.126.2 /24`.
        if let Some(space) = ip.find(char::is_whitespace) {
            ip.truncate(space);
        }
        ip
    })
}

/// Parses `easytier-cli node`. Reads only the whitelisted fields; the
/// `Config` (network name / secret) block is skipped entirely.
pub fn parse_node(body: &Value) -> NodeInfo {
    let listeners = body
        .get("Listeners")
        .or_else(|| body.get("listeners"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    NodeInfo {
        version: text(body, &["Version", "version"]).unwrap_or_default(),
        hostname: text(body, &["Hostname", "hostname"]).unwrap_or_default(),
        listeners,
        virtual_ip: ip_prefix(body, &["VirtualIpv4", "virtual_ipv4"]),
        nat_type: text(body, &["NatType", "nat_type"]),
        public_ip: text(body, &["PublicIp", "public_ip", "PublicAddr"]),
    }
}

/// Parses `easytier-cli peer`: a map (or array) of connection entries.
pub fn parse_peers(body: &Value) -> Vec<PeerInfo> {
    let entries: Vec<&Value> = match body {
        Value::Object(map) => map.values().collect(),
        Value::Array(items) => items.iter().collect(),
        _ => vec![],
    };
    entries
        .iter()
        .filter_map(|entry| {
            let object = entry.as_object()?;
            let value = Value::Object(object.clone());
            let peer_id = text(&value, &["peer_id", "PeerId", "id", "Id"])?;
            Some(PeerInfo {
                peer_id,
                virtual_ip: ip_prefix(&value, &["ipv4", "Ipv4"]),
                hostname: text(&value, &["hostname", "Hostname"]).unwrap_or_default(),
                latency_ms: number(&value, &["latency_ms", "Latency", "latency"]),
                // Loss arrives as a 0..1 ratio or a 0..100 percentage.
                loss_rate: value
                    .get("loss_rate")
                    .or_else(|| value.get("LossRate"))
                    .and_then(scalar_f64)
                    .map(normalize_loss_rate),
                rx_bytes: number(&value, &["rx_bytes", "RxBytes", "Up"]),
                tx_bytes: number(&value, &["tx_bytes", "TxBytes", "Down"]),
                transport: text(&value, &["tunnel_proto", "TunnelProto", "protocol"])
                    .unwrap_or_default(),
                direct: value
                    .get("direct")
                    .or_else(|| value.get("Direct"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        })
        .collect()
}

/// Loss rates arrive as 0..1 ratios or 0..100 percentages; normalize to
/// percent. (Public for reuse by the runtime when merging results.)
pub fn normalize_loss_rate(raw: f64) -> u64 {
    let percent = if raw <= 1.0 { raw * 100.0 } else { raw };
    percent.clamp(0.0, 100.0).round() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "TOPSECRET-ET-VALUE";

    fn node_fixture() -> Value {
        json!({
            "Version": "2.1.0",
            "Hostname": "node-a",
            "Config": format!("NetworkName: mesh\nNetworkSecret: {SECRET}\nVirtualIpv4: 10.126.126.1"),
            "NetworkName": "mesh",
            "NetworkSecret": SECRET,
            "Listeners": ["tcp://0.0.0.0:11010", "udp://0.0.0.0:11010"],
            "VirtualIpv4": "10.126.126.1 /24",
            "NatType": "cone",
            "PublicIp": "203.0.113.7",
            "UnknownFutureField": {"deep": [1, 2, 3]}
        })
    }

    #[test]
    fn easytier_status_parsed_from_cli_json() {
        let node = parse_node(&node_fixture());
        assert_eq!(node.version, "2.1.0");
        assert_eq!(node.hostname, "node-a");
        assert_eq!(node.listeners.len(), 2);
        assert_eq!(node.virtual_ip.as_deref(), Some("10.126.126.1"));
        assert_eq!(node.nat_type.as_deref(), Some("cone"));
        assert_eq!(node.public_ip.as_deref(), Some("203.0.113.7"));
        let peers = parse_peers(&json!({
            "conn-1": {
                "peer_id": "p1",
                "ipv4": "10.126.126.2 /24",
                "hostname": "node-b",
                "latency_ms": 12,
                "loss_rate": 0.04,
                "rx_bytes": 1024,
                "tx_bytes": 2048,
                "tunnel_proto": "udp",
                "direct": true
            },
            "conn-2": {
                "peer_id": "p2",
                "ipv4": "10.126.126.3/24",
                "hostname": "node-c",
                "latency_ms": "103ms",
                "loss_rate": 50,
                "tunnel_proto": "tcp",
                "direct": false
            }
        }));
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].peer_id, "p1");
        assert_eq!(peers[0].virtual_ip.as_deref(), Some("10.126.126.2"));
        assert_eq!(peers[0].latency_ms, Some(12));
        assert_eq!(peers[0].rx_bytes, Some(1024));
        assert_eq!(peers[0].loss_rate, Some(4), "0..1 丢包率归一化为百分比");
        assert!(peers[0].direct);
        assert_eq!(peers[1].loss_rate, Some(50));
        assert_eq!(peers[1].latency_ms, Some(103), "字符串延迟也要解析");
        assert!(!peers[1].direct);
        // Array form works too.
        assert_eq!(parse_peers(&json!([{"peer_id": "solo"}])).len(), 1);
        // Empty / non-JSON bodies produce an empty status, not an error.
        assert_eq!(parse_peers(&Value::Null).len(), 0);
    }

    #[test]
    fn easytier_status_output_contains_no_secret() {
        let node = parse_node(&node_fixture());
        let debug = format!("{node:?}");
        let status = InstanceStatus {
            node: Some(node),
            peers: parse_peers(&json!([{"peer_id": "p1"}])),
            error: None,
        };
        let rendered = serde_json::to_string(&status).expect("serialize");
        assert!(
            !rendered.contains(SECRET),
            "状态输出绝不能包含网络密钥: {rendered}"
        );
        assert!(!rendered.contains("NetworkSecret"));
        assert!(!rendered.contains("mesh"), "配置字段不转发到界面");
        // The parse result itself never holds the secret either.
        assert!(!debug.contains(SECRET));
    }
}
