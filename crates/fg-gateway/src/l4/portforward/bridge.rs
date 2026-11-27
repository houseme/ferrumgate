//! Bridges the portforward.json model onto the legacy TCP/UDP forward data
//! plane (WP-34 step 7-10).
//!
//! [`to_tcp_forward`] and [`to_udp_forward`] map one [`CompiledRule`] onto
//! the `RawForward`/`RawUdpForward` shapes that `TcpForward::compile` and
//! `UdpForward::compile` already validate, so every existing guarantee
//! (target distinctness, port ranges, listener conflicts, source policies)
//! applies unchanged. The raw shapes are assembled as JSON values and
//! deserialized with the very same serde definitions the TOML path uses;
//! omitted keys fall back to the raw defaults.
//!
//! Layout contract: a rule's listeners always share one address (the model
//! has a single `listen_address`), so one raw entry carries the whole rule —
//! `host:port,port,...` — and each target column is either a pinned
//! `address:port` repeated per listener or a bare IP with positionally
//! mapped ports (`ip:p1,p2`). That mirrors the one-listener-per-entry TOML
//! model once the raw compile expands listeners again.
//!
//! Not carried across (no model equivalent): the TCP connection lifetime
//! keeps its raw default, and the compiled `AccessFilter`/`RuleStats` stay
//! unused here — the legacy data plane re-derives its own `SourcePolicy`
//! from the same allow/deny lists.

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result, ensure};
use serde_json::json;

use super::model::{FileConfig, Protocol, RawAccess};
use super::{compile, validate};
use crate::{tcp_forward::RawForward, udp_forward::RawUdpForward};

/// Parses, validates, compiles and bridges a portforward.json document into
/// the legacy forward rules the gateway serves. Validation problems and
/// expansion problems are collected and reported together.
///
/// `pub(crate)` because the bridged legacy rule types are crate-private.
pub(crate) fn compile_from_json(
    json: &str,
) -> Result<(
    Vec<crate::tcp_forward::TcpForward>,
    Vec<crate::udp_forward::UdpForward>,
)> {
    let file: FileConfig = serde_json::from_str(json).context("invalid portforward.json")?;
    let problems = validate(&file);
    ensure!(
        problems.is_empty(),
        "invalid portforward.json: {}",
        problems
            .iter()
            .map(|problem| format!("{}: {}", problem.field, problem.reason))
            .collect::<Vec<_>>()
            .join("; ")
    );
    // The module switch gates serving, not compilation: an empty result is
    // a valid, disabled configuration.
    if !file.settings.enable {
        return Ok((Vec::new(), Vec::new()));
    }
    let compiled = compile(&file)
        .map_err(|errors| anyhow::anyhow!("invalid portforward.json: {}", errors.join("; ")))?;
    let mut tcp = Vec::new();
    let mut udp = Vec::new();
    for rule in &compiled {
        let key = &rule.cfg.key;
        if rule.cfg.protocols.contains(&Protocol::Tcp) {
            let raw = to_tcp_forward(rule).map_err(anyhow::Error::msg)?;
            let rules = crate::tcp_forward::TcpForward::compile(raw)
                .with_context(|| format!("invalid portforward rule {key}"))?;
            tcp.extend(rules);
        }
        if rule.cfg.protocols.contains(&Protocol::Udp) {
            let raw = to_udp_forward(rule).map_err(anyhow::Error::msg)?;
            let rules = crate::udp_forward::UdpForward::compile(raw)
                .with_context(|| format!("invalid portforward rule {key}"))?;
            udp.extend(rules);
        }
    }
    Ok((tcp, udp))
}

/// Maps one compiled rule onto a single `RawForward` covering every TCP
/// listener of the rule with its target row.
pub(crate) fn to_tcp_forward(rule: &super::CompiledRule) -> Result<RawForward, String> {
    let listen = listen_spec(&rule.listens)?;
    let targets = target_columns(rule)?;
    let mut raw = json!({
        "listen": listen,
        "targets": targets,
        "max_connections": rule.limits.max_connections,
        "connect_timeout_ms": millis(rule.limits.dial_timeout),
        "first_data_timeout_ms": millis(rule.limits.first_data_timeout),
        "connection_lifetime_ms": 300_000_u64,
        "source": source_value(&rule.cfg.access),
        "max_connections_per_source": rule.limits.max_conns_per_source,
    });
    match rule.cfg.proxy_protocol {
        super::model::ProxyProtocol::None => {}
        super::model::ProxyProtocol::V1 => raw["proxy_protocol"] = json!("v1"),
        super::model::ProxyProtocol::V2 => raw["proxy_protocol"] = json!("v2"),
    }
    if !rule.limits.exempt.is_empty() {
        raw["source_limit_exempt"] = json!(
            rule.limits
                .exempt
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );
    }
    serde_json::from_value(raw).map_err(|error| format!("rules.{}: {error}", rule.cfg.key))
}

/// Maps one compiled rule onto a single `RawUdpForward` covering every UDP
/// listener of the rule with its target row. The effective per-port
/// connection limit doubles as the session budget and the normalized UDP
/// session timeout as the idle timeout.
pub(crate) fn to_udp_forward(rule: &super::CompiledRule) -> Result<RawUdpForward, String> {
    let listen = listen_spec(&rule.listens)?;
    let targets = target_columns(rule)?;
    let raw = json!({
        "listen": listen,
        "targets": targets,
        "max_sessions": rule.limits.max_connections,
        "idle_timeout_ms": millis(rule.limits.udp_session_timeout),
        "source": source_value(&rule.cfg.access),
    });
    serde_json::from_value(raw).map_err(|error| format!("rules.{}: {error}", rule.cfg.key))
}

/// Renders the shared listen host with one port per listener
/// (`host:9000,9001`), bracketing IPv6 hosts.
fn listen_spec(listens: &[SocketAddr]) -> Result<String, String> {
    let Some(first) = listens.first() else {
        return Err("rule expands to no listeners".into());
    };
    let host = first.ip();
    if let Some(other) = listens.iter().find(|listen| listen.ip() != host) {
        return Err(format!(
            "rule listeners must share one address ({host} and {})",
            other.ip()
        ));
    }
    let ports = listens
        .iter()
        .map(|listen| listen.port().to_string())
        .collect::<Vec<_>>()
        .join(",");
    Ok(match host {
        IpAddr::V6(_) => format!("[{host}]:{ports}"),
        IpAddr::V4(_) => format!("{host}:{ports}"),
    })
}

/// Renders one string per target address column: a pinned `address:port`
/// repeats unchanged across listener rows, a bare IP receives the
/// positionally mapped port of each row (`ip:p1,p2`).
fn target_columns(rule: &super::CompiledRule) -> Result<Vec<String>, String> {
    let rows = &rule.targets;
    let Some(width) = rows.first().map(Vec::len) else {
        return Err(format!("rules.{}: no target addresses", rule.cfg.key));
    };
    let mut columns = Vec::with_capacity(width);
    for column in 0..width {
        let first = rows[0][column];
        let host = first.ip();
        if rows.iter().any(|row| row[column].ip() != host) {
            return Err(format!(
                "rules.{}: target column {column} changes address across listeners",
                rule.cfg.key
            ));
        }
        if rows.iter().all(|row| row[column] == first) {
            columns.push(first.to_string());
        } else {
            let ports = rows
                .iter()
                .map(|row| row[column].port().to_string())
                .collect::<Vec<_>>()
                .join(",");
            columns.push(match host {
                IpAddr::V6(_) => format!("[{host}]:{ports}"),
                IpAddr::V4(_) => format!("{host}:{ports}"),
            });
        }
    }
    Ok(columns)
}

fn source_value(access: &RawAccess) -> serde_json::Value {
    match &access.allow {
        Some(allow) => json!({ "allow": allow, "deny": access.deny }),
        None => json!({ "deny": access.deny }),
    }
}

fn millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l4::portforward::model::{Rule, Settings};

    fn file(rules: Vec<Rule>) -> String {
        serde_json::to_string(&FileConfig {
            settings: Settings::default(),
            rules,
        })
        .expect("serialize portforward.json")
    }

    fn tcp_rule() -> Rule {
        Rule {
            key: "web".into(),
            name: "web".into(),
            enable: true,
            protocols: vec![Protocol::Tcp],
            listen_address: "127.0.0.1".into(),
            listen_ports: "8080".into(),
            target_addresses: vec!["10.0.0.1:80".into()],
            target_ports: "80".into(),
            ..Rule::default()
        }
    }

    #[test]
    fn bridges_a_tcp_rule_with_defaults() {
        let rules = compile_from_json(&file(vec![tcp_rule()])).unwrap();
        let [rule] = rules.0.as_slice() else {
            panic!("one listener expected");
        };
        assert_eq!(rule.listen, "127.0.0.1:8080".parse().unwrap());
        // Normalized settings: dial 5s, first data 60s, max 256 (per-source
        // half of max, applied by the bridge).
        assert_eq!(rule.max_connections, 256);
        assert_eq!(rule.connect_timeout, std::time::Duration::from_secs(5));
        assert_eq!(rule.first_data_timeout, std::time::Duration::from_secs(60));
        assert_eq!(rule.proxy_protocol, None);
        assert!(rule.source.permits("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn bridges_positional_targets_and_proxy_protocol() {
        let mut rule = tcp_rule();
        rule.listen_ports = "8000-8001".into();
        rule.target_addresses = vec!["10.0.0.1".into(), "10.0.0.2:7000".into()];
        rule.target_ports = "90-91".into();
        rule.proxy_protocol = super::super::model::ProxyProtocol::V2;
        let rules = compile_from_json(&file(vec![rule])).unwrap();
        assert_eq!(rules.0.len(), 2);
        assert_eq!(rules.0[0].listen, "127.0.0.1:8000".parse().unwrap());
        assert_eq!(
            rules.0[0].targets,
            vec![
                "10.0.0.1:90".parse().unwrap(),
                "10.0.0.2:7000".parse().unwrap()
            ]
        );
        assert_eq!(rules.0[1].targets[0], "10.0.0.1:91".parse().unwrap());
        assert_eq!(rules.0[1].targets[1], "10.0.0.2:7000".parse().unwrap());
    }

    #[test]
    fn bridges_udp_rule_and_source_lists() {
        let mut rule = tcp_rule();
        rule.key = "dns".into();
        rule.protocols = vec![Protocol::Udp];
        rule.target_addresses = vec!["10.0.0.1:53".into()];
        rule.target_ports = "53".into();
        rule.udp_session_timeout = 30;
        rule.access.allow = Some(vec!["127.0.0.0/8".into()]);
        rule.access.deny = vec!["127.0.0.1".into()];
        let rules = compile_from_json(&file(vec![rule])).unwrap();
        assert!(rules.0.is_empty());
        let [udp] = rules.1.as_slice() else {
            panic!("one udp listener expected");
        };
        assert_eq!(udp.max_sessions, 256);
        assert_eq!(udp.idle, std::time::Duration::from_secs(30));
        assert!(udp.source.permits("127.0.0.2".parse().unwrap()));
        assert!(!udp.source.permits("127.0.0.1".parse().unwrap()));
        assert!(!udp.source.permits("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn collects_validation_and_expansion_problems() {
        let mut rule = tcp_rule();
        rule.target_addresses.clear();
        let Err(error) = compile_from_json(&file(vec![rule])) else {
            panic!("empty targets must fail");
        };
        assert!(error.to_string().contains("targetAddresses"), "{error}");

        let mut rule = tcp_rule();
        rule.listen_ports = "not-ports".into();
        let Err(error) = compile_from_json(&file(vec![rule])) else {
            panic!("invalid listen ports must fail");
        };
        assert!(error.to_string().contains("rules.web"), "{error}");
    }

    #[test]
    fn module_switch_disables_serving() {
        let mut config = FileConfig {
            settings: Settings::default(),
            rules: vec![tcp_rule()],
        };
        config.settings.enable = false;
        let json = serde_json::to_string(&config).unwrap();
        let rules = compile_from_json(&json).unwrap();
        assert!(rules.0.is_empty() && rules.1.is_empty());
    }
}
