//! WP-39 step 4: the TCP/UDP forwarding mapping — legacy `[[tcp_forward]]`
//! and `[[udp_forward]]` into `portforward.json` rules (spec:
//! docs/plan/WP-39-migrate-toml.md §3.3). Rule-level timeouts aggregate
//! into the global settings (dial timeout = max, UDP sessions = sum).
#![allow(dead_code)]

use super::report::{DroppedField, FieldMap, MigrateReport};
use fg_gateway::l4::portforward::model as pf;
use fg_gateway::legacy_config::RawConfig;

fn map(from: &str, report: &mut MigrateReport, to: &str) {
    report.mapped.push(FieldMap {
        from: from.to_owned(),
        to: to.to_owned(),
    });
}

fn drop_field(report: &mut MigrateReport, field: &str, reason: &str, hint: &str) {
    report.dropped.push(DroppedField {
        field: field.to_owned(),
        reason_key: reason.to_owned(),
        hint_key: hint.to_owned(),
    });
}

fn listen_parts(listen: &Option<String>) -> (String, String) {
    match listen {
        Some(text) => match text.rsplit_once(':') {
            Some((address, port)) => (address.to_owned(), port.to_owned()),
            None => (text.clone(), String::new()),
        },
        None => (String::new(), String::new()),
    }
}

fn access_from(policy: &serde_json::Value) -> pf::RawAccess {
    // The policy serializes its allow/deny lists; serde is the shared
    // view (fields stay module-private).
    serde_json::from_value(policy.clone()).unwrap_or_default()
}

/// Converts the forwarding sections into the typed portforward document.
/// TCP and UDP entries become rules with their protocol list; shared
/// timeouts aggregate: dial = max(connect), UDP session timeout = max
/// idle, UDP session budget = sum(max_sessions).
pub fn convert(
    config: &RawConfig,
    report: &mut MigrateReport,
) -> Result<pf::FileConfig, String> {
    let mut file = pf::FileConfig::default();
    let mut dial_timeout = 0u32;
    let mut first_data = 0u32;
    let mut udp_session_timeout = 0u32;
    let mut udp_sessions = 0u32;
    let mut rule_index = 0usize;

    for forward in &config.tcp_forward {
        // RawForward fields stay module-private; serde is the shared view.
        let Ok(view) = serde_json::to_value(forward) else {
            return Err("tcp_forward 条目无法读取".to_owned());
        };
        rule_index += 1;
        let listen = view.get("listen").and_then(|l| l.as_str()).map(str::to_owned);
        let (address, port) = listen_parts(&listen);
        let targets: Vec<String> = view["targets"]
            .as_array()
            .map(|list| {
                list.iter()
                    .filter_map(|t| t.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let ports: Vec<u16> = target_ports(&targets);
        let rule = pf::Rule {
            auto_firewall: false,
            group: String::new(),
            key: format!("tcp-{rule_index}"),
            name: format!("TCP {address}:{port}"),
            enable: true,
            protocols: vec![pf::Protocol::Tcp],
            listen_address: address,
            listen_ports: port,
            target_addresses: targets,
            target_ports: ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            max_connections: view
                .get("max_connections")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32,
            max_conns_per_source: view
                .get("max_connections_per_source")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32,
            udp_session_timeout: 0,
            proxy_protocol: pf::ProxyProtocol::None,
            access: access_from(view.get("source").unwrap_or(&serde_json::json!({}))),
            remark: String::new(),
        };
        map("tcp_forward.listen", report, "rules[].listenAddress + listenPorts");
        map("tcp_forward.targets", report, "rules[].targetAddresses + targetPorts");
        map(
            "tcp_forward.max_connections_per_source",
            report,
            "rules[].maxConnsPerSource",
        );
        dial_timeout = dial_timeout.max(
            ((view
                .get("connect_timeout_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                / 1000)
                .max(1)) as u32,
        );
        first_data = first_data.max(
            ((view
                .get("first_data_timeout_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                / 1000)
                .max(1)) as u32,
        );
        if view
            .get("connection_lifetime_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            != 0
        {
            drop_field(
                report,
                "tcp_forward.connection_lifetime_ms",
                "新模型没有总寿命限制",
                "确认默认保护值可接受",
            );
        }
        if let Some(exempt) = view.get("source_limit_exempt").and_then(|v| v.as_array())
            && !exempt.is_empty()
        {
            file.settings.per_source_exempt = exempt
                .iter()
                .filter_map(|entry| entry.as_str().map(str::to_owned))
                .collect();
            map(
                "tcp_forward.source_limit_exempt",
                report,
                "settings.perSourceExempt",
            );
        }
        file.rules.push(rule);
    }

    for forward in &config.udp_forward {
        let Ok(view) = serde_json::to_value(forward) else {
            return Err("udp_forward 条目无法读取".to_owned());
        };
        rule_index += 1;
        let listen = view.get("listen").and_then(|l| l.as_str()).map(str::to_owned);
        let (address, port) = listen_parts(&listen);
        let mut targets: Vec<String> = view["targets"]
            .as_array()
            .map(|list| {
                list.iter()
                    .filter_map(|t| t.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        if targets.is_empty()
            && let Some(target) = view.get("target").and_then(|t| t.as_str())
        {
            targets.push(target.to_owned());
        }
        let ports: Vec<u16> = target_ports(&targets);
        let sessions = view
            .get("max_sessions")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let idle = ((view
            .get("idle_timeout_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            / 1000)
            .max(1)) as u32;
        udp_sessions = udp_sessions.saturating_add(sessions as u32);
        udp_session_timeout = udp_session_timeout.max(idle);
        let rule = pf::Rule {
            auto_firewall: false,
            group: String::new(),
            key: format!("udp-{rule_index}"),
            name: format!("UDP {address}:{port}"),
            enable: true,
            protocols: vec![pf::Protocol::Udp],
            listen_address: address,
            listen_ports: port,
            target_addresses: targets,
            target_ports: ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            max_connections: 0,
            max_conns_per_source: 0,
            udp_session_timeout: idle,
            proxy_protocol: pf::ProxyProtocol::None,
            access: access_from(view.get("source").unwrap_or(&serde_json::json!({}))),
            remark: String::new(),
        };
        map("udp_forward.listen", report, "rules[].listenAddress + listenPorts");
        map("udp_forward.target(s)", report, "rules[].targetAddresses + targetPorts");
        map(
            "udp_forward.idle_timeout_ms",
            report,
            "rules[].udpSessionTimeout（秒）",
        );
        file.rules.push(rule);
    }

    if dial_timeout > 0 {
        file.settings.dial_timeout = dial_timeout;
        map(
            "tcp_forward.connect_timeout_ms",
            report,
            "settings.dialTimeout（各规则最大值）",
        );
    }
    if first_data > 0 {
        file.settings.first_data_timeout = first_data;
        map(
            "tcp_forward.first_data_timeout_ms",
            report,
            "settings.firstDataTimeout",
        );
    }
    if udp_session_timeout > 0 {
        file.settings.default_udp_session_timeout = udp_session_timeout;
    }
    if udp_sessions > 0 {
        file.settings.max_udp_sessions = udp_sessions;
        map(
            "udp_forward.max_sessions",
            report,
            "settings.maxUdpSessions（各规则之和）",
        );
    }
    Ok(file)
}

/// Extracts the distinct ports from `host:port` target addresses; an
/// address without a port contributes nothing (the rule leaves the port
/// list empty, which validate reports).
fn target_ports(targets: &[String]) -> Vec<u16> {
    let mut ports = Vec::new();
    for target in targets {
        if let Some((_, port)) = target.rsplit_once(':')
            && let Ok(parsed) = port.parse::<u16>()
            && parsed != 0
            && !ports.contains(&parsed)
        {
            ports.push(parsed);
        }
    }
    ports
}
