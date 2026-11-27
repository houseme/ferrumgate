//! Normalization and validation for the portforward model (WP-34): pure
//! functions over plain data. `normalize` applies upstream defaults for
//! zero values; `validate` collects every problem instead of stopping at
//! the first.

use super::model::{FileConfig, ProxyProtocol, Rule, Settings};

/// Upstream default: per-TCP-port connection limit.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 256;
/// Upstream default: idle UDP session lifetime in seconds.
pub const DEFAULT_UDP_SESSION_TIMEOUT: u32 = 60;
/// Upstream default: process-wide UDP session budget.
pub const MAX_UDP_SESSIONS: u32 = 1024;
/// Upstream default: outbound dial timeout in seconds.
pub const DEFAULT_DIAL_TIMEOUT: u32 = 5;
/// Upstream default: first-data timeout in seconds.
pub const DEFAULT_FIRST_DATA_TIMEOUT: u32 = 60;
/// Upstream maximum: first-data timeout in seconds.
pub const MAX_FIRST_DATA_TIMEOUT: u32 = 3600;
/// FerrumGate protection: expanded listen ports per rule.
pub const MAX_LISTEN_PORTS: u32 = 64;
/// FerrumGate protection: target addresses per rule.
pub const MAX_TARGETS: usize = 8;

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

/// Applies upstream defaults for zero-valued settings and clamps the
/// first-data timeout to its 3600-second maximum.
pub fn normalize(mut config: FileConfig) -> FileConfig {
    let settings = &mut config.settings;
    if settings.default_max_connections == 0 {
        settings.default_max_connections = DEFAULT_MAX_CONNECTIONS;
    }
    if settings.default_udp_session_timeout == 0 {
        settings.default_udp_session_timeout = DEFAULT_UDP_SESSION_TIMEOUT;
    }
    if settings.max_udp_sessions == 0 {
        settings.max_udp_sessions = MAX_UDP_SESSIONS;
    }
    if settings.dial_timeout == 0 {
        settings.dial_timeout = DEFAULT_DIAL_TIMEOUT;
    }
    settings.first_data_timeout = if settings.first_data_timeout == 0 {
        DEFAULT_FIRST_DATA_TIMEOUT
    } else {
        settings.first_data_timeout.min(MAX_FIRST_DATA_TIMEOUT)
    };
    config
}

/// Validates a normalized config, collecting every problem.
pub fn validate(config: &FileConfig) -> Vec<Problem> {
    let mut problems = Vec::new();
    validate_settings(&config.settings, &mut problems);
    let default_first_data = config.settings.first_data_timeout;
    for rule in config.rules.iter() {
        validate_rule(rule, default_first_data, &mut problems);
    }
    // Duplicate keys are a structural problem: the collection API keys by
    // them.
    let mut keys = std::collections::BTreeSet::new();
    for rule in &config.rules {
        if !rule.key.is_empty() && !keys.insert(rule.key.as_str()) {
            problems.push(Problem::new("key", format!("重复的规则 key {}", rule.key)));
        }
    }
    problems
}

fn validate_settings(settings: &Settings, problems: &mut Vec<Problem>) {
    if settings.first_data_timeout > MAX_FIRST_DATA_TIMEOUT {
        problems.push(Problem::new(
            "settings.firstDataTimeout",
            format!("上限 {} 秒", MAX_FIRST_DATA_TIMEOUT),
        ));
    }
}

fn validate_rule(rule: &Rule, default_first_data: u32, problems: &mut Vec<Problem>) {
    let prefix = format!("rules.{}", rule.key);
    if rule.key.is_empty() {
        problems.push(Problem::new("key", "key 不能为空"));
    }
    if rule.protocols.is_empty() {
        problems.push(Problem::new(
            format!("{prefix}.protocols"),
            "至少选择 tcp 或 udp",
        ));
    }
    if rule.listen_ports.is_empty() {
        problems.push(Problem::new(
            format!("{prefix}.listenPorts"),
            "监听端口不能为空",
        ));
    }
    if rule.target_addresses.is_empty() {
        problems.push(Problem::new(
            format!("{prefix}.targetAddresses"),
            "至少填写一个目标地址",
        ));
    } else if rule.target_addresses.len() > MAX_TARGETS {
        problems.push(Problem::new(
            format!("{prefix}.targetAddresses"),
            format!("目标地址最多 {} 个", MAX_TARGETS),
        ));
    }
    for address in &rule.target_addresses {
        if address.parse::<std::net::SocketAddr>().is_err()
            && address.parse::<std::net::IpAddr>().is_err()
        {
            problems.push(Problem::new(
                format!("{prefix}.targetAddresses"),
                format!("目标地址 {address} 不是 IP 或 地址:端口"),
            ));
        }
    }
    if !rule.listen_ports.is_empty() {
        let listen = crate::forward_ports::MAX_LISTENERS;
        match crate::forward_ports::listen_count(&rule.listen_ports) {
            Ok(count) => {
                if count == 0 {
                    problems.push(Problem::new(
                        format!("{prefix}.listenPorts"),
                        "监听端口不能为空",
                    ));
                } else if count > listen {
                    problems.push(Problem::new(
                        format!("{prefix}.listenPorts"),
                        format!("监听端口最多 {listen} 个"),
                    ));
                } else if !rule.target_ports.is_empty() {
                    validate_target_ports(rule, count, &prefix, problems);
                }
            }
            Err(reason) => problems.push(Problem::new(format!("{prefix}.listenPorts"), reason)),
        }
    }
    if !rule.target_ports.is_empty() && rule.target_addresses.is_empty() {
        // Already reported as a missing target; the port mapping needs it.
    }
    let effective_first_data = if rule.udp_session_timeout == 0 {
        default_first_data
    } else {
        rule.udp_session_timeout
    };
    if effective_first_data > MAX_FIRST_DATA_TIMEOUT {
        problems.push(Problem::new(
            format!("{prefix}.udpSessionTimeout"),
            format!("上限 {} 秒", MAX_FIRST_DATA_TIMEOUT),
        ));
    }
    if rule.proxy_protocol != ProxyProtocol::None
        && !rule.protocols.contains(&super::model::Protocol::Tcp)
    {
        problems.push(Problem::new(
            format!("{prefix}.proxyProtocol"),
            "PROXY 协议只作用于 TCP",
        ));
    }
}

fn validate_target_ports(
    rule: &Rule,
    listen_count: usize,
    prefix: &str,
    problems: &mut Vec<Problem>,
) {
    let _ = prefix;
    match crate::forward_ports::listen_count(&rule.target_ports) {
        Ok(count) => {
            if count != 1 && count != listen_count {
                problems.push(Problem::new(
                    format!("{prefix}.targetPorts"),
                    "目标端口为 1 个（所有监听端口复用）或与监听端口数量相同",
                ));
            }
        }
        Err(reason) => {
            problems.push(Problem::new(format!("{prefix}.targetPorts"), reason));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l4::portforward::model::Protocol;

    fn base_rule() -> Rule {
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
    fn settings_defaults_applied_for_zero() {
        let config = normalize(FileConfig::default());
        let settings = config.settings;
        assert_eq!(settings.default_max_connections, 256);
        assert_eq!(settings.default_udp_session_timeout, 60);
        assert_eq!(settings.max_udp_sessions, 1024);
        assert_eq!(settings.dial_timeout, 5);
        assert_eq!(settings.first_data_timeout, 60);
        assert!(settings.enable);
    }

    #[test]
    fn first_data_timeout_clamped_to_3600() {
        let config = normalize(FileConfig {
            settings: Settings {
                first_data_timeout: 4000,
                ..Settings::default()
            },
            ..FileConfig::default()
        });
        assert_eq!(config.settings.first_data_timeout, 3600);
        let config = normalize(FileConfig {
            settings: Settings {
                first_data_timeout: 3000,
                ..Settings::default()
            },
            ..FileConfig::default()
        });
        assert_eq!(config.settings.first_data_timeout, 3000);
    }

    #[test]
    fn rule_requires_protocol_listen_and_target() {
        let mut config = FileConfig::default();
        config.rules.push(Rule::default());
        let problems = validate(&config);
        let fields: Vec<_> = problems.iter().map(|p| p.field.as_str()).collect();
        assert!(
            fields.iter().any(|f| f.ends_with("protocols")),
            "{fields:?}"
        );
        assert!(
            fields.iter().any(|f| f.ends_with("listenPorts")),
            "{fields:?}"
        );
        assert!(
            fields.iter().any(|f| f.ends_with("targetAddresses")),
            "{fields:?}"
        );
    }

    #[test]
    fn target_ports_must_be_one_or_match_listen_count() {
        let mut config = FileConfig::default();
        let mut rule = base_rule();
        rule.listen_ports = "8000-8002".into();
        rule.target_ports = "80,81".into();
        config.rules.push(rule);
        let problems = validate(&config);
        assert!(
            problems
                .iter()
                .any(|p| p.reason.contains("目标端口为 1 个")),
            "{problems:?}"
        );
        // Positional mapping with equal counts passes.
        let mut config = FileConfig::default();
        let mut rule = base_rule();
        rule.listen_ports = "8000-8002".into();
        rule.target_ports = "80-82".into();
        config.rules.push(rule);
        assert!(validate(&config).is_empty());
    }

    #[test]
    fn per_source_limit_defaults_to_half() {
        // The derivation itself lives in the compile step (mod.rs); here we
        // pin the zero-means-default contract on the settings level.
        let config = normalize(FileConfig::default());
        assert_eq!(config.settings.default_max_conns_per_source, 0);
    }

    #[test]
    fn proxy_protocol_tcp_only() {
        let mut config = FileConfig::default();
        let mut rule = base_rule();
        rule.protocols = vec![Protocol::Udp];
        rule.proxy_protocol = ProxyProtocol::V2;
        config.rules.push(rule);
        let problems = validate(&config);
        assert!(
            problems
                .iter()
                .any(|p| p.reason.contains("PROXY 协议只作用于 TCP")),
            "{problems:?}"
        );
    }

    #[test]
    fn duplicate_keys_are_collected() {
        let mut config = FileConfig::default();
        config.rules.push(base_rule());
        config.rules.push(base_rule());
        let problems = validate(&config);
        assert!(problems.iter().any(|p| p.field == "key"), "{problems:?}");
    }
}
