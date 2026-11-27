//! Compilation of the portforward model into runtime-ready rules (WP-34).
//!
//! `compile` normalizes the config first, then expands every enabled rule
//! into a [`CompiledRule`]: concrete listen socket addresses, per-listener
//! target rows, effective limits, the source access filter and fresh
//! counters. Expansion problems are collected across all rules into one
//! `Vec<String>` (`field path: reason`, like `validate::Problem`) instead of
//! failing at the first rule.
//!
//! Decisions pinned here (all documented upstream-aligned behavior):
//! - An empty `listen_address` means all addresses and compiles as
//!   `0.0.0.0` (the IPv4 wildcard). A bare IPv6 address is bracketed so the
//!   `host:ports` split stays well-formed.
//! - `target_addresses` entries are either bare IPs (the mapped port
//!   supplies the port) or full `address:port` sockets (used as-is; the
//!   mapped port is ignored). Hostnames are rejected — `validate` already
//!   rejects them.
//! - An empty `target_ports` maps every listener to its own port
//!   (identity mapping); otherwise ports map positionally with a single
//!   target port reused by every listener (`fg_net::ports::map_targets`).
//! - The per-source limit is the rule value, else the settings default,
//!   else half of the port's `max_connections` (at least 1).
//! - `settings.enable` gates serving, not compilation: compile expands
//!   every rule-level-enabled rule regardless of the module switch.
//!
//! Compile only reports expansion problems (parse/mapping/access compile);
//! pair it with `validate`, which reports the model-level problems.

use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicI32, AtomicU64},
    },
    time::Duration,
};

use fg_net::source_rule::{AccessFilter, RawSourceRule, SourceRule};
use ipnet::IpNet;

use super::model::{FileConfig, Rule, Settings};

/// Live counters for one compiled rule, shared with the future serve loop
/// (WP-39 batch): per-transport active connections, admissions rejected by
/// the access filter, relayed bytes and totals.
#[derive(Debug, Default)]
pub struct RuleStats {
    pub active_tcp: AtomicI32,
    pub active_udp: AtomicI32,
    pub rejected: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub conns_total: AtomicU64,
}

/// Effective limits for one rule; every zero-derived value is already
/// resolved here, so the serve loop never re-derives defaults.
#[derive(Debug)]
pub struct Limits {
    pub max_connections: u32,
    pub max_conns_per_source: u32,
    pub udp_session_timeout: Duration,
    pub dial_timeout: Duration,
    pub first_data_timeout: Duration,
    /// Sources never subject to the per-source limit (from
    /// `settings.per_source_exempt`).
    pub exempt: Vec<IpNet>,
}

/// One enabled rule, fully expanded and ready to bind. Not `Debug`:
/// `AccessFilter` (fg_net) does not implement it; inspect `cfg` instead.
pub struct CompiledRule {
    /// The rule as written (settings already normalized); the *effective*
    /// values live in `limits`, rule-level zero fields stay zero here.
    pub cfg: Rule,
    pub listens: Vec<SocketAddr>,
    /// One row per listen address, one entry per target address; a pinned
    /// `address:port` target repeats unchanged across rows.
    pub targets: Vec<Vec<SocketAddr>>,
    pub limits: Limits,
    pub filter: AccessFilter,
    pub stats: Arc<RuleStats>,
}

/// Normalizes the config, then expands every enabled rule with protocols.
/// Returns all expansion problems across all rules when anything fails.
pub fn compile(config: &FileConfig) -> Result<Vec<CompiledRule>, Vec<String>> {
    let config = super::validate::normalize(config.clone());
    let mut errors = Vec::new();
    // Settings-level exempt list parsed once; a failure there is reported
    // but does not stop per-rule compilation (the error carries the
    // parser's generic `source` label).
    let exempt =
        match fg_net::source_rule::compile_networks(config.settings.per_source_exempt.clone()) {
            Ok(networks) => networks,
            Err(error) => {
                errors.push(format!("settings.perSourceExempt: {error}"));
                Vec::new()
            }
        };
    let mut compiled = Vec::new();
    for rule in &config.rules {
        // Disabled rules never serve. Protocol-less rules cannot bind
        // anything (validate reports them); skip them defensively.
        if !rule.enable || rule.protocols.is_empty() {
            continue;
        }
        match compile_rule(rule, &config.settings, &exempt) {
            Ok(rule) => compiled.push(rule),
            Err(mut rule_errors) => errors.append(&mut rule_errors),
        }
    }
    if errors.is_empty() {
        Ok(compiled)
    } else {
        Err(errors)
    }
}

fn compile_rule(
    rule: &Rule,
    settings: &Settings,
    exempt: &[IpNet],
) -> Result<CompiledRule, Vec<String>> {
    let mut errors = Vec::new();
    let prefix = format!("rules.{}", rule.key);

    // Listen expansion through the shared listener parser (`IP:ports` or a
    // full single `address:port`).
    let listens =
        match crate::forward_ports::parse(&listen_spec(&rule.listen_address, &rule.listen_ports)) {
            Ok(addresses) => addresses,
            Err(error) => {
                errors.push(format!("{prefix}.listenPorts: {error:#}"));
                Vec::new()
            }
        };

    let mut targets: Vec<Vec<SocketAddr>> = Vec::new();
    if !listens.is_empty() {
        match expand_targets(rule, &listens) {
            Ok(rows) => targets = rows,
            Err(mut expand_errors) => errors.append(&mut expand_errors),
        }
    }

    // Effective limits (rule value wins, then the normalized settings
    // default, then the upstream half-of-max per-source fallback).
    let max_connections = if rule.max_connections != 0 {
        rule.max_connections
    } else {
        settings.default_max_connections
    };
    let max_conns_per_source = if rule.max_conns_per_source != 0 {
        rule.max_conns_per_source
    } else if settings.default_max_conns_per_source != 0 {
        settings.default_max_conns_per_source
    } else {
        (max_connections / 2).max(1)
    };
    let udp_timeout_secs = if rule.udp_session_timeout != 0 {
        u64::from(rule.udp_session_timeout)
    } else {
        u64::from(settings.default_udp_session_timeout)
    };
    let limits = Limits {
        max_connections,
        max_conns_per_source,
        udp_session_timeout: Duration::from_secs(udp_timeout_secs),
        dial_timeout: Duration::from_secs(u64::from(settings.dial_timeout)),
        first_data_timeout: Duration::from_secs(u64::from(settings.first_data_timeout)),
        exempt: exempt.to_vec(),
    };

    // Source access lists: the rule's flattened `allow`/`deny` compile into
    // the shared filter. An empty pair yields the present-but-empty filter
    // (`AccessFilter::is_empty`) that admits everything. A compile failure
    // is collected and the rule dropped (via the errors below); the default
    // filter only keeps the value shape total.
    let filter = match SourceRule::compile(RawSourceRule {
        allow: rule.access.allow.clone(),
        deny: rule.access.deny.clone(),
    }) {
        Ok(rule) => AccessFilter::new(rule),
        Err(error) => {
            errors.push(format!("{prefix}.source: {error}"));
            AccessFilter::new(SourceRule::default())
        }
    };

    if errors.is_empty() {
        Ok(CompiledRule {
            cfg: rule.clone(),
            listens,
            targets,
            limits,
            filter,
            stats: Arc::new(RuleStats::default()),
        })
    } else {
        Err(errors)
    }
}

/// Builds the `host:ports` spec [`crate::forward_ports::parse`] accepts
/// (an IP-literal host plus port list, or a full single socket address):
/// - empty `listen_address` → `0.0.0.0` (all IPv4 addresses);
/// - a bare IPv6 address is bracketed so the `host:ports` split stays
///   well-formed.
fn listen_spec(address: &str, ports: &str) -> String {
    match address {
        "" => format!("0.0.0.0:{ports}"),
        host => match host.parse::<IpAddr>() {
            Ok(ip) if ip.is_ipv6() => format!("[{host}]:{ports}"),
            _ => format!("{host}:{ports}"),
        },
    }
}

/// Expands the target rows: one row per listen port (in order), one entry
/// per target address. A target written `address:port` is pinned; a bare IP
/// receives the mapped port for its row. All entry problems are reported
/// together.
fn expand_targets(
    rule: &Rule,
    listens: &[SocketAddr],
) -> Result<Vec<Vec<SocketAddr>>, Vec<String>> {
    let mut errors = Vec::new();
    #[derive(Clone, Copy)]
    enum Host {
        /// Written `address:port`; the mapped port is ignored.
        Pinned(SocketAddr),
        /// Bare IP; the mapped port supplies the port.
        Bare(IpAddr),
    }
    if rule.target_addresses.is_empty() {
        errors.push(format!(
            "rules.{}.targetAddresses: 至少填写一个目标地址",
            rule.key
        ));
    }
    let mut hosts = Vec::with_capacity(rule.target_addresses.len());
    for address in &rule.target_addresses {
        if let Ok(socket) = address.parse::<SocketAddr>() {
            hosts.push(Host::Pinned(socket));
        } else if let Ok(ip) = address.parse::<IpAddr>() {
            hosts.push(Host::Bare(ip));
        } else {
            errors.push(format!(
                "rules.{}.targetAddresses: {address} 不是 IP 或 地址:端口",
                rule.key
            ));
        }
    }

    let listen_ports: Vec<u16> = listens.iter().map(SocketAddr::port).collect();
    let mapped = if rule.target_ports.is_empty() {
        // No target ports: every listener forwards to its own port.
        listen_ports
            .iter()
            .map(|&port| vec![port])
            .collect::<Vec<_>>()
    } else {
        match fg_net::ports::parse_ports(&rule.target_ports) {
            Ok(list) => match fg_net::ports::map_targets(&listen_ports, &list) {
                Ok(mapped) => mapped,
                Err(error) => {
                    errors.push(format!("rules.{}.targetPorts: {error}", rule.key));
                    Vec::new()
                }
            },
            Err(error) => {
                errors.push(format!("rules.{}.targetPorts: {error}", rule.key));
                Vec::new()
            }
        }
    };
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(mapped
        .iter()
        .map(|ports| {
            let port = ports[0];
            hosts
                .iter()
                .map(|host| match *host {
                    Host::Pinned(socket) => socket,
                    Host::Bare(ip) => SocketAddr::new(ip, port),
                })
                .collect()
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l4::portforward::model::Protocol;

    fn rule(key: &str) -> Rule {
        Rule {
            key: key.into(),
            name: key.into(),
            enable: true,
            protocols: vec![Protocol::Tcp],
            listen_address: "127.0.0.1".into(),
            listen_ports: "8080".into(),
            target_addresses: vec!["10.0.0.1:80".into()],
            target_ports: "80".into(),
            ..Rule::default()
        }
    }

    fn config(rules: Vec<Rule>) -> FileConfig {
        FileConfig {
            settings: Settings::default(),
            rules,
        }
    }

    #[test]
    fn per_source_limit_defaults_to_half() {
        let rules = compile(&config(vec![rule("web")])).unwrap();
        let [web] = rules.as_slice() else {
            panic!("one rule expected");
        };
        // Normalized settings: default_max_connections 256, per-source zero
        // → half of the port max.
        assert_eq!(web.limits.max_connections, 256);
        assert_eq!(web.limits.max_conns_per_source, 128);
        // Normalized durations land on the upstream defaults.
        assert_eq!(web.limits.udp_session_timeout, Duration::from_secs(60));
        assert_eq!(web.limits.dial_timeout, Duration::from_secs(5));
        assert_eq!(web.limits.first_data_timeout, Duration::from_secs(60));

        // The rule value wins over the settings default.
        let mut pinned = rule("pinned");
        pinned.max_connections = 20;
        pinned.max_conns_per_source = 4;
        // Settings default applies when the rule leaves it zero.
        let mut config = config(vec![pinned, rule("defaulted")]);
        config.settings.default_max_conns_per_source = 100;
        let rules = compile(&config).unwrap();
        assert_eq!(rules[0].limits.max_connections, 20);
        assert_eq!(rules[0].limits.max_conns_per_source, 4);
        assert_eq!(rules[1].limits.max_connections, 256);
        assert_eq!(rules[1].limits.max_conns_per_source, 100);
    }

    #[test]
    fn compile_collects_errors_across_rules() {
        let mut first = rule("first");
        first.listen_ports = "not-ports".into();
        let mut second = rule("second");
        second.target_addresses = vec!["example.invalid".into()];
        let Err(errors) = compile(&config(vec![first, second])) else {
            panic!("both bad rules must fail compilation");
        };
        assert!(
            errors.iter().any(|error| error.contains("rules.first")),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|error| error.contains("rules.second")),
            "{errors:?}"
        );
    }

    #[test]
    fn disabled_rules_are_skipped() {
        let mut off = rule("off");
        off.enable = false;
        let rules = compile(&config(vec![off, rule("on")])).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].cfg.key, "on");
    }

    #[test]
    fn positional_target_mapping() {
        let mut wide = rule("wide");
        wide.listen_ports = "8000-8002".into();
        wide.target_ports = "90-92".into();
        wide.target_addresses = vec!["10.0.0.1".into(), "10.0.0.2:7000".into()];
        let rules = compile(&config(vec![wide])).unwrap();
        let [compiled] = rules.as_slice() else {
            panic!("one rule expected");
        };
        assert_eq!(compiled.listens.len(), 3);
        assert_eq!(compiled.listens[0], "127.0.0.1:8000".parse().unwrap());
        assert_eq!(compiled.targets.len(), 3);
        let bare: IpAddr = "10.0.0.1".parse().unwrap();
        let pinned: SocketAddr = "10.0.0.2:7000".parse().unwrap();
        for (index, row) in compiled.targets.iter().enumerate() {
            let mapped = 90 + index as u16;
            assert_eq!(
                row[0],
                SocketAddr::new(bare, mapped),
                "bare IP takes the positionally mapped port"
            );
            assert_eq!(
                row[1], pinned,
                "pinned address:port ignores the mapped port"
            );
        }
    }

    #[test]
    fn empty_listen_address_and_empty_target_ports() {
        // Empty listen address → the 0.0.0.0 wildcard; empty target ports →
        // every listener forwards to its own port.
        let mut wild = rule("wild");
        wild.listen_address = String::new();
        wild.target_ports = String::new();
        wild.target_addresses = vec!["203.0.113.9".into()];
        let rules = compile(&config(vec![wild])).unwrap();
        let [compiled] = rules.as_slice() else {
            panic!("one rule expected");
        };
        assert_eq!(compiled.listens, ["0.0.0.0:8080".parse().unwrap()]);
        assert_eq!(
            compiled.targets,
            [vec!["203.0.113.9:8080".parse().unwrap()]]
        );

        // A bare IPv6 listen address is bracketed, not mangled.
        let mut v6 = rule("six");
        v6.listen_address = "fe80::1".into();
        let rules = compile(&config(vec![v6])).unwrap();
        assert_eq!(rules[0].listens, ["[fe80::1]:8080".parse().unwrap()]);
    }
}
