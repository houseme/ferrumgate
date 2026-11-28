//! Lucky import (WP-34 step 9, plan §3.3): converts a Lucky export subset
//! into port-forward rules.
//!
//! Lucky is the upstream router tool whose port-forward rules are imported
//! here. The input is a normalized subset of Lucky's export (the exact
//! upstream JSON is translated into [`LuckyImport`] before this API runs).
//! Each Lucky rule carries a 安全模式 (security mode) that maps onto the
//! rule access lists:
//!
//! - 白名单 (whitelist): Lucky's IP filter whitelist becomes `allow`.
//! - 黑名单 (blacklist): the rule blacklist plus the global blacklist
//!   become `deny`.
//! - 关闭 (off): no lists, auto firewall off.
//!
//! Lucky's self-built IP filter rules are imported by action regardless of
//! mode: allow entries append to the whitelist, deny entries append to the
//! blacklist merged with the global blacklist. Items that cannot be
//! represented (IP libraries, auto-record markers, address-range types) are
//! reported in the result warnings instead of being dropped silently.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;

use super::model::RawAccess;
use super::{Protocol, ProxyProtocol, Rule};

/// Normalized subset of a Lucky export (plan §3.3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct LuckyImport {
    pub rules: Vec<LuckyRule>,
}

/// One Lucky port-forward rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct LuckyRule {
    pub name: String,
    pub enable: bool,
    pub listen_port: u16,
    pub target_address: String,
    pub target_port: u16,
    /// tcp/udp like the model; empty normalizes to TCP with a warning.
    pub protocols: Vec<Protocol>,
    /// 安全模式: whitelist | blacklist | off.
    pub security_mode: LuckySecurityMode,
    /// IPs or CIDRs from Lucky's IP filter whitelist.
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
    pub global_blacklist: Vec<String>,
    /// Self-built IP filter rules, imported by action.
    pub ip_filter_rules: Vec<LuckyIpFilterRule>,
    /// Markers for items that cannot be imported (IP 库, 自动记录, ...).
    pub unsupported: Vec<String>,
}

/// Lucky 安全模式 (security mode).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LuckySecurityMode {
    /// 白名单: the IP filter whitelist becomes the allow list.
    Whitelist,
    /// 黑名单: rule blacklist + global blacklist become the deny list.
    Blacklist,
    /// 关闭: no lists, no auto firewall.
    #[default]
    Off,
}

/// Action of a self-built Lucky IP filter rule.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LuckyFilterAction {
    #[default]
    Allow,
    Deny,
}

/// A self-built Lucky IP filter rule with its entries (IPs or CIDRs).
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct LuckyIpFilterRule {
    pub action: LuckyFilterAction,
    pub entries: Vec<String>,
}

/// Outcome of [`import`]: ready-to-use rules plus non-fatal warnings.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LuckyImportResult {
    pub rules: Vec<Rule>,
    pub warnings: Vec<String>,
}

/// Converts a Lucky export subset into port-forward rules (plan §3.3).
pub fn import(lucky: LuckyImport) -> LuckyImportResult {
    let mut rules = Vec::with_capacity(lucky.rules.len());
    let mut warnings = Vec::new();
    for rule in lucky.rules {
        let LuckyRule {
            name,
            enable,
            listen_port,
            target_address,
            target_port,
            protocols,
            security_mode,
            whitelist,
            blacklist,
            global_blacklist,
            ip_filter_rules,
            unsupported,
        } = rule;

        for item in &unsupported {
            warnings.push(format!("规则 {name}: {item} 无法导入"));
        }

        let protocols = if protocols.is_empty() {
            warnings.push(format!("规则 {name}: 协议为空,默认 TCP"));
            vec![Protocol::Tcp]
        } else {
            protocols
        };

        let mut allow: Vec<String> = Vec::new();
        let mut deny: Vec<String> = Vec::new();
        match security_mode {
            LuckySecurityMode::Whitelist => {
                for entry in whitelist {
                    push_unique(&mut allow, entry);
                }
            }
            LuckySecurityMode::Blacklist => {
                for entry in blacklist.into_iter().chain(global_blacklist) {
                    push_unique(&mut deny, entry);
                }
            }
            LuckySecurityMode::Off => {}
        }
        // Self-built IP filter rules import by action in every mode: allow
        // entries join the whitelist, deny entries join the blacklist.
        for filter in ip_filter_rules {
            let dst = match filter.action {
                LuckyFilterAction::Allow => &mut allow,
                LuckyFilterAction::Deny => &mut deny,
            };
            for entry in filter.entries {
                push_unique(dst, entry);
            }
        }

        rules.push(Rule {
            key: generate_rule_key(),
            name,
            enable,
            group: String::new(),
            protocols,
            listen_address: String::new(),
            listen_ports: listen_port.to_string(),
            auto_firewall: security_mode != LuckySecurityMode::Off,
            target_addresses: vec![target_address],
            target_ports: target_port.to_string(),
            max_connections: 0,
            max_conns_per_source: 0,
            udp_session_timeout: 0,
            proxy_protocol: ProxyProtocol::None,
            access: RawAccess {
                allow: (!allow.is_empty()).then_some(allow),
                deny,
            },
            remark: "导入自 Lucky".to_string(),
        });
    }
    LuckyImportResult { rules, warnings }
}

/// Appends `value` unless empty or already present; the merge keeps the
/// first occurrence order and de-duplicates.
fn push_unique(dst: &mut Vec<String>, value: String) {
    if !value.is_empty() && !dst.contains(&value) {
        dst.push(value);
    }
}

/// Generates a rule key: 12 lowercase hex chars from 6 random bytes. Falls
/// back to a counter+time hash if the system RNG fails, so keys stay unique.
fn generate_rule_key() -> String {
    let mut bytes = [0u8; 6];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        counter_time_key(&mut bytes);
    }
    let mut key = String::with_capacity(12);
    for byte in bytes {
        let _ = write!(key, "{byte:02x}");
    }
    key
}

/// Fallback key source when the system RNG is unavailable: a process counter
/// mixed with the wall clock through splitmix64.
fn counter_time_key(dst: &mut [u8; 6]) {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0);
    let mut state = nanos
        ^ COUNTER
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    state = (state ^ (state >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    state = (state ^ (state >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    state ^= state >> 31;
    let bytes = state.to_le_bytes();
    dst.copy_from_slice(&bytes[..6]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lucky_rule(name: &str) -> LuckyRule {
        LuckyRule {
            name: name.to_string(),
            enable: true,
            listen_port: 8443,
            target_address: "192.168.1.10".to_string(),
            target_port: 443,
            protocols: vec![Protocol::Tcp],
            ..LuckyRule::default()
        }
    }

    #[test]
    fn import_whitelist_mode_maps_allow_list() {
        let mut rule = lucky_rule("web");
        rule.security_mode = LuckySecurityMode::Whitelist;
        rule.whitelist = vec!["10.0.0.5".into(), "192.168.1.0/24".into()];

        let result = import(LuckyImport { rules: vec![rule] });

        assert!(result.warnings.is_empty());
        let imported = &result.rules[0];
        assert_eq!(imported.name, "web");
        assert!(imported.enable);
        assert_eq!(imported.protocols, vec![Protocol::Tcp]);
        assert_eq!(imported.listen_address, "");
        assert_eq!(imported.listen_ports, "8443");
        assert_eq!(imported.target_addresses, vec!["192.168.1.10"]);
        assert_eq!(imported.target_ports, "443");
        assert!(imported.auto_firewall);
        assert_eq!(
            imported.access.allow.as_deref(),
            Some(&["10.0.0.5".to_string(), "192.168.1.0/24".to_string()][..])
        );
        assert!(imported.access.deny.is_empty());
        assert_eq!(imported.remark, "导入自 Lucky");
    }

    #[test]
    fn import_blacklist_merges_global() {
        let mut rule = lucky_rule("ha");
        rule.protocols = vec![Protocol::Tcp, Protocol::Udp];
        rule.security_mode = LuckySecurityMode::Blacklist;
        rule.blacklist = vec!["1.2.3.4".into()];
        rule.global_blacklist = vec!["5.6.7.8".into(), "1.2.3.4".into()];

        let result = import(LuckyImport { rules: vec![rule] });

        let imported = &result.rules[0];
        assert!(imported.auto_firewall);
        assert_eq!(imported.access.allow, None);
        assert_eq!(
            imported.access.deny,
            vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()]
        );
    }

    #[test]
    fn ip_filter_rules_by_action() {
        let mut rule = lucky_rule("filter");
        rule.security_mode = LuckySecurityMode::Whitelist;
        rule.whitelist = vec!["10.0.0.5".into()];
        rule.ip_filter_rules = vec![
            LuckyIpFilterRule {
                action: LuckyFilterAction::Allow,
                entries: vec!["10.0.1.0/24".into(), "10.0.0.5".into()],
            },
            LuckyIpFilterRule {
                action: LuckyFilterAction::Deny,
                entries: vec!["9.9.9.9".into()],
            },
        ];

        let result = import(LuckyImport { rules: vec![rule] });

        let imported = &result.rules[0];
        assert_eq!(
            imported.access.allow.as_deref(),
            Some(&["10.0.0.5".to_string(), "10.0.1.0/24".to_string()][..])
        );
        assert_eq!(imported.access.deny, vec!["9.9.9.9".to_string()]);
    }

    #[test]
    fn unsupported_items_become_warnings() {
        let mut rule = lucky_rule("web");
        rule.protocols = Vec::new();
        rule.unsupported = vec!["IP 库".into(), "自动记录".into()];

        let result = import(LuckyImport { rules: vec![rule] });

        assert_eq!(result.rules[0].protocols, vec![Protocol::Tcp]);
        assert_eq!(
            result.warnings,
            vec![
                "规则 web: IP 库 无法导入".to_string(),
                "规则 web: 自动记录 无法导入".to_string(),
                "规则 web: 协议为空,默认 TCP".to_string(),
            ]
        );
    }

    #[test]
    fn keys_generated_and_unique() {
        let rules: Vec<LuckyRule> = (0..64).map(|i| lucky_rule(&format!("r{i}"))).collect();

        let result = import(LuckyImport { rules });

        assert_eq!(result.rules.len(), 64);
        for rule in &result.rules {
            assert_eq!(rule.key.len(), 12);
            assert!(rule.key.chars().all(|c| c.is_ascii_hexdigit()));
        }
        let unique: std::collections::HashSet<&str> =
            result.rules.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(unique.len(), 64);
    }

    #[test]
    fn parses_camel_case_export_subset() {
        let json = r#"{
            "rules": [{
                "name": "web",
                "enable": false,
                "listenPort": 8080,
                "targetAddress": "10.0.0.2",
                "targetPort": 80,
                "protocols": ["udp"],
                "securityMode": "blacklist",
                "blacklist": ["8.8.8.8"],
                "ipFilterRules": [{"action": "deny", "entries": ["9.9.9.9"]}]
            }]
        }"#;
        let lucky: LuckyImport = serde_json::from_str(json).expect("parse");
        let rule = &lucky.rules[0];
        assert_eq!(rule.security_mode, LuckySecurityMode::Blacklist);
        assert_eq!(rule.listen_port, 8080);
        assert_eq!(rule.target_address, "10.0.0.2");
        assert_eq!(rule.ip_filter_rules[0].action, LuckyFilterAction::Deny);
        assert!(rule.whitelist.is_empty());

        // Unknown fields are rejected: the normalized shape is strict.
        assert!(serde_json::from_str::<LuckyImport>(r#"{"rules": [], "x": 1}"#).is_err());
    }
}
