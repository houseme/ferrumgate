//! Normalization and validation for the knock model (WP-54 step 8): pure
//! functions over plain data. `normalize` applies defaults and clamps the
//! ceilings; `validate` collects every problem (field path + reason), and
//! takes the ports already occupied by protocol-routing `spa` routes as a
//! parameter so the firewall-conflict rule (WP-54 §3.3) can be checked
//! without touching other modules.

use std::collections::BTreeSet;
use std::net::IpAddr;

use base64::Engine as _;
use ipnet::IpNet;

use crate::model::{Access, FileConfig, Proto, Rule, Settings, limits};
use crate::spa::HmacType;

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

/// Applies defaults and clamps every ceiling: `maxAge` 0 → default and ≤
/// 3600; `timeout` 0 → default and ≤ 86400; `maxTimeout` ≤ 86400 (0 keeps
/// its "ignore the client" meaning); port lists are deduplicated and
/// sorted; text fields are trimmed.
pub fn normalize(mut config: FileConfig) -> FileConfig {
    normalize_settings(&mut config.settings);
    for rule in &mut config.rules {
        normalize_rule(rule);
    }
    config
}

fn normalize_settings(settings: &mut Settings) {
    settings.allow_list = settings
        .allow_list
        .iter()
        .map(|entry| entry.trim().to_owned())
        .filter(|entry| !entry.is_empty())
        .take(limits::ALLOW_LIST_MAX)
        .collect();
    settings.max_age = if settings.max_age == 0 {
        limits::MAX_AGE_DEFAULT
    } else {
        settings.max_age.min(limits::MAX_AGE_MAX)
    };
}

fn normalize_rule(rule: &mut Rule) {
    rule.key = rule.key.trim().to_owned();
    rule.name = rule.name.trim().to_owned();
    rule.group = rule.group.trim().to_owned();
    rule.user = rule.user.trim().to_owned();
    rule.remark = rule.remark.trim().to_owned();
    rule.enc_key = rule.enc_key.trim().to_owned();
    rule.hmac_key = rule.hmac_key.trim().to_owned();
    rule.ports = dedupe_ports(&rule.ports);
    rule.timeout = if rule.timeout == 0 {
        limits::TIMEOUT_DEFAULT
    } else {
        rule.timeout.min(limits::DURATION_MAX)
    };
    if rule.max_timeout > limits::DURATION_MAX {
        rule.max_timeout = limits::DURATION_MAX;
    }
    for identity in &mut rule.identities {
        identity.id = identity.id.trim().to_owned();
        identity.name = identity.name.trim().to_owned();
        identity.remark = identity.remark.trim().to_owned();
        identity.enc_key = identity.enc_key.trim().to_owned();
        identity.hmac_key = identity.hmac_key.trim().to_owned();
    }
}

/// Deduplicates and sorts a port list (order is irrelevant for matching).
fn dedupe_ports(ports: &[Access]) -> Vec<Access> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for port in ports {
        if port.port != 0 && seen.insert(*port) {
            out.push(*port);
        }
    }
    out
}

/// Validates a normalized config, collecting every problem. `spa_ports`
/// are the ports occupied by protocol-routing `spa` routes; rules with
/// firewall blocking must not cover them (nor the UDP knock port).
pub fn validate(config: &FileConfig) -> Vec<Problem> {
    validate_with(config, &[])
}

/// Same as [`validate`] with the protocol-routing port parameter.
pub fn validate_with(config: &FileConfig, spa_ports: &[Access]) -> Vec<Problem> {
    let mut problems = Vec::new();
    let mut keys = BTreeSet::new();
    let mut seen_keys = BTreeSet::new();
    let udp_port = config.settings.port;

    if let Some(problem) = validate_allow_list(&config.settings) {
        problems.push(problem);
    }

    for (rule_index, rule) in config.rules.iter().enumerate() {
        let prefix = if rule.key.is_empty() {
            format!("rules.{rule_index}")
        } else {
            format!("rules.{}", rule.key)
        };
        if rule.key.is_empty() {
            problems.push(Problem::new("key", "key 不能为空"));
        } else if !valid_key(&rule.key) {
            problems.push(Problem::new(&prefix, "key 只能为字母、数字、_ 或 -"));
        } else if !keys.insert(rule.key.clone()) {
            problems.push(Problem::new("key", format!("重复的 key {}", rule.key)));
        }
        if rule.name.is_empty() {
            problems.push(Problem::new(format!("{prefix}.name"), "名称不能为空"));
        } else if rule.name.chars().count() > limits::NAME_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.name"),
                format!("名称最多 {} 个字符", limits::NAME_MAX_CHARS),
            ));
        }
        if rule.group.chars().count() > limits::GROUP_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.group"),
                format!("分组最多 {} 个字符", limits::GROUP_MAX_CHARS),
            ));
        }
        if rule.remark.chars().count() > limits::REMARK_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.remark"),
                format!("备注最多 {} 个字符", limits::REMARK_MAX_CHARS),
            ));
        }
        if rule.ports.is_empty() {
            problems.push(Problem::new(
                format!("{prefix}.ports"),
                "至少需要一个放行端口",
            ));
        } else if rule.ports.len() > limits::RULE_PORTS_MAX {
            problems.push(Problem::new(
                format!("{prefix}.ports"),
                format!("端口最多 {} 个", limits::RULE_PORTS_MAX),
            ));
        }
        if rule.user.chars().count() > limits::USERNAME_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.user"),
                format!("用户名最多 {} 个字符", limits::USERNAME_MAX_CHARS),
            ));
        }
        if rule.identities.len() > limits::IDENTITIES_MAX {
            problems.push(Problem::new(
                format!("{prefix}.identities"),
                format!("身份最多 {} 个", limits::IDENTITIES_MAX),
            ));
        }
        if rule.enable {
            // Firewall conflicts: the knock UDP port and protocol-routing
            // spa ports must never sit behind a blocked rule (§3.3).
            if rule.firewall {
                if udp_port != 0
                    && rule
                        .ports
                        .iter()
                        .any(|p| p.proto == Proto::Udp && p.port == udp_port)
                {
                    problems.push(Problem::new(
                        format!("{prefix}.ports"),
                        format!("防火墙拦截的规则不能包含敲门端口 udp/{udp_port}"),
                    ));
                }
                for occupied in spa_ports {
                    if rule.ports.contains(occupied) {
                        problems.push(Problem::new(
                            format!("{prefix}.ports"),
                            format!("防火墙拦截的规则不能包含协议分流敲门端口 {occupied}"),
                        ));
                    }
                }
            }
            // Credentials of enabled rules must decode and stay in range.
            if !rule.shared_key_off {
                validate_key_material(
                    &rule.enc_key,
                    "encKey",
                    &format!("{prefix}.encKey"),
                    &mut problems,
                );
                validate_key_material(
                    &rule.hmac_key,
                    "hmacKey",
                    &format!("{prefix}.hmacKey"),
                    &mut problems,
                );
                register_key(
                    &rule.enc_key,
                    &rule.hmac_key,
                    rule.hmac_type,
                    &format!("{prefix}.hmacKey"),
                    &mut seen_keys,
                    &mut problems,
                );
            }
            validate_identities(rule, &prefix, &mut seen_keys, &mut problems);
        }
    }
    if seen_keys.len() > limits::TOTAL_KEYS_MAX {
        problems.push(Problem::new(
            "rules",
            format!("全部密钥合计最多 {} 个", limits::TOTAL_KEYS_MAX),
        ));
    }
    problems
}

fn validate_identities(
    rule: &Rule,
    prefix: &str,
    seen_keys: &mut BTreeSet<Vec<u8>>,
    problems: &mut Vec<Problem>,
) {
    let mut ids = BTreeSet::new();
    for identity in &rule.identities {
        if !identity.enable {
            continue;
        }
        let field = format!("{prefix}.identities.{}", identity.id);
        if identity.id.is_empty() {
            problems.push(Problem::new(field.clone(), "身份 id 不能为空"));
            continue;
        }
        if !ids.insert(identity.id.clone()) {
            problems.push(Problem::new(
                field,
                format!("重复的身份 id {}", identity.id),
            ));
            continue;
        }
        if identity.name.is_empty() {
            problems.push(Problem::new(field.clone(), "身份名称不能为空"));
        }
        validate_key_material(
            &identity.enc_key,
            "encKey",
            &format!("{field}.encKey"),
            problems,
        );
        validate_key_material(
            &identity.hmac_key,
            "hmacKey",
            &format!("{field}.hmacKey"),
            problems,
        );
        register_key(
            &identity.enc_key,
            &identity.hmac_key,
            rule.hmac_type,
            &format!("{field}.hmacKey"),
            seen_keys,
            problems,
        );
    }
}

/// Decodes one credential, reports out-of-range lengths and marks the
/// HMAC key as seen (duplicates are rejected across rules and identities).
fn register_key(
    enc_b64: &str,
    hmac_b64: &str,
    hmac_type: HmacType,
    hmac_field: &str,
    seen_keys: &mut BTreeSet<Vec<u8>>,
    problems: &mut Vec<Problem>,
) {
    let Ok(key) = crate::spa::Key::from_base64(enc_b64, hmac_b64, hmac_type) else {
        // Invalid base64 was already reported by `validate_key_material`.
        return;
    };
    if !key.lengths_ok(
        limits::ENC_KEY_MIN,
        limits::ENC_KEY_MAX,
        limits::HMAC_KEY_MIN,
        limits::HMAC_KEY_MAX,
    ) {
        problems.push(Problem::new(
            hmac_field,
            format!(
                "密钥长度超出范围（加密 {}–{} 字节，HMAC {}–{} 字节）",
                limits::ENC_KEY_MIN,
                limits::ENC_KEY_MAX,
                limits::HMAC_KEY_MIN,
                limits::HMAC_KEY_MAX
            ),
        ));
        return;
    }
    if !seen_keys.insert(key.hmac) {
        problems.push(Problem::new(hmac_field, "HMAC 密钥与其他规则或身份重复"));
    }
}

/// Reports a key field that is present but not valid base64.
fn validate_key_material(value: &str, name: &str, field: &str, problems: &mut Vec<Problem>) {
    if value.is_empty() {
        problems.push(Problem::new(field, format!("{name} 不能为空")));
        return;
    }
    if base64::engine::general_purpose::STANDARD
        .decode(value)
        .is_err()
    {
        problems.push(Problem::new(field, format!("{name} 不是有效的 base64")));
    }
}

/// The allow list must contain valid IPs or CIDRs.
fn validate_allow_list(settings: &Settings) -> Option<Problem> {
    for entry in &settings.allow_list {
        if !is_ip_or_cidr(entry) {
            return Some(Problem::new(
                "settings.allowList",
                format!("不是有效的 IP 或 CIDR：{entry}"),
            ));
        }
    }
    None
}

fn is_ip_or_cidr(text: &str) -> bool {
    if text.parse::<IpAddr>().is_ok() {
        return true;
    }
    text.parse::<IpNet>().is_ok()
}

/// Same key contract as the fg-admin collections: short, URL-safe.
pub fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key != "batch-delete"
        && key.len() <= 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// Total number of credentials the enabled rules would install (shared
/// keys plus enabled identities) — the HMAC work per forged packet.
pub fn total_key_count(config: &FileConfig) -> usize {
    config
        .rules
        .iter()
        .filter(|rule| rule.enable)
        .map(|rule| {
            usize::from(!rule.shared_key_off) + rule.identities.iter().filter(|i| i.enable).count()
        })
        .sum()
}

/// The enabled credential entries of a config, in stable order.
pub fn enabled_key_entries(
    config: &FileConfig,
) -> Vec<(String, Option<String>, String, String, HmacType)> {
    let mut out = Vec::new();
    for rule in config.rules.iter().filter(|rule| rule.enable) {
        if !rule.shared_key_off {
            out.push((
                rule.key.clone(),
                None,
                rule.enc_key.clone(),
                rule.hmac_key.clone(),
                rule.hmac_type,
            ));
        }
        for identity in rule.identities.iter().filter(|i| i.enable) {
            out.push((
                rule.key.clone(),
                Some(identity.id.clone()),
                identity.enc_key.clone(),
                identity.hmac_key.clone(),
                rule.hmac_type,
            ));
        }
    }
    out
}

/// Collects the credentials valid for one rule after an edit (enabled +
/// valid key material); used to revoke stale grants.
pub fn rule_credential_set(rule: &Rule) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if !rule.shared_key_off
        && let Ok(key) = crate::spa::Key::from_base64(&rule.enc_key, &rule.hmac_key, rule.hmac_type)
    {
        out.insert(crate::spa::cred_fingerprint(&key.hmac, rule.hmac_type));
    }
    for identity in rule.identities.iter().filter(|i| i.enable) {
        if let Ok(key) =
            crate::spa::Key::from_base64(&identity.enc_key, &identity.hmac_key, rule.hmac_type)
        {
            out.insert(crate::spa::cred_fingerprint(&key.hmac, rule.hmac_type));
        }
    }
    out
}

/// The rule list as seen by the grant registry (`knockgate` rule keys).
pub fn enabled_rule_keys(config: &FileConfig) -> Vec<String> {
    config
        .rules
        .iter()
        .filter(|rule| rule.enable)
        .map(|rule| rule.key.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Identity;
    use crate::model::limits;

    fn base_rule() -> Rule {
        Rule {
            key: "a1b2c3d4e5f6".into(),
            name: "ssh".into(),
            enable: true,
            ports: vec![Access::new(Proto::Tcp, 22)],
            enc_key: "MDEyMzQ1Njc4OWFiY2RlZg==".into(), // 16 decoded bytes
            hmac_key: hmac_key_b64(32),
            hmac_type: HmacType::Sha256,
            ..Rule::default()
        }
    }

    fn hmac_key_b64(len: usize) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(vec![b'k'; len])
    }

    /// A unique in-range HMAC key per (rule, identity) index, so cap tests
    /// really count distinct credentials.
    fn hmac_key_unique(parts: [u32; 2]) -> String {
        use base64::Engine as _;
        let mut bytes = vec![b'k'; 32];
        for (slot, value) in parts.iter().enumerate() {
            bytes[slot * 4..slot * 4 + 4].copy_from_slice(&value.to_be_bytes());
        }
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn normalize_applies_defaults_and_clamps() {
        let mut config = FileConfig::default();
        config.settings.max_age = 0;
        config.settings.port = 0;
        let mut rule = base_rule();
        rule.timeout = 0;
        rule.max_timeout = 100_000;
        rule.ports = vec![
            Access::new(Proto::Tcp, 22),
            Access::new(Proto::Tcp, 22),
            Access::new(Proto::Udp, 0),
            Access::new(Proto::Udp, 53),
        ];
        config.rules.push(rule);
        let config = normalize(config);
        assert_eq!(config.settings.max_age, limits::MAX_AGE_DEFAULT);
        assert_eq!(config.rules[0].timeout, limits::TIMEOUT_DEFAULT);
        assert_eq!(config.rules[0].max_timeout, limits::DURATION_MAX);
        assert_eq!(
            config.rules[0].ports,
            vec![Access::new(Proto::Tcp, 22), Access::new(Proto::Udp, 53)]
        );
    }

    #[test]
    fn normalize_zero_max_timeout_stays_zero() {
        let mut config = FileConfig::default();
        let mut rule = base_rule();
        rule.max_timeout = 0;
        config.rules.push(rule);
        let config = normalize(config);
        assert_eq!(config.rules[0].max_timeout, 0, "0 = ignore client requests");
    }

    #[test]
    fn validate_key_lengths_enforced() {
        let mut config = FileConfig::default();
        let mut rule = base_rule();
        rule.hmac_key = hmac_key_b64(8); // below HMAC_KEY_MIN
        config.rules.push(rule);
        let problems = validate(&normalize(config));
        assert!(
            problems
                .iter()
                .any(|p| p.field.ends_with("hmacKey") && p.reason.contains("长度")),
            "short key reported: {problems:?}"
        );
        // A valid 32-byte HMAC key passes; an over-range enc key fails.
        let mut config = FileConfig::default();
        config.rules.push(base_rule());
        assert!(validate(&normalize(config)).is_empty());
        let mut config = FileConfig::default();
        let mut rule = base_rule();
        rule.enc_key = hmac_key_b64(64); // above ENC_KEY_MAX
        config.rules.push(rule);
        let problems = validate(&normalize(config));
        assert!(
            problems
                .iter()
                .any(|p| p.field.ends_with("hmacKey") && p.reason.contains("长度"))
        );
    }

    #[test]
    fn validate_duplicate_hmac_keys_rejected() {
        // Duplicate across rules.
        let shared = hmac_key_b64(32);
        let mut config = FileConfig::default();
        let mut rule = base_rule();
        rule.hmac_key = shared.clone();
        config.rules.push(rule);
        let mut other = base_rule();
        other.key = "otherkey12345".into();
        other.name = "other".into();
        other.hmac_key = shared.clone();
        config.rules.push(other);
        let problems = validate(&normalize(config));
        assert_eq!(
            problems
                .iter()
                .filter(|p| p.reason.contains("HMAC 密钥"))
                .count(),
            1,
            "the second rule's shared key is rejected: {problems:?}"
        );

        // Identity colliding with its own rule's shared key.
        let mut config = FileConfig::default();
        let mut rule = base_rule();
        rule.hmac_key = shared.clone();
        rule.identities.push(Identity {
            id: "id1".into(),
            name: "alice".into(),
            enable: true,
            enc_key: rule.enc_key.clone(),
            hmac_key: shared,
            remark: String::new(),
        });
        config.rules.push(rule);
        let problems = validate(&normalize(config));
        assert!(
            problems.iter().any(|p| p.reason.contains("HMAC 密钥")),
            "{problems:?}"
        );
    }

    #[test]
    fn validate_total_keys_capped_at_1024() {
        let mut config = FileConfig::default();
        // 64 identities per rule, 16 rules: 1024 identities + 16 shared keys.
        for rule_index in 0..16u32 {
            let mut rule = base_rule();
            rule.key = format!("rule{rule_index:011}");
            rule.name = format!("rule{rule_index}");
            rule.hmac_key = hmac_key_unique([rule_index, u32::MAX]);
            rule.identities = (0..limits::IDENTITIES_MAX)
                .map(|i| Identity {
                    id: format!("id{i}"),
                    name: format!("user{i}"),
                    enable: true,
                    enc_key: rule.enc_key.clone(),
                    hmac_key: hmac_key_unique([rule_index, i as u32]),
                    remark: String::new(),
                })
                .collect();
            config.rules.push(rule);
        }
        let normalized = normalize(config);
        assert_eq!(total_key_count(&normalized), 16 * (1 + 64));
        let problems = validate(&normalized);
        assert!(
            problems
                .iter()
                .any(|p| p.field == "rules" && p.reason.contains("1024")),
            "{problems:?}"
        );
    }

    #[test]
    fn validate_ports_and_identities_caps() {
        let mut config = FileConfig::default();
        let mut rule = base_rule();
        rule.hmac_key = hmac_key_b64(32);
        rule.ports = (0..limits::RULE_PORTS_MAX as u16 + 1)
            .map(|i| Access::new(Proto::Tcp, 1000 + i))
            .collect();
        config.rules.push(rule.clone());
        assert!(
            validate(&normalize(config))
                .iter()
                .any(|p| p.field.ends_with(".ports"))
        );

        let mut config = FileConfig::default();
        rule.ports = vec![Access::new(Proto::Tcp, 22)];
        rule.identities = (0..limits::IDENTITIES_MAX + 1)
            .map(|i| Identity {
                id: format!("id{i}"),
                name: format!("user{i}"),
                enable: true,
                enc_key: rule.enc_key.clone(),
                hmac_key: hmac_key_b64(32),
                remark: String::new(),
            })
            .collect();
        config.rules.push(rule);
        let problems = validate(&normalize(config));
        assert!(problems.iter().any(|p| p.field.ends_with(".identities")));
    }

    #[test]
    fn validate_spa_route_port_not_protected() {
        let mut config = FileConfig::default();
        let mut rule = base_rule();
        rule.hmac_key = hmac_key_b64(32);
        rule.firewall = true;
        rule.ports = vec![Access::new(Proto::Tcp, 8443)];
        config.rules.push(rule);
        let config = normalize(config);
        assert!(
            validate_with(&config, &[Access::new(Proto::Tcp, 8443)])
                .iter()
                .any(|p| p.reason.contains("协议分流"))
        );
        assert!(validate_with(&config, &[Access::new(Proto::Udp, 8443)]).is_empty());

        // The UDP knock port itself must not be blocked either.
        let mut config = config;
        config.rules[0].ports = vec![Access::new(Proto::Udp, 62201)];
        assert!(config.rules[0].firewall);
        assert!(
            validate(&config)
                .iter()
                .any(|p| p.reason.contains("敲门端口"))
        );
    }

    #[test]
    fn validate_allow_list_entries_are_ips_or_cidrs() {
        let mut config = FileConfig::default();
        config.settings.allow_list = vec!["10.0.0.0/8".into(), "192.168.1.1".into(), "nope".into()];
        let problems = validate(&normalize(config));
        assert!(problems.iter().any(|p| p.field == "settings.allowList"));
    }

    #[test]
    fn disabled_rules_skip_key_validation() {
        let mut config = FileConfig::default();
        let mut rule = base_rule();
        rule.enable = false;
        rule.enc_key.clear();
        rule.hmac_key.clear();
        config.rules.push(rule);
        assert!(validate(&normalize(config)).is_empty());
    }

    #[test]
    fn valid_key_follows_collection_contract() {
        assert!(valid_key("a1b2c3d4e5f6"));
        assert!(valid_key("rule_1"));
        assert!(!valid_key("batch-delete"));
        assert!(!valid_key(""));
        assert!(!valid_key("with space"));
    }
}
