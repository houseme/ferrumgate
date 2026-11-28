//! Normalization and validation for the stun model (WP-42): pure functions
//! over plain data. `normalize` applies the upstream `fillDefaults`
//! behavior (interval floors, default server lists, canonical `host:port`
//! forms) and trims user-entered text; `validate` collects every problem
//! instead of stopping at the first.

use crate::model::{
    AccessConfig, Bind, BindMode, FileConfig, Rule, Settings, WebhookConfig, limits,
};

/// Webhook methods a rule or the settings may use.
const WEBHOOK_METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

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

/// Applies defaults and trims user-entered text:
///
/// - `heartbeatInterval` / `stunTimeout` / `retryInterval`: `0` reads as
///   3000 ms, everything clamps to the 500 ms floor.
/// - `addrCheckInterval`: below 10 seconds reads as 60.
/// - The settings' empty server lists fill with the upstream defaults so
///   they stay visible and editable.
/// - Server entries normalize to canonical `host:port` (`[v6]:port`),
///   adding the default port when missing.
pub fn normalize(mut config: FileConfig) -> FileConfig {
    normalize_settings(&mut config.settings);
    for rule in &mut config.rules {
        normalize_rule(rule);
    }
    config
}

fn normalize_settings(settings: &mut Settings) {
    if settings.stun_servers.is_empty() {
        settings.stun_servers = limits::DEFAULT_STUN_SERVERS
            .iter()
            .map(|s| (*s).into())
            .collect();
    }
    if settings.keep_alive_servers.is_empty() {
        settings.keep_alive_servers = limits::DEFAULT_KEEP_ALIVE_SERVERS
            .iter()
            .map(|s| (*s).into())
            .collect();
    }
    let stun_servers = std::mem::take(&mut settings.stun_servers);
    settings.stun_servers = normalize_servers(stun_servers, limits::STUN_DEFAULT_PORT);
    let keep_alive_servers = std::mem::take(&mut settings.keep_alive_servers);
    settings.keep_alive_servers =
        normalize_servers(keep_alive_servers, limits::KEEP_ALIVE_DEFAULT_PORT);
    settings.addr_check_interval = match settings.addr_check_interval {
        0 => limits::ADDR_CHECK_INTERVAL_DEFAULT_SECS,
        below if below < limits::ADDR_CHECK_INTERVAL_MIN_SECS => {
            limits::ADDR_CHECK_INTERVAL_DEFAULT_SECS
        }
        value => value,
    };
    normalize_webhook(&mut settings.webhook);
}

fn normalize_rule(rule: &mut Rule) {
    rule.key = rule.key.trim().to_owned();
    rule.name = rule.name.trim().to_owned();
    rule.group = rule.group.trim().to_owned();
    rule.remark = rule.remark.trim().to_owned();
    rule.bind.ip = rule.bind.ip.trim().to_owned();
    rule.bind.interface = rule.bind.interface.trim().to_owned();
    rule.bind.regex = rule.bind.regex.trim().to_owned();
    let stun_servers = std::mem::take(&mut rule.stun_servers);
    rule.stun_servers = normalize_servers(stun_servers, limits::STUN_DEFAULT_PORT);
    let keep_alive_servers = std::mem::take(&mut rule.keep_alive_servers);
    rule.keep_alive_servers =
        normalize_servers(keep_alive_servers, limits::KEEP_ALIVE_DEFAULT_PORT);
    rule.target_addresses = rule
        .target_addresses
        .iter()
        .map(|target| target.trim().to_owned())
        .filter(|target| !target.is_empty())
        .collect();
    rule.heartbeat_interval = clamp_interval(rule.heartbeat_interval);
    rule.stun_timeout = clamp_interval(rule.stun_timeout);
    rule.retry_interval = clamp_interval(rule.retry_interval);
    if rule.udp_session_timeout == 0 {
        rule.udp_session_timeout = limits::UDP_SESSION_TIMEOUT_DEFAULT_SECS;
    }
    normalize_webhook(&mut rule.webhook);
    normalize_access(&mut rule.access);
}

fn clamp_interval(value: u32) -> u32 {
    match value {
        0 => limits::INTERVAL_DEFAULT_MS,
        below if below < limits::INTERVAL_MIN_MS => limits::INTERVAL_MIN_MS,
        value => value,
    }
}

fn normalize_webhook(webhook: &mut WebhookConfig) {
    webhook.url = webhook.url.trim().to_owned();
    webhook.method = webhook.method.trim().to_ascii_uppercase();
    webhook.headers = webhook
        .headers
        .iter()
        .map(|header| header.trim().to_owned())
        .filter(|header| !header.is_empty())
        .collect();
    if webhook.timeout == 0 {
        webhook.timeout = limits::WEBHOOK_TIMEOUT_DEFAULT_SECS;
    }
    webhook.timeout = webhook.timeout.min(limits::WEBHOOK_TIMEOUT_MAX_SECS);
}

fn normalize_access(access: &mut AccessConfig) {
    access.whitelist = access
        .whitelist
        .iter()
        .map(|entry| entry.trim().to_owned())
        .filter(|entry| !entry.is_empty())
        .collect();
    access.blacklist = access
        .blacklist
        .iter()
        .map(|entry| entry.trim().to_owned())
        .filter(|entry| !entry.is_empty())
        .collect();
}

/// Trims, canonically renders and deduplicates (order-preserving) a server
/// list; bare hosts gain `default_port`.
pub fn normalize_servers(servers: Vec<String>, default_port: u16) -> Vec<String> {
    let mut out = Vec::new();
    for server in servers {
        let server = server.trim().to_owned();
        if server.is_empty() {
            continue;
        }
        if let Some((host, port)) = parse_host_port(&server, default_port) {
            let canonical = render_host_port(&host, port);
            if !out.contains(&canonical) {
                out.push(canonical);
            }
        }
    }
    out
}

fn normalize_access_entries(entries: &[String]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| entry.trim().to_owned())
        .filter(|entry| !entry.is_empty())
        .collect()
}

/// Validates a normalized config, collecting every problem.
pub fn validate(config: &FileConfig) -> Vec<Problem> {
    let mut problems = Vec::new();
    if config.rules.len() > limits::RULES_MAX {
        problems.push(Problem::new(
            "rules",
            format!("规则最多 {} 条", limits::RULES_MAX),
        ));
    }
    validate_settings(&config.settings, &mut problems);
    let mut keys = std::collections::BTreeSet::new();
    for rule in &config.rules {
        let prefix = if rule.key.is_empty() {
            format!("rules.{}", rule.name)
        } else {
            format!("rules.{}", rule.key)
        };
        if rule.key.is_empty() {
            problems.push(Problem::new("key", "key 不能为空"));
        } else if !keys.insert(rule.key.as_str()) {
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
        validate_bind(&prefix, &rule.bind, &mut problems);
        validate_servers(
            &format!("{prefix}.stunServers"),
            &rule.stun_servers,
            rule.use_global_servers,
            &mut problems,
        );
        validate_servers(
            &format!("{prefix}.keepAliveServers"),
            &rule.keep_alive_servers,
            true,
            &mut problems,
        );
        validate_forward(&prefix, rule, &mut problems);
        validate_webhook(&format!("{prefix}.webhook"), &rule.webhook, &mut problems);
        validate_script(&prefix, rule, &mut problems);
        validate_access(&prefix, &rule.access, &mut problems);
    }
    problems
}

fn validate_settings(settings: &Settings, problems: &mut Vec<Problem>) {
    validate_servers(
        "settings.stunServers",
        &settings.stun_servers,
        false,
        problems,
    );
    validate_servers(
        "settings.keepAliveServers",
        &settings.keep_alive_servers,
        false,
        problems,
    );
    validate_webhook("settings.webhook", &settings.webhook, problems);
}

fn validate_bind(prefix: &str, bind: &Bind, problems: &mut Vec<Problem>) {
    match bind.mode {
        BindMode::Ip => {
            if bind.ip.parse::<std::net::IpAddr>().is_err() {
                problems.push(Problem::new(
                    format!("{prefix}.bind.ip"),
                    format!("不是有效的 IP 地址：{}", bind.ip),
                ));
            }
        }
        BindMode::Interface => {
            if bind.interface.is_empty() {
                problems.push(Problem::new(
                    format!("{prefix}.bind.interface"),
                    "interface 模式需要填写网卡名",
                ));
            }
        }
        BindMode::Regex => match regex::Regex::new(&bind.regex) {
            Ok(_) => {
                if bind.regex.is_empty() {
                    problems.push(Problem::new(
                        format!("{prefix}.bind.regex"),
                        "regex 模式需要填写匹配表达式",
                    ));
                }
            }
            Err(error) => problems.push(Problem::new(
                format!("{prefix}.bind.regex"),
                format!("正则无效：{error}"),
            )),
        },
        BindMode::Auto => {}
    }
}

fn validate_servers(field: &str, servers: &[String], optional: bool, problems: &mut Vec<Problem>) {
    if servers.is_empty() {
        if !optional {
            problems.push(Problem::new(field, "服务器列表不能为空"));
        }
        return;
    }
    if servers.len() > limits::SERVERS_MAX {
        problems.push(Problem::new(
            field,
            format!("服务器最多 {} 个", limits::SERVERS_MAX),
        ));
    }
    for server in servers {
        if server.chars().count() > limits::SERVER_MAX_CHARS {
            problems.push(Problem::new(field, format!("地址过长：{server}")));
        }
        if parse_host_port(server, 0).is_none() {
            problems.push(Problem::new(
                field,
                format!("不是有效的 host:port：{server}"),
            ));
        }
    }
}

fn validate_forward(prefix: &str, rule: &Rule, problems: &mut Vec<Problem>) {
    if rule.disable_forward {
        return;
    }
    if rule.target_addresses.is_empty() {
        problems.push(Problem::new(
            format!("{prefix}.targetAddresses"),
            "内置转发需要填写目标地址",
        ));
    } else if rule.target_addresses.len() > limits::FORWARD_TARGETS_MAX {
        problems.push(Problem::new(
            format!("{prefix}.targetAddresses"),
            format!("目标地址最多 {} 个", limits::FORWARD_TARGETS_MAX),
        ));
    }
    for target in &rule.target_addresses {
        // Targets are `host` or `host:port`; the missing port comes from
        // `targetPort`, so only an explicit port of 0 is invalid here.
        if parse_host_port(target, 1).is_none() {
            problems.push(Problem::new(
                format!("{prefix}.targetAddresses"),
                format!("不是有效的 host 或 host:port：{target}"),
            ));
        }
    }
    if rule.target_port == 0 {
        problems.push(Problem::new(
            format!("{prefix}.targetPort"),
            "内置转发需要填写目标端口",
        ));
    }
}

fn validate_webhook(field: &str, webhook: &WebhookConfig, problems: &mut Vec<Problem>) {
    if webhook.url.is_empty() {
        return;
    }
    if !webhook.url.starts_with("http://") && !webhook.url.starts_with("https://") {
        problems.push(Problem::new(
            format!("{field}.url"),
            "URL 需以 http:// 或 https:// 开头",
        ));
    }
    if !webhook.method.is_empty() && !WEBHOOK_METHODS.contains(&webhook.method.as_str()) {
        problems.push(Problem::new(
            format!("{field}.method"),
            format!("方法只支持 {}", WEBHOOK_METHODS.join(" / ")),
        ));
    }
    if webhook.headers.len() > limits::SERVERS_MAX {
        problems.push(Problem::new(
            format!("{field}.headers"),
            format!("请求头最多 {} 条", limits::SERVERS_MAX),
        ));
    }
    for header in &webhook.headers {
        if parse_header(header).is_none() {
            problems.push(Problem::new(
                format!("{field}.headers"),
                format!("请求头需为 \"名称: 值\"：{header}"),
            ));
        }
    }
}

fn validate_script(prefix: &str, rule: &Rule, problems: &mut Vec<Problem>) {
    if !rule.script_enable {
        return;
    }
    if rule.script.trim().is_empty() {
        problems.push(Problem::new(
            format!("{prefix}.script"),
            "脚本已启用但内容为空",
        ));
    } else if rule.script.chars().count() > limits::SCRIPT_MAX_CHARS {
        problems.push(Problem::new(
            format!("{prefix}.script"),
            format!("脚本最多 {} 个字符", limits::SCRIPT_MAX_CHARS),
        ));
    }
}

fn validate_access(prefix: &str, access: &AccessConfig, problems: &mut Vec<Problem>) {
    if !access.enable {
        return;
    }
    let whitelist = normalize_access_entries(&access.whitelist);
    let blacklist = normalize_access_entries(&access.blacklist);
    for (field, entries) in [
        ("access.whitelist", whitelist),
        ("access.blacklist", blacklist),
    ] {
        for entry in entries {
            if parse_ip_or_cidr(&entry).is_none() {
                problems.push(Problem::new(
                    format!("{prefix}.{field}"),
                    format!("不是有效的 IP 或 CIDR：{entry}"),
                ));
            }
        }
    }
}

/// Splits a raw `Key: Value` header line.
pub fn parse_header(header: &str) -> Option<(String, String)> {
    let (name, value) = header.split_once(':')?;
    let name = name.trim();
    if name.is_empty() || name.contains(char::is_whitespace) {
        return None;
    }
    Some((name.to_owned(), value.trim().to_owned()))
}

/// Parses `host`, `host:port` or `[v6]:port`; a missing port becomes
/// `default_port` (pass 0 to require an explicit port). Returns the host
/// without brackets plus the effective port. Entries containing whitespace
/// are never valid.
pub fn parse_host_port(entry: &str, default_port: u16) -> Option<(String, u16)> {
    let entry = entry.trim();
    if entry.is_empty() || entry.chars().any(char::is_whitespace) {
        return None;
    }
    if let Some(rest) = entry.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let host = host.trim();
        if host.is_empty() || host.parse::<std::net::IpAddr>().is_err() {
            return None;
        }
        match after.strip_prefix(':') {
            Some(port) => Some((host.to_owned(), parse_port(port)?)),
            None if after.is_empty() => {
                (default_port != 0).then(|| (host.to_owned(), default_port))
            }
            None => None,
        }
    } else {
        match entry.rsplit_once(':') {
            Some((host, port)) => {
                let host = host.trim();
                let port = parse_port(port)?;
                if host.is_empty() || host.contains(':') {
                    // A bare IPv6 literal has several colons and no port.
                    if entry.parse::<std::net::IpAddr>().is_ok() {
                        return (default_port != 0).then(|| (entry.to_owned(), default_port));
                    }
                    return None;
                }
                Some((host.to_owned(), port))
            }
            None => (default_port != 0).then(|| (entry.to_owned(), default_port)),
        }
    }
}

fn parse_port(text: &str) -> Option<u16> {
    text.trim().parse::<u16>().ok().filter(|&port| port != 0)
}

/// Canonical `host:port` form; IPv6 literals are bracketed.
pub fn render_host_port(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Parses an IP address or `IP/prefix` CIDR entry.
pub fn parse_ip_or_cidr(entry: &str) -> Option<std::net::IpAddr> {
    let Some((ip, prefix)) = entry.split_once('/') else {
        return entry.trim().parse::<std::net::IpAddr>().ok();
    };
    let ip: std::net::IpAddr = ip.trim().parse().ok()?;
    let max = match ip {
        std::net::IpAddr::V4(_) => 32,
        std::net::IpAddr::V6(_) => 128,
    };
    let prefix: u8 = prefix.trim().parse().ok()?;
    (prefix <= max).then_some(ip)
}

/// The STUN servers a rule uses: its own list, or the module's when
/// `useGlobalServers` is set (empty globals fall back to the defaults).
pub fn effective_servers(rule: &Rule, settings: &Settings) -> Vec<String> {
    if rule.use_global_servers {
        if settings.stun_servers.is_empty() {
            limits::DEFAULT_STUN_SERVERS
                .iter()
                .map(|s| (*s).into())
                .collect()
        } else {
            settings.stun_servers.clone()
        }
    } else {
        rule.stun_servers.clone()
    }
}

/// The TCP keep-alive targets a rule uses: its own list, or the module's.
pub fn effective_keep_alive(rule: &Rule, settings: &Settings) -> Vec<String> {
    if rule.keep_alive_servers.is_empty() {
        if settings.keep_alive_servers.is_empty() {
            limits::DEFAULT_KEEP_ALIVE_SERVERS
                .iter()
                .map(|s| (*s).into())
                .collect()
        } else {
            settings.keep_alive_servers.clone()
        }
    } else {
        rule.keep_alive_servers.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BindMode, Proto};

    fn base_rule() -> Rule {
        Rule {
            key: "abc123".into(),
            name: "home lab".into(),
            protocol: Proto::Udp,
            stun_servers: vec!["127.0.0.1:3478".into()],
            heartbeat_interval: 3000,
            stun_timeout: 3000,
            retry_interval: 3000,
            ..Rule::default()
        }
    }

    #[test]
    fn rule_defaults_fill_and_clamp() {
        let config = normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![Rule {
                key: "r1".into(),
                name: "rule".into(),
                heartbeat_interval: 0,
                stun_timeout: 100,
                retry_interval: 99_999,
                udp_session_timeout: 0,
                ..Rule::default()
            }],
        });
        // The module defaults appear in the settings so they stay editable.
        assert_eq!(config.settings.stun_servers, limits::DEFAULT_STUN_SERVERS);
        assert_eq!(
            config.settings.keep_alive_servers,
            limits::DEFAULT_KEEP_ALIVE_SERVERS
        );
        assert_eq!(
            config.settings.addr_check_interval,
            limits::ADDR_CHECK_INTERVAL_DEFAULT_SECS
        );
        let rule = &config.rules[0];
        assert_eq!(rule.heartbeat_interval, limits::INTERVAL_DEFAULT_MS);
        assert_eq!(rule.stun_timeout, limits::INTERVAL_MIN_MS);
        assert_eq!(rule.retry_interval, 99_999);
        assert_eq!(
            rule.udp_session_timeout,
            limits::UDP_SESSION_TIMEOUT_DEFAULT_SECS
        );
        assert_eq!(rule.webhook.timeout, limits::WEBHOOK_TIMEOUT_DEFAULT_SECS);
    }

    #[test]
    fn addr_check_interval_below_min_reads_as_default() {
        let settings = Settings {
            addr_check_interval: 5,
            ..Settings::default()
        };
        let config = normalize(FileConfig {
            settings,
            rules: Vec::new(),
        });
        assert_eq!(
            config.settings.addr_check_interval,
            limits::ADDR_CHECK_INTERVAL_DEFAULT_SECS
        );
    }

    #[test]
    fn servers_canonicalize_deduplicate_and_drop_broken_entries() {
        let servers = normalize_servers(
            vec![
                "stun.example.com".into(),
                " 2001:db8::1 ".into(),
                "stun.example.com:3478".into(),
                "not a server!!".into(),
                "".into(),
                "10.0.0.1:9999".into(),
            ],
            limits::STUN_DEFAULT_PORT,
        );
        assert_eq!(
            servers,
            [
                "stun.example.com:3478",
                "[2001:db8::1]:3478",
                "10.0.0.1:9999"
            ]
        );
    }

    #[test]
    fn missing_rules_are_collected() {
        let mut rule = base_rule();
        rule.name = String::new();
        rule.use_global_servers = true;
        rule.webhook = WebhookConfig {
            url: "ftp://example.com".into(),
            ..WebhookConfig::default()
        };
        rule.bind = Bind {
            mode: BindMode::Ip,
            ip: "not-an-ip".into(),
            ..Bind::default()
        };
        let config = normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![rule],
        });
        let fields: Vec<_> = validate(&config)
            .into_iter()
            .map(|problem| problem.field)
            .collect();
        assert!(fields.iter().any(|f| f.ends_with(".name")), "{fields:?}");
        assert!(
            fields.iter().any(|f| f.ends_with(".webhook.url")),
            "{fields:?}"
        );
        assert!(fields.iter().any(|f| f.ends_with(".bind.ip")), "{fields:?}");
    }

    #[test]
    fn forward_requires_targets_when_enabled() {
        let mut rule = base_rule();
        rule.disable_forward = false;
        rule.target_addresses = vec!["127.0.0.1".into()];
        // targetPort missing: collected.
        let problems = validate(&normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![rule.clone()],
        }));
        assert!(problems.iter().any(|p| p.field.ends_with(".targetPort")));
        rule.target_port = 8080;
        let problems = validate(&normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![rule.clone()],
        }));
        assert!(problems.is_empty(), "{problems:?}");
        rule.target_addresses = vec!["bad target".into()];
        let problems = validate(&normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![rule],
        }));
        assert!(
            problems
                .iter()
                .any(|p| p.field.ends_with(".targetAddresses"))
        );
    }

    #[test]
    fn private_stun_servers_required_when_not_global() {
        let mut rule = base_rule();
        rule.use_global_servers = false;
        rule.stun_servers = Vec::new();
        let problems = validate(&normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![rule],
        }));
        assert!(problems.iter().any(|p| p.field.ends_with(".stunServers")));
    }

    #[test]
    fn regex_bind_mode_rejects_broken_patterns() {
        let mut rule = base_rule();
        rule.bind.mode = BindMode::Regex;
        rule.bind.regex = "(unclosed".into();
        let problems = validate(&normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![rule],
        }));
        assert!(problems.iter().any(|p| p.field.ends_with(".bind.regex")));
    }

    #[test]
    fn access_entries_must_parse_as_ip_or_cidr() {
        let mut rule = base_rule();
        rule.access.enable = true;
        rule.access.whitelist = vec!["10.0.0.0/8".into(), "bad".into()];
        rule.access.blacklist = vec!["2001:db8::/32".into(), "10.0.0.0/40".into()];
        let problems = validate(&normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![rule],
        }));
        let reasons: Vec<_> = problems.into_iter().map(|p| p.reason).collect();
        let joined = reasons.join(";");
        assert!(joined.contains("bad"), "{joined}");
        assert!(joined.contains("10.0.0.0/40"), "{joined}");
    }

    #[test]
    fn host_port_parsing_handles_v6_and_defaults() {
        assert_eq!(
            parse_host_port("stun.example.com", 3478),
            Some(("stun.example.com".into(), 3478))
        );
        assert_eq!(
            parse_host_port("stun.example.com:9999", 3478),
            Some(("stun.example.com".into(), 9999))
        );
        assert_eq!(
            parse_host_port("[2001:db8::1]:3478", 80),
            Some(("2001:db8::1".into(), 3478))
        );
        assert_eq!(
            parse_host_port("2001:db8::1", 3478),
            Some(("2001:db8::1".into(), 3478))
        );
        assert_eq!(parse_host_port("host.example", 0), None);
        assert_eq!(parse_host_port("host.example:0", 3478), None);
        assert_eq!(parse_host_port("", 3478), None);
        assert_eq!(render_host_port("2001:db8::1", 3478), "[2001:db8::1]:3478");
    }

    #[test]
    fn effective_servers_follow_the_global_switch() {
        let settings = normalize(FileConfig {
            settings: Settings::default(),
            rules: Vec::new(),
        })
        .settings;
        let mut rule = base_rule();
        rule.use_global_servers = true;
        assert_eq!(effective_servers(&rule, &settings), settings.stun_servers);
        rule.use_global_servers = false;
        assert_eq!(effective_servers(&rule, &settings), rule.stun_servers);
        let mut rule = base_rule();
        rule.keep_alive_servers = vec!["keep.example".into()];
        let normalized = normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![rule],
        });
        assert_eq!(
            effective_keep_alive(&normalized.rules[0], &settings),
            vec!["keep.example:80".to_owned()]
        );
    }

    #[test]
    fn header_parsing_requires_name() {
        assert_eq!(
            parse_header("X-Token: abc"),
            Some(("X-Token".into(), "abc".into()))
        );
        assert_eq!(parse_header(":v"), None);
        assert_eq!(parse_header("no colon"), None);
    }
}
