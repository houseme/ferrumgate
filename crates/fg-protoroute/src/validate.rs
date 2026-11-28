//! Normalization and validation for the protoroute model (WP-35): pure
//! functions over plain data. `normalize` applies the upstream
//! `fillDefaults` behavior (sniff-timeout floor and range, legacy
//! `host:port` default-target splitting, domain canonicalization to
//! lower-case punycode) and trims user-entered text; `validate` collects
//! every problem instead of stopping at the first, including the route
//! conflict checks delegated to [`crate::router::RouteTable::compile`].

use crate::model::{AccessConfig, FileConfig, Protocol, Route, Rule, Settings, limits};
use crate::router;

/// A collected validation problem: the offending field path and reason.
#[derive(Debug, PartialEq, Eq)]
pub struct Problem {
    pub field: String,
    pub reason: String,
}

impl Problem {
    pub(crate) fn new(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

/// Applies defaults and trims user-entered text:
///
/// - `sniffTimeout`: `0` reads as 5 s, the value is clamped into
///   0.1 - 60 and rounded to one decimal place.
/// - `dialTimeout`: `0` reads as 5 s.
/// - `listenPorts` / `targetPorts` are canonicalized (sorted, deduped,
///   ranges collapsed).
/// - Default-target entries in legacy `host:port` form are split: the
///   host stays in `targetAddresses`, the port moves into `targetPorts`.
/// - Domains are lower-cased, stripped of trailing dots and converted to
///   punycode per label.
pub fn normalize(mut config: FileConfig) -> FileConfig {
    normalize_settings(&mut config.settings);
    for rule in &mut config.rules {
        normalize_rule(rule);
    }
    config
}

fn normalize_settings(settings: &mut Settings) {
    settings.per_source_exempt = normalize_entries(&settings.per_source_exempt);
    settings.dial_timeout = match settings.dial_timeout {
        0 => limits::DIAL_TIMEOUT_DEFAULT_SECS,
        v => v.min(3600),
    };
}

fn normalize_rule(rule: &mut Rule) {
    rule.key = rule.key.trim().to_owned();
    rule.name = rule.name.trim().to_owned();
    rule.group = rule.group.trim().to_owned();
    rule.remark = rule.remark.trim().to_owned();
    rule.listen_address = rule.listen_address.trim().to_owned();
    rule.knock = normalize_knock(rule.knock.take());
    let mut seen = std::collections::BTreeSet::new();
    rule.protocols.retain(|net| seen.insert(*net));
    rule.listen_ports = match parse_listen_ports(&rule.listen_ports) {
        Ok(ranges) => render_listen_ports(&ranges),
        Err(_) => rule.listen_ports.trim().to_owned(),
    };
    rule.sniff_timeout = clamp_sniff_timeout(rule.sniff_timeout);
    rule.access = normalize_access(rule.access.clone());
    // Default target: split legacy host:port entries, canonicalize ports.
    let mut default_ports = parse_port_list(&rule.target_ports);
    rule.target_addresses = rule
        .target_addresses
        .iter()
        .filter_map(|entry| split_target(entry))
        .filter_map(|(host, port)| {
            if let Some(port) = port {
                default_ports.push(port);
            }
            let host = punycode_domain(&host)?;
            (!host.is_empty()).then_some(host)
        })
        .collect();
    default_ports.sort_unstable();
    default_ports.dedup();
    rule.target_ports = default_ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    for route in &mut rule.routes {
        normalize_route_entry(route);
    }
}

fn normalize_route_entry(route: &mut Route) {
    route.name = route.name.trim().to_owned();
    route.knock = normalize_knock(route.knock.take());
    route.domains = route
        .domains
        .iter()
        .filter_map(|domain| {
            let domain = punycode_domain(domain)?;
            (!domain.is_empty()).then_some(domain)
        })
        .collect();
    route.domains.sort_unstable();
    route.domains.dedup();
    route.alpn = {
        let mut seen = std::collections::BTreeSet::new();
        route
            .alpn
            .iter()
            .map(|id| id.trim().to_owned())
            .filter(|id| !id.is_empty() && id.len() <= 255)
            .filter(|id| seen.insert(id.clone()))
            .collect()
    };
    route.target_addresses = route
        .target_addresses
        .iter()
        .filter_map(|entry| {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                return None;
            }
            match split_target(trimmed) {
                Some((host, None)) => punycode_domain(&host).filter(|h| !h.is_empty()),
                // Routes carry a single `targetPort`: keep entries with an
                // explicit port or invalid syntax untouched so `validate`
                // reports them instead of silently dropping them.
                _ => Some(trimmed.to_owned()),
            }
        })
        .collect();
}

fn normalize_knock(knock: Option<String>) -> Option<String> {
    knock
        .map(|key| key.trim().to_owned())
        .filter(|key| !key.is_empty())
}

fn normalize_access(mut access: AccessConfig) -> AccessConfig {
    access.whitelist = normalize_entries(&access.whitelist);
    access.blacklist = normalize_entries(&access.blacklist);
    access
}

fn normalize_entries(entries: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.trim().to_owned();
        if !entry.is_empty() && !out.contains(&entry) {
            out.push(entry);
        }
    }
    out
}

/// `sniffTimeout` defaults, clamps and rounds to one decimal place.
pub fn clamp_sniff_timeout(value: f32) -> f32 {
    let value = if !value.is_finite() || value == 0.0 {
        limits::SNIFF_TIMEOUT_DEFAULT_SECS
    } else {
        value
    };
    let value = value.clamp(
        limits::SNIFF_TIMEOUT_MIN_SECS,
        limits::SNIFF_TIMEOUT_MAX_SECS,
    );
    (value * 10.0).round() / 10.0
}

/// Validates a normalized config, collecting every problem.
pub fn validate(config: &FileConfig) -> Vec<Problem> {
    validate_with_caps(config, true)
}

/// Validates a normalized config, taking into account whether the optional
/// port-knock module is compiled in / wired (`knock_available`).
pub fn validate_with_caps(config: &FileConfig, knock_available: bool) -> Vec<Problem> {
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
        if rule.protocols.is_empty() {
            problems.push(Problem::new(
                format!("{prefix}.protocols"),
                "至少选择一个监听协议（tcp / tcp4 / tcp6）",
            ));
        }
        validate_listen_address(&prefix, &rule.listen_address, &mut problems);
        validate_listen_ports(&prefix, &rule.listen_ports, &mut problems);
        validate_knock(
            &format!("{prefix}.knock"),
            rule.knock.as_deref(),
            knock_available,
            &mut problems,
        );
        validate_entries(
            &format!("{prefix}.access.whitelist"),
            &rule.access.whitelist,
            &mut problems,
        );
        validate_entries(
            &format!("{prefix}.access.blacklist"),
            &rule.access.blacklist,
            &mut problems,
        );
        validate_targets(
            &format!("{prefix}.targetAddresses"),
            &format!("{prefix}.targetPorts"),
            &rule.target_addresses,
            &rule.target_ports,
            true,
            &mut problems,
        );
        validate_routes(&prefix, rule, knock_available, &mut problems);
    }
    problems
}

fn validate_settings(settings: &Settings, problems: &mut Vec<Problem>) {
    validate_entries(
        "settings.perSourceExempt",
        &settings.per_source_exempt,
        problems,
    );
}

fn validate_entries(field: &str, entries: &[String], problems: &mut Vec<Problem>) {
    if entries.len() > limits::ACCESS_MAX {
        problems.push(Problem::new(
            field,
            format!("条目最多 {} 个", limits::ACCESS_MAX),
        ));
    }
    for entry in entries {
        if parse_ip_or_cidr(entry).is_none() {
            problems.push(Problem::new(
                field,
                format!("不是有效的 IP 或 CIDR：{entry}"),
            ));
        }
    }
}

fn validate_listen_address(prefix: &str, address: &str, problems: &mut Vec<Problem>) {
    if !address.is_empty() && address.parse::<std::net::IpAddr>().is_err() {
        problems.push(Problem::new(
            format!("{prefix}.listenAddress"),
            format!("不是有效的 IP 地址：{address}"),
        ));
    }
}

fn validate_listen_ports(prefix: &str, ports: &str, problems: &mut Vec<Problem>) {
    match parse_listen_ports(ports) {
        Err(reason) => problems.push(Problem::new(
            format!("{prefix}.listenPorts"),
            format!("端口写法无效：{reason}"),
        )),
        Ok(ranges) => {
            let count: usize = ranges
                .iter()
                .map(|(a, b)| (*b as usize) - (*a as usize) + 1)
                .sum();
            if ranges.is_empty() {
                problems.push(Problem::new(
                    format!("{prefix}.listenPorts"),
                    "至少填写一个监听端口",
                ));
            } else if count > limits::PORTS_MAX {
                problems.push(Problem::new(
                    format!("{prefix}.listenPorts"),
                    format!("监听端口最多 {} 个", limits::PORTS_MAX),
                ));
            }
        }
    }
}

fn validate_targets(
    address_field: &str,
    port_field: &str,
    addresses: &[String],
    ports: &str,
    ports_optional: bool,
    problems: &mut Vec<Problem>,
) {
    if addresses.len() > limits::TARGETS_MAX {
        problems.push(Problem::new(
            address_field,
            format!("目标地址最多 {} 个", limits::TARGETS_MAX),
        ));
    }
    for address in addresses {
        if address.chars().count() > limits::TARGET_MAX_CHARS {
            problems.push(Problem::new(address_field, format!("地址过长：{address}")));
        }
        if !is_host(address) {
            problems.push(Problem::new(
                address_field,
                format!("不是有效的主机名或 IP：{address}"),
            ));
        }
    }
    let port_list = parse_port_list(ports);
    if port_list.len() > limits::TARGETS_MAX {
        problems.push(Problem::new(
            port_field,
            format!("目标端口最多 {} 个", limits::TARGETS_MAX),
        ));
    }
    if !addresses.is_empty() {
        if port_list.is_empty() {
            if !ports_optional {
                problems.push(Problem::new(port_field, "需要填写目标端口"));
            } else {
                problems.push(Problem::new(
                    port_field,
                    "填写了目标地址但没有目标端口（留空地址 = 断开连接）",
                ));
            }
        }
    } else if !port_list.is_empty() {
        problems.push(Problem::new(
            address_field,
            "填写了目标端口但没有目标地址；地址留空表示直接断开",
        ));
    }
}

fn validate_routes(prefix: &str, rule: &Rule, knock_available: bool, problems: &mut Vec<Problem>) {
    if rule.routes.len() > limits::ROUTES_MAX {
        problems.push(Problem::new(
            format!("{prefix}.routes"),
            format!("路由最多 {} 条", limits::ROUTES_MAX),
        ));
    }
    for (index, route) in rule.routes.iter().enumerate() {
        let field = format!("{prefix}.routes.{}", route.name);
        if route.name.is_empty() {
            problems.push(Problem::new(
                format!("{prefix}.routes[{index}].name"),
                "路由名称不能为空",
            ));
        } else if route.name.chars().count() > limits::ROUTE_NAME_MAX_CHARS {
            problems.push(Problem::new(
                format!("{field}.name"),
                format!("路由名称最多 {} 个字符", limits::ROUTE_NAME_MAX_CHARS),
            ));
        }
        validate_domains(&format!("{field}.domains"), &route.domains, problems);
        if route.alpn.len() > limits::ALPN_MAX {
            problems.push(Problem::new(
                format!("{field}.alpn"),
                format!("ALPN 最多 {} 个", limits::ALPN_MAX),
            ));
        }
        if route.domains.len() > limits::DOMAINS_MAX {
            problems.push(Problem::new(
                format!("{field}.domains"),
                format!("域名最多 {} 个", limits::DOMAINS_MAX),
            ));
        }
        validate_knock(
            &format!("{field}.knock"),
            route.knock.as_deref(),
            knock_available,
            problems,
        );
        if route.protocol == Protocol::Spa {
            if !knock_available {
                problems.push(Problem::new(
                    format!("{field}.protocol"),
                    "端口敲门模块未包含在此构建中，spa 路由不可用",
                ));
            }
            if route.knock.is_some() {
                problems.push(Problem::new(
                    format!("{field}.knock"),
                    "spa 路由不能设置敲门条件",
                ));
            }
        }
        // `spa` routes never forward; everything else needs a target. The
        // per-route port lives in `targetPort` (`0` = the listen port), so
        // only the address list is checked here.
        if route.protocol != Protocol::Spa && route.target_addresses.is_empty() {
            problems.push(Problem::new(
                format!("{field}.targetAddresses"),
                "路由需要至少一个目标地址",
            ));
        }
        if route.target_addresses.len() > limits::TARGETS_MAX {
            problems.push(Problem::new(
                format!("{field}.targetAddresses"),
                format!("目标地址最多 {} 个", limits::TARGETS_MAX),
            ));
        }
        for address in &route.target_addresses {
            if !is_host(address) {
                problems.push(Problem::new(
                    format!("{field}.targetAddresses"),
                    format!("不是有效的主机名或 IP：{address}"),
                ));
            }
        }
    }
    // Conflict checks (enabled routes only) come from the routing table
    // compiler so the same rules apply at runtime.
    let default_exists = !rule.target_addresses.is_empty();
    if let Err(errors) = router::RouteTable::compile(&rule.routes, default_exists, None) {
        for reason in errors {
            problems.push(Problem::new(format!("{prefix}.routes"), reason));
        }
    }
}

fn validate_domains(field: &str, domains: &[String], problems: &mut Vec<Problem>) {
    for domain in domains {
        if domain == "*" {
            continue;
        }
        let body = if let Some(rest) = domain.strip_prefix("*.") {
            rest
        } else if domain.starts_with('*') {
            problems.push(Problem::new(
                field,
                format!(
                    "域名写法无效（支持精确域名、*.后缀 通配或单个 *，不支持端口 / 路径 / @）：{domain}"
                ),
            ));
            continue;
        } else {
            domain.as_str()
        };
        let bad = body.is_empty()
            || body.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            });
        if bad {
            problems.push(Problem::new(
                field,
                format!(
                    "域名写法无效（支持精确域名、*.后缀 通配或单个 *，不支持端口 / 路径 / @）：{domain}"
                ),
            ));
        }
    }
}

fn validate_knock(
    field: &str,
    knock: Option<&str>,
    knock_available: bool,
    problems: &mut Vec<Problem>,
) {
    if let Some(key) = knock {
        if !knock_available {
            problems.push(Problem::new(field, "端口敲门模块未包含在此构建中"));
        }
        if key.chars().any(char::is_whitespace) {
            problems.push(Problem::new(field, "敲门规则标识不能包含空白"));
        }
    }
}

/// The effective connection caps of a rule: per-rule values win over the
/// module defaults; `0` means "half of the effective total" for the
/// per-source cap (at least 1). When a rule overrides `max_connections`
/// without setting `max_conns_per_source`, the per-source cap defaults to
/// half of the rule's own cap rather than inheriting the global default.
pub fn effective_limits(rule: &Rule, settings: &Settings) -> (u32, u32) {
    let max = if rule.max_connections != 0 {
        rule.max_connections
    } else if settings.default_max_connections != 0 {
        settings.default_max_connections
    } else {
        limits::DEFAULT_MAX_CONNECTIONS
    };
    let per_source = if rule.max_conns_per_source != 0 {
        rule.max_conns_per_source
    } else if rule.max_connections == 0 && settings.default_max_conns_per_source != 0 {
        settings.default_max_conns_per_source
    } else {
        (max / 2).max(1)
    };
    (max, per_source.min(max))
}

/// Parses `443,8443` or `8000-8010` into sorted, deduplicated ranges.
/// Port `0` is rejected.
pub fn parse_listen_ports(raw: &str) -> Result<Vec<(u16, u16)>, String> {
    let mut out = Vec::new();
    for part in raw.split([',', ';', ' ']) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (first, last) = match part.split_once('-') {
            Some((a, b)) => {
                let a: u16 = a.trim().parse().map_err(|_| part.to_owned())?;
                let b: u16 = b.trim().parse().map_err(|_| part.to_owned())?;
                if a == 0 || b == 0 {
                    return Err(part.to_owned());
                }
                (a.min(b), a.max(b))
            }
            None => {
                let port: u16 = part.parse().map_err(|_| part.to_owned())?;
                if port == 0 {
                    return Err(part.to_owned());
                }
                (port, port)
            }
        };
        out.push((first, last));
    }
    out.sort_unstable();
    let mut merged: Vec<(u16, u16)> = Vec::new();
    for (first, last) in out {
        match merged.last_mut() {
            // Overlapping or adjacent ranges merge.
            Some(range) if first <= range.1.saturating_add(1) => range.1 = range.1.max(last),
            _ => merged.push((first, last)),
        }
    }
    Ok(merged)
}

/// The canonical text for parsed listen-port ranges.
pub fn render_listen_ports(ranges: &[(u16, u16)]) -> String {
    ranges
        .iter()
        .map(|(first, last)| {
            if first == last {
                first.to_string()
            } else {
                format!("{first}-{last}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Parses a comma / space separated port list (default target).
pub fn parse_port_list(raw: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for part in raw.split([',', ';', ' ']) {
        if let Ok(port) = part.trim().parse::<u16>()
            && port != 0
            && !out.contains(&port)
        {
            out.push(port);
        }
    }
    out
}

/// Splits a legacy `host:port` target into host and optional port.
/// IPv6 literals must be bracketed to carry a port.
pub fn split_target(entry: &str) -> Option<(String, Option<u16>)> {
    let entry = entry.trim();
    if entry.is_empty() || entry.chars().any(char::is_whitespace) {
        return None;
    }
    if let Some(rest) = entry.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let host = host.trim();
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return None;
        }
        match after.strip_prefix(':') {
            Some(port) => Some((host.to_owned(), Some(port.parse().ok()?))),
            None if after.is_empty() => Some((host.to_owned(), None)),
            None => None,
        }
    } else if entry.parse::<std::net::Ipv6Addr>().is_ok() {
        Some((entry.to_owned(), None))
    } else {
        match entry.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() && host.find(':').is_none() => {
                Some((host.to_owned(), Some(port.parse().ok()?)))
            }
            _ => Some((entry.to_owned(), None)),
        }
    }
}

/// Whether a normalized entry is a host name or an IP literal.
pub fn is_host(entry: &str) -> bool {
    if entry.is_empty() {
        return false;
    }
    if entry.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    entry
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// Lower-cases a domain, strips trailing dots and converts non-ASCII
/// labels to punycode (`xn--`). `*` passes through untouched.
pub fn punycode_domain(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    if domain == "*" {
        return Some(domain);
    }
    if domain.is_empty() {
        return Some(String::new());
    }
    let mut out = Vec::new();
    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        if label.is_ascii() {
            out.push(label.to_owned());
        } else {
            out.push(format!("xn--{}", punycode_encode(label)?));
        }
    }
    Some(out.join("."))
}

// ---------------------------------------------------------------------------
// Punycode (RFC 3492) encoder: only the encoding direction is needed —
// domains in configuration arrive as Unicode and are stored as punycode.
// ---------------------------------------------------------------------------

const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 0x80;

fn digit(value: u32) -> char {
    match value {
        0..=25 => char::from(b'a' + value as u8),
        _ => char::from(b'0' + (value - 26) as u8),
    }
}

fn adapt(mut delta: u64, points: u64, first: bool) -> u32 {
    delta = if first {
        delta / u64::from(DAMP)
    } else {
        delta / 2
    };
    delta += delta / points;
    let mut k = 0u64;
    while delta > ((u64::from(BASE) - u64::from(TMIN)) * u64::from(TMAX)) / 2 {
        delta /= u64::from(BASE) - u64::from(TMIN);
        k += u64::from(BASE);
    }
    ((k + ((u64::from(BASE) - u64::from(TMIN) + 1) * delta) / (delta + u64::from(SKEW)))
        % u32::MAX as u64) as u32
}

/// Punycode-encodes one label (without the `xn--` prefix).
fn punycode_encode(label: &str) -> Option<String> {
    let chars: Vec<char> = label.chars().collect();
    let mut output: String = chars.iter().filter(|c| c.is_ascii()).collect();
    let basic = output.chars().count();
    if basic > 0 {
        output.push('-');
    }
    let mut code = INITIAL_N;
    let mut delta: u64 = 0;
    let mut bias = INITIAL_BIAS;
    let mut processed = basic;
    while processed < chars.len() {
        let next = chars
            .iter()
            .map(|c| u32::from(*c))
            .filter(|&cp| cp >= code)
            .min()?;
        delta += u64::from(next - code) * u64::try_from(processed + 1).ok()?;
        code = next;
        for &c in &chars {
            let cp = u32::from(c);
            if cp < code {
                delta += 1;
            }
            if cp == code {
                let mut q = delta;
                let mut k = TMIN;
                loop {
                    let threshold = if k <= bias {
                        TMIN
                    } else if k >= bias + TMAX {
                        TMAX
                    } else {
                        k - bias
                    };
                    if q < u64::from(threshold) {
                        break;
                    }
                    let rest = u64::from(BASE) - u64::from(threshold);
                    output.push(digit(
                        threshold + ((q - u64::from(threshold)) % rest) as u32,
                    ));
                    q = (q - u64::from(threshold)) / rest;
                    k += BASE;
                }
                output.push(digit(q as u32));
                bias = adapt(
                    delta,
                    u64::try_from(processed + 1).ok()?,
                    processed == basic,
                );
                delta = 0;
                processed += 1;
            }
        }
        delta += 1;
        code += 1;
    }
    Some(output)
}

/// Parses an IP address or `IP/prefix` CIDR entry.
pub fn parse_ip_or_cidr(entry: &str) -> Option<ipnet::IpNet> {
    if let Ok(net) = entry.parse::<ipnet::IpNet>() {
        return Some(net);
    }
    entry
        .parse::<std::net::IpAddr>()
        .ok()
        .map(ipnet::IpNet::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Net, ProxyProtocol};

    fn rule_with(routes: Vec<Route>) -> Rule {
        Rule {
            key: "abc123def456".into(),
            name: "shared 443".into(),
            protocols: vec![Net::Tcp],
            listen_address: "0.0.0.0".into(),
            listen_ports: "443".into(),
            routes,
            ..Rule::default()
        }
    }

    fn domain_route(name: &str, protocol: Protocol, domains: &[&str], alpn: &[&str]) -> Route {
        Route {
            name: name.into(),
            protocol,
            domains: domains.iter().map(|d| d.to_string()).collect(),
            alpn: alpn.iter().map(|a| a.to_string()).collect(),
            target_addresses: vec!["10.0.0.1".into()],
            target_port: 8000,
            ..Route::default()
        }
    }

    #[test]
    fn normalize_sniff_timeout_clamps_rounds_and_defaults() {
        assert_eq!(clamp_sniff_timeout(0.0), 5.0);
        assert_eq!(clamp_sniff_timeout(2.345), 2.3);
        assert_eq!(clamp_sniff_timeout(0.04), 0.1);
        assert_eq!(clamp_sniff_timeout(120.0), 60.0);
    }

    #[test]
    fn normalize_splits_legacy_host_port_default_targets() {
        let config = normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![Rule {
                key: "r1".into(),
                name: "r".into(),
                target_addresses: vec!["10.0.0.1:8443".into(), "10.0.0.2".into()],
                target_ports: "9443".into(),
                ..Rule::default()
            }],
        });
        assert_eq!(config.rules[0].target_addresses, ["10.0.0.1", "10.0.0.2"]);
        assert_eq!(config.rules[0].target_ports, "8443,9443");
    }

    #[test]
    fn normalize_domains_lowercase_punycode_and_dedupe() {
        let config = normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![rule_with(vec![domain_route(
                "a",
                Protocol::Tls,
                &["Bücher.Example.", "bücher.example", "example.com"],
                &[],
            )])],
        });
        assert_eq!(
            config.rules[0].routes[0].domains,
            ["example.com", "xn--bcher-kva.example"]
        );
    }

    #[test]
    fn normalize_listen_ports_canonicalizes() {
        let config = normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![Rule {
                key: "r1".into(),
                name: "r".into(),
                listen_ports: "8443,443,8000-8010".into(),
                ..Rule::default()
            }],
        });
        assert_eq!(config.rules[0].listen_ports, "443,8000-8010,8443");
    }

    #[test]
    fn validate_conflicts_among_enabled_routes_only() {
        let mut disabled = domain_route("backup", Protocol::Tls, &["a.example"], &[]);
        disabled.disabled = true;
        // One enabled TLS route for a.example plus disabled stand-ins: fine.
        let ok = rule_with(vec![
            domain_route("main", Protocol::Tls, &["a.example"], &[]),
            disabled,
        ]);
        assert!(
            validate(&normalize(FileConfig {
                settings: Settings::default(),
                rules: vec![ok],
            }))
            .is_empty()
        );
        // Two enabled routes for the same domain: conflict.
        let clash = rule_with(vec![
            domain_route("main", Protocol::Tls, &["a.example"], &[]),
            domain_route("second", Protocol::Tls, &["a.example"], &[]),
        ]);
        assert!(
            validate(&normalize(FileConfig {
                settings: Settings::default(),
                rules: vec![clash],
            }))
            .iter()
            .any(|p| p.field.ends_with(".routes"))
        );
    }

    #[test]
    fn validate_one_route_per_protocol_and_one_timeout() {
        let clash = rule_with(vec![
            domain_route("ssh1", Protocol::Ssh, &[], &[]),
            domain_route("ssh2", Protocol::Ssh, &[], &[]),
        ]);
        let problems = validate(&normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![clash],
        }));
        assert!(
            problems
                .iter()
                .any(|p| p.reason.contains("ssh") || p.reason.contains("一条")),
            "{problems:?}"
        );
        let timeout_clash = rule_with(vec![
            domain_route("wait1", Protocol::Timeout, &[], &[]),
            domain_route("wait2", Protocol::Timeout, &[], &[]),
        ]);
        assert!(
            validate(&normalize(FileConfig {
                settings: Settings::default(),
                rules: vec![timeout_clash],
            }))
            .iter()
            .any(|p| p.field.ends_with(".routes"))
        );
    }

    #[test]
    fn validate_rejects_port_path_at_in_domain() {
        for domain in [
            "a.example:443",
            "a.example/path",
            "a@b",
            "x.*.y",
            "*a.example",
        ] {
            let config = normalize(FileConfig {
                settings: Settings::default(),
                rules: vec![rule_with(vec![domain_route(
                    "d",
                    Protocol::Tls,
                    &[domain],
                    &[],
                )])],
            });
            assert!(
                validate(&config)
                    .iter()
                    .any(|p| p.field.ends_with(".domains")),
                "domain {domain} must be rejected"
            );
        }
    }

    #[test]
    fn validate_spa_route_cannot_require_knock() {
        let mut spa = domain_route("knock-in", Protocol::Spa, &[], &[]);
        spa.knock = Some("knock1".into());
        let config = normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![rule_with(vec![spa])],
        });
        assert!(validate(&config).iter().any(|p| p.reason.contains("spa")));
    }

    #[test]
    fn validate_default_target_needs_ports_when_set() {
        let mut rule = rule_with(vec![]);
        rule.target_addresses = vec!["10.0.0.1".into()];
        rule.target_ports = String::new();
        let problems = validate(&normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![rule.clone()],
        }));
        assert!(problems.iter().any(|p| p.field.ends_with(".targetPorts")));
        // Address list empty (drop-by-default) is fine.
        rule.target_addresses.clear();
        rule.target_ports = String::new();
        assert!(
            validate(&normalize(FileConfig {
                settings: Settings::default(),
                rules: vec![rule],
            }))
            .is_empty()
        );
    }

    #[test]
    fn effective_limits_fall_back_to_settings_and_halves() {
        let settings = Settings::default();
        let mut rule = rule_with(vec![]);
        let (max, per_source) = effective_limits(&rule, &settings);
        assert_eq!((max, per_source), (256, 128));
        rule.max_connections = 60;
        assert_eq!(effective_limits(&rule, &settings), (60, 30));
        let settings = Settings {
            default_max_connections: 100,
            default_max_conns_per_source: 20,
            ..Settings::default()
        };
        assert_eq!(effective_limits(&rule, &settings), (60, 30));
        rule.max_connections = 0;
        assert_eq!(effective_limits(&rule, &settings), (100, 20));
    }

    #[test]
    fn parse_listen_ports_ranges_merge_and_reject_zero() {
        assert_eq!(
            parse_listen_ports("443, 8443"),
            Ok(vec![(443, 443), (8443, 8443)])
        );
        assert_eq!(parse_listen_ports("8000-8010"), Ok(vec![(8000, 8010)]));
        assert_eq!(parse_listen_ports("10-2"), Ok(vec![(2, 10)]));
        assert_eq!(parse_listen_ports("443,444"), Ok(vec![(443, 444)]));
        assert!(parse_listen_ports("0").is_err());
        assert!(parse_listen_ports("abc").is_err());
        assert_eq!(
            render_listen_ports(&[(443, 444), (8010, 8010)]),
            "443-444,8010"
        );
    }

    #[test]
    fn split_target_handles_v6_and_ports() {
        assert_eq!(
            split_target("10.0.0.1:8443"),
            Some(("10.0.0.1".into(), Some(8443)))
        );
        assert_eq!(
            split_target("backend.local"),
            Some(("backend.local".into(), None))
        );
        assert_eq!(
            split_target("[2001:db8::1]:443"),
            Some(("2001:db8::1".into(), Some(443)))
        );
        assert_eq!(
            split_target("2001:db8::1"),
            Some(("2001:db8::1".into(), None))
        );
        assert_eq!(split_target("host:not-a-port"), None);
        assert_eq!(split_target("bad host"), None);
    }

    #[test]
    fn punycode_encodes_unicode_labels() {
        assert_eq!(
            punycode_domain("Bücher.Example.").as_deref(),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(
            punycode_domain(" example.com "),
            Some("example.com".to_owned())
        );
        assert_eq!(punycode_domain("*"), Some("*".to_owned()));
    }

    #[test]
    fn validate_route_without_target_is_collected() {
        let mut route = domain_route("empty", Protocol::Ssh, &[], &[]);
        route.target_addresses.clear();
        let config = normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![rule_with(vec![route])],
        });
        assert!(
            validate(&config)
                .iter()
                .any(|p| p.field.ends_with(".targetAddresses"))
        );
    }

    #[test]
    fn validate_proxy_protocol_round_trips() {
        let mut rule = rule_with(vec![]);
        rule.proxy_protocol = ProxyProtocol::V2;
        let text = serde_json::to_string(&rule).expect("serialize");
        assert!(text.contains("\"proxyProtocol\":\"v2\""));
        let back: Rule = serde_json::from_str(&text).expect("deserialize");
        assert_eq!(back.proxy_protocol, ProxyProtocol::V2);
    }
}
