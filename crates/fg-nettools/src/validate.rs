//! Validation and normalization (WP-71 §3.3/§3.4): pure functions over
//! plain data — no I/O, no network. Targets are hostnames or IPs; the deny
//! list from the settings is the only target policy (nettools exists to
//! probe internal networks too, so internal/loopback targets are classified
//! and reported, not rejected — WP-71 §8).

use std::net::{IpAddr, SocketAddr};

use ipnet::IpNet;
use serde::Serialize;

use crate::model::limits;

/// One validation problem, reported as `{"field":…,"reason":…}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Problem {
    pub field: String,
    pub reason: String,
}

/// Clamps and cleans the settings so every value is within the documented
/// bounds; values beyond a ceiling are pulled back to it.
pub fn normalize(mut config: crate::model::FileConfig) -> crate::model::FileConfig {
    let settings = &mut config.settings;
    settings.max_running = settings.max_running.clamp(1, limits::MAX_RUNNING_CEILING);
    settings.max_tasks = settings.max_tasks.clamp(1, limits::MAX_TASKS_CEILING);
    settings.max_task_lines = settings
        .max_task_lines
        .clamp(1, limits::MAX_TASK_LINES_CEILING);
    settings.task_timeout_seconds = settings.task_timeout_seconds.clamp(
        limits::TASK_TIMEOUT_MIN.as_secs(),
        limits::TASK_TIMEOUT_CEILING.as_secs(),
    );
    let mut deny: Vec<String> = settings
        .deny_list
        .iter()
        .map(|entry| entry.trim().to_lowercase())
        .filter(|entry| !entry.is_empty() && entry.len() <= limits::TARGET_MAX_CHARS)
        .collect();
    deny.truncate(limits::DENY_LIST_MAX);
    deny.dedup();
    settings.deny_list = deny;
    settings.default_speed_url = settings.default_speed_url.trim().to_owned();
    if settings.default_speed_url.len() > limits::URL_MAX_CHARS
        || !settings.default_speed_url.starts_with("http://")
            && !settings.default_speed_url.starts_with("https://")
    {
        settings.default_speed_url = limits::DEFAULT_SPEED_URL.to_owned();
    }
    config
}

/// Settings-level problems (applied after [`normalize`]: only what the
/// clamp cannot repair is reported).
pub fn validate(config: &crate::model::FileConfig) -> Vec<Problem> {
    let mut problems = Vec::new();
    for entry in &config.settings.deny_list {
        if parse_deny_entry(entry).is_none() {
            problems.push(Problem {
                field: "denyList".into(),
                reason: format!("无法识别的条目 {entry}（应为 IP、CIDR 或主机名）"),
            });
        }
    }
    let url = &config.settings.default_speed_url;
    if url.parse::<hyper::Uri>().is_err() {
        problems.push(Problem {
            field: "defaultSpeedUrl".into(),
            reason: "不是有效的 URL".into(),
        });
    }
    problems
}

/// Whether `text` is an acceptable target for the tools: an IPv4/IPv6
/// address or a hostname (RFC 1123 labels, optional trailing dot). A
/// dotted quad that fails the IP parse is rejected as a typo rather than
/// passed on as a hostname.
pub fn valid_target(text: &str) -> bool {
    if text.len() > limits::TARGET_MAX_CHARS || text.is_empty() {
        return false;
    }
    if text.parse::<IpAddr>().is_ok() {
        return true;
    }
    let bare = text.strip_suffix('.').unwrap_or(text);
    let labels = bare.split('.').collect::<Vec<_>>();
    // All-numeric names ("999.1.1.1", "1.2.3") never resolve — treat them
    // as typos instead of hostnames.
    if labels.len() > 1
        && labels
            .iter()
            .all(|label| !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    valid_hostname(text)
}

/// RFC 1123 hostname check (labels of alphanumerics and hyphens, no
/// leading/trailing hyphen, at most 63 bytes per label; a single trailing
/// dot marks an FQDN).
pub fn valid_hostname(text: &str) -> bool {
    let name = text.strip_suffix('.').unwrap_or(text);
    !name.is_empty() && name.split('.').all(valid_label)
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// Where a target address sits; shown in tool output, never a rejection
/// (diagnostics are meant to reach internal networks too).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetClass {
    Loopback,
    Private,
    LinkLocal,
    Cgnat,
    UniqueLocal,
    Public,
}

impl TargetClass {
    /// Chinese label used in task output lines.
    pub fn label(self) -> &'static str {
        match self {
            Self::Loopback => "回环",
            Self::Private => "内网",
            Self::LinkLocal => "链路本地",
            Self::Cgnat => "运营商级 NAT",
            Self::UniqueLocal => "内网（IPv6 ULA）",
            Self::Public => "公网",
        }
    }
}

/// Classifies an address. Uses `fg_net`'s internal-address predicate so the
/// classification agrees with the rest of the stack.
pub fn classify(ip: IpAddr) -> TargetClass {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                TargetClass::Loopback
            } else if v4.is_link_local() {
                TargetClass::LinkLocal
            } else if v4.is_private() {
                TargetClass::Private
            } else if fg_net::client_addr::is_cgnat(v4) {
                TargetClass::Cgnat
            } else {
                TargetClass::Public
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                TargetClass::Loopback
            } else if v6.is_unicast_link_local() {
                TargetClass::LinkLocal
            } else if v6.is_unique_local() {
                TargetClass::UniqueLocal
            } else {
                TargetClass::Public
            }
        }
    }
}

/// Parses `22,80,443,8000-8100` into a sorted, de-duplicated port list with
/// at most `max` entries (WP-71 §3.4: 1024 for one port-probe run).
pub fn parse_ports(spec: &str, max: usize) -> Result<Vec<u16>, PortsError> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(PortsError::Empty);
    }
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let range = part.split_once('-');
        let (start, end) = match range {
            Some((start, end)) => {
                let start: u16 = start
                    .trim()
                    .parse()
                    .map_err(|_| PortsError::Invalid(part.to_owned()))?;
                let end: u16 = end
                    .trim()
                    .parse()
                    .map_err(|_| PortsError::Invalid(part.to_owned()))?;
                (start, end)
            }
            None => {
                let port: u16 = part
                    .parse()
                    .map_err(|_| PortsError::Invalid(part.to_owned()))?;
                (port, port)
            }
        };
        if start == 0 || end < start {
            return Err(PortsError::Invalid(part.to_owned()));
        }
        for port in start..=end {
            if ports.contains(&port) {
                continue;
            }
            ports.push(port);
            if ports.len() > max {
                return Err(PortsError::TooMany);
            }
        }
    }
    if ports.is_empty() {
        return Err(PortsError::Empty);
    }
    ports.sort_unstable();
    Ok(ports)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortsError {
    Empty,
    Invalid(String),
    TooMany,
}

impl std::fmt::Display for PortsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "端口列表为空"),
            Self::Invalid(part) => write!(f, "无法识别的端口或范围 {part:?}"),
            Self::TooMany => write!(
                f,
                "端口数量超过上限 {}（一次最多 {} 个）",
                limits::PORT_PROBE_MAX_PORTS,
                limits::PORT_PROBE_MAX_PORTS
            ),
        }
    }
}

/// A DNS server from the `server` parameter: `IP`, `IP:端口` or a DoH URL
/// (`https://dns.alidns.com/dns-query`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerSpec {
    Udp(SocketAddr),
    Doh(String),
}

/// Parses the server parameter. A bare IP gets port 53; `IP:port` keeps the
/// port; `http(s)://…` is taken as a DoH endpoint.
pub fn parse_server(text: &str) -> Result<ServerSpec, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("DNS 服务器为空".into());
    }
    if text.starts_with("http://") || text.starts_with("https://") {
        let uri: hyper::Uri = text
            .parse()
            .map_err(|_| format!("无法解析 DoH 地址 {text}"))?;
        let host = uri
            .host()
            .ok_or_else(|| format!("DoH 地址缺少主机 {text}"))?;
        if host.parse::<IpAddr>().is_err() && !valid_hostname(host) {
            return Err(format!("DoH 地址的主机名无效 {host}"));
        }
        if text.len() > limits::URL_MAX_CHARS {
            return Err("DoH 地址过长".into());
        }
        return Ok(ServerSpec::Doh(text.to_owned()));
    }
    if text.parse::<IpAddr>().is_ok() {
        return Ok(ServerSpec::Udp(SocketAddr::new(
            text.parse().expect("checked"),
            53,
        )));
    }
    if let Some((host, port)) = text.rsplit_once(':') {
        let port: u16 = port.parse().map_err(|_| format!("无法识别的端口 {port}"))?;
        let host = host.trim_matches(|c| c == '[' || c == ']');
        let ip: IpAddr = host
            .parse()
            .map_err(|_| format!("DNS 服务器应为 IP、IP:端口 或 DoH 地址 {text}"))?;
        return Ok(ServerSpec::Udp(SocketAddr::new(ip, port)));
    }
    Err(format!("DNS 服务器应为 IP、IP:端口 或 DoH 地址 {text}"))
}

/// One settings `denyList` entry: a single IP, a CIDR or a hostname.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DenyEntry {
    Ip(IpAddr),
    Net(IpNet),
    Host(String),
}

/// Parses a deny-list entry; `None` when the text fits none of the shapes.
pub fn parse_deny_entry(text: &str) -> Option<DenyEntry> {
    let text = text.trim().to_lowercase();
    if text.is_empty() {
        return None;
    }
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Some(DenyEntry::Ip(ip));
    }
    if let Ok(net) = text.parse::<IpNet>() {
        return Some(DenyEntry::Net(net));
    }
    if valid_hostname(&text) {
        return Some(DenyEntry::Host(
            text.strip_suffix('.').unwrap_or(&text).to_owned(),
        ));
    }
    None
}

/// Compiles the settings list into matchable entries (invalid entries are
/// dropped — the settings validator reports them separately).
pub fn parse_deny_list(entries: &[String]) -> Vec<DenyEntry> {
    entries
        .iter()
        .map(String::as_str)
        .filter_map(parse_deny_entry)
        .collect()
}

/// Whether a run may proceed. `target` is the raw user input (matched
/// against hostname entries), `resolved` the addresses the target resolved
/// to (matched against IP and CIDR entries). Returns the refusal reason.
pub fn deny_reason(target: &str, resolved: &[IpAddr], entries: &[DenyEntry]) -> Option<String> {
    let target = target.trim().to_lowercase();
    let target = target.strip_suffix('.').unwrap_or(&target);
    for entry in entries {
        match entry {
            DenyEntry::Ip(ip) => {
                if resolved.contains(ip) {
                    return Some(format!("目标在拒绝列表中（{ip}）"));
                }
            }
            DenyEntry::Net(net) => {
                if resolved.iter().any(|ip| net.contains(ip)) {
                    return Some(format!("目标在拒绝列表中（{net}）"));
                }
            }
            DenyEntry::Host(host) => {
                if target == host {
                    return Some(format!("目标在拒绝列表中（{host}）"));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_target_accepts_ips_and_hostnames_rejects_bad() {
        for good in [
            "127.0.0.1",
            "::1",
            "8.8.8.8",
            "example.com",
            "example.com.",
            "sub.domain-1.example",
            "a.de",
        ] {
            assert!(valid_target(good), "{good} should be valid");
        }
        for bad in [
            "",
            "-bad.example",
            "bad-.example",
            "under_score.example",
            "double..dot",
            "bad ip",
            "999.1.1.1",
            "1.2.3",
        ] {
            assert!(!valid_target(bad), "{bad} should be invalid");
        }
        let long_label = "a".repeat(64);
        assert!(!valid_target(&long_label));
        // Total length cap of 253 with 63-byte labels.
        let full = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert_eq!(full.len(), 253);
        assert!(valid_target(&full));
        assert!(!valid_target(&format!("{full}x")));
    }

    #[test]
    fn parse_ports_handles_ranges_dedup_and_caps() {
        let ports =
            parse_ports("22,80,443,8000-8100", limits::PORT_PROBE_MAX_PORTS).expect("parse ports");
        assert_eq!(ports.len(), 104);
        assert_eq!(ports[0], 22);
        assert_eq!(ports[2], 443);
        assert_eq!(ports[3], 8000);
        assert_eq!(ports.last(), Some(&8100));
        let dupes = parse_ports("80,80,81-83,82", 10).expect("dupes");
        assert_eq!(dupes, vec![80, 81, 82, 83]);
        assert_eq!(parse_ports("", 10), Err(PortsError::Empty));
        assert_eq!(
            parse_ports("a,80", 10),
            Err(PortsError::Invalid("a".into()))
        );
        assert_eq!(
            parse_ports("9000-8000", 10),
            Err(PortsError::Invalid("9000-8000".into()))
        );
        assert_eq!(parse_ports("0", 10), Err(PortsError::Invalid("0".into())));
        assert_eq!(parse_ports("1-2000", 1024), Err(PortsError::TooMany));
    }

    #[test]
    fn parse_server_accepts_ip_port_and_doh() {
        assert_eq!(
            parse_server("8.8.8.8"),
            Ok(ServerSpec::Udp("8.8.8.8:53".parse().expect("addr")))
        );
        assert_eq!(
            parse_server("[2001:db8::1]:5353"),
            Ok(ServerSpec::Udp("[2001:db8::1]:5353".parse().expect("addr")))
        );
        assert_eq!(
            parse_server("2001:db8::1"),
            Ok(ServerSpec::Udp("[2001:db8::1]:53".parse().expect("addr")))
        );
        assert_eq!(
            parse_server("https://dns.alidns.com/dns-query"),
            Ok(ServerSpec::Doh("https://dns.alidns.com/dns-query".into()))
        );
        assert!(parse_server("example.com").is_err());
        assert!(parse_server("ftp://x").is_err());
        assert!(parse_server("https://bad_host").is_err());
    }

    #[test]
    fn classify_labels_internal_and_public() {
        assert_eq!(
            classify("127.0.0.1".parse().unwrap()),
            TargetClass::Loopback
        );
        assert_eq!(classify("10.1.2.3".parse().unwrap()), TargetClass::Private);
        assert_eq!(
            classify("169.254.9.9".parse().unwrap()),
            TargetClass::LinkLocal
        );
        assert_eq!(classify("100.64.0.1".parse().unwrap()), TargetClass::Cgnat);
        assert_eq!(
            classify("fd00::5".parse().unwrap()),
            TargetClass::UniqueLocal
        );
        assert_eq!(
            classify("203.0.113.9".parse().unwrap()),
            TargetClass::Public
        );
        assert_eq!(
            classify("2606:4700::1".parse().unwrap()),
            TargetClass::Public
        );
        assert!(fg_net::client_addr::is_internal(
            "192.168.0.1".parse().unwrap()
        ));
    }

    #[test]
    fn deny_reason_matches_ips_cidrs_and_hosts() {
        let entries = parse_deny_list(&[
            "192.168.1.10".into(),
            "10.0.0.0/8".into(),
            "forbidden.example".into(),
        ]);
        assert!(
            deny_reason("192.168.1.10", &["192.168.1.10".parse().unwrap()], &entries).is_some()
        );
        assert!(deny_reason("10.9.9.9", &["10.9.9.9".parse().unwrap()], &entries).is_some());
        assert!(deny_reason("FORBIDDEN.example", &[], &entries).is_some());
        assert!(deny_reason("forbidden.example.", &[], &entries).is_some());
        assert!(deny_reason("other.example", &["8.8.8.8".parse().unwrap()], &entries).is_none());
        assert!(deny_reason("11.0.0.1", &["11.0.0.1".parse().unwrap()], &entries).is_none());
        // A hostname that resolves into a denied CIDR is refused too.
        assert!(
            deny_reason("internal.example", &["10.1.1.1".parse().unwrap()], &entries).is_some()
        );
    }

    #[test]
    fn normalize_clamps_settings_and_cleans_deny_list() {
        let mut config = crate::model::FileConfig::default();
        config.settings.max_running = 999;
        config.settings.max_tasks = 0;
        config.settings.max_task_lines = 0;
        config.settings.task_timeout_seconds = 1;
        config.settings.deny_list = vec![" 10.0.0.0/8 ".into(), "".into(), "10.0.0.0/8".into()];
        config.settings.default_speed_url = "not a url".into();
        let normalized = normalize(config);
        assert_eq!(normalized.settings.max_running, limits::MAX_RUNNING_CEILING);
        assert_eq!(normalized.settings.max_tasks, 1);
        assert_eq!(normalized.settings.max_task_lines, 1);
        assert_eq!(
            normalized.settings.task_timeout_seconds,
            limits::TASK_TIMEOUT_MIN.as_secs()
        );
        assert_eq!(normalized.settings.deny_list, vec!["10.0.0.0/8".to_owned()]);
        assert_eq!(
            normalized.settings.default_speed_url,
            limits::DEFAULT_SPEED_URL
        );
    }
}
