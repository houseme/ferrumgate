//! IP acquisition (WP-40 §3.3): extract/pick helpers over plain text,
//! the three source kinds (`url`, `netInterface`, `command`) and the
//! replacement table for retired public-IP query services.
//!
//! The `url` source dials the requested address family only: the host is
//! resolved first and the request is pinned (reqwest `resolve`) to an
//! address of the requested family, so an IPv4 query can never return the
//! IPv6 egress address (and vice versa) while TLS still verifies the
//! hostname. When `fg-net` gains the shared `OutboundHttp`/`ip_source`
//! support crate, this module moves there unchanged (WP-40 steps 1-3).

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use crate::model::{IpSource, IpSourceKind, limits};

/// Address family of a source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn as_str(self) -> &'static str {
        match self {
            Family::V4 => "ipv4",
            Family::V6 => "ipv6",
        }
    }
}

impl std::fmt::Display for Family {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Upstream default IPv4 query services (public, user-visible and
/// user-replaceable; never add a project-owned address here).
pub const DEFAULT_IPV4_URLS: &[&str] = &[
    "https://ipv4.ddnspod.com",
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
    "https://myip.ipip.net",
];

/// Upstream default IPv6 query services.
pub const DEFAULT_IPV6_URLS: &[&str] = &[
    "https://ipv6.ddnspod.com",
    "https://api6.ipify.org",
    "https://ipv6.icanhazip.com",
    "https://v6.ident.me",
];

/// Query services that stopped resolving (or changed hands) and their
/// replacements, taken from the default lists. Keyed by full URL prefix;
/// matches are prefix matches so `https://ipw.cn/…` variants are caught.
const RETIRED_URLS: &[(&str, &str)] = &[
    ("https://ipw.cn", "https://api.ipify.org"),
    ("https://4.ipw.cn", "https://api.ipify.org"),
    ("https://v4.ipw.cn", "https://api.ipify.org"),
    ("https://6.ipw.cn", "https://api6.ipify.org"),
    ("https://v6.ipw.cn", "https://api6.ipify.org"),
];

/// Replaces retired query URLs; returns the cleaned list and whether
/// anything changed (the caller logs it).
pub fn replace_retired_urls(urls: &[String]) -> (Vec<String>, bool) {
    let mut replaced = Vec::with_capacity(urls.len());
    let mut changed = false;
    let mut seen = HashSet::new();
    for url in urls {
        let mut url = url.trim().to_owned();
        for (retired, substitute) in RETIRED_URLS {
            if url == *retired
                || url
                    .strip_prefix(retired)
                    .is_some_and(|rest| rest.starts_with('/'))
            {
                tracing::warn!(
                    retired = %url,
                    substitute = %substitute,
                    "已停用的公网 IP 查询地址，已自动替换为替代地址"
                );
                url = (*substitute).to_owned();
                changed = true;
                break;
            }
        }
        if url.is_empty() || !seen.insert(url.clone()) {
            changed = changed || !url.is_empty();
            continue;
        }
        replaced.push(url);
    }
    (replaced, changed)
}

/// Extracts addresses of the requested family from arbitrary text
/// (HTML pages, `current IP: 1.2.3.4`, JSON, …), keeping the order of
/// appearance and deduplicating. Runs of hex/colon/dot characters are
/// parsed as addresses; a trailing `.` (sentence punctuation) is trimmed
/// and IPv4-mapped IPv6 addresses count as their embedded IPv4 address.
pub fn extract(text: &str, fam: Family) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let is_start = bytes[index].is_ascii_hexdigit() || bytes[index] == b':';
        if !is_start {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len()
            && (bytes[index].is_ascii_hexdigit() || matches!(bytes[index], b':' | b'.'))
        {
            index += 1;
        }
        let run = text[start..index].trim_end_matches('.');
        let Ok(ip) = run.parse::<IpAddr>() else {
            continue;
        };
        let ip = ip.to_canonical();
        if family_of(ip) == fam && !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

fn family_of(ip: IpAddr) -> Family {
    match ip {
        IpAddr::V4(_) => Family::V4,
        IpAddr::V6(_) => Family::V6,
    }
}

/// Upstream `IsPublic`: excludes loopback, link-local, private ranges,
/// IPv6 ULA, CGNAT, unspecified, multicast and documentation ranges.
/// IPv4-mapped IPv6 addresses are judged by their embedded IPv4 address.
pub fn is_public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(v4: Ipv4Addr) -> bool {
    !(v4.is_unspecified()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_private()
        || v4.is_broadcast()
        || v4.is_multicast()
        || v4.is_documentation()
        // CGNAT 100.64/10 (std has no helper for the shared range).
        || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
        // Benchmarking 198.18/15.
        || (v4.octets()[0] == 198 && matches!(v4.octets()[1], 18 | 19))
        // Limited broadcast style reserved blocks up to 240/4.
        || v4.octets()[0] >= 240)
}

fn is_public_v6(v6: Ipv6Addr) -> bool {
    !(v6.is_unspecified()
        || v6.is_loopback()
        // fe80::/10 link-local.
        || (v6.segments()[0] & 0xffc0) == 0xfe80
        // fc00::/7 unique local.
        || (v6.segments()[0] & 0xfe00) == 0xfc00
        || v6.is_multicast()
        // 2001:db8::/32 documentation.
        || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8)
        // ::ffff:0:0/96 falls through `to_canonical` only for mapped
        // addresses handled above; discard remaining IPv4-translated ranges.
        || (v6.segments()[0] == 0 && v6.segments()[1] == 0 && v6.segments()[2] == 0
            && v6.segments()[3] == 0 && v6.segments()[4] == 0xffff))
}

/// Why [`pick`] found no usable candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PickError {
    /// No candidate address in the requested family.
    NoFamilyMatch,
    /// Candidates exist but none passed the regex.
    NoRegexMatch,
    /// Candidates exist but none is public (no regex configured).
    NoPublicAddress,
}

impl std::fmt::Display for PickError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PickError::NoFamilyMatch => write!(f, "候选地址中没有该协议栈的地址"),
            PickError::NoRegexMatch => write!(f, "候选地址没有匹配筛选正则"),
            PickError::NoPublicAddress => write!(f, "候选地址中没有公网地址"),
        }
    }
}

/// Candidate selection: with a non-empty `regex` the first regex match
/// wins (private addresses allowed on purpose); otherwise the first
/// public address is preferred.
pub fn pick(
    cands: &[IpAddr],
    fam: Family,
    regex: Option<&regex::Regex>,
) -> Result<IpAddr, PickError> {
    let mut in_family = cands.iter().copied().filter(|ip| family_of(*ip) == fam);
    if let Some(regex) = regex {
        return in_family
            .find(|ip| regex.is_match(&ip.to_string()))
            .ok_or(PickError::NoRegexMatch);
    }
    let has_family = cands.iter().any(|ip| family_of(*ip) == fam);
    in_family.find(|ip| is_public(*ip)).ok_or(if has_family {
        PickError::NoPublicAddress
    } else {
        PickError::NoFamilyMatch
    })
}

/// Why an IP source failed this round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceError {
    /// `url` source: no URL configured or all failed.
    Url(String),
    /// `netInterface` source: unknown interface or no usable address.
    Interface(String),
    /// `command` source: failed, timed out or no address in the output.
    Command(String),
    /// Regex configured for the source does not compile.
    Regex(String),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceError::Url(detail) => write!(f, "URL 查询失败：{detail}"),
            SourceError::Interface(detail) => write!(f, "网卡地址获取失败：{detail}"),
            SourceError::Command(detail) => write!(f, "命令执行失败：{detail}"),
            SourceError::Regex(detail) => write!(f, "正则无效：{detail}"),
        }
    }
}

/// Compiled source filter, shared by all source kinds.
pub struct SourceFilter {
    regex: Option<regex::Regex>,
}

impl SourceFilter {
    /// Compiles `source.regex`; an invalid regex is reported instead of
    /// silently matching nothing.
    pub fn new(source: &IpSource) -> Result<Self, SourceError> {
        let regex = if source.regex.trim().is_empty() {
            None
        } else {
            Some(
                regex::Regex::new(source.regex.trim())
                    .map_err(|error| SourceError::Regex(error.to_string()))?,
            )
        };
        Ok(Self { regex })
    }
}

/// Runs one IP source; the family decides which addresses are considered.
pub async fn get(
    source: &IpSource,
    fam: Family,
    timeout: Duration,
    filter: &SourceFilter,
) -> Result<IpAddr, SourceError> {
    match source.kind {
        IpSourceKind::Url => from_urls(source, fam, timeout, filter).await,
        IpSourceKind::NetInterface => from_interface(source, fam, filter),
        IpSourceKind::Command => from_command(source, fam, timeout, filter).await,
    }
}

async fn from_urls(
    source: &IpSource,
    fam: Family,
    timeout: Duration,
    filter: &SourceFilter,
) -> Result<IpAddr, SourceError> {
    let mut last_error = String::from("没有配置查询地址");
    for url in source
        .urls
        .iter()
        .map(|url| url.trim())
        .filter(|url| !url.is_empty())
    {
        match fetch_url(url, fam, timeout).await {
            Ok(text) => {
                let cands = extract(&text, fam);
                match pick(&cands, fam, filter.regex.as_ref()) {
                    Ok(ip) => return Ok(ip),
                    Err(error) => last_error = format!("{url}: {error}"),
                }
            }
            Err(error) => last_error = format!("{url}: {error}"),
        }
    }
    Err(SourceError::Url(last_error))
}

/// Fetches one query URL with family-forced dialing: the host is resolved,
/// only addresses of the requested family are dialed.
async fn fetch_url(url: &str, fam: Family, timeout: Duration) -> Result<String, String> {
    let uri: url::Url = url::Url::parse(url).map_err(|error| error.to_string())?;
    let host = uri
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| "URL 缺少主机名".to_owned())?
        .to_owned();
    let port = uri
        .port_or_known_default()
        .ok_or_else(|| "URL 缺少端口".to_owned())?;
    let pinned = resolve_pinned(&host, port, fam).await?;
    let client = reqwest::Client::builder()
        .connect_timeout(limits::IP_DIAL_TIMEOUT)
        .timeout(timeout)
        // The query service is pinned to one address; never follow a
        // redirect to another host (family pinning would be lost).
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host, pinned)
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    let text = response.text().await.map_err(|error| error.to_string())?;
    Ok(text)
}

async fn resolve_pinned(host: &str, port: u16, fam: Family) -> Result<SocketAddr, String> {
    // A literal IP host skips DNS; the family filter still applies.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if family_of(ip) == fam {
            return Ok(SocketAddr::new(ip, port));
        }
        return Err(format!("地址 {host} 不是 {fam} 地址"));
    }
    let mut addrs = tokio::net::lookup_host((host.to_owned(), port))
        .await
        .map_err(|error| format!("解析 {host} 失败：{error}"))?
        .filter(|addr| family_of(addr.ip()) == fam);
    addrs
        .next()
        .ok_or_else(|| format!("{host} 没有可拨号的 {fam} 地址"))
}

fn from_interface(
    source: &IpSource,
    fam: Family,
    filter: &SourceFilter,
) -> Result<IpAddr, SourceError> {
    let interface = source.interface.trim();
    if interface.is_empty() {
        return Err(SourceError::Interface("未指定网卡名称".to_owned()));
    }
    let mut cands = Vec::new();
    match if_addrs::get_if_addrs() {
        Ok(interfaces) => {
            for iface in interfaces {
                if iface.name != interface {
                    continue;
                }
                cands.push(iface.ip());
            }
        }
        Err(error) => return Err(SourceError::Interface(error.to_string())),
    }
    pick(&cands, fam, filter.regex.as_ref()).map_err(|error| match error {
        PickError::NoRegexMatch | PickError::NoFamilyMatch | PickError::NoPublicAddress => {
            SourceError::Interface(format!("{interface}: {error}"))
        }
    })
}

async fn from_command(
    source: &IpSource,
    fam: Family,
    timeout: Duration,
    filter: &SourceFilter,
) -> Result<IpAddr, SourceError> {
    let command = source.command.trim();
    if command.is_empty() {
        return Err(SourceError::Command("未配置命令".to_owned()));
    }
    let timeout = timeout.min(limits::COMMAND_TIMEOUT_MAX);
    let mut child = tokio::process::Command::new(if cfg!(windows) { "cmd" } else { "sh" })
        .args(if cfg!(windows) {
            ["/C", command]
        } else {
            ["-c", command]
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| SourceError::Command(error.to_string()))?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let read = async {
        let mut buf = Vec::with_capacity(1024);
        let mut chunk = [0u8; 4096];
        use tokio::io::AsyncReadExt;
        loop {
            if buf.len() >= limits::COMMAND_OUTPUT_MAX_BYTES {
                break;
            }
            let chunk_len = chunk.len();
            let room = (limits::COMMAND_OUTPUT_MAX_BYTES - buf.len()).min(chunk_len);
            let read = stdout.read(&mut chunk[..room]).await;
            match read {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        buf
    };
    let output = match tokio::time::timeout(timeout, read).await {
        Ok(buf) => buf,
        Err(_) => {
            let _ = child.start_kill();
            return Err(SourceError::Command(format!(
                "命令超过 {} 秒未结束，已终止",
                timeout.as_secs()
            )));
        }
    };
    // Reap the child so it does not linger.
    let _ = tokio::time::timeout(Duration::from_millis(200), child.wait()).await;
    let text = String::from_utf8_lossy(&output);
    let cands = extract(&text, fam);
    pick(&cands, fam, filter.regex.as_ref())
        .map_err(|error| SourceError::Command(format!("输出中没有可用地址：{error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter()
            .map(|text| text.parse::<IpAddr>().expect("ip"))
            .collect()
    }

    #[test]
    fn extract_keeps_order_and_dedups() {
        let text = "IPv4: 1.2.3.4, IPv6: 2001:db8::1, again 1.2.3.4 and 2001:0DB8:0000:0000:0000:0000:0000:0001";
        assert_eq!(extract(text, Family::V4), ips(&["1.2.3.4"]));
        assert_eq!(
            extract(text, Family::V6),
            ips(&["2001:db8::1"]),
            "expanded upper-case form is the same address, deduplicated"
        );
        assert!(extract("no addresses here", Family::V4).is_empty());
        // Junk runs that merely look address-like stay out.
        assert!(extract("deadbeef :::", Family::V6).is_empty());
    }

    #[test]
    fn is_public_excludes_special_ranges() {
        let excluded = [
            "127.0.0.1",       // loopback
            "10.0.0.5",        // RFC1918
            "172.16.9.9",      // RFC1918
            "192.168.1.1",     // RFC1918
            "169.254.1.2",     // link-local
            "100.64.0.1",      // CGNAT
            "100.127.255.255", // CGNAT top
            "0.0.0.0",         // unspecified
            "224.0.0.1",       // multicast
            "255.255.255.255", // broadcast
            "192.0.2.9",       // documentation
            "198.18.0.9",      // benchmarking
            "240.0.0.1",       // reserved
            "::1",             // loopback
            "::",              // unspecified
            "fe80::9",         // link-local
            "fc00::9",         // ULA
            "fd12:3456::9",    // ULA
            "ff02::1",         // multicast
            "2001:db8::9",     // documentation
        ];
        for text in excluded {
            let ip: IpAddr = text.parse().expect("ip");
            assert!(!is_public(ip), "{text} should not be public");
        }
        let included = [
            "1.2.3.4",
            "203.0.114.9",
            "2001:4860:4860::8888",
            "2620:fe::fe",
        ];
        for text in included {
            let ip: IpAddr = text.parse().expect("ip");
            assert!(is_public(ip), "{text} should be public");
        }
        // 100.128/17 is outside CGNAT and stays public.
        assert!(is_public("100.128.0.1".parse().expect("ip")));
    }

    #[test]
    fn pick_prefers_public_unless_regex() {
        let cands = ips(&["192.168.1.10", "fe80::1", "1.2.3.4", "2606:4700::10"]);
        assert_eq!(
            pick(&cands, Family::V4, None),
            Ok("1.2.3.4".parse().unwrap())
        );
        assert_eq!(
            pick(&cands, Family::V6, None),
            Ok("2606:4700::10".parse().unwrap())
        );
        // Regex decides alone: a private address may be chosen on purpose.
        let regex = regex::Regex::new(r"^192\.168\.").expect("regex");
        assert_eq!(
            pick(&cands, Family::V4, Some(&regex)),
            Ok("192.168.1.10".parse().unwrap())
        );
        let no_v6 = ips(&["1.2.3.4"]);
        assert_eq!(
            pick(&no_v6, Family::V6, None),
            Err(PickError::NoFamilyMatch)
        );
        assert_eq!(
            pick(&ips(&["10.0.0.9"]), Family::V4, None),
            Err(PickError::NoPublicAddress)
        );
    }

    #[test]
    fn replace_retired_urls_swaps_and_dedups() {
        let (out, changed) = replace_retired_urls(&[
            "https://4.ipw.cn".into(),
            " https://api.ipify.org ".into(),
            "https://6.ipw.cn/sub".into(),
            "https://api.ipify.org".into(),
            "".into(),
        ]);
        assert!(changed);
        assert_eq!(out, ["https://api.ipify.org", "https://api6.ipify.org"]);
        let (out, changed) = replace_retired_urls(&["https://ipv4.ddnspod.com".into()]);
        assert!(!changed);
        assert_eq!(out, ["https://ipv4.ddnspod.com"]);
    }

    #[test]
    fn interface_source_filters_by_regex() {
        let source = IpSource {
            enable: true,
            kind: IpSourceKind::NetInterface,
            interface: "no-such-interface".into(),
            ..IpSource::default()
        };
        let filter = SourceFilter::new(&source).expect("filter");
        let error = from_interface(&source, Family::V4, &filter).expect_err("missing interface");
        assert!(matches!(error, SourceError::Interface(_)), "{error}");

        // The loopback interface exists on every supported platform, but
        // its name differs per OS (lo / lo0). The contract: without a
        // regex a loopback address is refused as not public; with a
        // regex matching any address it is chosen on purpose.
        let name = if_addrs::get_if_addrs()
            .expect("interfaces")
            .into_iter()
            .find(|iface| iface.ip().is_loopback())
            .map(|iface| iface.name)
            .expect("loopback interface");
        let source = IpSource {
            enable: true,
            kind: IpSourceKind::NetInterface,
            interface: name.clone(),
            ..IpSource::default()
        };
        let filter = SourceFilter::new(&source).expect("filter");
        assert!(matches!(
            from_interface(&source, Family::V4, &filter),
            Err(SourceError::Interface(_))
        ));
        let source = IpSource {
            regex: r".+".into(),
            ..source
        };
        let filter = SourceFilter::new(&source).expect("filter");
        let ip = from_interface(&source, Family::V4, &filter).expect("regex overrides public");
        assert!(matches!(ip, IpAddr::V4(_)), "{ip}");
        let _ = name;
    }

    #[tokio::test]
    async fn command_source_extracts_ip_with_timeout() {
        let source = IpSource {
            enable: true,
            kind: IpSourceKind::Command,
            command: "printf 'addr 9.9.9.9 extra'".into(),
            ..IpSource::default()
        };
        let filter = SourceFilter::new(&source).expect("filter");
        let ip = from_command(&source, Family::V4, Duration::from_secs(5), &filter)
            .await
            .expect("address");
        assert_eq!(ip, "9.9.9.9".parse::<IpAddr>().expect("ip"));

        // Output far beyond the cap is truncated (the address must be
        // within the readable window).
        let long = IpSource {
            enable: true,
            kind: IpSourceKind::Command,
            command: "printf 'addr 8.8.8.8 '; head -c 200000 /dev/zero | tr '\\0' 'x'".into(),
            ..IpSource::default()
        };
        let filter = SourceFilter::new(&long).expect("filter");
        let ip = from_command(&long, Family::V4, Duration::from_secs(10), &filter)
            .await
            .expect("address within the capped window");
        assert_eq!(ip, "8.8.8.8".parse::<IpAddr>().expect("ip"));

        // A sleeping command is killed at the timeout.
        let slow = IpSource {
            enable: true,
            kind: IpSourceKind::Command,
            command: "sleep 5; echo 1.2.3.4".into(),
            ..IpSource::default()
        };
        let filter = SourceFilter::new(&slow).expect("filter");
        let started = std::time::Instant::now();
        let error = from_command(&slow, Family::V4, Duration::from_millis(300), &filter)
            .await
            .expect_err("timeout");
        assert!(matches!(error, SourceError::Command(_)), "{error}");
        assert!(started.elapsed() < Duration::from_secs(3), "was killed");
    }

    #[tokio::test]
    async fn command_source_rejects_bad_output() {
        let source = IpSource {
            enable: true,
            kind: IpSourceKind::Command,
            command: "echo not-an-address".into(),
            ..IpSource::default()
        };
        let filter = SourceFilter::new(&source).expect("filter");
        let error = from_command(&source, Family::V4, Duration::from_secs(5), &filter)
            .await
            .expect_err("no address");
        assert!(matches!(error, SourceError::Command(_)), "{error}");
    }
}
