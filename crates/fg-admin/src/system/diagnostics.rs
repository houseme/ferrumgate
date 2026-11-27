//! The diagnostics bundle: sanitized runtime facts for support tickets.
//! Everything leaving the process passes the redactor — literals (config
//! dir, home, hostname), credential-bearing key/value pairs, auth headers,
//! bearer/basic credentials, secret CLI flags, addresses reduced to IP
//! classes, non-public domains, long tokens and user paths. JSON
//! configurations keep their structure with every non-whitelisted string
//! replaced; account and token files are never read.

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
    path::Path,
    sync::Arc,
};

use axum::Json;
use regex::Regex;
use serde::Serialize;

use crate::{ApiError, ApiRouter, RouteModels};
use super::SummarySource;

const REDACTED: &str = "<redacted>";

/// Files never read into the bundle: credentials only, no diagnostic value.
const SKIP_CONFIGS: [&str; 2] = ["account", "tokens"];

/// Arrays keep at most this many elements; the rest collapse into a note.
const MAX_ARRAY_ITEMS: usize = 100;

/// Keys whose values are fixed enums (protocols, modes, provider ids).
const VERBATIM_KEYS: [&str; 44] = [
    "type", "mode", "protocol", "protocols", "proto", "network", "provider", "kind", "family",
    "level", "minLevel", "tlsMode", "minTls", "lbPolicy", "authType", "keyType", "method",
    "format", "countryMode", "proxyMode", "ipMode", "channel", "role", "state", "status",
    "backendState", "language", "timeZone", "schedule", "repeat", "version", "os", "arch",
    "edgeIpVersion", "scope", "scopes", "tool", "healthStatus", "driver", "contentType", "acme",
    "restart", "tlsVersion", "shell",
];

/// Timestamp keys: times carry no privacy and help correlate issues.
const TIME_KEYS: [&str; 25] = [
    "createdAt", "updatedAt", "lastRun", "nextRun", "lastCheck", "lastSync", "lastAttempt",
    "nextRetry", "notBefore", "notAfter", "expiresAt", "lastUsedAt", "lastSeen", "lastAction",
    "lastActive", "started", "finished", "startedAt", "modTime", "time", "sampledAt", "checkedAt",
    "created", "deadline", "applied",
];

/// Address-family keys: keep scheme/port/IP class, drop the host.
const ADDR_KEYS: [&str; 47] = [
    "listen", "httpsListen", "listenAddress", "listenIp", "bind", "bindAddr", "localAddr",
    "localIp", "target", "targets", "targetAddresses", "to", "from", "dest", "destination",
    "upstreams", "addr", "addrs", "serverAddr", "server", "publicAddr", "stunServer",
    "stunServers", "keepAliveServers", "checkAddr", "upnpGateway", "natpmpGateway",
    "dashboardAddr", "broadcastIps", "ip", "ips", "ipv4", "ipv6", "lastUsedIP", "ipList",
    "resolvers", "dnsServers", "dns", "curAddr", "trustedProxies", "host", "hostIp",
    "upnpLocalHost", "upnpControlUrl", "publicHost", "socks5", "proxy",
];

/// Free-text keys (errors, reasons): keep content, redact like logs.
const TEXT_KEYS: [&str; 10] = [
    "error", "lastError", "ipError", "message", "reason", "lastExit", "warnings", "errors",
    "summary", "detail",
];

/// One bundle file (name → text content); the endpoint serves them as a
/// JSON preview.
pub struct BundleFile {
    pub name: String,
    pub content: String,
}

struct Literals {
    config_dir: String,
    home: String,
    hostname: String,
}

/// The redactor over one instance's sensitive literals.
pub struct Redactor {
    literals: Literals,
    re_url: Regex,
    re_email: Regex,
    re_mac: Regex,
    re_kv: Regex,
    re_header_line: Regex,
    re_flag: Regex,
    re_flag_name: Regex,
    re_bearer: Regex,
    re_basic: Regex,
    re_ipv4: Regex,
    re_ipv6: Regex,
    re_domain: Regex,
    re_long_token: Regex,
    re_user_path: Regex,
    re_plain_key: Regex,
    re_digit_run: Regex,
    re_hex_like: Regex,
    re_number_only: Regex,
    re_sensitive_key: Regex,
    verbatim: HashSet<&'static str>,
    times: HashSet<&'static str>,
    addrs: HashSet<&'static str>,
    texts: HashSet<&'static str>,
    public_domains: HashSet<&'static str>,
    file_exts: HashSet<&'static str>,
}

impl Redactor {
    /// Builds the redactor for one configuration directory.
    pub fn new(config_dir: &Path) -> Self {
        let home = std::env::var("HOME").unwrap_or_default();
        let hostname = hostname();
        Self {
            literals: Literals {
                config_dir: config_dir.display().to_string(),
                home,
                hostname,
            },
            re_url: Regex::new(r#"(?i)\b([a-z][a-z0-9+.-]{1,15})://[^\s"'<>]+"#).unwrap(),
            re_email: Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap(),
            re_mac: Regex::new(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b").unwrap(),
            re_kv: Regex::new(
                r#"(?i)([A-Za-z0-9_.-]*(?:password|passwd|pwd|passphrase|secret|token|api[-_]?key|access[-_]?key|auth[-_]?key|private[-_]?key|setup[-_]?key|consumer[-_]?key|authorization|cookie|credential|signature)[A-Za-z0-9_-]*)(["']?\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)"#,
            )
            .unwrap(),
            re_header_line: Regex::new(
                r#"(?i)\b((?:proxy-)?authorization|(?:set-)?cookie)\b(\s*[:=]\s*)([^\s"'][^\r\n]*)"#,
            )
            .unwrap(),
            re_flag: Regex::new(r"(?i)(^|\s)(--?[a-z][a-z0-9_-]*)(\s+)([^\s-]\S*)").unwrap(),
            re_flag_name: Regex::new(
                r"(?i)password|passwd|pwd|passphrase|secret|token|api[-_]?key|access[-_]?key|auth[-_]?key|private[-_]?key|setup[-_]?key|consumer[-_]?key|authorization|cookie|credential|signature|key",
            )
            .unwrap(),
            re_bearer: Regex::new(r"(?i)\bbearer\s+\S+").unwrap(),
            re_basic: Regex::new(r"(?i)\b(basic|digest|negotiate|ntlm)(\s+)([A-Za-z0-9+/._~-]{8,}={0,2})")
                .unwrap(),
            re_ipv4: Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").unwrap(),
            re_ipv6: Regex::new(r"[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(?:%[A-Za-z0-9]+)?")
                .unwrap(),
            re_domain: Regex::new(
                r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b",
            )
            .unwrap(),
            re_long_token: Regex::new(r"\b[A-Za-z0-9_-]{32,}\b").unwrap(),
            re_user_path: Regex::new(r"(?i)(/Users/|/home/|[A-Za-z]:\\Users\\)[^/\\\s]+").unwrap(),
            re_plain_key: Regex::new(r"^[A-Za-z][A-Za-z0-9_]{0,39}$").unwrap(),
            re_digit_run: Regex::new(r"\d{6,}").unwrap(),
            re_hex_like: Regex::new(r"^[0-9a-fA-F]{12,}$").unwrap(),
            re_number_only: Regex::new(r"^\d+$").unwrap(),
            re_sensitive_key: Regex::new(
                r"(?i)pass|pwd|pin|secret|token|key|salt|hash|otp|totp|cookie|credential|auth|code",
            )
            .unwrap(),
            verbatim: VERBATIM_KEYS.into_iter().collect(),
            times: TIME_KEYS.into_iter().collect(),
            addrs: ADDR_KEYS.into_iter().collect(),
            texts: TEXT_KEYS.into_iter().collect(),
            public_domains: [
                "github.com", "githubusercontent.com", "docker.io", "docker.com", "ghcr.io",
                "gcr.io", "letsencrypt.org", "zerossl.com", "google.com", "cloudflare.com",
                "aliyuncs.com", "dnspod.cn", "tencentcloudapi.com", "myhuaweicloud.com",
                "godaddy.com", "porkbun.com", "duckdns.org", "dynv6.com", "baidubce.com",
                "volcengineapi.com", "dns.la", "rainyun.com", "now.cn", "vercel.com",
                "namesilo.com", "dynadot.com", "spaceship.dev", "name.com", "gcore.com",
                "cloudns.net", "desec.io", "edgeone.ai", "crates.io", "rust-lang.org",
            ]
            .into_iter()
            .collect(),
            file_exts: [
                "go", "json", "yml", "yaml", "log", "conf", "txt", "zip", "pem", "crt", "key",
                "sh", "db", "sock", "toml", "ini", "html", "js", "css", "md", "enc", "tmp",
                "bak", "lock", "rs",
            ]
            .into_iter()
            .collect(),
        }
    }

    /// Redacts free text (logs, error messages).
    pub fn text(&self, s: &str) -> String {
        if s.is_empty() {
            return s.to_owned();
        }
        let s = self.replace_literals(s);
        let s = self
            .re_user_path
            .replace_all(&s, "${1}<user>")
            .into_owned();
        let s = self
            .re_url
            .replace_all(&s, |captures: &regex::Captures| {
                let matched = &captures[0];
                let scheme = matched.split("://").next().unwrap_or("");
                match scheme.to_ascii_lowercase().as_str() {
                    // Local sockets and file paths carry no network privacy.
                    "unix" | "file" => matched.to_owned(),
                    _ => format!("{}://<url>", scheme.to_ascii_lowercase()),
                }
            })
            .into_owned();
        let s = self.re_email.replace_all(&s, "<email>").into_owned();
        let s = self
            .re_header_line
            .replace_all(&s, format!("${{1}}${{2}}{REDACTED}"))
            .into_owned();
        let s = self
            .re_bearer
            .replace_all(&s, format!("Bearer {REDACTED}"))
            .into_owned();
        let s = self
            .re_basic
            .replace_all(&s, |captures: &regex::Captures| {
                let credential = &captures[3];
                // Plain lowercase words ("basic authentication") are not
                // credentials.
                let credential_like = credential.bytes().any(|b| {
                    b.is_ascii_digit() || b.is_ascii_uppercase() || b == b'+' || b == b'/' || b == b'='
                });
                if credential_like {
                    format!("{}{}{REDACTED}", &captures[1], &captures[2])
                } else {
                    captures[0].to_owned()
                }
            })
            .into_owned();
        let s = self
            .re_kv
            .replace_all(&s, format!("${{1}}${{2}}{REDACTED}"))
            .into_owned();
        let s = self
            .re_flag
            .replace_all(&s, |captures: &regex::Captures| {
                let flag = &captures[2];
                if self.re_flag_name.is_match(flag) {
                    format!("{}{}{}{REDACTED}", &captures[1], flag, &captures[3])
                } else {
                    captures[0].to_owned()
                }
            })
            .into_owned();
        let s = self.re_mac.replace_all(&s, "<mac>").into_owned();
        let s = self
            .re_ipv6
            .replace_all(&s, |captures: &regex::Captures| {
                let candidate = captures[0].split('%').next().unwrap_or("");
                match candidate.parse::<IpAddr>() {
                    Ok(IpAddr::V6(ip)) => ip_placeholder(&IpAddr::V6(ip)),
                    _ => captures[0].to_owned(),
                }
            })
            .into_owned();
        let s = self
            .re_ipv4
            .replace_all(&s, |captures: &regex::Captures| {
                match captures[0].parse::<Ipv4Addr>() {
                    Ok(ip) => ip_placeholder(&IpAddr::V4(ip)),
                    Err(_) => captures[0].to_owned(),
                }
            })
            .into_owned();
        let s = self
            .re_domain
            .replace_all(&s, |captures: &regex::Captures| {
                let domain = &captures[0];
                let extension = domain.rsplit('.').next().unwrap_or("");
                if self.file_exts.contains(extension) || self.is_public_domain(domain) {
                    domain.to_owned()
                } else {
                    "<domain>".to_owned()
                }
            })
            .into_owned();
        self.re_long_token.replace_all(&s, "<secret>").into_owned()
    }

    /// Address-family values: keep the scheme and port, reduce the host to
    /// an IP class or `<host>`, drop paths, queries and credentials.
    pub fn addr(&self, s: &str) -> String {
        let mut s = s.trim();
        if s.is_empty() || is_number_list(s) {
            return s.to_owned();
        }
        let mut scheme = String::new();
        if let Some(index) = s.find("://").filter(|index| *index > 0 && *index <= 10) {
            scheme = s[..index + 3].to_owned();
            s = &s[index + 3..];
        }
        if let Some(index) = s.find(['/', '?', '#']) {
            s = &s[..index];
        }
        if let Some(index) = s.rfind('@') {
            s = &s[index + 1..];
        }
        let (host, port) = match s.rsplit_once(':') {
            Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) && !port.is_empty() => {
                (host.trim_matches(['[', ']']), format!(":{port}"))
            }
            _ => (s.trim_matches(['[', ']']), String::new()),
        };
        let host = host.split('%').next().unwrap_or(host);
        match host {
            "" => format!("{scheme}{port}"),
            _ => match host.parse::<IpAddr>() {
                Ok(ip) => format!("{scheme}{}{port}", ip_placeholder(&ip)),
                Err(_) => format!("{scheme}<host>{port}"),
            },
        }
    }

    /// Structural view of a configuration file: keys, hierarchy, numbers,
    /// booleans and whitelisted enums survive; every other string becomes
    /// `<redacted>` (empty stays empty so "filled or not" remains visible).
    pub fn sanitize_json(&self, raw: &[u8]) -> Result<String, String> {
        let value: serde_json::Value =
            serde_json::from_slice(raw).map_err(|error| error.to_string())?;
        let sanitized = self.sanitize_value(value, "");
        serde_json::to_string_pretty(&sanitized).map_err(|error| error.to_string())
    }

    fn is_public_domain(&self, domain: &str) -> bool {
        let lowered = domain.to_ascii_lowercase();
        self.public_domains.iter().any(|public| {
            lowered == *public || lowered.ends_with(&format!(".{public}"))
        })
    }

    fn replace_literals(&self, s: &str) -> String {
        let mut out = s.to_owned();
        if self.literals.config_dir.len() >= 3 {
            out = out.replace(&self.literals.config_dir, "<config-dir>");
        }
        if self.literals.home.len() >= 3 {
            out = out.replace(&self.literals.home, "<home>");
        }
        if self.literals.hostname.len() >= 3 {
            out = replace_word(&out, &self.literals.hostname, "<hostname>");
        }
        out
    }

    fn sanitize_value(&self, value: serde_json::Value, key: &str) -> serde_json::Value {
        use serde_json::Value;
        match value {
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                let mut anonymous = 0usize;
                for (name, child) in map {
                    if self.re_plain_key.is_match(&name)
                        && !self.re_digit_run.is_match(&name)
                        && !self.re_hex_like.is_match(&name)
                        && !self.re_number_only.is_match(&name)
                    {
                        out.insert(name.clone(), self.sanitize_value(child, &name));
                    } else {
                        // Domain, id and user-defined keys are not kept.
                        anonymous += 1;
                        out.insert(
                            format!("<key-{anonymous}>"),
                            self.sanitize_value(child, ""),
                        );
                    }
                }
                Value::Object(out)
            }
            Value::Array(items) => {
                let total = items.len();
                let kept: Vec<_> = items
                    .into_iter()
                    .take(MAX_ARRAY_ITEMS)
                    .map(|item| self.sanitize_value(item, key))
                    .collect();
                let mut out = kept;
                if total > MAX_ARRAY_ITEMS {
                    out.push(Value::String(format!(
                        "<{} more items omitted>",
                        total - MAX_ARRAY_ITEMS
                    )));
                }
                Value::Array(out)
            }
            Value::String(text) => {
                Value::String(self.sanitize_string(&text, key))
            }
            Value::Number(number) => {
                if self.re_sensitive_key.is_match(key) && !self.verbatim.contains(key) {
                    Value::String(REDACTED.to_owned())
                } else {
                    Value::Number(number)
                }
            }
            other => other,
        }
    }

    fn sanitize_string(&self, s: &str, key: &str) -> String {
        if s.is_empty() {
            return s.to_owned();
        }
        if self.verbatim.contains(key) || self.times.contains(key) {
            return self.text(s);
        }
        if self.addrs.contains(key) {
            return self.addr(s);
        }
        if self.texts.contains(key) {
            return self.text(s);
        }
        REDACTED.to_owned()
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "localhost".to_owned())
}

/// 100.64.0.0/10.
fn is_cgnat(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
}

/// The network-environment class of an address, without the address.
pub fn ip_placeholder(ip: &IpAddr) -> String {
    let family = if ip.is_ipv4() { "ipv4" } else { "ipv6" };
    let class = match ip {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                "unspecified"
            } else if v4.is_loopback() {
                "loopback"
            } else if v4.is_private() {
                "private"
            } else if v4.is_link_local() {
                "linklocal"
            } else if is_cgnat(*v4) {
                "cgnat"
            } else {
                "public"
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                "loopback"
            } else if v6.is_unique_local() {
                "private"
            } else if v6.is_unicast_link_local() {
                "linklocal"
            } else {
                "public"
            }
        }
    };
    format!("<{family}:{class}>")
}

/// Word-boundary, case-insensitive literal replacement: hostname `gate`
/// matches in `gate.lan` but not in `gately`.
fn replace_word(s: &str, from: &str, to: &str) -> String {
    let is_word_byte = |b: u8| b.is_ascii_alphanumeric();
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    let lowered_from = from.to_ascii_lowercase();
    loop {
        let mut position = None;
        let mut lowered_rest = rest.to_ascii_lowercase();
        let mut offset = 0usize;
        while let Some(found) = lowered_rest[offset..].find(&lowered_from) {
            let start = offset + found;
            let end = start + lowered_from.len();
            let before_ok = start == 0 || !is_word_byte(rest.as_bytes()[start - 1]);
            let after_ok = end == rest.len() || !is_word_byte(rest.as_bytes()[end]);
            if before_ok && after_ok {
                position = Some((start, end));
                break;
            }
            offset = end;
        }
        let Some((start, end)) = position else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..start]);
        out.push_str(to);
        rest = &rest[end..];
        let _ = lowered_rest;
    }
}

fn is_number_list(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_digit() || b == b',' || b == b'-' || b == b':' || b == b' '
        })
}

/// Builds the sanitized bundle. `config_files` are the raw top-level
/// configuration files (name → bytes); account and token stores are
/// filtered by the caller with SKIP_CONFIGS.
pub fn build_bundle(
    redactor: &Redactor,
    summary: serde_json::Value,
    config_files: Vec<(String, Vec<u8>)>,
    include_logs_note: bool,
) -> Vec<BundleFile> {
    let mut files = Vec::new();
    files.push(BundleFile {
        name: "README.txt".to_owned(),
        content:
            "FerrumGate 诊断包\n\n所有文本经过脱敏：配置目录、主目录与主机名替换为占位符；\n\
             密钥值、认证头、令牌、地址（保留类别与端口）与非公共域名均已移除。\n\
             config/ 下的 JSON 保留结构与枚举，其余字符串替换为 <redacted>。\n\
             日志导出（logs=1）与崩溃记录随后续增量接入。\n"
                .to_owned(),
    });
    let summary_text = serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".into());
    files.push(BundleFile {
        name: "summary.json".to_owned(),
        content: summary_text,
    });
    let mut names: Vec<&str> = config_files
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| !SKIP_CONFIGS.contains(name))
        .collect();
    names.sort_unstable();
    names.dedup();
    let mut ordered = Vec::new();
    for name in names {
        if let Some((_, bytes)) = config_files.iter().find(|(candidate, _)| candidate == name) {
            ordered.push((name, bytes));
        }
    }
    let _ = include_logs_note;
    for (name, bytes) in ordered {
        let sanitized = match redactor.sanitize_json(bytes) {
            Ok(text) => text,
            Err(_) => "{\"error\": \"config file is not valid JSON\"}".to_owned(),
        };
        files.push(BundleFile {
            name: format!("config/{name}.json"),
            content: sanitized,
        });
    }
    files
}

/// Response shape for the preview endpoint.
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsPreview {
    pub files: Vec<DiagnosticsFile>,
}

#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsFile {
    pub name: String,
    pub size: usize,
    pub content: String,
}

impl BundleFile {
    pub fn preview(&self) -> DiagnosticsFile {
        DiagnosticsFile {
            name: self.name.clone(),
            size: self.content.len(),
            content: self.content.clone(),
        }
    }
}

/// Reads the applicable configuration files, skipping credential stores.
pub fn read_config_files(store: &fg_config::ConfigStore) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(store.dir()) else {
        return files;
    };
    let mut paths: Vec<_> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    for path in paths {
        let Some(name) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if SKIP_CONFIGS.contains(&name) {
            continue;
        }
        if let Ok(bytes) = std::fs::read(&path) {
            files.push((name.to_owned(), bytes));
        }
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redactor() -> Redactor {
        let dir = tempfile::tempdir().unwrap();
        Redactor::new(dir.path())
    }

    #[test]
    fn text_redacts_credentials_addresses_and_domains() {
        let redactor = redactor();
        // Header lines redact to end of line (upstream semantics), so the
        // phrases live on separate lines like real log entries.
        let text = redactor.text(
            "password=hunter2\nAuthorization: Bearer abc.def.ghi\n\
             connect 203.0.113.7:443\nvia vpn.example.com\n\
             token 0123456789abcdef0123456789abcdef",
        );
        assert!(!text.contains("hunter2"), "{text}");
        assert!(!text.contains("Bearer abc"), "{text}");
        assert!(text.contains("<ipv4:public>"), "{text}");
        assert!(text.contains("<domain>"), "{text}");
        assert!(text.contains("<secret>"), "{text}");

        let internal = redactor.text("peer 192.168.1.10 refused");
        assert!(internal.contains("<ipv4:private>"), "{internal}");
        let keep = redactor.text("see github.com and main.rs for details");
        assert!(keep.contains("github.com"), "{keep}");
        assert!(keep.contains("main.rs"), "file extensions stay: {keep}");
    }

    #[test]
    fn literals_replace_config_dir_home_and_hostname() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().display().to_string();
        let redactor = Redactor::new(dir.path());
        let text = redactor.text(&format!("stored at {path}/logs under {path}"));
        assert!(!text.contains(&path), "{text}");
        assert!(text.contains("<config-dir>"), "{text}");
    }

    #[test]
    fn addr_keeps_scheme_port_and_ip_class() {
        let redactor = redactor();
        assert_eq!(
            redactor.addr("http://10.1.2.3:8080/metrics?key=x"),
            "http://<ipv4:private>:8080"
        );
        assert_eq!(redactor.addr("nas.lan:445"), "<host>:445");
        assert_eq!(redactor.addr("80 443"), "80 443", "numeric lists stay");
    }

    #[test]
    fn sanitize_json_keeps_structure_and_redacts_values() {
        let redactor = redactor();
        let raw = br#"{
            "listen": "0.0.0.0:16680",
            "provider": "cloudflare",
            "token": "super-secret-value",
            "passwordHash": "abcdefghijkl",
            "remark": "my home tunnel",
            "lastCheck": "2026-11-27T00:00:00Z",
            "My-Domain-Key": {"nested": "value"},
            "rows": [1, 2, 3]
        }"#;
        let out = redactor.sanitize_json(raw).unwrap();
        let value: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(value["listen"], "<ipv4:unspecified>:16680");
        assert_eq!(value["provider"], "cloudflare", "verbatim enum kept");
        assert_eq!(value["token"], REDACTED);
        assert_eq!(value["passwordHash"], REDACTED, "sensitive numbers/strings");
        assert_eq!(value["remark"], REDACTED);
        assert_eq!(value["lastCheck"], "2026-11-27T00:00:00Z", "time keys kept");
        assert!(
            value["<key-1>"].is_object(),
            "dynamic keys are anonymized: {out}"
        );
        assert_eq!(value["rows"][2], 3);
        assert!(!out.contains("super-secret-value"));
        assert!(!out.contains("my home tunnel"));
    }

    #[test]
    fn bundle_skips_credential_stores_and_sanitizes_configs() {
        let dir = tempfile::tempdir().unwrap();
        let redactor = Redactor::new(dir.path());
        let files = vec![
            ("account".to_owned(), br#"{"passwordHash":"x"}"#.to_vec()),
            ("tokens".to_owned(), br#"{"tokens":[]}"#.to_vec()),
            ("ddns".to_owned(), br#"{"token":"fix-secret-1","server":"dns.example.com"}"#.to_vec()),
        ];
        let summary = serde_json::json!({"version": env!("CARGO_PKG_VERSION")});
        let bundle = build_bundle(&redactor, summary, files, false);
        let names: Vec<_> = bundle.iter().map(|file| file.name.as_str()).collect();
        assert_eq!(names, ["README.txt", "summary.json", "config/ddns.json"]);
        let ddns = bundle.iter().find(|file| file.name == "config/ddns.json").unwrap();
        assert!(!ddns.content.contains("fix-secret-1"), "{}", ddns.content);
        // "server" is an address key: the domain collapses to <host>.
        assert!(ddns.content.contains("<host>"), "{}", ddns.content);
        assert!(!ddns.content.contains("example.com"), "{}", ddns.content);
    }
}

/// Mounts `GET /api/system/diagnostics` (session-only via the forbidden
/// prefix table): serves the sanitized bundle as a JSON preview. `?logs=0`
/// is accepted for interface compatibility; log export lands with the
/// logging-buffer handoff.
pub(crate) fn mount(router: ApiRouter, source: Arc<SummarySource>) -> ApiRouter {
    router.modeled_route(
        axum::http::Method::GET,
        "/api/system/diagnostics",
        "Preview the sanitized diagnostics bundle",
        RouteModels::default().response::<DiagnosticsPreview>(),
        move || {
            let source = source.clone();
            async move {
                let redactor = Redactor::new(&source.config_dir);
                let summary = serde_json::json!({
                    "generatedAt": time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                    "version": env!("CARGO_PKG_VERSION"),
                    "os": std::env::consts::OS,
                    "arch": std::env::consts::ARCH,
                    "rustc": option_env!("FERRUMGATE_RUSTC_VERSION").unwrap_or(""),
                    "uptimeSeconds": source.uptime_seconds(),
                    "timeZone": source.settings.time_zone.clone(),
                    "inDocker": Path::new("/.dockerenv").exists(),
                    "adminListen": {
                        "http": source.settings.listen,
                        "https": source.settings.https_listen,
                    },
                    "procRssBytes": source.proc_rss_bytes,
                    "modules": source.module_states(),
                });
                let store = fg_config::ConfigStore::open(&source.config_dir)
                    .map_err(|_| ApiError::internal())?;
                let configs = read_config_files(&store);
                let bundle = build_bundle(&redactor, summary, configs, false);
                Ok::<_, ApiError>(Json(DiagnosticsPreview {
                    files: bundle.iter().map(BundleFile::preview).collect(),
                }))
            }
        },
    )
}
