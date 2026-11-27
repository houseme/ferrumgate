//! Normalization and validation for the web service model (WP-20 step 3):
//! pure functions over plain data.
//!
//! [`Problem::field`] is a JSON-style path into `webservice.json` using the
//! serialized (camelCase) field names, e.g. `listeners[0].sites[1].redirectTo`.
#![allow(dead_code)]

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

use fg_net::source_rule::compile_networks;

use super::domains::normalize_pattern;
use super::identity;
use super::model::{FileConfig, Site};
use super::proxy::headers::parse_edits;
use super::proxy::rewrite::Rewrite;
use super::upstream::{Policy, parse_target};
use super::userroute::RouteUserKey;

/// A collected validation problem.
#[derive(Debug, PartialEq, Eq)]
pub struct Problem {
    pub field: String,
    pub reason: String,
}

/// Applies normalization (plan §3.3):
/// - strings (`name` / `group` / `remark` / `listenIp` / `redirectTo` /
///   `root` / `textBody` and the keys) lose surrounding whitespace;
/// - domains are lowercased, trailing dots stripped, empty entries removed
///   and duplicates dropped preserving order (per site);
/// - group names are truncated to 64 characters;
/// - listener keys are unique across the file, site keys unique within
///   their listener; empty or clashing keys are replaced by a fresh
///   12-lowercase-hex value;
/// - an empty `listenIp` becomes `0.0.0.0`.
pub fn normalize(mut config: FileConfig) -> FileConfig {
    let random = ring::rand::SystemRandom::new();
    let mut listener_keys = HashSet::new();
    for listener in &mut config.listeners {
        listener.key = listener.key.trim().to_string();
        if (listener.key.is_empty() || !listener_keys.insert(listener.key.clone()))
            && let Some(key) = generate_key(&random, &mut listener_keys)
        {
            listener.key = key;
        }
        listener.name = listener.name.trim().to_string();
        listener.remark = listener.remark.trim().to_string();
        listener.listen_ip = listener.listen_ip.trim().to_string();
        if listener.listen_ip.is_empty() {
            listener.listen_ip = "0.0.0.0".to_string();
        }
        let mut site_keys = HashSet::new();
        for site in &mut listener.sites {
            site.key = site.key.trim().to_string();
            if (site.key.is_empty() || !site_keys.insert(site.key.clone()))
                && let Some(key) = generate_key(&random, &mut site_keys)
            {
                site.key = key;
            }
            site.name = site.name.trim().to_string();
            site.group = site.group.trim().chars().take(64).collect();
            site.remark = site.remark.trim().to_string();
            site.redirect_to = site.redirect_to.trim().to_string();
            site.root = site.root.trim().to_string();
            site.text_body = site.text_body.trim().to_string();
            site.domains = dedupe_domains(&site.domains);
        }
    }
    config
}

/// A fresh 12-lowercase-hex key absent from `taken` (which records the
/// generated key). `None` means the system RNG kept failing, which in
/// practice never happens; the caller then leaves the key untouched.
fn generate_key(random: &ring::rand::SystemRandom, taken: &mut HashSet<String>) -> Option<String> {
    use ring::rand::SecureRandom;

    for _ in 0..8 {
        let mut bytes = [0u8; 6];
        random.fill(&mut bytes).ok()?;
        let key: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        if taken.insert(key.clone()) {
            return Some(key);
        }
    }
    None
}

/// Lowercases, strips trailing dots, drops empty entries and deduplicates
/// preserving order.
fn dedupe_domains(domains: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut unique = Vec::with_capacity(domains.len());
    for domain in domains {
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty() || !seen.insert(normalized.clone()) {
            continue;
        }
        unique.push(normalized);
    }
    unique
}

/// Validates a (normalized) config, collecting every problem.
///
/// Listener rules: `port != 0`, `network` is `""` or `"tcp"`, listener keys
/// unique across the file, ports unique across *enabled* listeners. Site
/// rules: at least one domain, each domain passing [`normalize_pattern`], a
/// known `siteType` with its type-specific field filled in, group names
/// within 64 characters, and compileable source access lists
/// ([`compile_networks`]). Proxy sites (WP-23) additionally validate every
/// `targets` line ([`check_target_line`]), the `lbPolicy`, timeout
/// ranges, and compile checks for rewrites, header edits, identity
/// headers, CORS origins and per-user routes; PROXY protocol and
/// visitor-SNI verification are mutually exclusive
/// ([`validate_proxy_fields`]). The same domain in multiple sites of one
/// listener is not an error (first wins — plan §3.3 匹配).
pub fn validate(config: &FileConfig) -> Vec<Problem> {
    let mut problems = Vec::new();
    let mut seen_keys: HashSet<&str> = HashSet::new();
    let mut seen_ports: HashMap<u16, String> = HashMap::new();

    for (listener_index, listener) in config.listeners.iter().enumerate() {
        let field = |name: &str| format!("listeners[{listener_index}].{name}");

        if listener.port == 0 {
            problems.push(Problem {
                field: field("port"),
                reason: "监听端口不能为 0".to_string(),
            });
        }
        if !listener.network.is_empty() && listener.network != "tcp" {
            problems.push(Problem {
                field: field("network"),
                reason: format!("network 只能为空或 tcp，当前为 {:?}", listener.network),
            });
        }
        if !seen_keys.insert(listener.key.as_str()) {
            problems.push(Problem {
                field: field("key"),
                reason: format!("监听器 key {:?} 在文件中重复", listener.key),
            });
        }
        if listener.enable {
            match seen_ports.entry(listener.port) {
                Entry::Occupied(first) => problems.push(Problem {
                    field: field("port"),
                    reason: format!("端口 {} 已被监听器 {} 占用", listener.port, first.get()),
                }),
                Entry::Vacant(slot) => {
                    slot.insert(listener.key.clone());
                }
            }
        }

        for (site_index, site) in listener.sites.iter().enumerate() {
            let path = format!("listeners[{listener_index}].sites[{site_index}]");
            validate_site(site, &path, &mut problems);
        }
    }
    problems
}

/// Per-site rules: domains, `siteType` requirements, the group cap, the
/// source access lists and — for proxy sites — the WP-23 proxy fields
/// ([`validate_proxy_fields`]).
fn validate_site(site: &Site, path: &str, problems: &mut Vec<Problem>) {
    let field = |name: &str| format!("{path}.{name}");

    if site.domains.is_empty() {
        problems.push(Problem {
            field: field("domains"),
            reason: "站点至少需要填写一个域名".to_string(),
        });
    }
    for (index, domain) in site.domains.iter().enumerate() {
        if let Err(error) = normalize_pattern(domain) {
            problems.push(Problem {
                field: field(&format!("domains[{index}]")),
                reason: error.to_string(),
            });
        }
    }

    match site.site_type.trim() {
        "proxy" if site.targets.is_empty() => problems.push(Problem {
            field: field("targets"),
            reason: "proxy 站点至少需要填写一个后端地址 targets".to_string(),
        }),
        "redirect" if site.redirect_to.trim().is_empty() => problems.push(Problem {
            field: field("redirectTo"),
            reason: "redirect 站点需要填写 redirectTo".to_string(),
        }),
        "static" if site.root.trim().is_empty() => problems.push(Problem {
            field: field("root"),
            reason: "static 站点需要填写 root".to_string(),
        }),
        "text" if site.text_body.trim().is_empty() => problems.push(Problem {
            field: field("textBody"),
            reason: "text 站点需要填写 textBody".to_string(),
        }),
        "proxy" | "redirect" | "static" | "text" => {}
        other => problems.push(Problem {
            field: field("siteType"),
            reason: format!("siteType 只能为 proxy、redirect、static 或 text，当前为 {other:?}"),
        }),
    }

    if site.group.chars().count() > 64 {
        problems.push(Problem {
            field: field("group"),
            reason: "分组名最长 64 个字符".to_string(),
        });
    }

    for (name, entries) in [
        ("accessAllow", &site.access_allow),
        ("accessDeny", &site.access_deny),
    ] {
        if let Err(error) = compile_networks(entries.clone()) {
            problems.push(Problem {
                field: field(name),
                reason: error.to_string(),
            });
        }
    }

    if site.site_type.trim() == "proxy" {
        validate_proxy_fields(site, path, problems);
    }
}

/// One backend address line (site `targets` and user-route targets): a
/// full `URL [weight=N] [backup]` line parses as-is; a bare `host:port`
/// (legacy data) is retried with an implied `http://`. The `Err` carries
/// the message for the problem list.
fn check_target_line(line: &str) -> Result<(), String> {
    let first = match parse_target(line) {
        Ok(_) => return Ok(()),
        Err(error) => error,
    };
    // The fallback only makes sense for a bare address: a line that also
    // carries `weight=`/`backup` already had them parsed, so its error is
    // final.
    if line.split_whitespace().count() == 1
        && parse_target(&format!("http://{}", line.trim())).is_ok()
    {
        return Ok(());
    }
    Err(first.to_string())
}

/// A CORS origin: `*` or `scheme://host[:port]` with scheme http/https.
/// An origin never carries a path, query, fragment or userinfo, and the
/// port must be numeric (a bracketed IPv6 host keeps its colons out of
/// the port check).
fn valid_cors_origin(origin: &str) -> bool {
    if origin == "*" {
        return true;
    }
    let Some(rest) = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
    else {
        return false;
    };
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
        return false;
    }
    let port_text = match rest.rfind(']') {
        Some(close) => rest[close + 1..].strip_prefix(':'),
        None => rest.split_once(':').map(|(_, port)| port),
    };
    port_text.is_none_or(|port| !port.is_empty() && port.parse::<u16>().is_ok())
}

/// WP-23 proxy-site fields: every `targets` line must parse as
/// `URL [weight=N] [backup]` (legacy bare `host:port` still passes),
/// `lbPolicy` must be a known policy, timeouts stay in range, and
/// rewrites / header edits / identity headers / CORS / per-user routes
/// must compile. PROXY protocol to the backend excludes using (and
/// verifying) the visitor's hostname as SNI — documented decision.
fn validate_proxy_fields(site: &Site, path: &str, problems: &mut Vec<Problem>) {
    let field = |name: &str| format!("{path}.{name}");

    for (index, line) in site.targets.iter().enumerate() {
        if let Err(reason) = check_target_line(line) {
            problems.push(Problem {
                field: field(&format!("targets[{index}]")),
                reason: format!("第 {} 行后端地址无效：{line}（{reason}）", index + 1),
            });
        }
    }

    if Policy::parse(site.lb_policy.trim()).is_none() {
        problems.push(Problem {
            field: field("lbPolicy"),
            reason: format!(
                "lbPolicy 只能为空、round_robin、random、ip_hash 或 least_conn，当前为 {:?}",
                site.lb_policy
            ),
        });
    }

    // `0` keeps the built-in default, so only values past the cap fail.
    for (name, secs, max) in [
        ("timeoutsConnectSecs", site.timeouts_connect_secs, 300),
        ("timeoutsTlsSecs", site.timeouts_tls_secs, 300),
        ("timeoutsResponseSecs", site.timeouts_response_secs, 86_400),
        ("clientIdleReadSecs", site.client_idle_read_secs, 3_600),
        ("clientIdleWriteSecs", site.client_idle_write_secs, 3_600),
    ] {
        if secs > max {
            problems.push(Problem {
                field: field(name),
                reason: format!("{name} 范围是 1..={max}（0 表示使用默认值）"),
            });
        }
    }

    if let Err(error) = identity::compile(&site.identity_headers) {
        problems.push(Problem {
            field: field("identityHeaders"),
            reason: error.to_string(),
        });
    }

    for (index, rule) in site.rewrites.iter().enumerate() {
        let redirect = rule.redirect.then_some(if rule.code == 0 { 302 } else { rule.code });
        if let Err(error) = Rewrite::compile(&rule.pattern, &rule.to, redirect) {
            problems.push(Problem {
                field: field(&format!("rewrites[{index}]")),
                reason: error.to_string(),
            });
        }
    }

    for (name, lines) in [
        ("requestHeaders", &site.request_headers),
        ("responseHeaders", &site.response_headers),
    ] {
        if let Err(error) = parse_edits(lines) {
            problems.push(Problem {
                field: field(name),
                reason: error.to_string(),
            });
        }
    }

    if !site.cors.allow_origins.is_empty() {
        for (index, origin) in site.cors.allow_origins.iter().enumerate() {
            if !valid_cors_origin(origin) {
                problems.push(Problem {
                    field: field(&format!("cors.allowOrigins[{index}]")),
                    reason: format!("CORS origin 必须形如 http(s)://host[:port] 或 *：{origin}"),
                });
            }
        }
        if site.cors.max_age_secs > 86_400 {
            problems.push(Problem {
                field: field("cors.maxAgeSecs"),
                reason: format!(
                    "cors.maxAgeSecs 范围是 0..=86400，当前为 {}",
                    site.cors.max_age_secs
                ),
            });
        }
    }

    // Third-party keys (`provider:id`) normalize case in `key()`, so the
    // same identity under different spellings collides here too; site
    // usernames compare exactly.
    let mut seen_users = HashSet::new();
    for (index, route) in site.user_routes.iter().enumerate() {
        let route_field = |name: &str| field(&format!("userRoutes[{index}].{name}"));
        if route.users.is_empty() {
            problems.push(Problem {
                field: route_field("users"),
                reason: "分流规则至少要有一个用户".to_string(),
            });
        }
        if route.targets.is_empty() {
            problems.push(Problem {
                field: route_field("targets"),
                reason: "分流规则至少需要填写一个后端地址 targets".to_string(),
            });
        }
        for (line_index, line) in route.targets.iter().enumerate() {
            if let Err(reason) = check_target_line(line) {
                problems.push(Problem {
                    field: route_field(&format!("targets[{line_index}]")),
                    reason: format!("第 {} 行后端地址无效：{line}（{reason}）", line_index + 1),
                });
            }
        }
        for user in &route.users {
            if !seen_users.insert(RouteUserKey::parse(user).key()) {
                problems.push(Problem {
                    field: route_field("users"),
                    reason: format!("同一用户不能出现在两条分流规则：{user}"),
                });
            }
        }
    }

    if site.send_proxy_protocol && site.upstream_sni_from_host {
        problems.push(Problem {
            field: field("sendProxyProtocol"),
            reason:
                "sendProxyProtocol 与 upstreamSniFromHost 不能同时开启（PROXY 协议与访客 SNI 校验互斥）"
                    .to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::model::{
        CorsSite, IdentitySite, Listener, RewriteSite, Settings, UserRouteSite,
    };

    fn site(key: &str, site_type: &str, domains: &[&str]) -> Site {
        Site {
            key: key.to_string(),
            enable: true,
            domains: domains.iter().map(|domain| domain.to_string()).collect(),
            site_type: site_type.to_string(),
            ..Site::default()
        }
    }

    fn proxy_site(key: &str, domains: &[&str]) -> Site {
        let mut site = site(key, "proxy", domains);
        site.targets = vec!["http://127.0.0.1:9000".to_string()];
        site
    }

    fn listener(key: &str, port: u16, sites: Vec<Site>) -> Listener {
        Listener {
            key: key.to_string(),
            enable: true,
            network: "tcp".to_string(),
            port,
            sites,
            ..Listener::default()
        }
    }

    fn config(listeners: Vec<Listener>) -> FileConfig {
        FileConfig {
            settings: Settings::default(),
            listeners,
        }
    }

    fn is_hex_key(key: &str) -> bool {
        key.len() == 12
            && key
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    }

    #[test]
    fn normalize_trims_and_dedupes_domains() {
        let mut edge = listener(
            "l1",
            8080,
            vec![proxy_site(
                "s1",
                &[
                    "Example.COM.",
                    "example.com",
                    " *.foo.com ",
                    "",
                    "EXAMPLE.com",
                ],
            )],
        );
        edge.name = "  edge  ".to_string();
        edge.remark = "  front  ".to_string();
        edge.listen_ip = "  127.0.0.1  ".to_string();
        let mut site = edge.sites[0].clone();
        site.name = "  web  ".to_string();
        site.group = "  g  ".to_string();
        site.remark = "  m  ".to_string();
        site.redirect_to = "  https://a.example.com/path  ".to_string();
        site.root = "  /srv/www  ".to_string();
        site.text_body = "  hi  ".to_string();
        edge.sites = vec![site];

        let mut bare = listener("l2", 8081, Vec::new());
        bare.listen_ip = String::new();

        let normalized = normalize(config(vec![edge, bare]));
        let listener = &normalized.listeners[0];
        assert_eq!(listener.name, "edge");
        assert_eq!(listener.remark, "front");
        assert_eq!(listener.listen_ip, "127.0.0.1");
        let site = &listener.sites[0];
        assert_eq!(site.name, "web");
        assert_eq!(site.group, "g");
        assert_eq!(site.remark, "m");
        assert_eq!(site.redirect_to, "https://a.example.com/path");
        assert_eq!(site.root, "/srv/www");
        assert_eq!(site.text_body, "hi");
        assert_eq!(site.domains, vec!["example.com", "*.foo.com"]);
        assert_eq!(normalized.listeners[1].listen_ip, "0.0.0.0");
    }

    #[test]
    fn normalize_generates_keys_for_empty_entries() {
        let normalized = normalize(config(vec![
            listener(
                "",
                8080,
                vec![
                    site("", "proxy", &["a.test"]),
                    site("s1", "proxy", &["b.test"]),
                    site("s1", "proxy", &["c.test"]),
                ],
            ),
            listener("", 8081, Vec::new()),
            listener("dup", 8082, Vec::new()),
            listener("dup", 8083, Vec::new()),
            listener("keep", 8084, Vec::new()),
        ]));

        let listener_keys: Vec<&str> = normalized
            .listeners
            .iter()
            .map(|listener| listener.key.as_str())
            .collect();
        assert_eq!(listener_keys.len(), 5);
        assert!(
            listener_keys
                .iter()
                .all(|key| is_hex_key(key) || *key == "keep" || *key == "dup")
        );
        let mut distinct = listener_keys.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), listener_keys.len(), "{listener_keys:?}");

        let site_keys: Vec<&str> = normalized.listeners[0]
            .sites
            .iter()
            .map(|site| site.key.as_str())
            .collect();
        assert!(site_keys.contains(&"s1"), "{site_keys:?}");
        assert!(
            site_keys.iter().all(|key| is_hex_key(key) || *key == "s1"),
            "{site_keys:?}"
        );
        let mut distinct_sites = site_keys.clone();
        distinct_sites.sort();
        distinct_sites.dedup();
        assert_eq!(distinct_sites.len(), site_keys.len(), "{site_keys:?}");
    }

    #[test]
    fn normalize_truncates_long_group() {
        let mut listener = listener("a", 8080, vec![proxy_site("s", &["a.test"])]);
        listener.sites[0].group = "x".repeat(70);
        let normalized = normalize(config(vec![listener]));
        assert_eq!(normalized.listeners[0].sites[0].group.chars().count(), 64);
    }

    #[test]
    fn validate_catches_missing_fields() {
        let mut bad_network = listener("a", 8080, vec![proxy_site("s", &["a.test"])]);
        bad_network.network = "udp".to_string();
        let mut bad_sources = listener("a", 8080, vec![proxy_site("s", &["a.test"])]);
        bad_sources.sites[0].access_allow = vec!["not-a-network".to_string()];
        let cases: Vec<(FileConfig, &str)> = vec![
            // port != 0
            (
                config(vec![listener("a", 0, vec![proxy_site("s", &["a.test"])])]),
                "listeners[0].port",
            ),
            // network is "" or "tcp"
            (config(vec![bad_network]), "listeners[0].network"),
            // listener keys unique across the file
            (
                config(vec![
                    listener("dup", 8080, vec![proxy_site("s1", &["a.test"])]),
                    listener("dup", 8081, vec![proxy_site("s2", &["b.test"])]),
                ]),
                "listeners[1].key",
            ),
            // at least one domain per site
            (
                config(vec![listener("a", 8080, vec![proxy_site("s", &[])])]),
                "listeners[0].sites[0].domains",
            ),
            // every domain must pass normalize_pattern
            (
                config(vec![listener("a", 8080, vec![proxy_site("s", &["a..b"])])]),
                "listeners[0].sites[0].domains[0]",
            ),
            // site_type must be a known type
            (
                config(vec![listener(
                    "a",
                    8080,
                    vec![site("s", "mail", &["a.test"])],
                )]),
                "listeners[0].sites[0].siteType",
            ),
            // proxy requires targets
            (
                config(vec![listener(
                    "a",
                    8080,
                    vec![site("s", "proxy", &["a.test"])],
                )]),
                "listeners[0].sites[0].targets",
            ),
            // source access lists must compile
            (
                config(vec![bad_sources]),
                "listeners[0].sites[0].accessAllow",
            ),
        ];
        for (config, field) in &cases {
            let problems = validate(config);
            assert!(
                problems.iter().any(|problem| &problem.field == field),
                "expected a problem on {field}, got {problems:?}"
            );
        }

        // Duplicate ports across enabled listeners carry the exact message.
        let problems = validate(&config(vec![
            listener("a", 9000, vec![proxy_site("s1", &["a.test"])]),
            listener("b", 9000, vec![proxy_site("s2", &["b.test"])]),
        ]));
        assert!(
            problems
                .iter()
                .any(|problem| problem.field == "listeners[1].port"
                    && problem.reason == "端口 9000 已被监听器 a 占用"),
            "{problems:?}"
        );

        // A disabled listener may share the port; "" is a valid network.
        let mut lone = listener("a", 9000, vec![proxy_site("s1", &["a.test"])]);
        lone.network = String::new();
        let mut disabled = listener("c", 9000, vec![proxy_site("s3", &["c.test"])]);
        disabled.enable = false;
        assert!(validate(&config(vec![lone, disabled])).is_empty());
    }

    #[test]
    fn validate_accepts_valid_config_and_allows_shared_domains() {
        let mut first = listener(
            "a",
            8080,
            vec![
                proxy_site("s1", &["app.test"]),
                proxy_site("s2", &["app.test"]),
            ],
        );
        first.sites[0].access_allow = vec!["10.0.0.0/8".to_string()];
        first.sites[0].access_deny = vec!["192.168.1.1".to_string()];

        let mut second = listener(
            "b",
            8081,
            vec![
                site("s3", "redirect", &["go.test"]),
                site("s4", "static", &["*.example.com"]),
                site("s5", "text", &["info.test"]),
            ],
        );
        second.network = String::new();
        second.listen_ip = "127.0.0.1".to_string();
        second.sites[0].redirect_to = "https://b.test".to_string();
        second.sites[1].root = "/srv/www".to_string();
        second.sites[2].text_body = "hello".to_string();

        // The same domain across sites of one listener is not an error
        // (first wins, documented), and neither is a shared domain across
        // different listeners.
        let problems = validate(&config(vec![
            first,
            second,
            listener("c", 8082, vec![proxy_site("s6", &["app.test"])]),
        ]));
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn validate_group_length_capped() {
        let mut long = listener("a", 8080, vec![proxy_site("s", &["a.test"])]);
        long.sites[0].group = "组".repeat(65);
        let problems = validate(&config(vec![long]));
        assert!(
            problems
                .iter()
                .any(|problem| problem.field == "listeners[0].sites[0].group"),
            "{problems:?}"
        );

        // Exactly 64 characters passes, and normalize truncates anything
        // longer so the normalized config always validates.
        let mut capped = listener("a", 8080, vec![proxy_site("s", &["a.test"])]);
        capped.sites[0].group = "组".repeat(64);
        assert!(validate(&config(vec![capped])).is_empty());

        let mut raw = listener("a", 8080, vec![proxy_site("s", &["a.test"])]);
        raw.sites[0].group = "x".repeat(70);
        let normalized = normalize(config(vec![raw]));
        assert!(validate(&normalized).is_empty());
    }

    #[test]
    fn validate_site_type_field_requirements() {
        let missing = [
            ("targets", site("s", "proxy", &["a.test"])),
            ("redirectTo", site("s", "redirect", &["a.test"])),
            ("root", site("s", "static", &["a.test"])),
            ("textBody", site("s", "text", &["a.test"])),
        ];
        for (field, site) in missing {
            let problems = validate(&config(vec![listener("a", 8080, vec![site])]));
            assert!(
                problems
                    .iter()
                    .any(|problem| problem.field == format!("listeners[0].sites[0].{field}")),
                "{field}: {problems:?}"
            );
        }

        let mut with_targets = site("s", "proxy", &["a.test"]);
        with_targets.targets = vec!["http://127.0.0.1:1".to_string()];
        let mut with_redirect = site("s", "redirect", &["a.test"]);
        with_redirect.redirect_to = "https://b.test".to_string();
        let mut with_root = site("s", "static", &["a.test"]);
        with_root.root = "/srv/www".to_string();
        let mut with_text = site("s", "text", &["a.test"]);
        with_text.text_body = "hi".to_string();
        for (field, site) in [
            ("targets", with_targets),
            ("redirectTo", with_redirect),
            ("root", with_root),
            ("textBody", with_text),
        ] {
            let problems = validate(&config(vec![listener("a", 8080, vec![site])]));
            assert!(problems.is_empty(), "{field}: {problems:?}");
        }
    }

    #[test]
    fn wp23_target_lines_validate() {
        // Full lines with parameters, bare legacy `host:port`, https.
        let mut good = listener("a", 8080, vec![proxy_site("s", &["a.test"])]);
        good.sites[0].targets = vec![
            "http://10.0.0.1:8080 weight=3 backup".to_string(),
            "127.0.0.1:9000".to_string(),
            "https://backend.internal".to_string(),
        ];
        assert!(validate(&config(vec![good])).is_empty());

        // A bad line is reported with its number and the original text.
        let mut bad_weight = listener("a", 8080, vec![proxy_site("s", &["a.test"])]);
        bad_weight.sites[0].targets = vec![
            "http://10.0.0.1:8080".to_string(),
            "http://10.0.0.2:8080 weight=101".to_string(),
        ];
        let problems = validate(&config(vec![bad_weight]));
        assert!(
            problems.iter().any(|problem| {
                problem.field == "listeners[0].sites[0].targets[1]"
                    && problem.reason.contains("第 2 行")
                    && problem.reason.contains("weight=101")
            }),
            "{problems:?}"
        );

        // A path is a non-origin both as-is and with the implied scheme.
        let mut bad_path = listener("a", 8080, vec![proxy_site("s", &["a.test"])]);
        bad_path.sites[0].targets = vec!["http://x.test/api".to_string()];
        let problems = validate(&config(vec![bad_path]));
        assert!(
            problems.iter().any(|problem| {
                problem.field == "listeners[0].sites[0].targets[0]"
                    && problem.reason.contains("http://x.test/api")
            }),
            "{problems:?}"
        );

        // The legacy fallback covers plain addresses only: a bare
        // host:port that also carries parameters must spell the scheme.
        let mut bare_params = listener("a", 8080, vec![proxy_site("s", &["a.test"])]);
        bare_params.sites[0].targets = vec!["10.0.0.2:8080 backup".to_string()];
        let problems = validate(&config(vec![bare_params]));
        assert!(
            problems
                .iter()
                .any(|problem| problem.field == "listeners[0].sites[0].targets[0]"),
            "{problems:?}"
        );
    }

    #[test]
    fn wp23_lb_policy_and_timeouts() {
        let mut bad = proxy_site("s", &["a.test"]);
        bad.lb_policy = "fastest".to_string();
        bad.timeouts_connect_secs = 301;
        bad.timeouts_tls_secs = 301;
        bad.timeouts_response_secs = 86_401;
        bad.client_idle_read_secs = 3601;
        let problems = validate(&config(vec![listener("a", 8080, vec![bad])]));
        for name in [
            "lbPolicy",
            "timeoutsConnectSecs",
            "timeoutsTlsSecs",
            "timeoutsResponseSecs",
            "clientIdleReadSecs",
        ] {
            assert!(
                problems
                    .iter()
                    .any(|problem| problem.field == format!("listeners[0].sites[0].{name}")),
                "{name}: {problems:?}"
            );
        }

        // `clientIdleWriteSecs` has its own range.
        let mut idle = proxy_site("s", &["a.test"]);
        idle.client_idle_write_secs = 3601;
        let problems = validate(&config(vec![listener("a", 8080, vec![idle])]));
        assert!(
            problems
                .iter()
                .any(|problem| problem.field == "listeners[0].sites[0].clientIdleWriteSecs"),
            "{problems:?}"
        );

        // 0 keeps the default and the maxima are inclusive.
        let mut edge = proxy_site("s", &["a.test"]);
        edge.lb_policy = "ip_hash".to_string();
        edge.timeouts_connect_secs = 300;
        edge.timeouts_tls_secs = 300;
        edge.timeouts_response_secs = 86_400;
        edge.client_idle_read_secs = 3600;
        edge.client_idle_write_secs = 0;
        assert!(validate(&config(vec![listener("a", 8080, vec![edge])])).is_empty());

        // PROXY protocol and visitor-SNI verification are exclusive.
        let mut clash = proxy_site("s", &["a.test"]);
        clash.send_proxy_protocol = true;
        clash.upstream_sni_from_host = true;
        let problems = validate(&config(vec![listener("a", 8080, vec![clash])]));
        assert!(
            problems
                .iter()
                .any(|problem| problem.field == "listeners[0].sites[0].sendProxyProtocol"),
            "{problems:?}"
        );
    }

    #[test]
    fn wp23_identity_rewrite_header_edits() {
        let mut bad = proxy_site("s", &["a.test"]);
        bad.identity_headers = vec![IdentitySite {
            header: "X-Forwarded-For".to_string(),
            field: "user".to_string(),
        }];
        bad.rewrites = vec![
            // Bad regex.
            RewriteSite {
                pattern: "([".to_string(),
                to: "/v2/$1".to_string(),
                redirect: false,
                code: 0,
            },
            // Internal rewrite target without the leading `/`.
            RewriteSite {
                pattern: "/api/(.*)".to_string(),
                to: "https://x.test/v2".to_string(),
                redirect: false,
                code: 0,
            },
            // Redirect code outside 301/302/307/308.
            RewriteSite {
                pattern: "/old(.*)".to_string(),
                to: "https://x.test/new".to_string(),
                redirect: true,
                code: 303,
            },
        ];
        bad.request_headers = vec!["no-colon-here".to_string()];
        bad.response_headers = vec!["X-Ok: fine".to_string()];
        let problems = validate(&config(vec![listener("a", 8080, vec![bad])]));
        let reason_on = |field: &str| {
            problems
                .iter()
                .find(|problem| problem.field == field)
                .map(|problem| problem.reason.clone())
        };
        assert!(
            reason_on("listeners[0].sites[0].identityHeaders")
                .unwrap_or_default()
                .contains("不允许用作身份请求头"),
            "{problems:?}"
        );
        assert!(
            reason_on("listeners[0].sites[0].rewrites[0]")
                .unwrap_or_default()
                .contains("不是合法正则"),
            "{problems:?}"
        );
        assert!(
            reason_on("listeners[0].sites[0].rewrites[1]")
                .unwrap_or_default()
                .contains("必须以 / 开头"),
            "{problems:?}"
        );
        assert!(
            reason_on("listeners[0].sites[0].rewrites[2]")
                .unwrap_or_default()
                .contains("301/302/307/308"),
            "{problems:?}"
        );
        assert!(
            reason_on("listeners[0].sites[0].requestHeaders")
                .unwrap_or_default()
                .contains("Key: Value"),
            "{problems:?}"
        );
        // The valid response-header block raises nothing.
        assert!(
            problems
                .iter()
                .all(|problem| !problem.field.contains("responseHeaders")),
            "{problems:?}"
        );
    }

    #[test]
    fn wp23_cors_and_user_routes() {
        let mut bad = proxy_site("s", &["a.test"]);
        bad.cors = CorsSite {
            allow_origins: vec![
                "https://good.test".to_string(),
                "ftp://bad.test".to_string(),
                "https://bad.test/path".to_string(),
                "*".to_string(),
            ],
            max_age_secs: 86_401,
            ..CorsSite::default()
        };
        bad.user_routes = vec![
            UserRouteSite {
                users: vec!["alice".to_string()],
                targets: vec!["127.0.0.1:8001".to_string()],
            },
            UserRouteSite {
                users: Vec::new(),
                targets: vec!["127.0.0.1:8002".to_string()],
            },
            UserRouteSite {
                users: vec!["alice".to_string()],
                targets: Vec::new(),
            },
            UserRouteSite {
                users: vec!["oidc:Portal-1".to_string()],
                targets: vec!["http://10.0.0.1:8003 weight=2".to_string()],
            },
            UserRouteSite {
                users: vec!["OIDC:portal-1".to_string()],
                targets: vec!["127.0.0.1:8004".to_string()],
            },
        ];
        let problems = validate(&config(vec![listener("a", 8080, vec![bad])]));
        let has = |field: &str| problems.iter().any(|problem| problem.field == field);
        let base = "listeners[0].sites[0]";

        // Origins 1 and 2 are malformed; 0 and the wildcard pass.
        assert!(has(&format!("{base}.cors.allowOrigins[1]")), "{problems:?}");
        assert!(has(&format!("{base}.cors.allowOrigins[2]")), "{problems:?}");
        assert!(
            !problems
                .iter()
                .any(|problem| problem.field.contains("allowOrigins[0]")
                    || problem.field.contains("allowOrigins[3]")),
            "{problems:?}"
        );
        assert!(has(&format!("{base}.cors.maxAgeSecs")), "{problems:?}");

        // Empty users, empty targets, duplicate names and duplicate
        // third-party identities (case-normalized) all report.
        assert!(has(&format!("{base}.userRoutes[1].users")), "{problems:?}");
        assert!(has(&format!("{base}.userRoutes[2].targets")), "{problems:?}");
        assert!(has(&format!("{base}.userRoutes[2].users")), "{problems:?}");
        assert!(has(&format!("{base}.userRoutes[4].users")), "{problems:?}");
        // Routes 0 and 3 (a fresh third-party identity) stay clean.
        assert!(
            !problems
                .iter()
                .any(|problem| problem.field.starts_with(&format!("{base}.userRoutes[0]"))
                    || problem.field.starts_with(&format!("{base}.userRoutes[3]"))),
            "{problems:?}"
        );
    }

    #[test]
    fn wp23_clean_proxy_site_has_no_problems() {
        let mut site = proxy_site("s", &["a.test"]);
        site.targets = vec![
            "http://10.0.0.1:8080 weight=3".to_string(),
            "http://10.0.0.2:8080 backup".to_string(),
        ];
        site.lb_policy = "least_conn".to_string();
        site.use_target_host = true;
        site.forwarded_headers = true;
        site.insecure_skip_verify = true;
        site.disable_keep_alives = true;
        site.send_proxy_protocol = false;
        site.upstream_sni_from_host = true;
        site.pass_auth_cookies = true;
        site.timeouts_connect_secs = 10;
        site.timeouts_tls_secs = 10;
        site.timeouts_response_secs = 3600;
        site.client_idle_read_secs = 60;
        site.client_idle_write_secs = 60;
        site.rewrites = vec![
            RewriteSite {
                pattern: "^/api/(.*)".to_string(),
                to: "/v2/$1".to_string(),
                redirect: false,
                code: 0,
            },
            RewriteSite {
                pattern: "^/old".to_string(),
                to: "https://{host}/new".to_string(),
                redirect: true,
                code: 308,
            },
        ];
        site.request_headers = vec!["X-Request-Id: kept".to_string(), "X-Trace:".to_string()];
        site.response_headers = vec!["X-Frame-Options: DENY".to_string()];
        site.cors = CorsSite {
            allow_origins: vec![
                "https://app.test:8443".to_string(),
                "http://app.test".to_string(),
                "*".to_string(),
            ],
            allow_methods: vec!["GET".to_string(), "POST".to_string()],
            allow_headers: vec!["X-Token".to_string()],
            allow_credentials: true,
            max_age_secs: 86_400,
        };
        site.identity_headers = vec![
            IdentitySite {
                header: "X-User".to_string(),
                field: "user".to_string(),
            },
            IdentitySite {
                header: "X-User-Email".to_string(),
                field: "email".to_string(),
            },
            IdentitySite {
                header: "X-User-Groups".to_string(),
                field: "groups".to_string(),
            },
        ];
        site.user_routes = vec![
            UserRouteSite {
                users: vec!["alice".to_string(), "oidc:Portal-1".to_string()],
                targets: vec!["127.0.0.1:8001".to_string()],
            },
            UserRouteSite {
                users: vec!["bob".to_string(), "OIDC:portal-2".to_string()],
                targets: vec!["http://10.0.0.3:8002 weight=2 backup".to_string()],
            },
        ];
        let problems = validate(&config(vec![listener("a", 8080, vec![site])]));
        assert!(problems.is_empty(), "{problems:?}");
    }
}
