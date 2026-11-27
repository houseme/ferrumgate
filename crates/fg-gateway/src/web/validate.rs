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
use super::model::{FileConfig, Site};

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
/// ([`compile_networks`]). The same domain in multiple sites of one
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

/// Per-site rules: domains, `siteType` requirements, the group cap and the
/// source access lists.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::model::{Listener, Settings};

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
}
