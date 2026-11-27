//! Library-level integration tests for the WP-20 web service model: the
//! `domains`, `model`, `validate` and `table` modules working together.
//! This covers the library half of plan step 6 (「监听器集合接口与保存后的
//! 生效比较」); the listener collection routes land in a later increment,
//! so no HTTP server is started here.

use fg_gateway::web::{domains, model, table, validate};

/// A site with the shared boilerplate filled in and `site_type` set.
fn site(key: &str, site_type: &str, site_domains: &[&str]) -> model::Site {
    model::Site {
        key: key.to_string(),
        name: format!("{key} site"),
        enable: true,
        domains: site_domains.iter().map(|d| d.to_string()).collect(),
        site_type: site_type.to_string(),
        ..model::Site::default()
    }
}

fn proxy_site(key: &str, site_domains: &[&str], target: &str) -> model::Site {
    let mut site = site(key, "proxy", site_domains);
    site.targets = vec![target.to_string()];
    site
}

fn redirect_site(key: &str, site_domains: &[&str], redirect_to: &str) -> model::Site {
    let mut site = site(key, "redirect", site_domains);
    site.redirect_to = redirect_to.to_string();
    site.redirect_code = 302;
    site
}

fn static_site(key: &str, site_domains: &[&str], root: &str) -> model::Site {
    let mut site = site(key, "static", site_domains);
    site.root = root.to_string();
    site
}

fn text_site(key: &str, site_domains: &[&str], body: &str) -> model::Site {
    let mut site = site(key, "text", site_domains);
    site.text_body = body.to_string();
    site.text_content_type = "text/plain".to_string();
    site
}

fn listener(key: &str, enable: bool, sites: Vec<model::Site>) -> model::Listener {
    model::Listener {
        key: key.to_string(),
        name: format!("{key} listener"),
        enable,
        network: "tcp".to_string(),
        port: 443,
        tls: true,
        sites,
        ..model::Listener::default()
    }
}

fn config(listeners: Vec<model::Listener>) -> model::FileConfig {
    model::FileConfig {
        settings: model::Settings {
            enable: true,
            ..model::Settings::default()
        },
        listeners,
    }
}

/// The site key a compiled table resolves a host to, if any.
fn resolved_key(compiled: &table::SiteTable, host: &str) -> Option<String> {
    compiled
        .find(host)
        .map(|index| compiled.site(index).site.key.clone())
}

#[test]
fn domain_capture_feeds_redirect_variables() {
    // A site with a wildcard domain and a redirect template: the capture
    // from the request host is the redirect variable `{1}`.
    let shop = redirect_site("shop", &["*.Example.COM."], "https://target.test/{1}");

    let pattern = domains::normalize_pattern(&shop.domains[0]).expect("wildcard normalizes");
    let captured = domains::capture(&pattern, "Shop.Example.COM").expect("request host matches");
    assert_eq!(
        captured, "shop",
        "the capture is the text the wildcard consumed"
    );

    let redirect_to = shop.redirect_to.replace("{1}", &captured);
    assert_eq!(redirect_to, "https://target.test/shop");

    // Multi-label hosts capture everything the wildcard consumed at once.
    let captured = domains::capture(&pattern, "a.b.Example.COM").expect("deep subdomain matches");
    assert_eq!(
        shop.redirect_to.replace("{1}", &captured),
        "https://target.test/a.b"
    );

    // The same pipeline feeds redirect variables for the in-label form.
    let pattern = domains::normalize_pattern("api-*.example.com").expect("in-label normalizes");
    let captured = domains::capture(&pattern, "API-7.Example.COM").expect("api-7 matches");
    assert_eq!(captured, "7");
    assert_eq!(
        "https://api.target.test/{1}".replace("{1}", &captured),
        "https://api.target.test/7"
    );

    // Hosts outside the pattern produce no variable at all.
    assert_eq!(domains::capture(&pattern, "example.com"), None);
    assert_eq!(domains::capture(&pattern, "notexample.com"), None);
}

#[test]
fn validate_then_compile_produces_table() {
    let good = config(vec![
        listener(
            "edge",
            true,
            vec![
                proxy_site("api", &["api.example.com"], "127.0.0.1:8080"),
                redirect_site("shop", &["*.example.com"], "https://target.test/{1}"),
                static_site("files", &["static.example.com"], "/srv/www"),
                text_site("notice", &["text.example.com"], "maintenance"),
            ],
        ),
        // A disabled listener: its sites are never compiled below.
        listener(
            "admin",
            false,
            vec![redirect_site(
                "panel",
                &["admin.internal.test"],
                "https://internal.test/",
            )],
        ),
    ]);

    let normalized = validate::normalize(good);
    let problems = validate::validate(&normalized);
    assert!(
        problems.is_empty(),
        "well-formed config must validate clean: {problems:?}"
    );

    let enabled = normalized
        .listeners
        .iter()
        .find(|listener| listener.enable)
        .expect("one enabled listener");
    let compiled = table::SiteTable::compile(enabled, None);
    assert_eq!(
        compiled.len(),
        4,
        "only the enabled listener's sites are compiled"
    );

    // Exact rules resolve through the hash index, mixed case included.
    assert_eq!(
        resolved_key(&compiled, "api.example.com").as_deref(),
        Some("api")
    );
    assert_eq!(
        resolved_key(&compiled, "API.Example.COM").as_deref(),
        Some("api")
    );
    assert_eq!(
        resolved_key(&compiled, "static.example.com").as_deref(),
        Some("files")
    );
    assert_eq!(
        resolved_key(&compiled, "text.example.com").as_deref(),
        Some("notice")
    );

    // The wildcard serves the remaining subdomains; unmatched hosts miss.
    assert_eq!(
        resolved_key(&compiled, "shop.example.com").as_deref(),
        Some("shop")
    );
    assert_eq!(
        resolved_key(&compiled, "a.b.example.com").as_deref(),
        Some("shop"),
        "one or more leading labels match"
    );
    assert_eq!(resolved_key(&compiled, "unrelated.test"), None);

    // A malformed config collects problems instead: a proxy without
    // targets, a redirect without a target, an unknown site type. Overlap
    // between two sites' domains is deliberately absent — the first site
    // wins and saving is not rejected (plan §3.3).
    let mut no_targets = proxy_site("broken", &["broken.example.com"], "127.0.0.1:9000");
    no_targets.targets.clear();
    let no_target_url = redirect_site("drift", &["drift.example.com"], "");
    let unknown_type = site("mystery", "warp", &["warp.example.com"]);
    let bad = config(vec![listener(
        "bad",
        true,
        vec![no_targets, no_target_url, unknown_type],
    )]);
    let problems = validate::validate(&validate::normalize(bad));
    assert!(
        !problems.is_empty(),
        "proxy without targets, redirect without target and unknown site type must collect problems: {problems:?}"
    );
}

#[test]
fn old_table_captures_subsequent_matches() {
    let first = config(vec![listener(
        "edge",
        true,
        vec![
            proxy_site("api", &["api.example.com"], "127.0.0.1:8080"),
            redirect_site("old", &["old.example.com"], "https://legacy.example.test/"),
        ],
    )]);
    let normalized = validate::normalize(first);
    let current = table::SiteTable::compile(&normalized.listeners[0], None);
    assert_eq!(current.len(), 2);
    assert_eq!(
        resolved_key(&current, "api.example.com").as_deref(),
        Some("api")
    );

    // Save a modified site list: "api" is deleted, "old" is retargeted,
    // "notice" is added.
    let mut updated = normalized.clone();
    let listener = &mut updated.listeners[0];
    listener.sites.retain(|site| site.key != "api");
    let old = listener
        .sites
        .iter_mut()
        .find(|site| site.key == "old")
        .expect("the old site is kept");
    old.redirect_to = "https://moved.example.test/".to_string();
    listener
        .sites
        .push(text_site("notice", &["notice.example.com"], "hello"));

    // Re-compile with the previous table handed over.
    let next = table::SiteTable::compile(listener, Some(&current));
    assert_eq!(next.len(), 2, "the removed site is no longer compiled");
    assert_eq!(
        resolved_key(&next, "api.example.com"),
        None,
        "a deleted site stops resolving"
    );
    assert_eq!(
        resolved_key(&next, "notice.example.com").as_deref(),
        Some("notice"),
        "an added site resolves"
    );
    let index = next
        .find("old.example.com")
        .expect("the kept site still resolves");
    assert_eq!(
        next.site(index).site.redirect_to,
        "https://moved.example.test/",
        "the re-compiled table carries the modified redirect target"
    );
}
