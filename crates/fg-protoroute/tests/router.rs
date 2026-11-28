//! Integration tests for route validation, compilation, matching priority,
//! and MatchKey counter inheritance semantics (WP-35 §6).

use fg_protoroute::model::{FileConfig, Net, Protocol, ProxyProtocol, Route, Rule, Settings};
use fg_protoroute::router::{RouteTable, Target, match_key};
use fg_protoroute::sniff::SniffResult;
use fg_protoroute::validate::{normalize, validate, validate_with_caps};

fn make_route(name: &str, protocol: Protocol, domains: &[&str], alpn: &[&str]) -> Route {
    Route {
        name: name.into(),
        protocol,
        domains: domains.iter().map(|d| (*d).into()).collect(),
        alpn: alpn.iter().map(|a| (*a).into()).collect(),
        target_addresses: vec!["10.0.0.1".into()],
        target_port: 8443,
        ..Route::default()
    }
}

fn make_rule(routes: Vec<Route>) -> Rule {
    Rule {
        key: "rule00000001".into(),
        name: "shared-443".into(),
        enable: true,
        protocols: vec![Net::Tcp],
        listen_address: "0.0.0.0".into(),
        listen_ports: "443".into(),
        routes,
        ..Rule::default()
    }
}

fn sniff_tls(sni: Option<&str>, alpn: &[&str]) -> SniffResult {
    SniffResult {
        protocol: Protocol::Tls,
        server_name: sni.map(str::to_owned),
        alpn: alpn.iter().map(|a| (*a).to_owned()).collect(),
        host: None,
        raw: Vec::new(),
    }
}

#[test]
fn validate_conflicts_among_enabled_routes_only() {
    let mut disabled = make_route("backup", Protocol::Tls, &["a.example"], &[]);
    disabled.disabled = true;
    let ok = FileConfig {
        settings: Settings::default(),
        rules: vec![make_rule(vec![
            make_route("primary", Protocol::Tls, &["a.example"], &[]),
            disabled,
        ])],
    };
    assert!(validate(&normalize(ok)).is_empty());

    // Overlapping domain sets across two enabled routes must conflict.
    let overlap = FileConfig {
        settings: Settings::default(),
        rules: vec![make_rule(vec![
            make_route("r1", Protocol::Tls, &["a.example", "b.example"], &[]),
            make_route("r2", Protocol::Tls, &["b.example"], &[]),
        ])],
    };
    let problems = validate(&normalize(overlap));
    assert!(
        problems.iter().any(|p| p.field.ends_with(".routes")),
        "overlapping domain sets must fail validation: {problems:?}"
    );

    // Overlapping ALPN sets on the same domain must conflict.
    let alpn_overlap = FileConfig {
        settings: Settings::default(),
        rules: vec![make_rule(vec![
            make_route("r1", Protocol::Tls, &["a.example"], &["h2", "http/1.1"]),
            make_route("r2", Protocol::Tls, &["a.example"], &["h2"]),
        ])],
    };
    assert!(
        validate(&normalize(alpn_overlap))
            .iter()
            .any(|p| p.field.ends_with(".routes"))
    );
}

#[test]
fn validate_one_route_per_protocol_and_one_timeout() {
    let ssh_dup = FileConfig {
        settings: Settings::default(),
        rules: vec![make_rule(vec![
            make_route("ssh1", Protocol::Ssh, &[], &[]),
            make_route("ssh2", Protocol::Ssh, &[], &[]),
        ])],
    };
    assert!(!validate(&normalize(ssh_dup)).is_empty());

    let timeout_dup = FileConfig {
        settings: Settings::default(),
        rules: vec![make_rule(vec![
            make_route("t1", Protocol::Timeout, &[], &[]),
            make_route("t2", Protocol::Timeout, &[], &[]),
        ])],
    };
    assert!(!validate(&normalize(timeout_dup)).is_empty());
}

#[test]
fn validate_rejects_port_path_at_in_domain() {
    for bad in [
        "a.example:443",
        "a.example/path",
        "user@a.example",
        "*a.example",
        "a.*.example",
    ] {
        let cfg = normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![make_rule(vec![make_route("r", Protocol::Tls, &[bad], &[])])],
        });
        assert!(
            validate(&cfg).iter().any(|p| p.field.ends_with(".domains")),
            "must reject invalid domain {bad:?}"
        );
    }

    // Valid wildcards & exact & star must pass.
    for good in ["*", "*.example", "*.sub.example", "exact.example"] {
        let cfg = normalize(FileConfig {
            settings: Settings::default(),
            rules: vec![make_rule(vec![make_route(
                "r",
                Protocol::Tls,
                &[good],
                &[],
            )])],
        });
        assert!(
            validate(&cfg).is_empty(),
            "valid domain {good:?} should pass: {:?}",
            validate(&cfg)
        );
    }
}

#[test]
fn validate_spa_route_cannot_require_knock() {
    let mut spa = Route {
        name: "knock-in".into(),
        protocol: Protocol::Spa,
        knock: Some("k1".into()),
        ..Route::default()
    };
    let cfg = normalize(FileConfig {
        settings: Settings::default(),
        rules: vec![make_rule(vec![spa.clone()])],
    });
    assert!(validate(&cfg).iter().any(|p| p.field.ends_with(".knock")));

    // Without knock module compiled in, spa route and knock rule gate both fail.
    spa.knock = None;
    let mut rule = make_rule(vec![spa]);
    rule.knock = Some("k1".into());
    let cfg = normalize(FileConfig {
        settings: Settings::default(),
        rules: vec![rule],
    });
    let problems = validate_with_caps(&cfg, false);
    assert!(
        problems.len() >= 2,
        "expected knock-unavailable errors: {problems:?}"
    );
}

#[test]
fn match_exact_then_longest_wildcard_then_star_then_generic() {
    let routes = vec![
        make_route("generic", Protocol::Tls, &[], &[]),
        make_route("star", Protocol::Tls, &["*"], &[]),
        make_route("short-wild", Protocol::Tls, &["*.example"], &[]),
        make_route("long-wild", Protocol::Tls, &["*.svc.example"], &[]),
        make_route("exact", Protocol::Tls, &["api.svc.example"], &[]),
    ];
    let table = RouteTable::compile(&routes, true, None).expect("compile");
    assert_eq!(
        table.route(&sniff_tls(Some("api.svc.example"), &[])),
        Target::Route(4)
    );
    assert_eq!(
        table.route(&sniff_tls(Some("web.svc.example"), &[])),
        Target::Route(3)
    );
    assert_eq!(
        table.route(&sniff_tls(Some("a.b.svc.example"), &[])),
        Target::Route(3)
    );
    assert_eq!(
        table.route(&sniff_tls(Some("other.example"), &[])),
        Target::Route(2)
    );
    assert_eq!(
        table.route(&sniff_tls(Some("random.org"), &[])),
        Target::Route(1)
    );
    assert_eq!(table.route(&sniff_tls(None, &[])), Target::Route(0));
}

#[test]
fn match_alpn_more_specific_wins_and_falls_back_outward() {
    let routes = vec![
        make_route("exact-h2", Protocol::Tls, &["app.example"], &["h2"]),
        make_route("wild-http11", Protocol::Tls, &["*.example"], &["http/1.1"]),
        make_route("wild-any", Protocol::Tls, &["*.example"], &[]),
        make_route("star-acme", Protocol::Tls, &["*"], &["acme-tls/1"]),
        make_route("generic", Protocol::Tls, &[], &[]),
    ];
    let table = RouteTable::compile(&routes, false, None).expect("compile");
    assert_eq!(
        table.route(&sniff_tls(Some("app.example"), &["h2"])),
        Target::Route(0)
    );
    // Exact has only h2; client offers http/1.1 -> continues outward to *.example (http/1.1).
    assert_eq!(
        table.route(&sniff_tls(Some("app.example"), &["http/1.1"])),
        Target::Route(1)
    );
    // Exact has only h2, wildcard has http/1.1 + any -> client offers acme-tls/1 -> hits wild-any
    // because wildcard's unrestricted route is at the wildcard level (more specific than `*`).
    assert_eq!(
        table.route(&sniff_tls(Some("app.example"), &["acme-tls/1"])),
        Target::Route(2)
    );
    // Unrelated domain with acme-tls/1 hits `*` ALPN route.
    assert_eq!(
        table.route(&sniff_tls(Some("other.net"), &["acme-tls/1"])),
        Target::Route(3)
    );
    // Unrelated domain with no matching ALPN falls through `*` to generic.
    assert_eq!(
        table.route(&sniff_tls(Some("other.net"), &["h2"])),
        Target::Route(4)
    );
}

#[test]
fn match_alpn_by_client_preference_order() {
    let routes = vec![
        make_route("r-h2", Protocol::Tls, &["app.example"], &["h2"]),
        make_route("r-h1", Protocol::Tls, &["app.example"], &["http/1.1"]),
    ];
    let table = RouteTable::compile(&routes, false, None).expect("compile");
    assert_eq!(
        table.route(&sniff_tls(Some("app.example"), &["http/1.1", "h2"])),
        Target::Route(1)
    );
    assert_eq!(
        table.route(&sniff_tls(Some("app.example"), &["h2", "http/1.1"])),
        Target::Route(0)
    );
}

#[test]
fn counts_inherit_by_match_key() {
    let r1 = make_route(
        "web",
        Protocol::Tls,
        &["b.example", "A.Example."],
        &["http/1.1", "h2"],
    );
    let mut r2 = make_route(
        "renamed",
        Protocol::Tls,
        &["a.example", "b.example"],
        &["h2", "http/1.1"],
    );
    r2.target_addresses = vec!["10.9.9.9".into()];
    r2.target_port = 9999;
    r2.proxy_protocol = ProxyProtocol::V2;
    assert_eq!(match_key(&r1), match_key(&r2));

    let mut changed_domain = r1.clone();
    changed_domain.domains = vec!["c.example".into()];
    assert_ne!(match_key(&r1), match_key(&changed_domain));

    let mut changed_alpn = r1.clone();
    changed_alpn.alpn = vec!["h2".into()];
    assert_ne!(match_key(&r1), match_key(&changed_alpn));

    let mut changed_proto = r1.clone();
    changed_proto.protocol = Protocol::Http;
    assert_ne!(match_key(&r1), match_key(&changed_proto));
}
