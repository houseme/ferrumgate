//! Integration tests for the WAF engine surface (WP-55 §6 引擎层, mapped
//! to this tier): JSON rule sets end to end — parse, compile, snapshot
//! evaluation, actions, counting, reload, metrics and the event surface.

use std::net::{IpAddr, Ipv4Addr};

use fg_waf_engine::{
    ActionKind, Decision, Engine, EngineConfig, EngineHooks, Evaluated, RuleSetFile, blocked_event,
    compile, evaluate,
};
use fg_waf_engine::{HeaderPair, Request};

fn request<'a>(
    method: &'a str,
    path: &'a str,
    query: &'a str,
    headers: &'a [HeaderPair<'a>],
    body: Option<&'a [u8]>,
    client_ip: Option<IpAddr>,
) -> Request<'a> {
    Request {
        method,
        host: "example.com",
        path,
        query,
        user_agent: "integration-test/1.0",
        client_ip,
        body,
        headers,
    }
}

const RULES_JSON: &str = r#"{
    "version": 1,
    "name": "integration",
    "rules": [
        {
            "id": "1000",
            "name": "allow health checks",
            "match": { "field": "path", "op": "prefix", "value": "/health" },
            "action": "allow"
        },
        {
            "id": "1001",
            "name": "block env probes",
            "match": { "any": [
                { "field": "path", "op": "regex", "value": "\\.(env|git|bak)$" },
                { "field": "query", "op": "contains", "value": "../" }
            ] },
            "action": "deny",
            "status": 403,
            "message": "probe blocked",
            "tags": ["scanner"]
        },
        {
            "id": "1002",
            "name": "count internal scanners",
            "match": { "all": [
                { "field": "clientIp", "op": "ipIn", "value": "10.0.0.0/8" },
                { "field": "path", "op": "prefix", "value": "/admin" }
            ] },
            "action": "count"
        }
    ]
}"#;

fn engine_with_rules() -> Engine {
    let set = RuleSetFile::from_json(RULES_JSON.as_bytes()).expect("rule set parses");
    Engine::new(EngineConfig::default(), &set, EngineHooks::default()).expect("rule set compiles")
}

#[test]
fn ruleset_json_roundtrip_preserves_the_document() {
    let set = RuleSetFile::from_json(RULES_JSON.as_bytes()).expect("parses");
    let bytes = serde_json::to_vec(&set).expect("serializes");
    let reparsed = RuleSetFile::from_json(&bytes).expect("reparses");
    assert_eq!(set, reparsed);
}

#[test]
fn compiled_ruleset_reports_its_shape_and_actions() {
    let set = RuleSetFile::from_json(RULES_JSON.as_bytes()).expect("parses");
    let compiled = compile(&set, EngineConfig::default()).expect("compiles");
    assert_eq!(compiled.name, "integration");
    assert_eq!(compiled.rule_count(), 3);
    let actions: Vec<ActionKind> = compiled.rules().iter().map(|rule| rule.action).collect();
    assert_eq!(
        actions,
        vec![ActionKind::Allow, ActionKind::Deny, ActionKind::Count]
    );
}

#[test]
fn probe_rules_block_env_and_traversal_payloads() {
    let engine = engine_with_rules();
    let probe = request("GET", "/credentials.env", "", &[], None, None);
    assert_eq!(engine.check(&probe), Decision::Deny { status: 403 });
    let traversal = request("GET", "/", "?file=../../etc/passwd", &[], None, None);
    assert_eq!(engine.check(&traversal), Decision::Deny { status: 403 });
    let normal = request("GET", "/", "?page=2", &[], None, None);
    assert_eq!(engine.check(&normal), Decision::Pass);
}

#[test]
fn allow_rule_precedes_deny_for_health_paths() {
    let engine = engine_with_rules();
    let health = request("GET", "/health/live", "", &[], None, None);
    assert_eq!(engine.check(&health), Decision::Allow);
}

#[test]
fn count_rule_records_internal_scanner_hits_and_continues() {
    let engine = engine_with_rules();
    let internal = request(
        "GET",
        "/admin/console",
        "",
        &[],
        None,
        Some(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40))),
    );
    assert_eq!(engine.check(&internal), Decision::Pass);
    let snapshot = engine.snapshot();
    let counter = snapshot
        .rules()
        .iter()
        .find(|rule| &*rule.id == "1002")
        .expect("count rule present");
    assert_eq!(counter.hit_count(), 1);
    // An external client does not fill the counter.
    let external = request(
        "GET",
        "/admin/console",
        "",
        &[],
        None,
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
    );
    assert_eq!(engine.check(&external), Decision::Pass);
    assert_eq!(counter.hit_count(), 1);
}

#[test]
fn reload_replaces_the_active_rules_and_keeps_the_old_snapshot() {
    let engine = engine_with_rules();
    let old_snapshot = engine.snapshot();
    let probe = request("GET", "/credentials.env", "", &[], None, None);
    assert_eq!(engine.check(&probe), Decision::Deny { status: 403 });
    let updated = RuleSetFile::from_json(
        br#"{ "name": "integration", "rules": [
            { "id": "2000", "match": { "field": "path", "op": "prefix", "value": "/blocked" } }
        ] }"#,
    )
    .expect("parses");
    engine.reload(&updated).expect("reload");
    assert_eq!(engine.check(&probe), Decision::Pass, "old rule is gone");
    let blocked = request("GET", "/blocked/now", "", &[], None, None);
    assert_eq!(engine.check(&blocked), Decision::Deny { status: 403 });
    // The handle taken before the reload still evaluates its own rules.
    assert_eq!(
        evaluate(&old_snapshot, &probe).decision,
        Decision::Deny { status: 403 }
    );
}

#[test]
fn blocked_hook_and_event_surface_carry_the_hit_details() {
    let events: std::sync::Arc<std::sync::Mutex<Vec<u16>>> = std::sync::Arc::default();
    let hook = {
        let events = std::sync::Arc::clone(&events);
        std::sync::Arc::new(move |hit: &fg_waf_engine::BlockedHit<'_>| {
            let event = blocked_event(hit);
            assert_eq!(event.kind.info().name, "waf.blocked");
            events.lock().expect("events").push(hit.status);
        })
    };
    let set = RuleSetFile::from_json(
        br#"{ "rules": [
            { "id": "1", "status": 406, "match": { "field": "userAgent", "op": "contains", "value": "curl" } }
        ] }"#,
    )
    .expect("parses");
    let engine = Engine::new(
        EngineConfig::default(),
        &set,
        EngineHooks {
            blocked: Some(hook),
        },
    )
    .expect("compiles");
    let curl = request("GET", "/", "", &[], None, None);
    let curl = Request {
        user_agent: "curl/8.4",
        ..curl
    };
    assert_eq!(engine.check(&curl), Decision::Deny { status: 406 });
    assert_eq!(events.lock().expect("events").clone(), vec![406]);
}

#[test]
fn metrics_surface_counts_requests_hits_and_denials() {
    let engine = engine_with_rules();
    for (path, expected) in [
        ("/health", Decision::Allow),
        ("/credentials.env", Decision::Deny { status: 403 }),
        ("/", Decision::Pass),
    ] {
        let req = request("GET", path, "", &[], None, None);
        assert_eq!(engine.check(&req), expected);
    }
    let samples = fg_waf_engine::metrics::samples(&engine);
    let value = |name: &str| {
        samples
            .iter()
            .find(|sample| sample.name == name)
            .unwrap_or_else(|| panic!("missing {name}"))
            .value
    };
    assert_eq!(value("ferrumgate_waf_requests_total"), 3.0);
    assert_eq!(value("ferrumgate_waf_hits_total"), 2.0);
    assert_eq!(value("ferrumgate_waf_denied_total"), 1.0);
    assert_eq!(value("ferrumgate_waf_allowed_total"), 1.0);
    assert_eq!(value("ferrumgate_waf_rules"), 3.0);
}

#[test]
fn evaluate_reports_matched_rules_for_hit_logs() {
    let engine = engine_with_rules();
    let snapshot = engine.snapshot();
    let probe = request("GET", "/secret.env", "", &[], None, None);
    let evaluated: Evaluated<'_> = evaluate(&snapshot, &probe);
    assert_eq!(evaluated.decision, Decision::Deny { status: 403 });
    let hit = evaluated.matched.last().expect("deciding rule");
    assert_eq!(&*hit.id, "1001");
    assert_eq!(&*hit.name, "block env probes");
    assert_eq!(&*hit.message, "probe blocked");
    assert_eq!(hit.tags.len(), 1);
}
