//! The metrics output surface (WP-55: "计数与指标输出面", counters per the
//! upstream display fields 累计拦截数/命中数). Sample names follow the
//! workspace convention `ferrumgate_<module>_<name>` (see
//! `fg_core::metrics`); render them with
//! `fg_core::metrics::write_text` at the global metrics endpoint. The
//! integration layer (WP-55 集成层) forwards these per instance.

use fg_core::metrics::Sample;

use crate::engine::Engine;

/// Collects the engine's Prometheus samples:
///
/// - `ferrumgate_waf_requests_total` — requests evaluated
/// - `ferrumgate_waf_hits_total` — rule hits in total
/// - `ferrumgate_waf_denied_total` — requests denied by a rule
/// - `ferrumgate_waf_allowed_total` — requests explicitly allowed
/// - `ferrumgate_waf_rules` — rules in the active compiled snapshot
/// - `ferrumgate_waf_compile_errors` — errors from the last reload
///   attempt (the "最近一次错误" seam for the instance list)
/// - `ferrumgate_waf_rule_hits_total{rule}` — hits per rule
pub fn samples(engine: &Engine) -> Vec<Sample> {
    let stats = engine.stats();
    let snapshot = engine.snapshot();
    let compile_errors = engine.compile_errors().len();
    let mut out = Vec::with_capacity(7 + snapshot.rule_count());
    out.push(Sample::counter(
        "ferrumgate_waf_requests_total",
        "Requests evaluated by the WAF engine",
        stats.requests as f64,
    ));
    out.push(Sample::counter(
        "ferrumgate_waf_hits_total",
        "Rule hits recorded by the WAF engine",
        stats.hits as f64,
    ));
    out.push(Sample::counter(
        "ferrumgate_waf_denied_total",
        "Requests denied by a WAF rule",
        stats.denied as f64,
    ));
    out.push(Sample::counter(
        "ferrumgate_waf_allowed_total",
        "Requests explicitly allowed by a WAF rule",
        stats.allowed as f64,
    ));
    out.push(Sample::gauge(
        "ferrumgate_waf_rules",
        "Rules in the active compiled WAF snapshot",
        snapshot.rule_count() as f64,
    ));
    out.push(Sample::gauge(
        "ferrumgate_waf_compile_errors",
        "Compile errors reported by the last WAF reload attempt",
        compile_errors as f64,
    ));
    for rule in snapshot.rules() {
        out.push(
            Sample::counter(
                "ferrumgate_waf_rule_hits_total",
                "Hits per WAF rule",
                rule.hit_count() as f64,
            )
            .label("rule", rule.id.as_ref()),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::EngineConfig;
    use crate::rule::RuleSetFile;

    fn engine_with_two_rules() -> Engine {
        let set = RuleSetFile::from_json(
            br#"{ "name": "set", "rules": [
                { "id": "1", "match": { "field": "path", "op": "contains", "value": "/a" } },
                { "id": "2", "action": "allow", "match": { "field": "path", "op": "contains", "value": "/b" } }
            ] }"#,
        )
        .expect("parses");
        Engine::new(
            EngineConfig::default(),
            &set,
            crate::engine::EngineHooks::default(),
        )
        .expect("compiles")
    }

    #[test]
    fn samples_expose_the_engine_counters_and_per_rule_hits() {
        let engine = engine_with_two_rules();
        let req = crate::request::Request {
            method: "GET",
            host: "example.com",
            path: "/a",
            query: "",
            user_agent: "",
            client_ip: None,
            body: None,
            headers: &[],
        };
        assert_eq!(
            engine.check(&req),
            crate::engine::Decision::Deny { status: 403 }
        );
        let samples = samples(&engine);
        let find = |name: &str| {
            samples
                .iter()
                .find(|sample| sample.name == name)
                .unwrap_or_else(|| panic!("missing sample {name}"))
        };
        assert_eq!(find("ferrumgate_waf_requests_total").value, 1.0);
        assert_eq!(find("ferrumgate_waf_hits_total").value, 1.0);
        assert_eq!(find("ferrumgate_waf_denied_total").value, 1.0);
        assert_eq!(find("ferrumgate_waf_allowed_total").value, 0.0);
        assert_eq!(find("ferrumgate_waf_rules").value, 2.0);
        assert_eq!(find("ferrumgate_waf_compile_errors").value, 0.0);
        let rule_hits: Vec<&Sample> = samples
            .iter()
            .filter(|sample| sample.name == "ferrumgate_waf_rule_hits_total")
            .collect();
        assert_eq!(rule_hits.len(), 2);
        assert_eq!(
            rule_hits[0].labels.get("rule"),
            Some(&"1".to_owned()),
            "rule hits carry the rule id label"
        );
        assert_eq!(rule_hits[0].value, 1.0);
    }

    #[test]
    fn samples_render_with_the_shared_prometheus_writer() {
        let engine = engine_with_two_rules();
        let text = fg_core::metrics::write_text(&samples(&engine));
        assert!(
            text.contains("# TYPE ferrumgate_waf_requests_total counter"),
            "{text}"
        );
        assert!(
            text.contains("ferrumgate_waf_rule_hits_total{rule=\"1\"} 0"),
            "{text}"
        );
    }

    #[test]
    fn samples_report_compile_errors_from_the_last_reload() {
        let engine = engine_with_two_rules();
        let broken = RuleSetFile::from_json(
            br#"{ "rules": [ { "id": "1", "match": { "field": "path", "op": "regex", "value": "[" } } ] }"#,
        )
        .expect("parses");
        engine.reload(&broken).expect_err("broken rule set");
        let samples = samples(&engine);
        let find = |name: &str| {
            samples
                .iter()
                .find(|sample| sample.name == name)
                .unwrap_or_else(|| panic!("missing sample {name}"))
        };
        assert_eq!(find("ferrumgate_waf_compile_errors").value, 1.0);
        assert_eq!(
            find("ferrumgate_waf_rules").value,
            2.0,
            "a failed reload keeps the previous snapshot"
        );
    }
}
