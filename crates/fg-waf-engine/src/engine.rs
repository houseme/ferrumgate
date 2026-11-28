//! The matching engine (WP-55 first engine tier): rules are compiled once
//! into an immutable [`Compiled`] snapshot published through
//! `arc_swap::ArcSwap`; a request reads exactly one snapshot and the
//! evaluation itself is a pure function over that snapshot — mirroring the
//! lock-free snapshot pattern of `fg-net`'s ban table. Mutations
//! (reloads) happen outside the hot path and atomically replace the whole
//! snapshot, so a reader never sees a half-updated rule set.
//!
//! Actions follow the batch scope: `deny` stops evaluation and rejects,
//! `allow` stops evaluation and passes, `count` records the hit and keeps
//! evaluating. A request only denied by nothing passes. Rule hits are
//! counted per rule (inside the snapshot) and per engine (aggregate
//! counters), exposed as `ferrumgate_waf_*` Prometheus samples by
//! [`crate::metrics::samples`]. Deny decisions additionally fire the
//! [`EngineHooks::blocked`] hook so the embedding module can publish the
//! registered `waf.blocked` event ([`blocked_event`]) without the engine
//! itself depending on an event bus or a tokio runtime.

use std::{
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use arc_swap::ArcSwap;
use fg_core::events::{Event, Kind};

use crate::{
    compile::{CompileError, Compiled, CompiledRule, compile},
    limits::EngineConfig,
    request::Request,
    rule::{ActionKind, RuleSetFile},
};

/// The verdict for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// No rule decided; the request passes.
    Pass,
    /// A rule with action `allow` matched; later rules were not evaluated.
    Allow,
    /// A rule with action `deny` matched; the deciding rule supplies the
    /// status.
    Deny { status: u16 },
}

/// The full result of one evaluation: the decision plus every rule that
/// matched, borrowed from the snapshot the caller holds.
#[derive(Debug)]
pub struct Evaluated<'a> {
    pub decision: Decision,
    /// Matched rules in evaluation order; for [`Decision::Allow`] and
    /// [`Decision::Deny`] the deciding rule is the last entry.
    pub matched: Vec<&'a CompiledRule>,
}

/// Evaluates a request against a snapshot. Pure with respect to
/// decisions; the only side effect is the per-rule hit counters inside
/// the snapshot (`count` rules exist to fill them).
pub fn evaluate<'a>(snapshot: &'a Compiled, req: &Request<'_>) -> Evaluated<'a> {
    let mut matched = Vec::new();
    for rule in snapshot.rules() {
        if !rule.matches(req, snapshot.body_inspect_limit) {
            continue;
        }
        rule.record_hit();
        matched.push(rule);
        match rule.action {
            ActionKind::Deny => {
                return Evaluated {
                    decision: Decision::Deny {
                        status: rule.status,
                    },
                    matched,
                };
            }
            ActionKind::Allow => {
                return Evaluated {
                    decision: Decision::Allow,
                    matched,
                };
            }
            // Count rules keep evaluating; the hit is already recorded.
            ActionKind::Count => {}
        }
    }
    Evaluated {
        decision: Decision::Pass,
        matched,
    }
}

/// Details of one deny decision, passed to [`EngineHooks::blocked`].
#[derive(Clone, Copy, Debug)]
pub struct BlockedHit<'a> {
    pub rule_id: &'a str,
    pub rule_name: &'a str,
    pub status: u16,
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    pub client_ip: Option<IpAddr>,
}

/// Hook called when a request is denied. Runs on the request's thread;
/// slow work (event bus publish, logging) belongs to the callee.
pub type BlockedHook = Arc<dyn Fn(&BlockedHit<'_>) + Send + Sync>;

/// Optional callbacks for the engine. All hooks run outside the snapshot.
#[derive(Clone, Default)]
pub struct EngineHooks {
    /// Called at most once per `check` that ends in a deny decision.
    pub blocked: Option<BlockedHook>,
}

/// Aggregate counters for observability (also exported as Prometheus
/// samples; see [`crate::metrics::samples`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EngineStats {
    /// Requests evaluated via [`Engine::check`].
    pub requests: u64,
    /// Total rule hits across all evaluations (a request can hit several
    /// `count` rules).
    pub hits: u64,
    /// Requests that ended in a deny decision.
    pub denied: u64,
    /// Requests that ended in an explicit allow decision.
    pub allowed: u64,
}

#[derive(Default)]
struct Stats {
    requests: AtomicU64,
    hits: AtomicU64,
    denied: AtomicU64,
    allowed: AtomicU64,
}

/// The shared engine. Clone-free sharing: hand out `Arc<Engine>` wherever
/// requests are checked.
pub struct Engine {
    snapshot: ArcSwap<Compiled>,
    config: EngineConfig,
    hooks: EngineHooks,
    stats: Stats,
    last_errors: Mutex<Vec<CompileError>>,
}

impl Engine {
    /// Compiles `rule_set` and returns the engine, or every compile error
    /// found (nothing is published on failure).
    pub fn new(
        config: EngineConfig,
        rule_set: &RuleSetFile,
        hooks: EngineHooks,
    ) -> Result<Self, Vec<CompileError>> {
        let config = EngineConfig::clamped(config.body_inspect_limit);
        let compiled = compile(rule_set, config)?;
        Ok(Self {
            snapshot: ArcSwap::from_pointee(compiled),
            config,
            hooks,
            stats: Stats::default(),
            last_errors: Mutex::new(Vec::new()),
        })
    }

    /// The active compiled snapshot. Call this once per request and pass
    /// the returned `Arc` to [`evaluate`]; keep holding it while reading
    /// [`Evaluated::matched`].
    pub fn snapshot(&self) -> Arc<Compiled> {
        self.snapshot.load_full()
    }

    /// The normalized configuration this engine runs with.
    pub fn config(&self) -> EngineConfig {
        self.config
    }

    /// Replaces the rule set: compiles first and keeps the previous
    /// snapshot on failure, reporting the errors through the return value
    /// and [`Engine::compile_errors`].
    pub fn reload(&self, rule_set: &RuleSetFile) -> Result<(), Vec<CompileError>> {
        match compile(rule_set, self.config) {
            Ok(compiled) => {
                *self
                    .last_errors
                    .lock()
                    .expect("waf engine compile error lock") = Vec::new();
                tracing::info!(
                    rules = compiled.rule_count(),
                    "waf engine snapshot published"
                );
                self.snapshot.store(Arc::new(compiled));
                Ok(())
            }
            Err(errors) => {
                tracing::warn!(
                    errors = errors.len(),
                    "waf rule set rejected; keeping the previous snapshot"
                );
                *self
                    .last_errors
                    .lock()
                    .expect("waf engine compile error lock") = errors.clone();
                Err(errors)
            }
        }
    }

    /// Compile errors from the last [`Engine::reload`] attempt (empty
    /// after a successful compile). Lets the integration layer show "the
    /// last error" without recompiling.
    pub fn compile_errors(&self) -> Vec<CompileError> {
        self.last_errors
            .lock()
            .expect("waf engine compile error lock")
            .clone()
    }

    /// Aggregate counters.
    pub fn stats(&self) -> EngineStats {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        EngineStats {
            requests: load(&self.stats.requests),
            hits: load(&self.stats.hits),
            denied: load(&self.stats.denied),
            allowed: load(&self.stats.allowed),
        }
    }

    /// Convenience path for callers that only need the verdict: loads the
    /// snapshot once, evaluates, updates the aggregate counters and fires
    /// the [`EngineHooks::blocked`] hook on a deny decision. Callers that
    /// need the matched rules use [`Engine::snapshot`] + [`evaluate`]
    /// instead.
    pub fn check(&self, req: &Request<'_>) -> Decision {
        let snapshot = self.snapshot();
        let evaluated = evaluate(&snapshot, req);
        let decision = evaluated.decision;
        self.stats.requests.fetch_add(1, Ordering::Relaxed);
        self.stats
            .hits
            .fetch_add(evaluated.matched.len() as u64, Ordering::Relaxed);
        match decision {
            Decision::Deny { status } => {
                self.stats.denied.fetch_add(1, Ordering::Relaxed);
                if let (Some(hook), Some(rule)) = (&self.hooks.blocked, evaluated.matched.last()) {
                    hook(&BlockedHit {
                        rule_id: &rule.id,
                        rule_name: &rule.name,
                        status,
                        method: req.method,
                        host: req.host,
                        path: req.path,
                        client_ip: req.client_ip,
                    });
                }
            }
            Decision::Allow => {
                self.stats.allowed.fetch_add(1, Ordering::Relaxed);
            }
            Decision::Pass => {}
        }
        decision
    }
}

/// Builds the `waf.blocked` event for a deny decision, using the Kind
/// registered in `fg_core::events::KINDS` (stable name `waf.blocked`,
/// default level `Warn`). The embedding module publishes it; the engine
/// never touches the bus itself.
pub fn blocked_event(hit: &BlockedHit<'_>) -> Event {
    let mut event = Event::new(Kind::WafBlocked, "waf");
    event.args = vec![
        ("rule", hit.rule_id.to_owned()),
        ("path", hit.path.to_owned()),
    ];
    event.fields = vec![
        ("rule", hit.rule_id.to_owned()),
        ("ruleName", hit.rule_name.to_owned()),
        ("status", hit.status.to_string()),
        ("method", hit.method.to_owned()),
        ("host", hit.host.to_owned()),
        ("path", hit.path.to_owned()),
    ];
    if let Some(ip) = hit.client_ip {
        event.fields.push(("ip", ip.to_string()));
    }
    event
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::{
        limits::{DEFAULT_BODY_INSPECT_LIMIT, MAX_BODY_INSPECT_LIMIT},
        request::HeaderPair,
    };

    fn engine_from_json(json: &str) -> Engine {
        let set = RuleSetFile::from_json(json.as_bytes()).expect("test rule set parses");
        Engine::new(EngineConfig::default(), &set, EngineHooks::default())
            .expect("test rule set compiles")
    }

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
            user_agent: "test-agent/1.0",
            client_ip,
            body,
            headers,
        }
    }

    fn deny_rule(id: &str, matcher: &str) -> String {
        format!(r#"{{ "id": "{id}", "match": {matcher} }}"#)
    }

    #[test]
    fn evaluate_regex_rule_blocks_the_matching_path() {
        let engine = engine_from_json(&format!(
            r#"{{ "rules": [ {} ] }}"#,
            deny_rule(
                "1001",
                r#"{ "field": "path", "op": "regex", "value": "\\.env$|\\.git/" }"#
            )
        ));
        let snapshot = engine.snapshot();
        let blocked = request("GET", "/.env", "", &[], None, None);
        let evaluated = evaluate(&snapshot, &blocked);
        assert_eq!(evaluated.decision, Decision::Deny { status: 403 });
        assert_eq!(evaluated.matched.len(), 1);
        assert_eq!(&*evaluated.matched[0].id, "1001");
        let clean = request("GET", "/environment", "", &[], None, None);
        assert_eq!(evaluate(&snapshot, &clean).decision, Decision::Pass);
    }

    #[test]
    fn evaluate_nonmatching_rules_pass_without_hits() {
        let engine = engine_from_json(&format!(
            r#"{{ "rules": [ {} ] }}"#,
            deny_rule(
                "1",
                r#"{ "field": "method", "op": "equals", "value": "TRACE" }"#
            )
        ));
        let snapshot = engine.snapshot();
        let req = request("GET", "/", "", &[], None, None);
        let evaluated = evaluate(&snapshot, &req);
        assert_eq!(evaluated.decision, Decision::Pass);
        assert!(evaluated.matched.is_empty());
        assert_eq!(snapshot.rules()[0].hit_count(), 0);
    }

    #[test]
    fn evaluate_count_action_records_the_hit_and_continues() {
        let engine = engine_from_json(
            r#"{ "rules": [
                { "id": "1", "action": "count", "match": { "field": "path", "op": "prefix", "value": "/api/" } },
                { "id": "2", "match": { "field": "path", "op": "contains", "value": "secret" } }
            ] }"#,
        );
        let snapshot = engine.snapshot();
        let req = request("GET", "/api/secret", "", &[], None, None);
        let evaluated = evaluate(&snapshot, &req);
        assert_eq!(evaluated.decision, Decision::Deny { status: 403 });
        assert_eq!(evaluated.matched.len(), 2, "count keeps evaluating");
        assert_eq!(&*evaluated.matched[1].id, "2", "the deny rule decided");
        assert_eq!(snapshot.rules()[0].hit_count(), 1);
        assert_eq!(snapshot.rules()[1].hit_count(), 1);
    }

    #[test]
    fn evaluate_allow_action_stops_the_evaluation() {
        let engine = engine_from_json(
            r#"{ "rules": [
                { "id": "1", "action": "allow", "match": { "field": "path", "op": "prefix", "value": "/health" } },
                { "id": "2", "match": { "field": "path", "op": "prefix", "value": "/health/live" } }
            ] }"#,
        );
        let snapshot = engine.snapshot();
        let req = request("GET", "/health/live", "", &[], None, None);
        let evaluated = evaluate(&snapshot, &req);
        assert_eq!(evaluated.decision, Decision::Allow);
        assert_eq!(evaluated.matched.len(), 1, "later rules are not evaluated");
        assert_eq!(snapshot.rules()[1].hit_count(), 0);
    }

    #[test]
    fn evaluate_first_deny_wins_when_several_rules_match() {
        let engine = engine_from_json(
            r#"{ "rules": [
                { "id": "1", "status": 418, "match": { "field": "query", "op": "contains", "value": "evil" } },
                { "id": "2", "status": 503, "match": { "field": "query", "op": "contains", "value": "vil" } }
            ] }"#,
        );
        let snapshot = engine.snapshot();
        let req = request("GET", "/", "?x=evil", &[], None, None);
        let evaluated = evaluate(&snapshot, &req);
        assert_eq!(
            evaluated.decision,
            Decision::Deny { status: 418 },
            "the first matching deny rule decides"
        );
        assert_eq!(evaluated.matched.len(), 1);
    }

    #[test]
    fn evaluate_negate_flips_present_and_absent_subjects() {
        let engine = engine_from_json(
            r#"{ "rules": [
                { "id": "1", "action": "count", "match": { "field": "method", "op": "equals", "value": "GET", "negate": true } },
                { "id": "2", "match": { "field": "header", "name": "X-Present", "op": "contains", "value": "a", "negate": true } }
            ] }"#,
        );
        let snapshot = engine.snapshot();
        let headers = [HeaderPair::new("X-Present", "abc")];
        // method GET, header present: both negated conditions fail.
        let clean = request("GET", "/", "", &headers, None, None);
        assert_eq!(evaluate(&snapshot, &clean).decision, Decision::Pass);
        // method POST, header missing: both negated conditions hold.
        let flipped = request("POST", "/", "", &[], None, None);
        let evaluated = evaluate(&snapshot, &flipped);
        assert_eq!(evaluated.decision, Decision::Deny { status: 403 });
        assert_eq!(
            evaluated.matched.len(),
            2,
            "count keeps evaluating past rule 1"
        );
    }

    #[test]
    fn evaluate_all_and_any_and_not_groups_behave_logically() {
        let engine = engine_from_json(
            r#"{ "rules": [
                { "id": "1", "match": { "all": [
                    { "field": "method", "op": "equals", "value": "POST" },
                    { "field": "path", "op": "prefix", "value": "/admin" }
                ] } },
                { "id": "2", "match": { "any": [
                    { "field": "path", "op": "suffix", "value": ".php" },
                    { "field": "query", "op": "contains", "value": "exec" }
                ] } },
                { "id": "3", "match": { "not": { "field": "method", "op": "equals", "value": "GET" } } }
            ] }"#,
        );
        let snapshot = engine.snapshot();
        let all_hit = request("POST", "/admin/users", "", &[], None, None);
        assert_eq!(
            evaluate(&snapshot, &all_hit).decision,
            Decision::Deny { status: 403 }
        );
        let all_miss = request("GET", "/admin/users", "", &[], None, None);
        assert_eq!(evaluate(&snapshot, &all_miss).decision, Decision::Pass);
        let any_hit = request("GET", "/index.php", "", &[], None, None);
        let evaluated = evaluate(&snapshot, &any_hit);
        assert_eq!(evaluated.decision, Decision::Deny { status: 403 });
        assert_eq!(&*evaluated.matched[0].id, "2");
        let not_hit = request("POST", "/x", "", &[], None, None);
        let evaluated = evaluate(&snapshot, &not_hit);
        assert_eq!(evaluated.decision, Decision::Deny { status: 403 });
        assert_eq!(&*evaluated.matched[0].id, "3");
        // A GET request makes the inner condition true, so `not` misses.
        let get = request("GET", "/x", "", &[], None, None);
        assert_eq!(evaluate(&snapshot, &get).decision, Decision::Pass);
    }

    #[test]
    fn evaluate_header_lookup_ignores_name_case() {
        let engine = engine_from_json(&format!(
            r#"{{ "rules": [ {} ] }}"#,
            deny_rule(
                "1",
                r#"{ "field": "header", "name": "content-type", "op": "contains", "value": "vnd.php" }"#
            )
        ));
        let snapshot = engine.snapshot();
        let headers = [HeaderPair::new(
            "Content-Type",
            "application/vnd.php.serialized",
        )];
        let req = request("POST", "/", "", &headers, None, None);
        assert_eq!(
            evaluate(&snapshot, &req).decision,
            Decision::Deny { status: 403 }
        );
    }

    #[test]
    fn evaluate_body_is_truncated_to_the_inspect_limit() {
        // The body excerpt is longer than a tiny limit: only the first
        // `limit` bytes are inspected, so "tail" never matches.
        let tiny = EngineConfig {
            body_inspect_limit: 8,
        };
        let set = RuleSetFile::from_json(
            br#"{ "rules": [
                { "id": "1", "match": { "field": "body", "op": "contains", "value": "inside" } },
                { "id": "2", "match": { "field": "body", "op": "suffix", "value": "tail" } }
            ] }"#,
        )
        .expect("parses");
        let compiled = crate::compile::compile(&set, tiny).expect("compiles");
        assert_eq!(compiled.body_inspect_limit, 8);
        let body = b"inside-of-the-body-tail";
        let req = request("POST", "/", "", &[], Some(body), None);
        let evaluated = evaluate(&compiled, &req);
        assert_eq!(evaluated.decision, Decision::Deny { status: 403 });
        assert_eq!(evaluated.matched.len(), 1, "only the prefix rule matched");
        assert_eq!(&*evaluated.matched[0].id, "1");
    }

    #[test]
    fn evaluate_multibyte_utf8_subjects_match_whole_characters() {
        let engine = engine_from_json(
            r#"{ "rules": [
                { "id": "1", "match": { "field": "path", "op": "regex", "value": "\\u4e2d\\u6587" } },
                { "id": "2", "match": { "field": "userAgent", "op": "contains", "value": "héllo" } }
            ] }"#,
        );
        let snapshot = engine.snapshot();
        let req = request("GET", "/files/中文/资料", "", &[], None, None);
        assert_eq!(
            evaluate(&snapshot, &req).decision,
            Decision::Deny { status: 403 }
        );
        let req = Request {
            user_agent: "x héllo y",
            ..request("GET", "/ok", "", &[], None, None)
        };
        let evaluated = evaluate(&snapshot, &req);
        assert_eq!(evaluated.matched.len(), 1, "the path rule misses");
        assert_eq!(&*evaluated.matched[0].id, "2");
    }

    #[test]
    fn evaluate_truncated_utf8_body_never_panics() {
        // A multibyte character cut in half at the inspection limit stays
        // bytes; matching must not panic or spuriously match.
        let set = RuleSetFile::from_json(
            r#"{ "rules": [ { "id": "1", "match": { "field": "body", "op": "regex", "value": "中文" } } ] }"#.as_bytes(),
        )
        .expect("parses");
        let tiny = EngineConfig {
            body_inspect_limit: 4,
        };
        let compiled = crate::compile::compile(&set, tiny).expect("compiles");
        let body = "中文".as_bytes(); // 6 bytes; limit 4 cuts the second char
        let req = request("POST", "/", "", &[], Some(body), None);
        let evaluated = evaluate(&compiled, &req);
        assert!(
            evaluated.matched.is_empty(),
            "the truncated tail cannot match"
        );
    }

    #[test]
    fn evaluate_case_insensitive_regex_folds_unicode_case() {
        let engine = engine_from_json(
            r#"{ "rules": [ { "id": "1", "match": { "field": "userAgent", "op": "regex", "value": "passwörd", "caseInsensitive": true } } ] }"#,
        );
        let snapshot = engine.snapshot();
        let req = Request {
            user_agent: "PASSWÖRD-1",
            ..request("GET", "/", "", &[], None, None)
        };
        assert_eq!(
            evaluate(&snapshot, &req).decision,
            Decision::Deny { status: 403 }
        );
        // Case-sensitive spelling only matches exactly.
        let engine = engine_from_json(
            r#"{ "rules": [ { "id": "1", "match": { "field": "userAgent", "op": "regex", "value": "passwörd" } } ] }"#,
        );
        let snapshot = engine.snapshot();
        let req = Request {
            user_agent: "PASSWÖRD-1",
            ..request("GET", "/", "", &[], None, None)
        };
        assert_eq!(evaluate(&snapshot, &req).decision, Decision::Pass);
    }

    #[test]
    fn evaluate_ascii_case_insensitive_string_operators() {
        let engine = engine_from_json(
            r#"{ "rules": [
                { "id": "1", "match": { "field": "path", "op": "equals", "value": "/AdMiN", "caseInsensitive": true } },
                { "id": "2", "match": { "field": "path", "op": "equals", "value": "/AdMiN" } },
                { "id": "3", "match": { "field": "host", "op": "suffix", "value": ".EXAMPLE.com", "caseInsensitive": true } }
            ] }"#,
        );
        let snapshot = engine.snapshot();
        let req = request("GET", "/admin", "", &[], None, None);
        let evaluated = evaluate(&snapshot, &req);
        assert_eq!(evaluated.decision, Decision::Deny { status: 403 });
        assert_eq!(
            evaluated.matched.len(),
            1,
            "only the case-insensitive equals matched"
        );
        assert_eq!(&*evaluated.matched[0].id, "1");
    }

    #[test]
    fn evaluate_ip_in_matches_ipv4_and_ipv6_networks() {
        let engine = engine_from_json(&format!(
            r#"{{ "rules": [ {} ] }}"#,
            deny_rule(
                "1",
                r#"{ "field": "clientIp", "op": "ipIn", "value": "10.0.0.0/8 2001:db8::/32, 192.168.1.1" }"#
            )
        ));
        let snapshot = engine.snapshot();
        let in_v4 = request(
            "GET",
            "/",
            "",
            &[],
            None,
            Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
        );
        assert_eq!(
            evaluate(&snapshot, &in_v4).decision,
            Decision::Deny { status: 403 }
        );
        let exact_v4 = request(
            "GET",
            "/",
            "",
            &[],
            None,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        );
        assert_eq!(
            evaluate(&snapshot, &exact_v4).decision,
            Decision::Deny { status: 403 }
        );
        let in_v6 = request(
            "GET",
            "/",
            "",
            &[],
            None,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        );
        assert_eq!(
            evaluate(&snapshot, &in_v6).decision,
            Decision::Deny { status: 403 }
        );
        let outside = request(
            "GET",
            "/",
            "",
            &[],
            None,
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        );
        assert_eq!(evaluate(&snapshot, &outside).decision, Decision::Pass);
    }

    #[test]
    fn evaluate_missing_client_ip_never_matches_ip_in() {
        let engine = engine_from_json(&format!(
            r#"{{ "rules": [ {} ] }}"#,
            deny_rule(
                "1",
                r#"{ "field": "clientIp", "op": "ipIn", "value": "0.0.0.0/0" }"#
            )
        ));
        let snapshot = engine.snapshot();
        let req = request("GET", "/", "", &[], None, None);
        assert_eq!(evaluate(&snapshot, &req).decision, Decision::Pass);
    }

    #[test]
    fn engine_check_records_stats_and_fires_the_blocked_hook() {
        let blocked_hits: Arc<Mutex<Vec<(String, u16)>>> = Arc::default();
        let hook: BlockedHook = {
            let recorder = Arc::clone(&blocked_hits);
            Arc::new(move |hit: &BlockedHit<'_>| {
                recorder
                    .lock()
                    .expect("recorder")
                    .push((hit.rule_id.to_owned(), hit.status));
            })
        };
        let engine = {
            let set = RuleSetFile::from_json(
                br#"{ "rules": [
                    { "id": "1", "action": "count", "match": { "field": "path", "op": "prefix", "value": "/p" } },
                    { "id": "2", "status": 418, "match": { "field": "path", "op": "contains", "value": "bad" } }
                ] }"#,
            )
            .expect("parses");
            Engine::new(
                EngineConfig::default(),
                &set,
                EngineHooks {
                    blocked: Some(hook),
                },
            )
            .expect("compiles")
        };
        let req = request("GET", "/p/bad", "", &[], None, None);
        assert_eq!(engine.check(&req), Decision::Deny { status: 418 });
        let stats = engine.stats();
        assert_eq!(stats.requests, 1);
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.denied, 1);
        assert_eq!(stats.allowed, 0);
        assert_eq!(
            blocked_hits.lock().expect("recorder").clone(),
            vec![("2".to_owned(), 418)]
        );

        assert_eq!(engine.check(&req), Decision::Deny { status: 418 });
        assert_eq!(engine.stats().requests, 2);

        let pass = request("GET", "/other", "", &[], None, None);
        assert_eq!(engine.check(&pass), Decision::Pass);
        let hits_before = engine.stats().hits;
        let stats = engine.stats();
        assert_eq!(stats.requests, 3);
        assert_eq!(stats.hits, hits_before, "passes add no hits");
        assert_eq!(stats.denied, 2);
    }

    #[test]
    fn engine_reload_publishes_a_new_snapshot() {
        let engine = engine_from_json(&format!(
            r#"{{ "rules": [ {} ] }}"#,
            deny_rule(
                "1",
                r#"{ "field": "path", "op": "equals", "value": "/old" }"#
            )
        ));
        let req = request("GET", "/new", "", &[], None, None);
        assert_eq!(engine.check(&req), Decision::Pass);
        let set = RuleSetFile::from_json(
            br#"{ "rules": [ { "id": "1", "match": { "field": "path", "op": "equals", "value": "/new" } } ] }"#,
        )
        .expect("parses");
        engine.reload(&set).expect("reload");
        assert_eq!(engine.check(&req), Decision::Deny { status: 403 });
        assert!(engine.compile_errors().is_empty());
    }

    #[test]
    fn engine_failed_reload_keeps_the_previous_snapshot_and_reports() {
        let engine = engine_from_json(&format!(
            r#"{{ "rules": [ {} ] }}"#,
            deny_rule(
                "1",
                r#"{ "field": "path", "op": "equals", "value": "/keep" }"#
            )
        ));
        let req = request("GET", "/keep", "", &[], None, None);
        assert_eq!(engine.check(&req), Decision::Deny { status: 403 });
        let broken = RuleSetFile::from_json(
            br#"{ "rules": [ { "id": "1", "match": { "field": "path", "op": "regex", "value": "[" } } ] }"#,
        )
        .expect("parses");
        let errors = engine.reload(&broken).expect_err("broken rule set");
        assert_eq!(errors.len(), 1);
        assert_eq!(
            engine.compile_errors().len(),
            1,
            "the last reload errors stay readable"
        );
        assert_eq!(
            engine.check(&req),
            Decision::Deny { status: 403 },
            "the previous snapshot keeps serving"
        );
    }

    #[test]
    fn engine_per_rule_hit_counters_accumulate_across_checks() {
        let engine = engine_from_json(&format!(
            r#"{{ "rules": [ {} ] }}"#,
            deny_rule(
                "1",
                r#"{ "field": "path", "op": "prefix", "value": "/hit" }"#
            )
        ));
        let req = request("GET", "/hit", "", &[], None, None);
        engine.check(&req);
        engine.check(&req);
        let snapshot = engine.snapshot();
        assert_eq!(snapshot.rules()[0].hit_count(), 2);
        // The old snapshot handle keeps serving and counting its rules.
        assert_eq!(engine.snapshot().rules()[0].hit_count(), 2);
    }

    #[test]
    fn engine_config_reports_the_normalized_inspect_limit() {
        let engine = engine_from_json(r#"{ "rules": [] }"#);
        assert_eq!(
            engine.config().body_inspect_limit,
            DEFAULT_BODY_INSPECT_LIMIT
        );
        let set = RuleSetFile::from_json(br#"{ "rules": [] }"#).expect("parses");
        let engine = Engine::new(
            EngineConfig {
                body_inspect_limit: MAX_BODY_INSPECT_LIMIT * 2,
            },
            &set,
            EngineHooks::default(),
        )
        .expect("compiles");
        assert_eq!(engine.config().body_inspect_limit, MAX_BODY_INSPECT_LIMIT);
    }

    #[test]
    fn blocked_event_uses_the_registered_waf_blocked_kind() {
        let hit = BlockedHit {
            rule_id: "942100",
            rule_name: "SQLi",
            status: 403,
            method: "GET",
            host: "example.com",
            path: "/a?x=1",
            client_ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
        };
        let event = blocked_event(&hit);
        let info = event.kind.info();
        assert_eq!(info.name, "waf.blocked", "the Kind comes from KINDS");
        assert_eq!(info.default_level, fg_core::events::Level::Warn);
        assert_eq!(event.module, "waf");
        assert_eq!(event.message_key, "events.waf.blocked.desc");
        let fields: std::collections::BTreeMap<&str, &str> =
            event.fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(fields.get("rule"), Some(&"942100"));
        assert_eq!(fields.get("status"), Some(&"403"));
        assert_eq!(fields.get("ip"), Some(&"203.0.113.7"));
        assert_eq!(fields.get("path"), Some(&"/a?x=1"));
    }
}
