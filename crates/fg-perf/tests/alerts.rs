//! Alert state machine unit/integration tests (WP-69 §6).

use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fg_perf::{
    AlertEvent, AlertRule, AlertState, CmpOp, Evaluator, Level, Metric, Readings, RecoverReason,
    SiteReading, limits,
};

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn host_cpu_rule(key: &str, threshold: f64, duration_minutes: u32) -> AlertRule {
    AlertRule {
        key: key.to_owned(),
        name: "Host CPU high".to_owned(),
        metric: Metric::HostCpu,
        op: CmpOp::Gt,
        threshold,
        duration_minutes,
        level: Level::Warn,
        ..AlertRule::default()
    }
}

fn site_5xx_rule(key: &str, sites: Vec<String>, min_requests: u32) -> AlertRule {
    AlertRule {
        key: key.to_owned(),
        name: "Site 5xx high".to_owned(),
        metric: Metric::Site5xx,
        op: CmpOp::Gt,
        threshold: 5.0,
        duration_minutes: 1,
        sites,
        min_requests,
        level: Level::Error,
        ..AlertRule::default()
    }
}

fn cpu_readings(cpu: Option<f64>) -> Readings {
    Readings {
        host_cpu: cpu,
        ..Readings::default()
    }
}

#[test]
fn alert_pending_then_firing_after_duration() {
    let mut evaluator = Evaluator::new();
    let rules = vec![host_cpu_rule("aaaa00000001", 90.0, 2)];

    // At t=0: condition met -> Pending, no event yet.
    let events = evaluator.evaluate(&rules, &cpu_readings(Some(95.0)), at(0));
    assert!(events.is_empty());
    assert_eq!(evaluator.pending_count(), 1);
    assert_eq!(evaluator.firing_count(), 0);

    // At t=115s (< 120s): still Pending.
    let events = evaluator.evaluate(&rules, &cpu_readings(Some(96.0)), at(115));
    assert!(events.is_empty());
    assert_eq!(evaluator.pending_count(), 1);
    assert_eq!(evaluator.firing_count(), 0);

    // At t=120s (== 2 min): fires once.
    let events = evaluator.evaluate(&rules, &cpu_readings(Some(97.0)), at(120));
    assert_eq!(
        events,
        vec![AlertEvent::Fired {
            rule: "aaaa00000001".to_owned(),
            object: None,
            value: 97.0,
        }]
    );
    assert_eq!(evaluator.pending_count(), 0);
    assert_eq!(evaluator.firing_count(), 1);

    // Subsequent ticks while firing emit no duplicate event.
    let events = evaluator.evaluate(&rules, &cpu_readings(Some(98.0)), at(125));
    assert!(events.is_empty());
    assert_eq!(evaluator.firing_count(), 1);
}

#[test]
fn alert_resets_timer_on_single_dip() {
    let mut evaluator = Evaluator::new();
    let rules = vec![host_cpu_rule("aaaa00000002", 90.0, 1)];

    // Start pending at t=0.
    assert!(
        evaluator
            .evaluate(&rules, &cpu_readings(Some(95.0)), at(0))
            .is_empty()
    );
    assert_eq!(evaluator.pending_count(), 1);

    // Single dip at t=50s resets timer to Normal.
    assert!(
        evaluator
            .evaluate(&rules, &cpu_readings(Some(85.0)), at(50))
            .is_empty()
    );
    assert_eq!(evaluator.pending_count(), 0);

    // Condition returns at t=55s -> timer restarts from t=55s.
    assert!(
        evaluator
            .evaluate(&rules, &cpu_readings(Some(95.0)), at(55))
            .is_empty()
    );
    assert_eq!(evaluator.pending_count(), 1);

    // At t=110s (55s elapsed, < 60s): must NOT fire yet.
    assert!(
        evaluator
            .evaluate(&rules, &cpu_readings(Some(95.0)), at(110))
            .is_empty()
    );
    assert_eq!(evaluator.firing_count(), 0);

    // At t=115s (60s since t=55s): fires now.
    let events = evaluator.evaluate(&rules, &cpu_readings(Some(95.0)), at(115));
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], AlertEvent::Fired { .. }));
}

#[test]
fn alert_recovered_on_clear() {
    let mut evaluator = Evaluator::new();
    let rules = vec![host_cpu_rule("aaaa00000003", 90.0, 1)];

    evaluator.evaluate(&rules, &cpu_readings(Some(95.0)), at(0));
    let fired = evaluator.evaluate(&rules, &cpu_readings(Some(95.0)), at(60));
    assert_eq!(fired.len(), 1);
    assert_eq!(evaluator.firing_count(), 1);

    // Condition clears -> emits Recovered(ConditionCleared).
    let recovered = evaluator.evaluate(&rules, &cpu_readings(Some(40.0)), at(65));
    assert_eq!(
        recovered,
        vec![AlertEvent::Recovered {
            rule: "aaaa00000003".to_owned(),
            object: None,
            reason: RecoverReason::ConditionCleared,
        }]
    );
    assert_eq!(evaluator.firing_count(), 0);
}

#[test]
fn alert_recovered_on_insufficient_requests() {
    let mut evaluator = Evaluator::new();
    let rules = vec![site_5xx_rule("aaaa00000004", vec![], 20)];

    let mut readings = Readings::default();
    readings.sites.insert(
        "api".to_owned(),
        SiteReading {
            err5xx: Some(12.0),
            window_requests: 50,
            window_span: Duration::from_secs(60),
            ..SiteReading::default()
        },
    );

    evaluator.evaluate(&rules, &readings, at(0));
    let fired = evaluator.evaluate(&rules, &readings, at(60));
    assert_eq!(
        fired,
        vec![AlertEvent::Fired {
            rule: "aaaa00000004".to_owned(),
            object: Some("api".to_owned()),
            value: 12.0,
        }]
    );

    // Drop requests below minimum -> recovers with InsufficientRequests.
    readings.sites.get_mut("api").unwrap().window_requests = 5;
    let recovered = evaluator.evaluate(&rules, &readings, at(65));
    assert_eq!(
        recovered,
        vec![AlertEvent::Recovered {
            rule: "aaaa00000004".to_owned(),
            object: Some("api".to_owned()),
            reason: RecoverReason::InsufficientRequests,
        }]
    );
    assert_eq!(evaluator.firing_count(), 0);

    // Window span shorter than WINDOW_MIN (30s) also counts as insufficient.
    readings.sites.get_mut("api").unwrap().window_requests = 100;
    readings.sites.get_mut("api").unwrap().window_span =
        limits::WINDOW_MIN - Duration::from_secs(1);
    assert!(evaluator.evaluate(&rules, &readings, at(70)).is_empty());
    assert_eq!(evaluator.pending_count(), 0);
}

#[test]
fn alert_min_requests_default_20() {
    let mut evaluator = Evaluator::new();
    // min_requests = 0 must default to 20 even on an unnormalized AlertRule.
    let rules = vec![site_5xx_rule("aaaa00000005", vec![], 0)];
    assert_eq!(rules[0].effective_min_requests(), 20);

    let mut readings = Readings::default();
    readings.sites.insert(
        "blog".to_owned(),
        SiteReading {
            err5xx: Some(50.0),
            window_requests: 19,
            window_span: Duration::from_secs(60),
            ..SiteReading::default()
        },
    );

    // 19 requests < 20: not judgeable, stays Normal.
    evaluator.evaluate(&rules, &readings, at(0));
    assert_eq!(evaluator.pending_count(), 0);

    // 20 requests >= 20: enters Pending, then Firing after 1 min.
    readings.sites.get_mut("blog").unwrap().window_requests = 20;
    evaluator.evaluate(&rules, &readings, at(5));
    assert_eq!(evaluator.pending_count(), 1);
    let fired = evaluator.evaluate(&rules, &readings, at(65));
    assert_eq!(fired.len(), 1);
}

#[test]
fn alert_per_site_objects_evaluated_independently() {
    let mut evaluator = Evaluator::new();
    let rules = vec![site_5xx_rule("aaaa00000006", vec![], 20)];

    let mut readings = Readings::default();
    readings.sites.insert(
        "alpha".to_owned(),
        SiteReading {
            err5xx: Some(10.0),
            window_requests: 30,
            window_span: Duration::from_secs(60),
            ..SiteReading::default()
        },
    );
    readings.sites.insert(
        "beta".to_owned(),
        SiteReading {
            err5xx: Some(1.0),
            window_requests: 30,
            window_span: Duration::from_secs(60),
            ..SiteReading::default()
        },
    );

    // alpha starts pending at t=0, beta is normal.
    evaluator.evaluate(&rules, &readings, at(0));
    assert_eq!(evaluator.pending_count(), 1);

    // At t=30s beta starts exceeding too.
    readings.sites.get_mut("beta").unwrap().err5xx = Some(20.0);
    evaluator.evaluate(&rules, &readings, at(30));
    assert_eq!(evaluator.pending_count(), 2);

    // At t=60s alpha fires; beta is still pending.
    let events = evaluator.evaluate(&rules, &readings, at(60));
    assert_eq!(
        events,
        vec![AlertEvent::Fired {
            rule: "aaaa00000006".to_owned(),
            object: Some("alpha".to_owned()),
            value: 10.0,
        }]
    );
    assert_eq!(evaluator.firing_count(), 1);
    assert_eq!(evaluator.pending_count(), 1);

    // At t=90s beta fires independently.
    let events = evaluator.evaluate(&rules, &readings, at(90));
    assert_eq!(
        events,
        vec![AlertEvent::Fired {
            rule: "aaaa00000006".to_owned(),
            object: Some("beta".to_owned()),
            value: 20.0,
        }]
    );
    assert_eq!(evaluator.firing_count(), 2);
}

#[test]
fn alert_site_removed_clears_without_recovery() {
    let mut evaluator = Evaluator::new();
    let site_rule = site_5xx_rule("aaaa00000007", vec![], 20);
    let backend_rule = AlertRule {
        key: "aaaa00000008".to_owned(),
        name: "Backend conns".to_owned(),
        metric: Metric::BackendConns,
        op: CmpOp::Ge,
        threshold: 100.0,
        duration_minutes: 1,
        ..AlertRule::default()
    };
    let rules = vec![site_rule, backend_rule];

    let mut readings = Readings::default();
    readings.sites.insert(
        "shop".to_owned(),
        SiteReading {
            err5xx: Some(15.0),
            window_requests: 30,
            window_span: Duration::from_secs(60),
            ..SiteReading::default()
        },
    );
    readings.sites.insert(
        "shop2".to_owned(),
        SiteReading {
            err5xx: Some(15.0),
            window_requests: 30,
            window_span: Duration::from_secs(60),
            ..SiteReading::default()
        },
    );
    readings.backends.insert(
        "shop".to_owned(),
        BTreeMap::from([("node1".to_owned(), 150.0)]),
    );
    readings.backends.insert(
        "shop2".to_owned(),
        BTreeMap::from([("node1".to_owned(), 150.0)]),
    );

    evaluator.evaluate(&rules, &readings, at(0));
    evaluator.evaluate(&rules, &readings, at(60));
    assert_eq!(evaluator.firing_count(), 4);

    // Explicit site_removed("shop") drops "shop" and "shop/node1", keeping "shop2" & "shop2/node1".
    evaluator.site_removed("shop");
    assert_eq!(evaluator.firing_count(), 2);
    assert!(
        evaluator
            .active()
            .iter()
            .all(|a| a.object.as_deref().unwrap().starts_with("shop2"))
    );

    // Disappearing from readings also clears silently without any recovery event.
    readings.sites.remove("shop2");
    readings.backends.remove("shop2");
    let events = evaluator.evaluate(&rules, &readings, at(65));
    assert!(events.is_empty(), "removed site must not emit recovery");
    assert_eq!(evaluator.firing_count(), 0);
}

#[test]
fn alert_rule_semantic_edit_clears_and_emits_recovery() {
    let mut evaluator = Evaluator::new();
    let mut rules = vec![host_cpu_rule("aaaa00000009", 90.0, 1)];

    // Enter Pending at t=0.
    evaluator.evaluate(&rules, &cpu_readings(Some(95.0)), at(0));
    // Display-only edit (name, level, remark, group) preserves pending timer.
    rules[0].name = "Renamed CPU alert".to_owned();
    rules[0].level = Level::Error;
    rules[0].remark = "critical".to_owned();
    rules[0].group = "infra".to_owned();
    let events = evaluator.evaluate(&rules, &cpu_readings(Some(95.0)), at(30));
    assert!(events.is_empty());
    assert_eq!(
        evaluator.active()[0].state,
        AlertState::Pending { since: at(0) }
    );

    // Reaches 60s -> fires despite display-only edit.
    let events = evaluator.evaluate(&rules, &cpu_readings(Some(95.0)), at(60));
    assert_eq!(events.len(), 1);
    assert_eq!(evaluator.firing_count(), 1);

    // Semantic edit (threshold 90 -> 80) clears firing state and emits RuleEdited.
    rules[0].threshold = 80.0;
    let events = evaluator.sync_rules(&rules, at(65));
    assert_eq!(
        events,
        vec![AlertEvent::Recovered {
            rule: "aaaa00000009".to_owned(),
            object: None,
            reason: RecoverReason::RuleEdited,
        }]
    );
    assert_eq!(evaluator.firing_count(), 0);
    assert_eq!(evaluator.pending_count(), 0);
}

#[test]
fn alert_rule_disabled_emits_recovery() {
    let mut evaluator = Evaluator::new();
    let mut rules = vec![host_cpu_rule("aaaa0000000a", 90.0, 1)];

    evaluator.evaluate(&rules, &cpu_readings(Some(95.0)), at(0));
    evaluator.evaluate(&rules, &cpu_readings(Some(95.0)), at(60));
    assert_eq!(evaluator.firing_count(), 1);

    // Disabling emits Recovered(RuleDisabled).
    rules[0].enable = false;
    let events = evaluator.evaluate(&rules, &cpu_readings(Some(95.0)), at(65));
    assert_eq!(
        events,
        vec![AlertEvent::Recovered {
            rule: "aaaa0000000a".to_owned(),
            object: None,
            reason: RecoverReason::RuleDisabled,
        }]
    );
    assert_eq!(evaluator.firing_count(), 0);
}

#[test]
fn alert_rule_deleted_emits_recovery() {
    let mut evaluator = Evaluator::new();
    let rules = vec![host_cpu_rule("aaaa0000000b", 90.0, 1)];

    evaluator.evaluate(&rules, &cpu_readings(Some(95.0)), at(0));
    evaluator.evaluate(&rules, &cpu_readings(Some(95.0)), at(60));
    assert_eq!(evaluator.firing_count(), 1);

    let events = evaluator.evaluate(&[], &cpu_readings(Some(95.0)), at(65));
    assert_eq!(
        events,
        vec![AlertEvent::Recovered {
            rule: "aaaa0000000b".to_owned(),
            object: None,
            reason: RecoverReason::RuleDeleted,
        }]
    );
    assert_eq!(evaluator.firing_count(), 0);
}

#[test]
fn alert_state_lost_on_restart() {
    let rules = vec![host_cpu_rule("aaaa0000000c", 90.0, 1)];

    // Before restart: firing.
    let mut evaluator = Evaluator::new();
    evaluator.evaluate(&rules, &cpu_readings(Some(95.0)), at(0));
    evaluator.evaluate(&rules, &cpu_readings(Some(95.0)), at(60));
    assert_eq!(evaluator.firing_count(), 1);

    // After restart: fresh Evaluator starts clean (in-memory only),
    // must wait full duration again before firing.
    let mut restarted = Evaluator::new();
    assert_eq!(restarted.firing_count(), 0);
    assert!(restarted.active().is_empty());
    let events = restarted.evaluate(&rules, &cpu_readings(Some(95.0)), at(65));
    assert!(events.is_empty());
    assert_eq!(restarted.pending_count(), 1);
    assert_eq!(restarted.firing_count(), 0);
}

#[test]
fn unknown_value_is_not_met_and_qps_less_than_detects_drop() {
    let mut evaluator = Evaluator::new();
    let rules = vec![
        host_cpu_rule("aaaa0000000d", 90.0, 1),
        AlertRule {
            key: "aaaa0000000e".to_owned(),
            name: "Traffic drop".to_owned(),
            metric: Metric::SiteQps,
            op: CmpOp::Lt,
            threshold: 1.0,
            duration_minutes: 1,
            ..AlertRule::default()
        },
    ];
    let mut readings = Readings::default();
    readings.sites.insert(
        "web".to_owned(),
        SiteReading {
            qps: Some(0.2),
            ..SiteReading::default()
        },
    );
    // Host CPU is None -> never met; SiteQps = 0.2 < 1.0 -> pending then fires.
    evaluator.evaluate(&rules, &readings, at(0));
    let events = evaluator.evaluate(&rules, &readings, at(60));
    assert_eq!(
        events,
        vec![AlertEvent::Fired {
            rule: "aaaa0000000e".to_owned(),
            object: Some("web".to_owned()),
            value: 0.2,
        }]
    );
}
