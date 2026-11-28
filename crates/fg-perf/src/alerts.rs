//! The alert state machine (WP-69 §3.3 判定), pure logic driven by an
//! injected clock: every enabled rule is judged every
//! [`limits::SAMPLE_INTERVAL`] over the [`limits::WINDOW_SPAN`] window.
//!
//! Per rule and per object (host/process metrics: no object; site
//! metrics: one object per site; backend connections: one object per
//! `site/backend` node):
//!
//! 1. condition met → `Pending` (timing); continuously met for the
//!    configured duration → `Firing`, one `perf.alert` event.
//! 2. a single dip while pending resets the timer; a firing alert whose
//!    condition clears publishes `perf.recovered`. When the 5xx ratio or
//!    latency cannot be judged (fewer requests than the rule's minimum,
//!    or a window shorter than [`limits::WINDOW_MIN`]) a firing alert is
//!    recovered with the `InsufficientRequests` reason.
//! 3. a site (or backend) that disappeared is dropped silently — no
//!    recovery notification.
//! 4. display-only edits (name, group, level, remark) keep the timing;
//!    semantic edits or disabling the rule clear its states and emit one
//!    recovery per firing object. States live only in memory.
//!
//! Host/process metrics are instantaneous readings (the duration timer
//! is the debounce); the window-span and minimum-request guards apply to
//! the site window metrics, matching the WP-28 statistics window.

use std::{
    collections::{BTreeMap, HashSet},
    time::{Duration, SystemTime},
};

use crate::model::{AlertRule, CmpOp, Metric, limits};

pub use crate::model::limits::{WINDOW_MIN, WINDOW_SPAN};

/// One evaluation's inputs, built by the sampler from the current host /
/// process readings and the injected site statistics (WP-28, whose
/// "last ~60 s" window is shared verbatim).
#[derive(Clone, Debug, Default)]
pub struct Readings {
    pub host_cpu: Option<f64>,
    pub host_mem: Option<f64>,
    pub host_disk: Option<f64>,
    pub proc_cpu: Option<f64>,
    pub proc_rss: Option<f64>,
    /// Per-site readings keyed by site name.
    pub sites: BTreeMap<String, SiteReading>,
    /// Current forwarded connections per backend node, keyed by site
    /// then backend name.
    pub backends: BTreeMap<String, BTreeMap<String, f64>>,
}

/// One site's windowed readings. `window_requests` / `window_span`
/// describe the underlying ~60 s statistics window.
#[derive(Clone, Debug, Default)]
pub struct SiteReading {
    pub active: Option<f64>,
    pub qps: Option<f64>,
    pub err5xx: Option<f64>,
    pub latency_p95: Option<f64>,
    pub window_requests: u64,
    pub window_span: Duration,
}

/// The per-rule, per-object alert lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertState {
    Normal,
    Pending { since: SystemTime },
    Firing { since: SystemTime },
}

impl AlertState {
    pub fn is_firing(&self) -> bool {
        matches!(self, AlertState::Firing { .. })
    }

    /// When the current timing started (`None` for `Normal`).
    pub fn since(&self) -> Option<SystemTime> {
        match self {
            AlertState::Normal => None,
            AlertState::Pending { since } | AlertState::Firing { since } => Some(*since),
        }
    }
}

/// Why a firing alert recovered (the recovery notification names it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoverReason {
    ConditionCleared,
    InsufficientRequests,
    RuleEdited,
    RuleDisabled,
    RuleDeleted,
}

impl RecoverReason {
    pub fn tag(self) -> &'static str {
        match self {
            RecoverReason::ConditionCleared => "conditionCleared",
            RecoverReason::InsufficientRequests => "insufficientRequests",
            RecoverReason::RuleEdited => "ruleEdited",
            RecoverReason::RuleDisabled => "ruleDisabled",
            RecoverReason::RuleDeleted => "ruleDeleted",
        }
    }
}

/// The events one evaluation (or rule mutation) produces; the caller
/// publishes them on the event bus as `perf.alert` / `perf.recovered`.
#[derive(Clone, Debug, PartialEq)]
pub enum AlertEvent {
    Fired {
        rule: String,
        object: Option<String>,
        value: f64,
    },
    Recovered {
        rule: String,
        object: Option<String>,
        reason: RecoverReason,
    },
}

/// The kind of a rule mutation ([`Evaluator::rule_changed`]). Display
/// edits keep the timing; semantic edits and disabling clear it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleChange {
    /// Name, group, level or remark only — no state is dropped.
    NonSemantic,
    /// Metric, operator, threshold, duration, sites or minimum requests.
    Semantic,
    /// The rule was disabled (or an edit landed while it is disabled).
    Disabled,
}

/// The judgement of one rule against one object.
struct Judged {
    object: Option<String>,
    value: Option<f64>,
    outcome: Outcome,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Outcome {
    /// Condition met; carries the observed value.
    Met(f64),
    /// Condition not met (unknown values count as not met).
    NotMet,
    /// Not judgeable: too few requests / too little window data.
    Insufficient,
}

/// One active (pending or firing) alert for the management interface.
#[derive(Clone, Debug, PartialEq)]
pub struct ActiveAlert {
    pub rule: String,
    pub object: Option<String>,
    pub state: AlertState,
    pub value: Option<f64>,
}

/// What the engine remembers about a rule: the fingerprint it compares
/// against on every evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Fingerprint {
    enable: bool,
    metric: Metric,
    op: CmpOp,
    threshold_bits: u64,
    duration_minutes: u32,
    sites: Vec<String>,
    min_requests: u32,
}

impl Fingerprint {
    fn of(rule: &AlertRule) -> Self {
        let mut sites = rule.sites.clone();
        sites.sort();
        Self {
            enable: rule.enable,
            metric: rule.metric,
            op: rule.op,
            threshold_bits: rule.threshold.to_bits(),
            duration_minutes: rule.duration_minutes,
            sites,
            min_requests: rule.min_requests,
        }
    }
}

#[derive(Debug, Default)]
struct RuleStates {
    states: BTreeMap<Option<String>, AlertState>,
    last: BTreeMap<Option<String>, f64>,
}

/// The alert engine: rule fingerprints plus per-object states. States
/// live only in memory — a restart clears them (WP-69 §3.3.4).
#[derive(Debug, Default)]
pub struct Evaluator {
    fingerprints: BTreeMap<String, Fingerprint>,
    per_rule: BTreeMap<String, RuleStates>,
}

impl Evaluator {
    /// A fresh engine with no states; the first [`Evaluator::evaluate`]
    /// learns the rules silently (no events on a clean start).
    pub fn new() -> Self {
        Self::default()
    }

    /// Synchronizes rule fingerprints without advancing object timers:
    /// semantic edits and disables drop states and emit recovery events,
    /// deleted rules emit `RuleDeleted`, and display-only edits preserve
    /// pending/firing state.
    pub fn sync_rules(&mut self, rules: &[AlertRule], now: SystemTime) -> Vec<AlertEvent> {
        let mut events = Vec::new();
        let mut seen = HashSet::with_capacity(rules.len());
        for rule in rules {
            seen.insert(rule.key.clone());
            let fingerprint = Fingerprint::of(rule);
            match self.fingerprints.get(&rule.key) {
                None => {
                    self.fingerprints.insert(rule.key.clone(), fingerprint);
                }
                Some(existing) if *existing != fingerprint => {
                    let change = if rule.enable {
                        RuleChange::Semantic
                    } else {
                        RuleChange::Disabled
                    };
                    events.extend(self.rule_changed(&rule.key, change, now));
                    self.fingerprints.insert(rule.key.clone(), fingerprint);
                }
                Some(_) => {}
            }
        }
        let removed: Vec<String> = self
            .fingerprints
            .keys()
            .filter(|key| !seen.contains(*key))
            .cloned()
            .collect();
        for key in removed {
            events.extend(self.rule_removed(&key));
        }
        events
    }

    /// Judges every enabled rule against the readings and advances the
    /// per-object states. Rule-set drift (edits, disables, deletions —
    /// from the file, an import or the API) is detected here, so the
    /// corresponding recovery events flow even without a route hook.
    pub fn evaluate(
        &mut self,
        rules: &[AlertRule],
        readings: &Readings,
        now: SystemTime,
    ) -> Vec<AlertEvent> {
        let mut events = self.sync_rules(rules, now);

        // Per-rule, per-object judgement.
        for rule in rules.iter().filter(|rule| rule.enable) {
            let judged = judge_objects(rule, readings);
            let entry = self.per_rule.entry(rule.key.clone()).or_default();
            // Objects that vanished (site deleted or stopped) drop
            // silently: no recovery notification (WP-69 §3.3.3).
            let present: HashSet<Option<String>> =
                judged.iter().map(|judged| judged.object.clone()).collect();
            entry.states.retain(|object, _| present.contains(object));
            entry.last.retain(|object, _| present.contains(object));
            for judged in judged {
                let current = entry
                    .states
                    .get(&judged.object)
                    .copied()
                    .unwrap_or(AlertState::Normal);
                let next = match (current, judged.outcome) {
                    (AlertState::Normal, Outcome::Met(value)) => {
                        if rule.duration_window().is_zero() {
                            events.push(AlertEvent::Fired {
                                rule: rule.key.clone(),
                                object: judged.object.clone(),
                                value,
                            });
                            AlertState::Firing { since: now }
                        } else {
                            AlertState::Pending { since: now }
                        }
                    }
                    (AlertState::Pending { since }, Outcome::Met(value)) => {
                        if now.duration_since(since).unwrap_or_default() >= rule.duration_window() {
                            events.push(AlertEvent::Fired {
                                rule: rule.key.clone(),
                                object: judged.object.clone(),
                                value,
                            });
                            AlertState::Firing { since: now }
                        } else {
                            current
                        }
                    }
                    (AlertState::Firing { .. }, Outcome::Met(_)) => current,
                    (AlertState::Pending { .. }, Outcome::NotMet | Outcome::Insufficient) => {
                        // A single dip restarts the timing (WP-69 §3.3).
                        AlertState::Normal
                    }
                    (AlertState::Firing { .. }, Outcome::NotMet) => {
                        events.push(AlertEvent::Recovered {
                            rule: rule.key.clone(),
                            object: judged.object.clone(),
                            reason: RecoverReason::ConditionCleared,
                        });
                        AlertState::Normal
                    }
                    (AlertState::Firing { .. }, Outcome::Insufficient) => {
                        events.push(AlertEvent::Recovered {
                            rule: rule.key.clone(),
                            object: judged.object.clone(),
                            reason: RecoverReason::InsufficientRequests,
                        });
                        AlertState::Normal
                    }
                    (AlertState::Normal, Outcome::NotMet | Outcome::Insufficient) => {
                        AlertState::Normal
                    }
                };
                if let Some(value) = judged.value {
                    entry.last.insert(judged.object.clone(), value);
                }
                entry.states.insert(judged.object.clone(), next);
            }
        }
        events
    }

    /// A rule mutation reported by the management routes. Display-only
    /// edits keep the running timing; semantic edits and disables drop
    /// the rule's states and recover every firing object.
    pub fn rule_changed(
        &mut self,
        key: &str,
        change: RuleChange,
        _now: SystemTime,
    ) -> Vec<AlertEvent> {
        match change {
            RuleChange::NonSemantic => Vec::new(),
            RuleChange::Semantic => self.drop_rule(key, RecoverReason::RuleEdited),
            RuleChange::Disabled => self.drop_rule(key, RecoverReason::RuleDisabled),
        }
    }

    /// A deleted rule: its states drop and firing objects recover.
    pub fn rule_removed(&mut self, key: &str) -> Vec<AlertEvent> {
        self.fingerprints.remove(key);
        self.drop_rule(key, RecoverReason::RuleDeleted)
    }

    /// A site was deleted or stopped: its alerts (including its backend
    /// nodes, keyed `site/backend`) clear without recovery notifications.
    pub fn site_removed(&mut self, site: &str) {
        let gone = |object: &Option<String>| match object {
            None => false,
            Some(object) => {
                object == site
                    || object
                        .strip_prefix(site)
                        .is_some_and(|rest| rest.starts_with('/'))
            }
        };
        for entry in self.per_rule.values_mut() {
            entry.states.retain(|object, _| !gone(object));
            entry.last.retain(|object, _| !gone(object));
        }
    }

    /// Active (pending or firing) alerts for the management interface.
    pub fn active(&self) -> Vec<ActiveAlert> {
        let mut active = Vec::new();
        for (rule, entry) in &self.per_rule {
            for (object, state) in &entry.states {
                if *state == AlertState::Normal {
                    continue;
                }
                active.push(ActiveAlert {
                    rule: rule.clone(),
                    object: object.clone(),
                    state: *state,
                    value: entry.last.get(object).copied(),
                });
            }
        }
        active.sort_by(|left, right| (&left.rule, &left.object).cmp(&(&right.rule, &right.object)));
        active
    }

    /// How many objects are currently firing (`ferrumgate_perf_alerts_firing`).
    pub fn firing_count(&self) -> usize {
        self.per_rule
            .values()
            .flat_map(|entry| entry.states.values())
            .filter(|state| state.is_firing())
            .count()
    }

    /// How many objects are currently within their duration window.
    pub fn pending_count(&self) -> usize {
        self.per_rule
            .values()
            .flat_map(|entry| entry.states.values())
            .filter(|state| matches!(state, AlertState::Pending { .. }))
            .count()
    }

    fn drop_rule(&mut self, key: &str, reason: RecoverReason) -> Vec<AlertEvent> {
        let Some(entry) = self.per_rule.remove(key) else {
            return Vec::new();
        };
        entry
            .states
            .into_iter()
            .filter(|(_, state)| state.is_firing())
            .map(|(object, _)| AlertEvent::Recovered {
                rule: key.to_owned(),
                object,
                reason,
            })
            .collect()
    }
}

/// Judges a rule against every object it covers.
fn judge_objects(rule: &AlertRule, readings: &Readings) -> Vec<Judged> {
    let mut judged = Vec::new();
    match rule.metric {
        Metric::HostCpu => global(&mut judged, readings.host_cpu, rule),
        Metric::HostMem => global(&mut judged, readings.host_mem, rule),
        Metric::HostDisk => global(&mut judged, readings.host_disk, rule),
        Metric::ProcCpu => global(&mut judged, readings.proc_cpu, rule),
        Metric::ProcRss => global(&mut judged, readings.proc_rss, rule),
        Metric::SiteActive | Metric::SiteQps | Metric::Site5xx | Metric::SiteLatencyP95 => {
            for (name, site) in &readings.sites {
                if !in_scope(&rule.sites, name) {
                    continue;
                }
                let (value, insufficient) = site_judgement(rule.metric, site, rule);
                judged.push(Judged {
                    object: Some(name.clone()),
                    value,
                    outcome: outcome(value, insufficient, rule),
                });
            }
        }
        Metric::BackendConns => {
            for (site, backends) in &readings.backends {
                if !in_scope(&rule.sites, site) {
                    continue;
                }
                for (backend, conns) in backends {
                    judged.push(Judged {
                        object: Some(format!("{site}/{backend}")),
                        value: Some(*conns),
                        outcome: outcome(Some(*conns), false, rule),
                    });
                }
            }
        }
    }
    judged
}

fn global(judged: &mut Vec<Judged>, value: Option<f64>, rule: &AlertRule) {
    judged.push(Judged {
        object: None,
        value,
        outcome: outcome(value, false, rule),
    });
}

/// The site metric value plus whether the window is judgeable at all:
/// the 5xx ratio and latency need at least [`limits::WINDOW_MIN`] of
/// window data and at least the rule's minimum requests.
fn site_judgement(metric: Metric, site: &SiteReading, rule: &AlertRule) -> (Option<f64>, bool) {
    let insufficient = metric.needs_min_requests()
        && (site.window_span < limits::WINDOW_MIN
            || site.window_requests < u64::from(rule.effective_min_requests()));
    let value = match metric {
        Metric::SiteActive => site.active,
        Metric::SiteQps => site.qps,
        Metric::Site5xx => site.err5xx,
        Metric::SiteLatencyP95 => site.latency_p95,
        _ => None,
    };
    (value, insufficient)
}

fn outcome(value: Option<f64>, insufficient: bool, rule: &AlertRule) -> Outcome {
    if insufficient {
        return Outcome::Insufficient;
    }
    match value {
        Some(value) if rule.op.compare(value, rule.threshold) => Outcome::Met(value),
        _ => Outcome::NotMet,
    }
}

/// Empty scope means every site; otherwise the site must be listed.
fn in_scope(sites: &[String], site: &str) -> bool {
    sites.is_empty() || sites.iter().any(|listed| listed == site)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmp_op_operators_compare_thresholds() {
        assert!(CmpOp::Gt.compare(91.0, 90.0) && !CmpOp::Gt.compare(90.0, 90.0));
        assert!(CmpOp::Ge.compare(90.0, 90.0));
        assert!(CmpOp::Lt.compare(0.5, 1.0) && !CmpOp::Lt.compare(1.0, 1.0));
        assert!(CmpOp::Le.compare(1.0, 1.0));
        // Unknown values never satisfy a condition (upstream
        // TestUnknownValueIsNotMet): the state machine handles that via
        // Outcome::NotMet, the operator itself only sees numbers.
    }

    #[test]
    fn site_scope_matches_empty_and_listed() {
        assert!(in_scope(&[], "any"));
        let scope = vec!["blog".to_owned(), "shop".to_owned()];
        assert!(in_scope(&scope, "blog"));
        assert!(!in_scope(&scope, "wiki"));
    }
}
