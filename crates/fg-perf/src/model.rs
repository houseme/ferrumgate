//! The `perf.json` model (WP-69 §3.2/§3.4): the alert rule collection.
//! Upstream has no settings interface — the configuration file only
//! carries the rule list (`rules[]`). JSON field names follow upstream
//! (camelCase); percent metrics are 0–100, RSS thresholds are bytes and
//! the latency metric is milliseconds; durations are minutes.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Configuration file stem (`perf.json`).
pub const FILE_NAME: &str = "perf";

/// Shared ceilings and defaults for the module (conventions §2: every
/// background limit lives here). Values follow WP-69 §3.4.
pub mod limits {
    use std::time::Duration;

    /// Upstream `SampleInterval`: sampling and evaluation cadence.
    pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);
    /// Upstream `shortSlots`: 60 s / 5 s = samples in the short ring.
    pub const SHORT_SLOTS: usize = 12;
    /// 1-hour ring: one point per minute.
    pub const HOUR_SLOTS: usize = 60;
    /// 24-hour ring: one point per 5 minutes.
    pub const DAY_SLOTS: usize = 288;
    /// Upstream `windowSpan`: the alert evaluation window.
    pub const WINDOW_SPAN: Duration = Duration::from_secs(60);
    /// Upstream `windowMin`: minimum window data before site window
    /// metrics (5xx ratio, latency) may be judged.
    pub const WINDOW_MIN: Duration = Duration::from_secs(30);
    /// A vanished managed process keeps its row for one window.
    pub const GONE_GRACE: Duration = WINDOW_SPAN;
    /// Upstream `MaxRules`.
    pub const MAX_RULES: usize = 200;
    /// Rule name cap (the name appears in notification titles).
    pub const NAME_MAX_CHARS: usize = 64;
    /// Group name cap.
    pub const GROUP_MAX_CHARS: usize = 64;
    /// Duration bounds in minutes (WP-69 §3.3).
    pub const DURATION_MIN_MINUTES: u32 = 1;
    pub const DURATION_MAX_MINUTES: u32 = 1440;
    /// Fill-in default when a rule carries no duration (WP-69 §3.3:
    /// template defaults; the exact upstream template table is mirrored
    /// in [`crate::model::presets`]).
    pub const DEFAULT_DURATION_MINUTES: u32 = 5;
    /// Upstream default minimum requests for the 5xx ratio and latency
    /// metrics (`0` normalizes to this).
    pub const DEFAULT_MIN_REQUESTS: u32 = 20;
    /// Sites selectable per rule.
    pub const MAX_SITES_PER_RULE: usize = 256;
}

/// `perf.json`: only the rule list (WP-69 §4 — there is no settings
/// interface upstream).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    pub rules: Vec<AlertRule>,
}

/// One threshold alert rule (WP-69 §3.3). The alert engine judges every
/// object (host, site, backend node) separately.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct AlertRule {
    /// 12 lowercase hex characters ([`crate::validate::valid_key`]).
    pub key: String,
    /// Required, at most 64 characters; appears in notification titles.
    pub name: String,
    pub group: String,
    pub enable: bool,
    pub metric: Metric,
    /// Comparison against [`AlertRule::threshold`] (`>` `>=` `<` `<=`).
    pub op: CmpOp,
    pub threshold: f64,
    /// 1..=1440 minutes of continuously met condition before alerting;
    /// a single dip resets the timer (`0` normalizes to the default).
    pub duration_minutes: u32,
    /// Site scope for site/backend metrics; empty means every site.
    pub sites: Vec<String>,
    /// Minimum requests in the ~60 s window before the 5xx ratio and
    /// latency metrics are judged (`0` normalizes to 20).
    pub min_requests: u32,
    pub level: Level,
    pub remark: String,
}

impl Default for AlertRule {
    fn default() -> Self {
        Self {
            key: String::new(),
            name: String::new(),
            group: String::new(),
            enable: true,
            metric: Metric::HostCpu,
            op: CmpOp::Gt,
            threshold: 0.0,
            duration_minutes: limits::DEFAULT_DURATION_MINUTES,
            sites: Vec::new(),
            min_requests: limits::DEFAULT_MIN_REQUESTS,
            level: Level::Warn,
            remark: String::new(),
        }
    }
}

impl AlertRule {
    /// How long the condition must hold before firing.
    pub fn duration_window(&self) -> Duration {
        Duration::from_secs(u64::from(self.duration_minutes) * 60)
    }

    /// Effective minimum request threshold (`0` normalizes to 20).
    pub fn effective_min_requests(&self) -> u32 {
        if self.min_requests == 0 {
            limits::DEFAULT_MIN_REQUESTS
        } else {
            self.min_requests
        }
    }
}

/// The alertable metrics (WP-69 §3.2). Percent metrics are 0–100, RSS is
/// bytes, latency is milliseconds, the counters are per-second/absolute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Metric {
    /// Host CPU usage (percent).
    HostCpu,
    /// Host memory usage (percent).
    HostMem,
    /// Usage of the partition holding the config directory (percent).
    HostDisk,
    /// The Gately process CPU (percent).
    ProcCpu,
    /// The Gately process resident memory (bytes).
    ProcRss,
    /// Site in-flight requests.
    SiteActive,
    /// Site requests per second over the last ~60 s.
    SiteQps,
    /// Site 5xx ratio over the last ~60 s (percent).
    Site5xx,
    /// Site first-byte latency P95 over the last ~60 s (milliseconds).
    SiteLatencyP95,
    /// Current forwarded connections per backend node.
    BackendConns,
}

impl Metric {
    /// Every alertable metric in display order.
    pub const ALL: [Metric; 10] = [
        Metric::HostCpu,
        Metric::HostMem,
        Metric::HostDisk,
        Metric::ProcCpu,
        Metric::ProcRss,
        Metric::SiteActive,
        Metric::SiteQps,
        Metric::Site5xx,
        Metric::SiteLatencyP95,
        Metric::BackendConns,
    ];

    /// Stable camelCase tag used in series maps and event args.
    pub fn tag(self) -> &'static str {
        match self {
            Metric::HostCpu => "hostCpu",
            Metric::HostMem => "hostMem",
            Metric::HostDisk => "hostDisk",
            Metric::ProcCpu => "procCpu",
            Metric::ProcRss => "procRss",
            Metric::SiteActive => "siteActive",
            Metric::SiteQps => "siteQps",
            Metric::Site5xx => "site5xx",
            Metric::SiteLatencyP95 => "siteLatencyP95",
            Metric::BackendConns => "backendConns",
        }
    }

    /// Metrics judged per site (or per backend node) rather than globally.
    pub fn is_site_scoped(self) -> bool {
        matches!(
            self,
            Metric::SiteActive
                | Metric::SiteQps
                | Metric::Site5xx
                | Metric::SiteLatencyP95
                | Metric::BackendConns
        )
    }

    /// Metrics that honor the minimum-request guard.
    pub fn needs_min_requests(self) -> bool {
        matches!(self, Metric::Site5xx | Metric::SiteLatencyP95)
    }
}

/// Comparison operator (WP-69 §3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CmpOp {
    #[serde(rename = ">")]
    Gt,
    #[serde(rename = ">=")]
    Ge,
    #[serde(rename = "<")]
    Lt,
    #[serde(rename = "<=")]
    Le,
}

impl CmpOp {
    pub fn compare(self, value: f64, threshold: f64) -> bool {
        match self {
            CmpOp::Gt => value > threshold,
            CmpOp::Ge => value >= threshold,
            CmpOp::Lt => value < threshold,
            CmpOp::Le => value <= threshold,
        }
    }

    pub fn tag(self) -> &'static str {
        match self {
            CmpOp::Gt => ">",
            CmpOp::Ge => ">=",
            CmpOp::Lt => "<",
            CmpOp::Le => "<=",
        }
    }
}

/// Alert level; decides the notification event level (WP-69 §3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Level {
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "error")]
    Error,
}

impl Level {
    pub fn event_level(self) -> fg_core::events::Level {
        match self {
            Level::Warn => fg_core::events::Level::Warn,
            Level::Error => fg_core::events::Level::Error,
        }
    }
}

/// The three chart windows (WP-69 §3.2): 60 seconds at 5-second steps,
/// 1 hour per minute and 24 hours per 5 minutes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Window {
    #[serde(rename = "60s")]
    Min,
    #[serde(rename = "1h")]
    Hour,
    #[serde(rename = "24h")]
    Day,
}

impl Window {
    pub const ALL: [Window; 3] = [Window::Min, Window::Hour, Window::Day];

    pub fn range(self) -> &'static str {
        match self {
            Window::Min => "60s",
            Window::Hour => "1h",
            Window::Day => "24h",
        }
    }

    pub fn step(self) -> u32 {
        match self {
            Window::Min => 5,
            Window::Hour => 60,
            Window::Day => 300,
        }
    }
}

/// Built-in rule templates (WP-69 §3.3.5): the create form prefills one
/// of these; the values mirror the upstream template table (host CPU /
/// memory / disk, process memory, site 5xx, site latency, traffic drop).
pub fn presets() -> Vec<AlertRule> {
    let base = AlertRule::default();
    let preset = |name: &str, metric: Metric, op: CmpOp, threshold: f64, minutes: u32| AlertRule {
        name: name.to_owned(),
        metric,
        op,
        threshold,
        duration_minutes: minutes,
        ..base.clone()
    };
    let mut rules = vec![
        preset("Host CPU high", Metric::HostCpu, CmpOp::Gt, 90.0, 5),
        preset("Host memory high", Metric::HostMem, CmpOp::Gt, 90.0, 5),
        preset("Disk space low", Metric::HostDisk, CmpOp::Gt, 90.0, 5),
        preset(
            "Process memory high",
            Metric::ProcRss,
            CmpOp::Gt,
            1024.0 * 1024.0 * 1024.0,
            10,
        ),
        preset("Site 5xx rate high", Metric::Site5xx, CmpOp::Gt, 5.0, 5),
        preset(
            "Site latency high",
            Metric::SiteLatencyP95,
            CmpOp::Gt,
            2000.0,
            5,
        ),
        preset("Site traffic drop", Metric::SiteQps, CmpOp::Lt, 1.0, 10),
    ];
    for rule in &mut rules {
        rule.remark = "built-in template".to_owned();
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_config_json_is_rule_list_and_rejects_unknown() {
        let json = serde_json::json!({
            "rules": [{ "name": "cpu", "metric": "hostCpu", "op": ">", "threshold": 90 }]
        });
        let config: FileConfig = serde_json::from_value(json).expect("parse config");
        assert_eq!(config.rules.len(), 1);
        let rule = &config.rules[0];
        assert_eq!(rule.metric, Metric::HostCpu);
        assert_eq!(rule.op, CmpOp::Gt);
        assert!(rule.enable, "rules default to enabled");
        assert_eq!(rule.duration_minutes, limits::DEFAULT_DURATION_MINUTES);
        assert_eq!(rule.min_requests, limits::DEFAULT_MIN_REQUESTS);
        assert_eq!(rule.level, Level::Warn);
        // Unknown fields are refused (conventions §2).
        let bad = serde_json::json!({ "rules": [], "settings": {} });
        assert!(serde_json::from_value::<FileConfig>(bad).is_err());
        // An empty object yields the default config.
        let empty: FileConfig = serde_json::from_value(serde_json::json!({})).expect("empty");
        assert_eq!(empty, FileConfig::default());
    }

    #[test]
    fn alert_rule_round_trips_camel_case_fields() {
        let rule = AlertRule {
            key: "a1b2c3d4e5f6".to_owned(),
            name: "cpu".to_owned(),
            group: "host".to_owned(),
            enable: false,
            metric: Metric::SiteLatencyP95,
            op: CmpOp::Le,
            threshold: 12.5,
            duration_minutes: 30,
            sites: vec!["blog".to_owned()],
            min_requests: 50,
            level: Level::Error,
            remark: "r".to_owned(),
        };
        let text = serde_json::to_string(&rule).expect("serialize");
        for field in [
            "\"durationMinutes\":30",
            "\"minRequests\":50",
            "\"siteLatencyP95\"",
            "\"level\":\"error\"",
            "\"threshold\":12.5",
        ] {
            assert!(text.contains(field), "missing {field} in {text}");
        }
        let back: AlertRule = serde_json::from_str(&text).expect("deserialize");
        assert_eq!(back, rule);
    }

    #[test]
    fn metric_op_level_window_tags_are_stable() {
        assert_eq!(Metric::Site5xx.tag(), "site5xx");
        assert_eq!(Metric::SiteLatencyP95.tag(), "siteLatencyP95");
        assert_eq!(Metric::BackendConns.tag(), "backendConns");
        assert!(Metric::Site5xx.is_site_scoped());
        assert!(!Metric::HostCpu.is_site_scoped());
        assert!(Metric::Site5xx.needs_min_requests());
        assert!(!Metric::SiteQps.needs_min_requests());
        let op: CmpOp = serde_json::from_value(serde_json::json!(">=")).expect("op");
        assert_eq!(op, CmpOp::Ge);
        assert_eq!(op.tag(), ">=");
        let level: Level = serde_json::from_value(serde_json::json!("error")).expect("level");
        assert_eq!(level, Level::Error);
        let window: Window = serde_json::from_value(serde_json::json!("24h")).expect("window");
        assert_eq!(window, Window::Day);
        assert_eq!(Window::Min.range(), "60s");
        assert_eq!(Window::Min.step(), 5);
        assert_eq!(Window::Hour.step(), 60);
        assert_eq!(Window::Day.step(), 300);
    }

    #[test]
    fn presets_cover_documented_scenarios() {
        let presets = presets();
        assert!(presets.len() >= 4, "host cpu/disk/5xx/latency at minimum");
        assert!(
            presets
                .iter()
                .any(|rule| rule.metric == Metric::HostCpu && rule.op == CmpOp::Gt)
        );
        assert!(presets.iter().any(|rule| rule.metric == Metric::HostDisk));
        assert!(presets.iter().any(|rule| rule.metric == Metric::Site5xx));
        assert!(
            presets
                .iter()
                .all(|rule| rule.min_requests == limits::DEFAULT_MIN_REQUESTS),
            "presets keep the anti-flap default"
        );
    }
}
