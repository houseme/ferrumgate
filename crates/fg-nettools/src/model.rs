//! The `nettools.json` model (WP-71 §3.4): the module settings. There is no
//! entry collection — every tool run is an ephemeral in-memory job, so the
//! file config carries only the settings block.

use serde::{Deserialize, Serialize};

/// Shared ceilings and defaults for the module (conventions §2: every
/// background limit lives here). Values follow WP-71 §3.4.
pub mod limits {
    use std::time::Duration;

    /// Upstream `maxRunning`: jobs allowed to run at the same time.
    pub const MAX_RUNNING: usize = 4;
    /// Upstream `maxTasks`: finished jobs kept in history.
    pub const MAX_TASKS: usize = 50;
    /// Upstream `maxTaskLines`: output lines kept per job (ring buffer).
    pub const MAX_TASK_LINES: usize = 500;
    /// Upstream `taskTimeout`: a job longer than this is cancelled.
    pub const TASK_TIMEOUT: Duration = Duration::from_secs(300);

    /// Ping: default echo count (maximum [`PING_COUNT_MAX`]).
    pub const PING_COUNT_DEFAULT: u8 = 4;
    /// Ping: maximum echo count.
    pub const PING_COUNT_MAX: u8 = 20;
    /// Ping: per-echo timeout.
    pub const PING_TIMEOUT: Duration = Duration::from_secs(2);
    /// Ping: pause between echoes.
    pub const PING_INTERVAL: Duration = Duration::from_millis(700);

    /// Traceroute: maximum hops (no reverse resolution is done at all).
    pub const TRACEROUTE_MAX_HOPS: u8 = 20;

    /// Port probe: maximum ports per run.
    pub const PORT_PROBE_MAX_PORTS: usize = 1024;
    /// Port probe: default concurrency.
    pub const PORT_PROBE_CONCURRENCY: usize = 100;
    /// Port probe: per-port connect timeout.
    pub const PORT_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

    /// DNS lookup: query timeout.
    pub const DNS_TIMEOUT: Duration = Duration::from_secs(8);

    /// Speed test: concurrent download streams.
    pub const SPEED_CONCURRENCY: u32 = 4;
    /// Speed test: default measurement window.
    pub const SPEED_DURATION: Duration = Duration::from_secs(10);
    /// Upstream default speed URL (byte-counted download endpoint).
    pub const DEFAULT_SPEED_URL: &str = "https://speed.cloudflare.com/__down?bytes=104857600";

    /// LAN scan: hosts per scanned network (IPv4 scans beyond a /24 are
    /// clamped to the /24 containing the interface address).
    pub const LAN_SCAN_MAX_HOSTS: usize = 256;
    /// LAN scan: total hosts across all scanned networks.
    pub const LAN_SCAN_MAX_TOTAL: usize = 1024;

    /// FerrumGate protection: one output line is truncated to this length.
    pub const LINE_MAX_CHARS: usize = 2000;
    /// FerrumGate protection: hostname / target length.
    pub const TARGET_MAX_CHARS: usize = 253;
    /// FerrumGate protection: deny list entries.
    pub const DENY_LIST_MAX: usize = 64;
    /// FerrumGate protection: DoH / speed URL length.
    pub const URL_MAX_CHARS: usize = 2048;
    /// FerrumGate protection: settings clamps.
    pub const MAX_RUNNING_CEILING: usize = 16;
    pub const MAX_TASKS_CEILING: usize = 200;
    pub const MAX_TASK_LINES_CEILING: usize = 2000;
    pub const TASK_TIMEOUT_MIN: Duration = Duration::from_secs(10);
    pub const TASK_TIMEOUT_CEILING: Duration = Duration::from_secs(3600);
}

/// `nettools.json`: only the settings block.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    pub settings: Settings,
}

/// Module settings. The four `max*` / `taskTimeout*` fields default to the
/// upstream constants ([`limits`]) and are clamped by `normalize`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Settings {
    /// Jobs allowed to run at the same time.
    pub max_running: usize,
    /// Finished jobs kept in history.
    pub max_tasks: usize,
    /// Output lines kept per job.
    pub max_task_lines: usize,
    /// Job timeout in seconds (`taskTimeout`; 5 minutes upstream).
    pub task_timeout_seconds: u64,
    /// Targets that tools refuse to probe: IPs, CIDRs or hostnames
    /// (upstream `denyList`).
    pub deny_list: Vec<String>,
    /// Download URL used when a speed-test request does not carry one.
    pub default_speed_url: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_running: limits::MAX_RUNNING,
            max_tasks: limits::MAX_TASKS,
            max_task_lines: limits::MAX_TASK_LINES,
            task_timeout_seconds: limits::TASK_TIMEOUT.as_secs(),
            deny_list: Vec::new(),
            default_speed_url: limits::DEFAULT_SPEED_URL.to_owned(),
        }
    }
}

/// The diagnostic tools (WP-71 §3.3). The `tool` field of `POST /run`
/// selects the variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tool {
    Ping,
    Traceroute,
    /// TCP connect probe (`portprobe`).
    PortProbe,
    Dns,
    Speed,
    /// LAN scan (`lanscan`).
    LanScan,
}

impl Tool {
    /// The registry `kind` string.
    pub fn kind(self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Traceroute => "traceroute",
            Self::PortProbe => "portprobe",
            Self::Dns => "dns",
            Self::Speed => "speed",
            Self::LanScan => "lanscan",
        }
    }
}

/// DNS record kinds offered by the lookup tool (WP-71 §3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordKind {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Ns,
    Ptr,
}

impl RecordKind {
    /// The wire record type.
    pub fn record_type(self) -> hickory_proto::rr::RecordType {
        match self {
            Self::A => hickory_proto::rr::RecordType::A,
            Self::Aaaa => hickory_proto::rr::RecordType::AAAA,
            Self::Cname => hickory_proto::rr::RecordType::CNAME,
            Self::Mx => hickory_proto::rr::RecordType::MX,
            Self::Txt => hickory_proto::rr::RecordType::TXT,
            Self::Ns => hickory_proto::rr::RecordType::NS,
            Self::Ptr => hickory_proto::rr::RecordType::PTR,
        }
    }

    /// Display name used in output lines.
    pub fn label(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Mx => "MX",
            Self::Txt => "TXT",
            Self::Ns => "NS",
            Self::Ptr => "PTR",
        }
    }
}

macro_rules! tool_params {
    ($(#[$doc:meta])* $name:ident { $($(#[$field_doc:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        $(#[$doc])*
        #[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
        #[serde(default, deny_unknown_fields, rename_all = "camelCase")]
        pub struct $name {
            $($(#[$field_doc])* pub $field: $ty,)*
        }
    };
}

tool_params! {
    /// Ping: target plus the documented defaults (4 echoes, 2s timeout,
    /// 0.7s interval; `timeout`/`interval` are seconds).
    PingParams {
        /// IP or hostname.
        target: String,
        /// Echo count (1..=20).
        count: Option<u8>,
        /// Per-echo timeout in seconds.
        timeout: Option<f64>,
        /// Pause between echoes in seconds.
        interval: Option<f64>,
    }
}

tool_params! {
    /// Traceroute: system command, at most 20 hops, no reverse resolution.
    TracerouteParams {
        /// IP or hostname.
        target: String,
        /// Maximum hops (1..=20).
        max_hops: Option<u8>,
    }
}

tool_params! {
    /// TCP connect probe: at most 1024 ports, concurrency 100, 1.5s
    /// connect timeout; `timeout` is seconds.
    PortProbeParams {
        /// IP or hostname.
        target: String,
        /// `22,80,443,8000-8100` style port list.
        ports: String,
        /// Concurrent connects (1..=256).
        concurrency: Option<usize>,
        /// Per-port connect timeout in seconds.
        timeout: Option<f64>,
    }
}

tool_params! {
    /// DNS lookup: empty server = the system resolver (custom DNS from
    /// WP-07 applies); `IP`, `IP:端口` or a DoH URL; `timeout` seconds.
    DnsParams {
        /// Query name (an IP for PTR).
        name: String,
        /// Record kind, default A.
        record: Option<RecordKind>,
        /// Resolver to use instead of the system one.
        server: Option<String>,
        /// Query timeout in seconds.
        timeout: Option<f64>,
    }
}

tool_params! {
    /// Download speed test: 4 concurrent streams, 10s window; `duration`
    /// seconds. An absent URL falls back to `defaultSpeedUrl`.
    SpeedParams {
        /// Download URL (`http(s)://`).
        url: Option<String>,
        /// Concurrent streams (1..=16).
        concurrency: Option<u32>,
        /// Measurement window in seconds.
        duration: Option<f64>,
    }
}

tool_params! {
    /// LAN scan: `cidr` absent = inferred from the local NICs (IPv4,
    /// clamped to /24); names reverse-resolved when requested.
    LanScanParams {
        /// Network to scan (`192.168.1.0/24`).
        cidr: Option<String>,
        /// Reverse-resolve host names of alive hosts.
        include_names: Option<bool>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_defaults_match_doc_limits() {
        let settings = Settings::default();
        assert_eq!(settings.max_running, 4);
        assert_eq!(settings.max_tasks, 50);
        assert_eq!(settings.max_task_lines, 500);
        assert_eq!(settings.task_timeout_seconds, 300);
        assert!(settings.deny_list.is_empty());
        assert_eq!(settings.default_speed_url, limits::DEFAULT_SPEED_URL);
    }

    #[test]
    fn settings_json_is_camel_case_and_rejects_unknown() {
        let json = serde_json::json!({
            "maxRunning": 2,
            "maxTasks": 10,
            "maxTaskLines": 100,
            "taskTimeoutSeconds": 60,
            "denyList": ["10.0.0.0/8"],
            "defaultSpeedUrl": "https://example.test/down"
        });
        let settings: Settings = serde_json::from_value(json).expect("parse settings");
        assert_eq!(settings.max_running, 2);
        assert_eq!(settings.deny_list, vec!["10.0.0.0/8".to_owned()]);
        let bad = serde_json::json!({ "maxRunning": 2, "unknown": 1 });
        assert!(serde_json::from_value::<Settings>(bad).is_err());
        // Missing fields fall back to the defaults.
        let partial: Settings = serde_json::from_value(serde_json::json!({})).expect("partial");
        assert_eq!(partial, Settings::default());
    }

    #[test]
    fn file_config_round_trips_with_defaults() {
        let json = serde_json::json!({ "settings": { "maxRunning": 1 } });
        let config: FileConfig = serde_json::from_value(json).expect("parse");
        assert_eq!(config.settings.max_running, 1);
        assert_eq!(config.settings.max_tasks, 50);
        let text = serde_json::to_string(&FileConfig::default()).expect("serialize");
        assert!(text.contains("\"settings\""));
    }

    #[test]
    fn tool_params_deserialize_camel_case_and_reject_unknown() {
        let ping: PingParams =
            serde_json::from_value(serde_json::json!({ "target": "8.8.8.8", "count": 4 }))
                .expect("ping params");
        assert_eq!(ping.target, "8.8.8.8");
        assert_eq!(ping.count, Some(4));
        assert!(
            serde_json::from_value::<PingParams>(serde_json::json!({ "target": "x", "other": 1 }))
                .is_err()
        );
        let dns: DnsParams = serde_json::from_value(serde_json::json!({
            "name": "example.com", "record": "AAAA", "server": "8.8.8.8", "timeout": 8
        }))
        .expect("dns params");
        assert_eq!(dns.record, Some(RecordKind::Aaaa));
        let tool: Tool = serde_json::from_value(serde_json::json!("portprobe")).expect("tool");
        assert_eq!(tool, Tool::PortProbe);
        assert_eq!(tool.kind(), "portprobe");
        assert_eq!(
            serde_json::from_value::<Tool>(serde_json::json!("lanscan")).expect("lanscan"),
            Tool::LanScan
        );
    }
}
