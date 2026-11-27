//! The cron.json model (WP-62): the task collection. The upstream file
//! config carries only `tasks` — there is no settings block (verified
//! against `internal/modules/cron/cron.go`).

use serde::{Deserialize, Serialize};

/// Shared ceilings and defaults for the module (conventions §2: every
/// background limit lives here).
pub mod limits {
    use std::time::Duration;

    /// Upstream: execution records kept per task.
    pub const HISTORY_PER_TASK: usize = 20;
    /// Upstream: merged command/HTTP output summary length cap.
    pub const OUTPUT_MAX_CHARS: usize = 4000;
    /// FerrumGate protection: upstream has no per-task command timeout
    /// field, so the module applies a fixed ceiling to every command run.
    pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(600);
    /// HTTP tasks: `timeout: 0` normalizes to this many seconds.
    pub const HTTP_TIMEOUT_DEFAULT: u32 = 30;
    /// HTTP tasks: ceiling for `timeout` in seconds.
    pub const HTTP_TIMEOUT_MAX: u32 = 600;
    /// FerrumGate protection: cron expression length.
    pub const SPEC_MAX_CHARS: usize = 256;
    /// FerrumGate protection: `headers` entries per HTTP task.
    pub const HTTP_HEADERS_MAX: usize = 32;
    /// FerrumGate protection: response body excerpt kept in the summary.
    pub const HTTP_BODY_EXCERPT_CHARS: usize = 512;
    /// FerrumGate protection: task name length.
    pub const NAME_MAX_CHARS: usize = 128;
    /// FerrumGate protection: group name length (same cap as the collection
    /// group endpoint).
    pub const GROUP_MAX_CHARS: usize = 64;
    /// FerrumGate protection: remark length.
    pub const REMARK_MAX_CHARS: usize = 512;
    /// Grace period for in-flight runs when the module drains.
    pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);
}

/// cron.json: only the task collection.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    pub tasks: Vec<Task>,
}

/// One scheduled task: a cron expression plus either a shell command or an
/// HTTP request.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Task {
    pub key: String,
    pub name: String,
    pub group: String,
    /// Tasks default to disabled, matching the upstream zero value.
    pub enable: bool,
    /// Cron expression: 5 fields, 6 fields (seconds) or an `@` descriptor.
    pub spec: String,
    /// `command` or `http`.
    #[serde(rename = "type")]
    pub kind: TaskKind,
    /// Shell command for `kind: command`, run through `sh -c`.
    pub command: String,
    /// Request configuration for `kind: http`.
    pub http: Option<HttpTask>,
    pub remark: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskKind {
    #[default]
    Command,
    Http,
}

/// HTTP task request configuration (`http` object on the task).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpTask {
    /// `http(s)://` URL.
    pub url: String,
    /// One of GET | POST | PUT | PATCH | DELETE.
    pub method: String,
    /// Raw `Key: Value` header lines.
    pub headers: Vec<String>,
    /// Request body sent as-is.
    pub body: String,
    /// Response body must contain any one of these for the run to succeed;
    /// empty list means 2xx is enough.
    #[serde(rename = "successContent")]
    pub success_content: Vec<String>,
    /// Request timeout in seconds; 0 normalizes to
    /// [`limits::HTTP_TIMEOUT_DEFAULT`].
    pub timeout: u32,
    /// Skip TLS certificate verification.
    #[serde(rename = "insecureSkipVerify")]
    pub insecure_skip_verify: bool,
}
