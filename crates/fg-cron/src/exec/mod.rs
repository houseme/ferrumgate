//! Task execution (WP-62 §3.3): dispatch a task to its runner and turn the
//! result into a run-record summary.

pub mod command;
pub mod http;

use std::time::{Duration, Instant};

use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

use crate::history::RunRecord;
use crate::model::{Task, TaskKind, limits};

/// What a runner produces: success plus the merged output summary (already
/// truncated to [`limits::OUTPUT_MAX_CHARS`] by the runners).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub success: bool,
    pub output: String,
}

/// Runs one task once. `cancel` aborts the run when the module drains or a
/// manual caller gives up.
pub async fn run_task(
    task: &Task,
    http: Option<http::HttpExecutor>,
    cancel: &CancellationToken,
) -> Outcome {
    match task.kind {
        TaskKind::Command => {
            command::run(&task.command, &task.name, limits::COMMAND_TIMEOUT, cancel).await
        }
        TaskKind::Http => {
            let Some(http_task) = &task.http else {
                return Outcome {
                    success: false,
                    output: "HTTP 任务缺少请求配置".into(),
                };
            };
            http::run(http_task, http, cancel).await
        }
    }
}

/// Builds a run record around one execution.
pub async fn run_record(
    task: &Task,
    manual: bool,
    http: Option<http::HttpExecutor>,
    cancel: &CancellationToken,
    started: OffsetDateTime,
) -> RunRecord {
    let begun = Instant::now();
    let outcome = run_task(task, http, cancel).await;
    RunRecord {
        started,
        duration: begun.elapsed(),
        success: outcome.success,
        manual,
        skipped: false,
        output: outcome.output,
    }
}

/// The record for a skipped trigger.
pub fn skipped_record(started: OffsetDateTime, manual: bool, reason: &str) -> RunRecord {
    RunRecord {
        started,
        duration: Duration::ZERO,
        success: false,
        manual,
        skipped: true,
        output: reason.to_owned(),
    }
}

/// Hard cap for any runner output, applied at char boundaries.
pub fn truncate_output(output: &str) -> String {
    if output.chars().count() <= limits::OUTPUT_MAX_CHARS {
        return output.to_owned();
    }
    output.chars().take(limits::OUTPUT_MAX_CHARS).collect()
}
