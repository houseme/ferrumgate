//! Command execution (WP-62 §3.3): run the task's shell command through
//! `sh -c` (a temporary `.bat` through `cmd /C` on Windows) with the task
//! name injected into the environment, a fixed timeout and a merged output
//! summary truncated to [`limits::OUTPUT_MAX_CHARS`].
//!
//! The command string is user configuration and executed verbatim; access
//! to this module's write scope is the authorization boundary (WP-62 §8).

use std::process::Stdio;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::{Outcome, truncate_output};

/// Environment injected into every command run: the literal `taskName`
/// plus its uppercase form with the FerrumGate prefix (upstream used
/// `GATELY_`; migration notes live in `docs/EXECUTION.md`).
pub fn env_pairs(task_name: &str) -> [(&'static str, &str); 2] {
    [("taskName", task_name), ("FERRUMGATE_TASKNAME", task_name)]
}

/// Runs `command` via `sh -c` with the task environment, aborting after
/// `timeout` or when `cancel` fires. The future owns the child handle,
/// which is spawned with `kill_on_drop`: dropping the losing select branch
/// (timeout or cancellation) kills the process.
pub async fn run(
    command: &str,
    task_name: &str,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Outcome {
    let child = match spawn(command, task_name).await {
        Ok(child) => child,
        Err(error) => {
            return Outcome {
                success: false,
                output: format!("启动命令失败：{error}"),
            };
        }
    };
    let waited = tokio::time::timeout(timeout, child.wait_with_output());
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Outcome {
            success: false,
            output: "任务在模块关闭时被终止".into(),
        },
        result = waited => match result {
            Ok(Ok(output)) => Outcome {
                success: output.status.success(),
                output: truncate_output(&merged_output(&output.stdout, &output.stderr)),
            },
            Ok(Err(error)) => Outcome {
                success: false,
                output: format!("等待命令退出失败：{error}"),
            },
            Err(_) => Outcome {
                success: false,
                output: format!("命令超时（超过 {} 秒），已终止", timeout.as_secs().max(1)),
            },
        },
    }
}

fn merged_output(stdout: &[u8], stderr: &[u8]) -> String {
    let mut merged = String::from_utf8_lossy(stdout).into_owned();
    let stderr = String::from_utf8_lossy(stderr);
    if !stderr.is_empty() {
        if !merged.is_empty() && !merged.ends_with('\n') {
            merged.push('\n');
        }
        merged.push_str(&stderr);
    }
    merged
}

#[cfg(unix)]
async fn spawn(command: &str, task_name: &str) -> std::io::Result<tokio::process::Child> {
    let mut cmd = tokio::process::Command::new("sh");
    cmd.arg("-c").arg(command);
    apply_env(&mut cmd, task_name);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    cmd.spawn()
}

#[cfg(windows)]
async fn spawn(command: &str, task_name: &str) -> std::io::Result<tokio::process::Child> {
    // Upstream runs commands through a temporary .bat on Windows; the
    // script is removed again once the child handle exists.
    let path = std::env::temp_dir().join(format!("ferrumgate-cron-{}.bat", std::process::id()));
    std::fs::write(&path, format!("@echo off\r\n{command}\r\n"))?;
    let mut cmd = tokio::process::Command::new("cmd");
    cmd.arg("/C").arg(&path);
    apply_env(&mut cmd, task_name);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let spawned = cmd.spawn();
    let _ = std::fs::remove_file(&path);
    spawned
}

fn apply_env(cmd: &mut tokio::process::Command, task_name: &str) {
    for (name, value) in env_pairs(task_name) {
        cmd.env(name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::limits;

    #[test]
    fn command_output_truncated_4000() {
        let long = "x".repeat(limits::OUTPUT_MAX_CHARS + 500);
        let truncated = truncate_output(&long);
        assert_eq!(truncated.chars().count(), limits::OUTPUT_MAX_CHARS);
        assert_eq!(truncate_output("short"), "short");
        // Multi-byte characters are cut at char boundaries.
        let wide = "汉".repeat(limits::OUTPUT_MAX_CHARS + 10);
        let truncated = truncate_output(&wide);
        assert_eq!(truncated.chars().count(), limits::OUTPUT_MAX_CHARS);
        assert!(truncated.ends_with('汉'));
    }

    #[test]
    fn command_env_has_task_name_pairs() {
        let pairs = env_pairs("备份");
        assert_eq!(pairs[0], ("taskName", "备份"));
        assert_eq!(pairs[1], ("FERRUMGATE_TASKNAME", "备份"));
    }
}
