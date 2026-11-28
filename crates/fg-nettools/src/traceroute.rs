//! Traceroute via system commands (WP-71 §3.3): Windows uses `tracert`,
//! other platforms prefer `traceroute` and fall back to `tracepath`. The
//! command runs as an argument array (no shell), output streams line by
//! line into the job, and no reverse resolution is requested (`-n` /
//! `-d`). A missing command fails the job with a clear message instead of
//! failing silently.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::jobs::{JobError, JobFut, JobHandle};
use crate::model::{TracerouteParams, limits};
use crate::validate;

pub const TRACERT: &str = "tracert";
pub const TRACEROUTE: &str = "traceroute";
pub const TRACEPATH: &str = "tracepath";

/// Platform split for the command choice (WP-71 §3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Unix,
}

pub fn platform() -> Platform {
    if cfg!(windows) {
        Platform::Windows
    } else {
        Platform::Unix
    }
}

/// Picks the command per platform given what exists. Windows has exactly
/// one candidate; Unix prefers `traceroute` over `tracepath`.
pub fn select_command(platform: Platform, available: &[&str]) -> Result<&'static str, String> {
    match platform {
        Platform::Windows => available
            .contains(&TRACERT)
            .then_some(TRACERT)
            .ok_or_else(|| "系统中没有 tracert 命令".into()),
        Platform::Unix => {
            if available.contains(&TRACEROUTE) {
                Ok(TRACEROUTE)
            } else if available.contains(&TRACEPATH) {
                Ok(TRACEPATH)
            } else {
                Err(
                    "系统中没有 traceroute 或 tracepath 命令（Docker 镜像可安装 traceroute 包）"
                        .into(),
                )
            }
        }
    }
}

/// Candidate file names for a command on this platform.
fn candidates(name: &str) -> Vec<String> {
    if cfg!(windows) && !name.ends_with(".exe") {
        vec![format!("{name}.exe")]
    } else {
        vec![name.to_owned()]
    }
}

/// Looks a command up in `path_env`; `None` when not found.
pub fn find_in_path_env(name: &str, path_env: &OsStr) -> Option<PathBuf> {
    for dir in std::env::split_paths(path_env) {
        for candidate in candidates(name) {
            let path = dir.join(&candidate);
            if path.is_file() {
                return Some(path);
            }
        }
    }
    None
}

/// Resolves the command for the platform against a PATH value (pure
/// filesystem lookup, testable without environment mutation).
pub fn resolve_command(
    platform: Platform,
    path_env: &OsStr,
) -> Result<(PathBuf, &'static str), String> {
    let name = match platform {
        Platform::Windows => vec![TRACERT],
        Platform::Unix => vec![TRACEROUTE, TRACEPATH],
    };
    let mut available = Vec::new();
    for candidate in &name {
        if find_in_path_env(candidate, path_env).is_some() {
            available.push(*candidate);
        }
    }
    let chosen = select_command(platform, &available)?;
    let path = find_in_path_env(chosen, path_env).expect("checked above");
    Ok((path, chosen))
}

/// Builds the argument array: no reverse resolution (`-n` / `-d`), the hop
/// limit where supported. `tracepath` has no portable hop limit, so it
/// relies on the job timeout.
pub fn build_args(command: &str, max_hops: u8, target: &str) -> Vec<String> {
    match command {
        TRACERT => vec![
            "-d".into(),
            "-h".into(),
            max_hops.to_string(),
            "-w".into(),
            "2000".into(),
            target.to_owned(),
        ],
        TRACEROUTE => vec![
            "-n".into(),
            "-m".into(),
            max_hops.to_string(),
            "-w".into(),
            "2".into(),
            "-q".into(),
            "1".into(),
            target.to_owned(),
        ],
        TRACEPATH => vec!["-n".into(), target.to_owned()],
        _ => vec![target.to_owned()],
    }
}

/// Runs one already-resolved command to completion, streaming stdout lines
/// into the job. Returns the number of output lines; fails when the
/// process could not start, produced no output, or exited with an error
/// and no output. Cancellation kills the child.
pub async fn run_command(
    path: &Path,
    args: &[String],
    handle: &JobHandle,
) -> Result<usize, JobError> {
    let mut child = Command::new(path)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| JobError::Message(format!("无法启动 {}：{error}", path.display())))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| JobError::Message("无法读取命令输出".into()))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| JobError::Message("无法读取命令错误输出".into()))?;
    let stderr_task = tokio::spawn(async move {
        let mut buffer = String::new();
        let mut reader = BufReader::new(&mut stderr);
        while let Ok(count) = reader.read_line(&mut buffer).await {
            if count == 0 {
                break;
            }
            if buffer.len() > 16 * 1024 {
                break;
            }
        }
        buffer
    });
    let mut lines = BufReader::new(&mut stdout).lines();
    let mut count = 0usize;
    loop {
        tokio::select! {
            biased;
            _ = handle.token().cancelled() => {
                let _ = child.kill().await;
                return Ok(count);
            }
            line = lines.next_line() => {
                match line {
                    Ok(Some(text)) => {
                        handle.line(text);
                        count += 1;
                    }
                    Ok(None) => break,
                    Err(error) => {
                        handle.line(format!("读取输出失败：{error}"));
                        break;
                    }
                }
            }
        }
    }
    let status = child
        .wait()
        .await
        .map_err(|error| JobError::Message(format!("等待命令退出失败：{error}")))?;
    let error_text = stderr_task
        .await
        .unwrap_or_else(|_| String::from("命令错误输出不可读"));
    if count == 0 {
        let mut message = "命令没有输出".to_owned();
        if !status.success() {
            message.push_str(&format!("（退出码 {}）", status.code().unwrap_or(-1)));
        }
        let excerpt: String = error_text.trim().chars().take(200).collect();
        if !excerpt.is_empty() {
            message.push_str(&format!("：{excerpt}"));
        }
        return Err(JobError::Message(message));
    }
    handle.line(format!("追踪完成，共 {count} 行输出"));
    Ok(count)
}

/// Runs the traceroute tool job.
pub fn run(params: &TracerouteParams, handle: JobHandle, deny: &[validate::DenyEntry]) -> JobFut {
    let params = params.clone();
    let deny = deny.to_vec();
    Box::pin(async move {
        let target = params.target.trim().to_owned();
        if !validate::valid_target(&target) {
            return Err(JobError::Message(format!("无效的目标 {target}")));
        }
        let max_hops = params
            .max_hops
            .unwrap_or(limits::TRACEROUTE_MAX_HOPS)
            .clamp(1, limits::TRACEROUTE_MAX_HOPS);
        let ip = crate::dns_lookup::resolve_target(&target)
            .await
            .map_err(JobError::Message)?;
        if let Some(reason) = validate::deny_reason(&target, &[ip], &deny) {
            return Err(JobError::Message(reason));
        }
        let platform = platform();
        let path_env = std::env::var_os("PATH")
            .ok_or_else(|| JobError::Message("无法读取 PATH 环境变量".into()))?;
        let (path, command) = resolve_command(platform, &path_env).map_err(JobError::Message)?;
        handle.line(format!(
            "使用 {command} 追踪 {target}（{ip}，最多 {max_hops} 跳，不做反向解析）"
        ));
        let args = build_args(command, max_hops, &target);
        run_command(&path, &args, &handle).await?;
        Ok(())
    })
}
