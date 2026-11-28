//! Local shell backend (WP-61 §3.3 / §8):
//! Strictly gated behind `settings.allow_local_shell` (default `false`).
//! Runs a child shell with the FerrumGate process's user identity using
//! 100% safe Rust (`#![forbid(unsafe_code)]`) via `tokio::process::Command`.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::process::Stdio;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::{mpsc, watch};

use crate::model::{Connection, Settings};
use crate::session::{Backend, BackendError, ExitReason, OutputSink};

enum LocalCmd {
    Write(Vec<u8>),
    Terminate,
}

/// Active local shell backend implementing [`Backend`].
pub struct LocalShellBackend {
    cmd_tx: mpsc::UnboundedSender<LocalCmd>,
    exit_rx: watch::Receiver<Option<ExitReason>>,
}

/// Discovers usable local shells on this host (for `GET /api/webterminal/shells`).
pub fn available_shells() -> Vec<String> {
    let mut shells = Vec::new();
    if let Ok(env_shell) = std::env::var("SHELL") {
        let trimmed = env_shell.trim();
        if !trimmed.is_empty() && Path::new(trimmed).exists() {
            shells.push(trimmed.to_owned());
        }
    }
    let candidates = [
        "/bin/zsh",
        "/bin/bash",
        "/bin/sh",
        "/usr/bin/zsh",
        "/usr/bin/bash",
        "/usr/bin/fish",
        "/usr/local/bin/fish",
        "/opt/homebrew/bin/fish",
    ];
    for candidate in candidates {
        if Path::new(candidate).exists() && !shells.iter().any(|s| s == candidate) {
            shells.push(candidate.to_owned());
        }
    }
    shells
}

/// Resolves the default shell binary when `conn.shell_path` is empty.
pub fn default_shell() -> String {
    available_shells()
        .into_iter()
        .next()
        .unwrap_or_else(|| "/bin/sh".to_owned())
}

/// Opens a local shell session. Refuses immediately when
/// `settings.allow_local_shell` is `false` (WP-61 §8).
pub async fn open(
    conn: &Connection,
    settings: &Settings,
    cols: u16,
    rows: u16,
    sink: OutputSink,
) -> Result<LocalShellBackend, String> {
    if !settings.allow_local_shell {
        return Err("本机 Shell 功能未开启（请在设置中启用 allowLocalShell）".into());
    }

    let shell = if conn.shell_path.trim().is_empty() {
        default_shell()
    } else {
        conn.shell_path.trim().to_owned()
    };

    if !Path::new(&shell).exists() {
        return Err(format!("Shell 路径不存在：{shell}"));
    }

    let mut cmd = Command::new(&shell);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    if !conn.work_dir.trim().is_empty() {
        let wd = Path::new(conn.work_dir.trim());
        if !wd.is_dir() {
            return Err(format!("工作目录不存在：{}", conn.work_dir));
        }
        cmd.current_dir(wd);
    }

    cmd.env("TERM", conn.effective_terminal_type());
    cmd.env("COLUMNS", cols.to_string());
    cmd.env("LINES", rows.to_string());
    for (k, v) in &conn.env {
        if !k.trim().is_empty() {
            cmd.env(k.trim(), v);
        }
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("启动本机 Shell 失败（{shell}）：{e}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "无法打开本机 Shell 标准输入".to_owned())?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "无法打开本机 Shell 标准输出".to_owned())?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| "无法打开本机 Shell 标准错误".to_owned())?;

    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<LocalCmd>();
    let (exit_tx, exit_rx) = watch::channel(None);

    let sink_out = sink.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => sink_out(buf[..n].to_vec()),
            }
        }
    });

    let sink_err = sink;
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match stderr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => sink_err(buf[..n].to_vec()),
            }
        }
    });

    tokio::spawn(async move {
        let reason = loop {
            tokio::select! {
                biased;
                cmd = cmd_rx.recv() => match cmd {
                    Some(LocalCmd::Write(data)) => {
                        if stdin.write_all(&data).await.is_err() {
                            break ExitReason::Closed;
                        }
                        let _ = stdin.flush().await;
                    }
                    Some(LocalCmd::Terminate) | None => {
                        let _ = child.kill().await;
                        let _ = child.wait().await;
                        break ExitReason::Terminated;
                    }
                },
                status = child.wait() => {
                    match status {
                        Ok(exit) => {
                            if let Some(code) = exit.code() {
                                break ExitReason::Exited(code as u32);
                            } else {
                                break ExitReason::Closed;
                            }
                        }
                        Err(e) => break ExitReason::Failed(e.to_string()),
                    }
                }
            }
        };
        let _ = exit_tx.send(Some(reason));
    });

    Ok(LocalShellBackend { cmd_tx, exit_rx })
}

impl Backend for LocalShellBackend {
    fn write(&mut self, data: Vec<u8>) -> Result<(), BackendError> {
        self.cmd_tx
            .send(LocalCmd::Write(data))
            .map_err(|_| BackendError::Closed)
    }

    fn resize(&mut self, _cols: u16, _rows: u16) {
        // Pure-pipe child process does not support ioctl TIOCSWINSZ without unsafe.
    }

    fn terminate(&mut self) {
        let _ = self.cmd_tx.send(LocalCmd::Terminate);
    }

    fn wait_exit(&mut self) -> Pin<Box<dyn Future<Output = ExitReason> + Send + '_>> {
        Box::pin(async move {
            loop {
                if let Some(reason) = self.exit_rx.borrow().clone() {
                    return reason;
                }
                if self.exit_rx.changed().await.is_err() {
                    return ExitReason::Closed;
                }
            }
        })
    }
}
