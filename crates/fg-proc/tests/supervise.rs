//! 托管进程的集成测试（WP-43 §6）：用 rustc 现场编译的 Rust 夹具程序
//! 验证启动、异常退出重启、优雅停止宽限、启动失败上报、Drop 收尾、
//! 版本探测与输出日志（清理、分级、打码）。

mod common;

use std::{
    ffi::OsString,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use fg_logging::Level;
use fg_proc::{Owner, Spec, State, SuperviseError, Supervisor, supervise};

use common::{fixture, wait_until};

/// 收集 LogHandle 收到的行（级别 + 文本）。
type LogCapture = Arc<Mutex<Vec<(Level, String)>>>;

fn capture_logs() -> (LogCapture, fg_proc::LogHandle) {
    let lines: LogCapture = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    let handle = fg_proc::LogHandle::new(move |level, line| {
        sink.lock()
            .expect("log capture lock")
            .push((level, line.to_owned()));
    });
    (lines, handle)
}

fn spec_for(owner: &str, args: &[&str]) -> Spec {
    let mut spec = Spec::new(Owner::new("frp", owner), fixture());
    spec.args = args.iter().map(OsString::from).collect();
    spec
}

async fn start_ok(supervisor: &Arc<Supervisor>) {
    supervisor.start().await.expect("supervisor start succeeds");
}

#[tokio::test]
async fn supervisor_restarts_on_crash() {
    let (lines, logs) = capture_logs();
    // 夹具运行 300ms 后以非零码退出；stable_after 设为 200ms，让退避在
    // 每次重启后重置（同时覆盖「稳定运行后重置」的行为），重启节奏保持
    // 在 1 秒一拍。
    let mut spec = spec_for("crash", &["die", "300"]);
    spec.stable_after = Duration::from_millis(200);
    let supervisor = Supervisor::new(spec, logs);
    start_ok(&supervisor).await;
    // 等「第二次重启的进程回到运行状态」再断言，避免撞上退避等待的间隙。
    let restarted = wait_until(
        || {
            let state = supervisor.state();
            state.restarts >= 2 && state.running && state.pid.is_some()
        },
        Duration::from_secs(8),
    )
    .await;
    assert!(restarted, "崩溃后应自动重启，实际 {:?}", supervisor.state());
    let state = supervisor.state();
    assert!(state.running, "重启后进程在运行");
    assert!(state.pid.is_some());
    let last_exit = state.last_exit.expect("last exit recorded");
    assert_eq!(last_exit.code, Some(1), "退出码被记录");
    assert!(last_exit.at.elapsed().unwrap_or(Duration::MAX) < Duration::from_secs(30));
    // 每次退出都写了「进程异常退出」日志。
    let logged = lines
        .lock()
        .expect("log capture lock")
        .iter()
        .any(|(level, line)| *level == Level::Warn && line.contains("进程异常退出"));
    assert!(logged, "退出写入了警告日志");
    supervisor.stop().await.expect("stop");
}

#[tokio::test]
async fn supervisor_stop_grace_5s_then_kill() {
    let (_lines, logs) = capture_logs();
    let supervisor = Supervisor::new(spec_for("stubborn", &["ignoreterm", "30"]), logs);
    start_ok(&supervisor).await;
    assert!(supervisor.state().running);
    // 等夹具把 SIGTERM 设为忽略之后再停止；否则终止信号落在它设置
    // SIG_IGN 之前的默认处置窗口里，测不到宽限路径。
    tokio::time::sleep(Duration::from_millis(500)).await;
    let started = Instant::now();
    supervisor.stop().await.expect("stop succeeds");
    let elapsed = started.elapsed();
    // 忽略 SIGTERM 的夹具必须等到 5 秒宽限后被 SIGKILL 结束。
    assert!(
        elapsed >= Duration::from_secs(4),
        "优雅停止等待了 {elapsed:?}，应接近 5 秒宽限"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "强制结束耗时 {elapsed:?}"
    );
    let state = supervisor.state();
    assert!(!state.running);
    #[cfg(unix)]
    {
        let last_exit = state.last_exit.expect("exit recorded");
        assert_eq!(last_exit.signal, Some(9), "宽限超时后用 SIGKILL 结束");
    }
}

#[tokio::test]
async fn supervisor_start_failure_reported() {
    let (lines, logs) = capture_logs();
    let mut spec = Spec::new(Owner::new("frp", "missing"), "/nonexistent/fg-proc-fixture");
    spec.args = vec!["exit".into()];
    let supervisor = Supervisor::new(spec, logs);
    let error = supervisor
        .start()
        .await
        .expect_err("start with missing binary fails");
    assert!(matches!(error, SuperviseError::Start(_)), "{error:?}");
    let state: State = supervisor.state();
    assert!(!state.running);
    assert!(state.pid.is_none());
    assert!(
        state
            .failed
            .as_deref()
            .is_some_and(|m| m.contains("启动失败")),
        "启动失败原因被记录：{state:?}"
    );
    let logged = lines
        .lock()
        .expect("log capture lock")
        .iter()
        .any(|(level, line)| *level == Level::Error && line.contains("启动失败"));
    assert!(logged, "启动失败写入了错误日志");
    // 不重试：登记表里没有这个进程。
    let registered = fg_proc::registry::running()
        .iter()
        .any(|p| p.instance == "missing");
    assert!(!registered, "启动失败的进程不进登记表");
}

#[tokio::test]
async fn supervisor_drop_stops() {
    let (_lines, logs) = capture_logs();
    let supervisor = Supervisor::new(spec_for("dropped", &["sleep", "30"]), logs);
    start_ok(&supervisor).await;
    let pid = supervisor.state().pid.expect("running pid");
    drop(supervisor);
    // Drop 后短暂时进程应已不存在（SIGTERM + kill_on_drop 兜底）。
    let gone = wait_until(
        || {
            #[cfg(unix)]
            {
                // kill(pid, 0)：ESRCH 表示进程不存在。
                let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
                rc == -1
            }
            #[cfg(not(unix))]
            {
                true
            }
        },
        Duration::from_secs(3),
    )
    .await;
    assert!(gone, "Drop 后子进程应被结束，pid {pid} 仍在运行");
}

#[tokio::test]
async fn version_probe_first_line() {
    let first = supervise::probe(&fixture(), &["version".into()])
        .await
        .expect("probe succeeds");
    assert_eq!(first, "fakeprog 1.2.3", "取输出的第一行");
    // 探测失败（不存在的程序 / 非零退出）。
    assert!(
        supervise::probe(std::path::Path::new("/nonexistent/prog"), &[])
            .await
            .is_err()
    );
    assert!(
        supervise::probe(&fixture(), &["exit".into(), "3".into()])
            .await
            .is_err(),
        "非零退出码的探测失败"
    );
}

#[tokio::test]
async fn supervisor_logs_cleaned_and_masked_lines() {
    let (lines, logs) = capture_logs();
    let supervisor = Supervisor::new(spec_for("noisy", &["noisy"]), logs);
    start_ok(&supervisor).await;
    let collected = wait_until(
        || lines.lock().expect("log capture lock").len() >= 2,
        Duration::from_secs(3),
    )
    .await;
    assert!(collected, "stdout 与 stderr 都写进了日志");
    let all = lines.lock().expect("log capture lock").clone();
    // stdout：颜色码、回车、时间戳被清理，frp 风格级别被识别为错误。
    let stdout_line = all
        .iter()
        .find(|(_, line)| line.contains("connection refused"))
        .expect("stdout line captured");
    assert_eq!(stdout_line.0, Level::Error);
    assert_eq!(
        stdout_line.1, "[E] connection refused",
        "清理后 {}",
        stdout_line.1
    );
    // stderr：登录链接的路径与查询被打码。
    let stderr_line = all
        .iter()
        .find(|(_, line)| line.contains("login.tailscale.com"))
        .expect("stderr line captured");
    assert!(
        stderr_line.1.contains("login.tailscale.com/********"),
        "登录链接被打码：{}",
        stderr_line.1
    );
    assert!(!stderr_line.1.contains("token123"), "一次性令牌不进日志");
    supervisor.stop().await.expect("stop");
}
