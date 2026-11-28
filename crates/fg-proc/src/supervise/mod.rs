//! 进程托管（WP-43 §3.3）：启动官方外部程序（参数数组与环境，不经
//! shell）、把输出按行清理打码后写入模块日志、异常退出自动重启（带退避）、
//! 优雅停止（5 秒宽限后强制结束）、版本探测、运行中进程登记。
//!
//! 子进程生命周期与宿主绑定：[`Supervisor`] 被 Drop 时发送终止信号并中止
//! 监督任务（`kill_on_drop` 兜底），避免宿主重启后留下孤儿进程。
//!
//! 日志口径：fg-logging 目前没有托管进程的日志来源，输出行经
//! [`LogHandle`] 交给模块；[`LogHandle::tracing`] 按文档口径把每行接到
//! tracing（target `fg_proc::supervise`），等模块自己的日志来源就绪后再
//! 由装配层替换成写入 fg-logging 的句柄。

pub mod backoff;
pub mod output;

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, anyhow, bail};
use fg_logging::Level;
use tokio::{
    process::Child,
    sync::{mpsc, oneshot, watch},
};

use crate::registry::{self, Owner};

/// 停止宽限：5 秒（上游 `stopGrace`），超时强制结束。
pub const STOP_GRACE: Duration = Duration::from_secs(5);
/// 强制结束之后等待进程退出的追加宽限。
pub const KILL_GRACE: Duration = Duration::from_secs(2);
/// 版本探测的超时。
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// 单行输出的截断长度（超长日志行按 8 KiB 截断，避免长行占满内存）。
pub const LINE_CAP: usize = 8 * 1024;
/// `ExitInfo::output_tail` 保留的尾部字节数。
pub const OUTPUT_TAIL_CAP: usize = 4000;

/// 进程输出日志句柄：模块把清理打码后的每行接到自己的日志来源。
#[derive(Clone)]
pub struct LogHandle(LogFn);

type LogFn = Arc<dyn Fn(Level, &str) + Send + Sync>;

impl LogHandle {
    pub fn new(handle: impl Fn(Level, &str) + Send + Sync + 'static) -> Self {
        Self(Arc::new(handle))
    }

    /// 按文档口径接 tracing：target 固定为 `fg_proc::supervise`。注意
    /// fg-logging 的 LogLayer 目前不含托管程序日志来源，此句柄只进入
    /// 标准日志输出；模块接入时传入自己的句柄即可替换。
    pub fn tracing() -> Self {
        Self::new(|level, line| match level {
            Level::Debug => tracing::debug!(target: "fg_proc::supervise", "{line}"),
            Level::Info => tracing::info!(target: "fg_proc::supervise", "{line}"),
            Level::Warn => tracing::warn!(target: "fg_proc::supervise", "{line}"),
            Level::Error => tracing::error!(target: "fg_proc::supervise", "{line}"),
        })
    }

    pub fn write(&self, level: Level, line: &str) {
        (self.0)(level, line);
    }
}

/// 托管进程的启动规格。
#[derive(Clone, Debug)]
pub struct Spec {
    pub exe: PathBuf,
    pub args: Vec<std::ffi::OsString>,
    pub env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    pub cwd: Option<PathBuf>,
    /// 模块 + 实例名，只用于归属与登记。
    pub owner: Owner,
    /// 稳定运行多久后重置退避（默认 30 秒）。
    pub stable_after: Duration,
}

impl Spec {
    pub fn new(owner: Owner, exe: impl Into<PathBuf>) -> Self {
        Self {
            exe: exe.into(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            owner,
            stable_after: backoff::STABLE_AFTER,
        }
    }
}

/// 上一次退出的信息。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitInfo {
    pub at: SystemTime,
    /// 退出码；被信号结束时为 None。
    pub code: Option<i32>,
    /// 致命信号编号（Unix）；正常退出为 None。
    pub signal: Option<i32>,
    /// 退出前最后的输出（清理打码后），供状态页排障。
    pub output_tail: String,
}

/// 监督器状态快照。
#[derive(Clone, Debug, Default)]
pub struct State {
    pub running: bool,
    pub pid: Option<u32>,
    pub since: Option<SystemTime>,
    pub restarts: u32,
    pub last_exit: Option<ExitInfo>,
    /// 启动失败的原因（可执行文件不存在、没有执行权限等）；不重试，等待
    /// 用户修正配置后再次 `start`。
    pub failed: Option<String>,
}

impl State {
    /// 本次已运行的时长。
    pub fn uptime(&self) -> Option<Duration> {
        self.since.map(|since| {
            SystemTime::now()
                .duration_since(since)
                .unwrap_or(Duration::ZERO)
        })
    }
}

#[derive(Debug)]
pub enum SuperviseError {
    /// 启动失败（可执行文件不存在、没有执行权限等）。
    Start(String),
    /// 停止失败（宽限与强制结束后仍未退出）。
    Stop(String),
}

impl std::fmt::Display for SuperviseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Start(message) => write!(f, "{message}"),
            Self::Stop(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for SuperviseError {}

struct Supervision {
    running: bool,
    pid: Option<u32>,
    since: Option<SystemTime>,
    restarts: u32,
    last_exit: Option<ExitInfo>,
    failed: Option<String>,
}

struct Inner {
    spec: Spec,
    logs: LogHandle,
    state: Mutex<Supervision>,
    /// 停止代号：每调用一次 `stop` / Drop 就增加一次；监督任务只在代号
    /// 与自己启动时一致时继续重启。
    stop_tx: watch::Sender<u64>,
    exited_tx: watch::Sender<u64>,
    exited_rx: watch::Receiver<u64>,
    /// 串行化 start / stop。
    op: tokio::sync::Mutex<()>,
    session: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Inner {
    fn bump_exited(&self) {
        self.exited_tx.send_modify(|generation| *generation += 1);
    }

    fn stop_generation(&self) -> u64 {
        *self.stop_tx.subscribe().borrow()
    }
}

/// 一个受管进程的监督器。克隆 `Arc<Supervisor>` 供模块内各处使用；
/// 最后一个句柄被 Drop 时停止进程并移出登记表。
pub struct Supervisor {
    inner: Arc<Inner>,
}

impl Supervisor {
    pub fn new(spec: Spec, logs: LogHandle) -> Arc<Self> {
        let (stop_tx, _) = watch::channel(0u64);
        let (exited_tx, exited_rx) = watch::channel(0u64);
        Arc::new(Self {
            inner: Arc::new(Inner {
                spec,
                logs,
                state: Mutex::new(Supervision {
                    running: false,
                    pid: None,
                    since: None,
                    restarts: 0,
                    last_exit: None,
                    failed: None,
                }),
                stop_tx,
                exited_tx,
                exited_rx,
                op: tokio::sync::Mutex::new(()),
                session: Mutex::new(None),
            }),
        })
    }

    /// 启动进程；已在运行时先停止旧进程。启动失败（可执行文件不存在、
    /// 没有执行权限）时不重试：记录状态与日志，等待用户修正配置。
    pub async fn start(&self) -> Result<(), SuperviseError> {
        let _op = self.inner.op.lock().await;
        if self.inner.session.lock().expect("session lock").is_some() {
            self.stop_locked().await?;
        }
        let (first_tx, first_rx) = oneshot::channel();
        let stop_gen = self.inner.stop_generation();
        let handle = tokio::spawn(session_loop(
            Arc::clone(&self.inner),
            stop_gen,
            first_tx,
            self.inner.stop_tx.subscribe(),
        ));
        *self.inner.session.lock().expect("session lock") = Some(handle);
        match first_rx.await {
            Ok(result) => result,
            Err(_) => Err(SuperviseError::Start("监督任务意外退出".into())),
        }
    }

    /// 优雅停止：发送终止信号，等待 5 秒（`stopGrace`），未退出时强制
    /// 结束。停止后不再重启。
    pub async fn stop(&self) -> Result<(), SuperviseError> {
        let _op = self.inner.op.lock().await;
        self.stop_locked().await
    }

    /// 状态快照：pid / uptime / restarts / last_exit / 启动失败原因。
    pub fn state(&self) -> State {
        let st = self.inner.state.lock().expect("state lock");
        State {
            running: st.running,
            pid: st.pid,
            since: st.since,
            restarts: st.restarts,
            last_exit: st.last_exit.clone(),
            failed: st.failed.clone(),
        }
    }

    async fn stop_locked(&self) -> Result<(), SuperviseError> {
        let pid = self.inner.state.lock().expect("state lock").pid;
        self.inner
            .stop_tx
            .send_modify(|generation| *generation += 1);
        if self.inner.state.lock().expect("state lock").running
            && let Some(pid) = pid
        {
            signal_term(pid);
        }
        if !self.wait_not_running(STOP_GRACE).await {
            if let Some(pid) = self.inner.state.lock().expect("state lock").pid {
                tracing::warn!(owner = %self.inner.spec.owner, "优雅停止超时，强制结束进程");
                force_kill(pid);
            }
            if !self.wait_not_running(KILL_GRACE).await {
                return Err(SuperviseError::Stop("停止超时，进程仍未退出".into()));
            }
        }
        let handle = self.inner.session.lock().expect("session lock").take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
        Ok(())
    }

    async fn wait_not_running(&self, timeout: Duration) -> bool {
        let mut exited = self.inner.exited_rx.clone();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if !self.inner.state.lock().expect("state lock").running {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::select! {
                _ = exited.changed() => {}
                _ = tokio::time::sleep_until(deadline) => return false,
            }
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        let inner = &self.inner;
        inner.stop_tx.send_modify(|generation| *generation += 1);
        let (running, pid) = {
            let st = inner.state.lock().expect("state lock");
            (st.running, st.pid)
        };
        if running && let Some(pid) = pid {
            signal_term(pid);
        }
        // 中止监督任务：其持有的 Child（kill_on_drop）随之被杀，进程不会
        // 成为孤儿。之后再补一次登记表清理。
        if let Some(handle) = inner.session.lock().expect("session lock").take() {
            handle.abort();
        }
        registry::remove(&inner.spec.owner);
    }
}

fn program_name(spec: &Spec) -> String {
    spec.exe
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| spec.owner.instance.clone())
}

fn build_command(spec: &Spec) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(&spec.exe);
    command.args(&spec.args);
    for (key, value) in &spec.env {
        command.env(key, value);
    }
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}

#[cfg(unix)]
fn signal_term(pid: u32) {
    let Some(pid) = rustix::process::Pid::from_raw(pid as i32) else {
        return;
    };
    let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
}

#[cfg(unix)]
fn force_kill(pid: u32) {
    let Some(pid) = rustix::process::Pid::from_raw(pid as i32) else {
        return;
    };
    let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
}

#[cfg(windows)]
fn signal_term(_pid: u32) {
    // Windows 没有通用的优雅终止信号：宽限由后面的强制结束兜底。
}

#[cfg(windows)]
fn force_kill(pid: u32) {
    let _ = std::process::Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .spawn();
}

fn describe_exit(code: Option<i32>, signal: Option<i32>) -> String {
    match (code, signal) {
        (Some(code), _) => format!("退出码 {code}"),
        (None, Some(signal)) => format!("被信号 {signal} 结束"),
        (None, None) => "无退出状态".into(),
    }
}

fn decode_status(status: Option<std::process::ExitStatus>) -> (Option<i32>, Option<i32>) {
    let Some(status) = status else {
        return (None, None);
    };
    (status.code(), probe_signal(&status))
}

struct OutputTasks {
    tail: Arc<Mutex<String>>,
    readers: Vec<tokio::task::JoinHandle<()>>,
    processor: tokio::task::JoinHandle<()>,
}

async fn spawn_output_tasks(inner: &Inner, child: &mut Child) -> OutputTasks {
    let (line_tx, line_rx) = mpsc::unbounded_channel::<String>();
    let mut readers = Vec::new();
    if let Some(pipe) = child.stdout.take() {
        readers.push(tokio::spawn(read_lines(pipe, line_tx.clone())));
    }
    if let Some(pipe) = child.stderr.take() {
        readers.push(tokio::spawn(read_lines(pipe, line_tx)));
    }
    let tail = Arc::new(Mutex::new(String::new()));
    let processor = tokio::spawn(process_lines(
        line_rx,
        inner.logs.clone(),
        Arc::clone(&tail),
    ));
    OutputTasks {
        tail,
        readers,
        processor,
    }
}

async fn finish_output(tasks: OutputTasks) -> String {
    for reader in tasks.readers {
        let _ = reader.await;
    }
    // 进程死亡后管道很快 EOF；给处理任务一点时间排空剩余行。
    let _ = tokio::time::timeout(Duration::from_millis(300), tasks.processor).await;
    match Arc::try_unwrap(tasks.tail) {
        Ok(tail) => tail.into_inner().expect("tail lock"),
        Err(tail) => tail.lock().expect("tail lock").clone(),
    }
}

async fn read_lines<R>(pipe: R, line_tx: mpsc::UnboundedSender<String>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;

    let mut reader = tokio::io::BufReader::new(pipe);
    let mut buf = Vec::with_capacity(1024);
    loop {
        buf.clear();
        // 超长单行会在 read_until 中完整缓冲（截断到 LINE_CAP）；托管程序
        // 的日志行不会达到这个量级，先接受这个权衡。
        match reader.read_until(b'\n', &mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if buf.last() == Some(&b'\n') {
            buf.pop();
        }
        if buf.len() > LINE_CAP {
            buf.truncate(LINE_CAP);
        }
        if line_tx
            .send(String::from_utf8_lossy(&buf).into_owned())
            .is_err()
        {
            break;
        }
    }
}

async fn process_lines(
    mut line_rx: mpsc::UnboundedReceiver<String>,
    logs: LogHandle,
    tail: Arc<Mutex<String>>,
) {
    while let Some(line) = line_rx.recv().await {
        if line.trim().is_empty() {
            continue;
        }
        let (level, text) = output::process_line(&line);
        logs.write(level, &text);
        let mut tail = tail.lock().expect("tail lock");
        tail.push_str(&text);
        tail.push('\n');
        let excess = tail.len().saturating_sub(OUTPUT_TAIL_CAP);
        if excess > 0 {
            let mut cut = excess;
            while !tail.is_char_boundary(cut) {
                cut += 1;
            }
            tail.drain(..cut);
        }
    }
}

/// 监督任务：启动 → 记录状态 → 等待退出或停止 →（异常退出时）退避后重启。
/// 正常停止、启动失败或监督器被 Drop 时返回。
async fn session_loop(
    inner: Arc<Inner>,
    stop_gen: u64,
    first: oneshot::Sender<Result<(), SuperviseError>>,
    mut stop_rx: watch::Receiver<u64>,
) {
    let mut first = Some(first);
    let mut restarts = inner.state.lock().expect("state lock").restarts;
    let mut backoff =
        backoff::Backoff::new(backoff::INITIAL, backoff::MAX, inner.spec.stable_after);
    loop {
        let mut child = match build_command(&inner.spec).spawn() {
            Ok(child) => child,
            Err(error) => {
                let message = format!("启动失败：{error}");
                tracing::warn!(owner = %inner.spec.owner, "{message}");
                inner.logs.write(Level::Error, &message);
                {
                    let mut st = inner.state.lock().expect("state lock");
                    st.running = false;
                    st.pid = None;
                    st.since = None;
                    st.failed = Some(message.clone());
                }
                registry::remove(&inner.spec.owner);
                inner.bump_exited();
                if let Some(first) = first.take() {
                    let _ = first.send(Err(SuperviseError::Start(message)));
                }
                return;
            }
        };
        let pid = child.id();
        let since = SystemTime::now();
        {
            let mut st = inner.state.lock().expect("state lock");
            st.running = true;
            st.pid = pid;
            st.since = Some(since);
            st.failed = None;
        }
        registry::upsert(
            &inner.spec.owner,
            &program_name(&inner.spec),
            pid,
            Some(since),
            restarts,
        );
        if let Some(first) = first.take() {
            let _ = first.send(Ok(()));
        }
        let output = spawn_output_tasks(&inner, &mut child).await;
        let status = {
            let mut waiting = std::pin::pin!(child.wait());
            loop {
                tokio::select! {
                    biased;
                    // stop() 已发送终止信号；继续等待进程退出。stop_tx 活
                    // 在 Inner 里，监督任务活着它就不会消失。
                    _ = stop_rx.changed() => {}
                    status = &mut waiting => break status,
                }
            }
        };
        drop(child);
        let tail = finish_output(output).await;
        let ran_for = since.elapsed().unwrap_or(Duration::ZERO);
        let (code, signal) = decode_status(status.ok());
        {
            let mut st = inner.state.lock().expect("state lock");
            st.running = false;
            st.pid = None;
            st.last_exit = Some(ExitInfo {
                at: SystemTime::now(),
                code,
                signal,
                output_tail: tail,
            });
        }
        inner.bump_exited();
        // 正常停止（stop 被调用）不重启。
        if *stop_rx.borrow_and_update() != stop_gen {
            inner.logs.write(Level::Info, "进程已停止");
            registry::remove(&inner.spec.owner);
            return;
        }
        // 异常退出：退避从 1 秒起翻倍；稳定运行超过 stable_after 后重置。
        restarts = restarts.saturating_add(1);
        inner.state.lock().expect("state lock").restarts = restarts;
        let delay = backoff.next_delay(ran_for);
        let message = format!(
            "进程异常退出（{}），{} 秒后重启",
            describe_exit(code, signal),
            delay.as_secs()
        );
        tracing::warn!(owner = %inner.spec.owner, "{message}");
        inner.logs.write(Level::Warn, &message);
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = stop_rx.changed() => {
                inner.logs.write(Level::Info, "进程已停止");
                registry::remove(&inner.spec.owner);
                return;
            }
        }
        if *stop_rx.borrow_and_update() != stop_gen {
            inner.logs.write(Level::Info, "进程已停止");
            registry::remove(&inner.spec.owner);
            return;
        }
    }
}

/// 版本探测：运行 `<程序> <版本参数>`，取输出的第一行。
pub async fn probe(exe: &Path, args: &[std::ffi::OsString]) -> Result<String> {
    let mut command = tokio::process::Command::new(exe);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let output = tokio::time::timeout(PROBE_TIMEOUT, command.output())
        .await
        .map_err(|_| anyhow!("版本探测超过 {} 秒", PROBE_TIMEOUT.as_secs()))?
        .with_context(|| format!("运行 {} 失败（架构不符或缺少动态库）", exe.display()))?;
    if !output.status.success() {
        let signal = probe_signal(&output.status);
        bail!(
            "版本探测退出非 0（{}）",
            describe_exit(output.status.code(), signal)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let first = stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| anyhow!("版本探测没有输出"))?;
    Ok(first.to_owned())
}

#[cfg(unix)]
fn probe_signal(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn probe_signal(_: &std::process::ExitStatus) -> Option<i32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> Spec {
        Spec::new(Owner::new("frp", "test"), "/nonexistent/prog")
    }

    #[test]
    fn supervisor_new_state_idle() {
        let supervisor = Supervisor::new(spec(), LogHandle::tracing());
        let state = supervisor.state();
        assert!(!state.running);
        assert_eq!(state.pid, None);
        assert_eq!(state.uptime(), None);
        assert_eq!(state.last_exit, None);
    }

    #[test]
    fn describe_exit_covers_code_and_signal() {
        assert_eq!(describe_exit(Some(1), None), "退出码 1");
        assert_eq!(describe_exit(None, Some(9)), "被信号 9 结束");
        assert_eq!(describe_exit(None, None), "无退出状态");
    }
}
