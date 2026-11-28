//! Async SSH client built on `russh` (WP-61 §3.3):
//! - TOFU host key verification strictly BEFORE authentication (mismatched
//!   host key aborts the handshake without sending passwords or signatures).
//! - Host key family restriction & fallback loop with backfill (see [`hostkey`]).
//! - Password, pasted key, `keyFile`, and credential preset auth (see [`auth`]).
//! - Outbound SOCKS5 / HTTP CONNECT proxy support (see [`proxy`]).
//! - Interactive [`SshBackend`] implementing [`crate::session::Backend`],
//!   connection testing (without recording host keys), SFTP channel opening,
//!   and reusable `ssh_exec_target` / `ssh_push_target` helpers (which refuse
//!   untrusted hosts without a recorded host key).

pub mod auth;
pub mod hostkey;
pub mod proxy;

use std::borrow::Cow;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use russh::keys::PublicKeyOrCertificate;
use russh::{ChannelMsg, Disconnect};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, watch};

use crate::model::{AuthKind, ConnKind, Connection, HostKey, Preset, Proxy, limits};
use crate::session::{Backend, BackendError, ExitReason, OutputSink};
use crate::validate::host_key_label;

use self::auth::{AuthError, ResolvedAuth};
use self::hostkey::{HostKeyObservation, algorithms_of, attempts};

/// Resolved SSH connection parameters ready to dial.
#[derive(Clone, Debug)]
pub struct SshTarget {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: ResolvedAuth,
    pub work_dir: String,
    pub keep_alive: Option<Duration>,
    pub connect_timeout: Duration,
    pub host_key: Option<HostKey>,
    pub proxy: Option<Proxy>,
    pub terminal_type: String,
    pub env: Vec<(String, String)>,
    pub cols: u16,
    pub rows: u16,
}

impl SshTarget {
    /// Resolves a stored connection and preset table into an [`SshTarget`].
    pub fn resolve(conn: &Connection, presets: &[Preset]) -> Result<Self, AuthError> {
        Self::resolve_with_size(conn, presets, limits::DEFAULT_COLS, limits::DEFAULT_ROWS)
    }

    /// Resolves a stored connection with explicit initial terminal dimensions.
    pub fn resolve_with_size(
        conn: &Connection,
        presets: &[Preset],
        cols: u16,
        rows: u16,
    ) -> Result<Self, AuthError> {
        let resolved_auth = auth::resolve(&conn.auth, presets)?;
        let mut username = conn.username.clone();
        if username.is_empty()
            && conn.auth.kind == AuthKind::Preset
            && let Some(preset) = presets.iter().find(|p| p.key == conn.auth.preset)
        {
            username = preset.username.clone();
        }
        let port = conn.effective_port().unwrap_or(limits::SSH_PORT);
        let keep_alive =
            (conn.keep_alive > 0).then(|| Duration::from_secs(u64::from(conn.keep_alive)));
        Ok(Self {
            host: conn.host.clone(),
            port,
            username,
            auth: resolved_auth,
            work_dir: conn.work_dir.clone(),
            keep_alive,
            connect_timeout: conn.effective_timeout(),
            host_key: conn.host_key.clone(),
            proxy: conn.proxy.clone(),
            terminal_type: conn.effective_terminal_type().to_owned(),
            env: conn.env.clone(),
            cols: if cols == 0 {
                limits::DEFAULT_COLS
            } else {
                cols
            },
            rows: if rows == 0 {
                limits::DEFAULT_ROWS
            } else {
                rows
            },
        })
    }
}

/// Outcome of host key verification during an SSH handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKeyOutcome {
    /// Recorded key matched (no config update needed).
    Matched,
    /// First-use TOFU: a new host key should be recorded (unless this was a test).
    New(HostKey),
    /// Recorded fingerprint matched on a different/missing family: backfill `keyType`.
    Backfilled(HostKey),
}

impl HostKeyOutcome {
    /// Returns the host key that should be written back to configuration, if any.
    pub fn updated_key(&self) -> Option<&HostKey> {
        match self {
            Self::Matched => None,
            Self::New(hk) | Self::Backfilled(hk) => Some(hk),
        }
    }
}

/// Detailed SSH connection failure.
#[derive(Clone, Debug)]
pub enum SshConnectError {
    /// Server presented a host key that did not match the recorded fingerprint.
    /// Handshake was aborted BEFORE any credentials were sent.
    HostKeyChanged {
        recorded: HostKey,
        observed: HostKeyObservation,
    },
    /// Host has no recorded host key and unattended trust is refused.
    UntrustedHost,
    /// Authentication failed after host key verification succeeded.
    Auth(String),
    /// Network, proxy, timeout, or protocol failure.
    Transport(String),
}

impl std::fmt::Display for SshConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HostKeyChanged { recorded, observed } => write!(
                f,
                "主机密钥已变化：已记录 {}，服务器当前提供 {}",
                host_key_label(recorded),
                host_key_label(&observed.as_record())
            ),
            Self::UntrustedHost => write!(
                f,
                "主机尚未信任（未记录主机指纹），请先在 Web 终端中连接一次完成首次信任"
            ),
            Self::Auth(msg) => write!(f, "{msg}"),
            Self::Transport(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for SshConnectError {}

/// Response shape for `POST /api/webterminal/connections/test` and `…/{key}/test`
/// (WP-61 §2: `{ok, error?, serverVersion?, newHostKey?, latencyMs}`).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestConnectionResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_host_key: Option<HostKey>,
    pub latency_ms: u64,
}

/// Captures the server's `SSH-2.0-...` banner line without disturbing the stream.
struct BannerSniffer<S> {
    inner: S,
    buf: Vec<u8>,
    captured: Arc<Mutex<Option<String>>>,
    done: bool,
}

impl<S> BannerSniffer<S> {
    fn new(inner: S, captured: Arc<Mutex<Option<String>>>) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(64),
            captured,
            done: false,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for BannerSniffer<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll
            && !self.done
        {
            let newly_read = &buf.filled()[before..];
            for &b in newly_read {
                if self.buf.len() < 256 {
                    self.buf.push(b);
                }
                if b == b'\n' {
                    let line = String::from_utf8_lossy(&self.buf).trim().to_owned();
                    if line.starts_with("SSH-") {
                        *self.captured.lock().expect("banner lock") = Some(line);
                        self.done = true;
                        break;
                    }
                    self.buf.clear();
                }
            }
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for BannerSniffer<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Shared state observed during `check_server_key`.
#[derive(Default)]
struct VerifyState {
    observed: Option<HostKeyObservation>,
    rejected_mismatch: bool,
}

/// Minimal `russh::client::Handler` enforcing host key verification before auth.
pub struct SshClientHandler {
    expected_fp: Option<String>,
    state: Arc<Mutex<VerifyState>>,
}

impl russh::client::Handler for SshClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let Some(obs) = HostKeyObservation::from_wire(server_public_key) else {
            // Reject unsupported certificates.
            return Ok(false);
        };
        let mut st = self.state.lock().expect("verify state lock");
        st.observed = Some(obs.clone());
        match &self.expected_fp {
            None => Ok(true), // First-use TOFU
            Some(expected) => {
                if obs.fingerprint == *expected {
                    Ok(true)
                } else {
                    st.rejected_mismatch = true;
                    Ok(false)
                }
            }
        }
    }
}

/// An authenticated SSH handle along with host key verification outcome and server banner.
pub struct ConnectedSsh {
    pub handle: russh::client::Handle<SshClientHandler>,
    pub host_key_outcome: HostKeyOutcome,
    pub server_version: Option<String>,
}

/// Connects and authenticates an SSH session according to WP-61 TOFU rules.
/// If `require_trusted` is `true`, refuses connections without a recorded host key.
pub async fn connect_ssh(
    target: &SshTarget,
    require_trusted: bool,
) -> std::result::Result<ConnectedSsh, SshConnectError> {
    if require_trusted && target.host_key.is_none() {
        return Err(SshConnectError::UntrustedHost);
    }

    let attempt_list = attempts(target.host_key.as_ref());
    let mut last_mismatch: Option<HostKeyObservation> = None;
    let mut last_transport_err: Option<String> = None;

    for (idx, attempt) in attempt_list.iter().enumerate() {
        let stream = proxy::connect_tcp(
            &target.host,
            target.port,
            target.proxy.as_ref(),
            target.connect_timeout,
        )
        .await
        .map_err(|e| SshConnectError::Transport(e.to_string()))?;

        let banner = Arc::new(Mutex::new(None));
        let sniffer = BannerSniffer::new(stream, Arc::clone(&banner));

        let mut cfg = russh::client::Config {
            keepalive_interval: target.keep_alive,
            inactivity_timeout: None,
            nodelay: true,
            ..Default::default()
        };
        if let Some(restrict) = attempt.restrict {
            let algos = algorithms_of(restrict);
            if algos.is_empty() {
                continue;
            }
            cfg.preferred.key = Cow::Owned(algos);
        }

        let verify_state = Arc::new(Mutex::new(VerifyState::default()));
        let handler = SshClientHandler {
            expected_fp: attempt.expect.clone(),
            state: Arc::clone(&verify_state),
        };

        let connect_fut = russh::client::connect_stream(Arc::new(cfg), sniffer, handler);
        let connect_res = tokio::time::timeout(target.connect_timeout, connect_fut).await;

        match connect_res {
            Err(_) => {
                return Err(SshConnectError::Transport(format!(
                    "SSH 握手超时（{} 秒）",
                    target.connect_timeout.as_secs()
                )));
            }
            Ok(Ok(mut handle)) => {
                let observed = verify_state.lock().expect("verify state").observed.clone();
                let outcome = match (&target.host_key, observed) {
                    (None, Some(obs)) => HostKeyOutcome::New(obs.as_record()),
                    (Some(_), Some(obs)) if attempt.backfill => {
                        HostKeyOutcome::Backfilled(obs.as_record())
                    }
                    _ => HostKeyOutcome::Matched,
                };

                // Authenticate ONLY after host key verification succeeded.
                let auth_res = tokio::time::timeout(
                    target.connect_timeout,
                    auth::authenticate(&mut handle, &target.username, &target.auth),
                )
                .await;

                match auth_res {
                    Err(_) => {
                        let _ = handle.disconnect(Disconnect::ByApplication, "", "").await;
                        return Err(SshConnectError::Transport("SSH 认证超时".into()));
                    }
                    Ok(Err(auth_err)) => {
                        let _ = handle.disconnect(Disconnect::ByApplication, "", "").await;
                        // Auth failure must NEVER retry fallback host key families!
                        return Err(SshConnectError::Auth(auth_err.to_string()));
                    }
                    Ok(Ok(())) => {
                        let server_version = banner.lock().expect("banner").clone();
                        return Ok(ConnectedSsh {
                            handle,
                            host_key_outcome: outcome,
                            server_version,
                        });
                    }
                }
            }
            Ok(Err(err)) => {
                let st = verify_state.lock().expect("verify state");
                if st.rejected_mismatch {
                    let obs = st.observed.clone().expect("observed set on mismatch");
                    // If this was the explicitly recorded family (first attempt, not backfill),
                    // the server offered the recorded family with a DIFFERENT key -> host key changed!
                    if idx == 0 && !attempt.backfill {
                        return Err(SshConnectError::HostKeyChanged {
                            recorded: target.host_key.clone().expect("recorded key"),
                            observed: obs,
                        });
                    }
                    last_mismatch = Some(obs);
                    // Continue trying other families in case recorded family was missing/stale.
                    continue;
                }
                // Key exchange / algorithm negotiation failed before check_server_key (e.g. server
                // does not offer this host key family) -> try the next family in fallback order.
                last_transport_err = Some(err.to_string());
                continue;
            }
        }
    }

    if let (Some(recorded), Some(observed)) = (target.host_key.clone(), last_mismatch) {
        return Err(SshConnectError::HostKeyChanged { recorded, observed });
    }
    Err(SshConnectError::Transport(
        last_transport_err.unwrap_or_else(|| "SSH 连接失败".into()),
    ))
}

enum SshCmd {
    Write(Vec<u8>),
    Resize(u16, u16),
    Terminate,
}

/// Active interactive SSH terminal backend implementing [`Backend`].
pub struct SshBackend {
    cmd_tx: mpsc::UnboundedSender<SshCmd>,
    exit_rx: watch::Receiver<Option<ExitReason>>,
}

/// Opens an interactive SSH PTY shell session and returns the backend plus
/// any TOFU / backfill [`HostKeyOutcome`].
pub async fn open(
    target: &SshTarget,
    sink: OutputSink,
) -> std::result::Result<(SshBackend, HostKeyOutcome), String> {
    let connected = connect_ssh(target, false)
        .await
        .map_err(|e| e.to_string())?;
    let outcome = connected.host_key_outcome;
    let handle = connected.handle;

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("打开 SSH 会话通道失败：{e}"))?;

    channel
        .request_pty(
            false,
            &target.terminal_type,
            u32::from(target.cols),
            u32::from(target.rows),
            0,
            0,
            &[],
        )
        .await
        .map_err(|e| format!("请求 SSH PTY 失败：{e}"))?;

    for (k, v) in &target.env {
        if !k.trim().is_empty() {
            // Best effort: many sshd configs reject AcceptEnv.
            let _ = channel.set_env(false, k.trim(), v.as_str()).await;
        }
    }

    channel
        .request_shell(false)
        .await
        .map_err(|e| format!("启动 SSH Shell 失败：{e}"))?;

    if !target.work_dir.trim().is_empty() {
        let cmd = format!("cd {}\n", shell_quote(target.work_dir.trim()));
        let _ = channel.data(cmd.as_bytes()).await;
    }

    let (mut read_half, write_half) = channel.split();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<SshCmd>();
    let (exit_tx, exit_rx) = watch::channel(None);

    tokio::spawn(async move {
        let mut last_exit_code: Option<u32> = None;
        let reason = loop {
            tokio::select! {
                biased;
                cmd = cmd_rx.recv() => match cmd {
                    Some(SshCmd::Write(data)) => {
                        if write_half.data_bytes(data).await.is_err() {
                            break ExitReason::Closed;
                        }
                    }
                    Some(SshCmd::Resize(cols, rows)) => {
                        let _ = write_half
                            .window_change(u32::from(cols), u32::from(rows), 0, 0)
                            .await;
                    }
                    Some(SshCmd::Terminate) | None => {
                        let _ = write_half.eof().await;
                        let _ = write_half.close().await;
                        let _ = handle.disconnect(Disconnect::ByApplication, "", "").await;
                        break ExitReason::Terminated;
                    }
                },
                msg = read_half.wait() => match msg {
                    Some(ChannelMsg::Data { data }) => {
                        if !data.is_empty() {
                            sink(data.to_vec());
                        }
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        if !data.is_empty() {
                            sink(data.to_vec());
                        }
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        last_exit_code = Some(exit_status);
                    }
                    Some(ChannelMsg::Close) | None => {
                        let _ = handle.disconnect(Disconnect::ByApplication, "", "").await;
                        break match last_exit_code {
                            Some(code) => ExitReason::Exited(code),
                            None => ExitReason::Closed,
                        };
                    }
                    Some(ChannelMsg::Eof) => {
                        // Wait for Close / ExitStatus if coming next, otherwise exit on Close.
                    }
                    _ => {}
                }
            }
        };
        let _ = exit_tx.send(Some(reason));
    });

    Ok((SshBackend { cmd_tx, exit_rx }, outcome))
}

impl Backend for SshBackend {
    fn write(&mut self, data: Vec<u8>) -> std::result::Result<(), BackendError> {
        self.cmd_tx
            .send(SshCmd::Write(data))
            .map_err(|_| BackendError::Closed)
    }

    fn resize(&mut self, cols: u16, rows: u16) {
        let _ = self.cmd_tx.send(SshCmd::Resize(cols, rows));
    }

    fn terminate(&mut self) {
        let _ = self.cmd_tx.send(SshCmd::Terminate);
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

/// Tests a connection without mutating/recording host keys (WP-61 §3.3).
/// - SSH: verifies handshake (and returns `newHostKey` on first connect without saving),
///   authenticates, reports `serverVersion` and `latencyMs`.
/// - Telnet: verifies TCP (and optional proxy) reachability and `latencyMs`.
/// - Local: returns `Err` (routes answer HTTP 400).
pub async fn test_connection(
    conn: &Connection,
    presets: &[Preset],
) -> std::result::Result<TestConnectionResult, String> {
    let start = Instant::now();
    match conn.kind {
        ConnKind::Local => Err("本机 Shell 不支持连接测试".into()),
        ConnKind::Telnet => {
            let port = conn.effective_port().unwrap_or(limits::TELNET_PORT);
            match proxy::connect_tcp(
                &conn.host,
                port,
                conn.proxy.as_ref(),
                conn.effective_timeout(),
            )
            .await
            {
                Ok(_) => Ok(TestConnectionResult {
                    ok: true,
                    error: None,
                    server_version: None,
                    new_host_key: None,
                    latency_ms: start.elapsed().as_millis() as u64,
                }),
                Err(err) => Ok(TestConnectionResult {
                    ok: false,
                    error: Some(err.to_string()),
                    server_version: None,
                    new_host_key: None,
                    latency_ms: start.elapsed().as_millis() as u64,
                }),
            }
        }
        ConnKind::Ssh => {
            let target = match SshTarget::resolve(conn, presets) {
                Ok(t) => t,
                Err(err) => {
                    return Ok(TestConnectionResult {
                        ok: false,
                        error: Some(err.to_string()),
                        server_version: None,
                        new_host_key: None,
                        latency_ms: start.elapsed().as_millis() as u64,
                    });
                }
            };
            match connect_ssh(&target, false).await {
                Ok(connected) => {
                    let latency_ms = start.elapsed().as_millis() as u64;
                    let new_host_key = match connected.host_key_outcome {
                        HostKeyOutcome::New(hk) => Some(hk),
                        _ => None,
                    };
                    let _ = connected
                        .handle
                        .disconnect(Disconnect::ByApplication, "", "")
                        .await;
                    Ok(TestConnectionResult {
                        ok: true,
                        error: None,
                        server_version: connected.server_version,
                        new_host_key,
                        latency_ms,
                    })
                }
                Err(err) => Ok(TestConnectionResult {
                    ok: false,
                    error: Some(err.to_string()),
                    server_version: None,
                    new_host_key: None,
                    latency_ms: start.elapsed().as_millis() as u64,
                }),
            }
        }
    }
}

/// Opens an SFTP subsystem session over SSH.
pub async fn open_sftp_session(
    target: &SshTarget,
    require_trusted: bool,
) -> Result<(
    russh::client::Handle<SshClientHandler>,
    russh_sftp::client::SftpSession,
    HostKeyOutcome,
)> {
    let connected = connect_ssh(target, require_trusted)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let channel = connected
        .handle
        .channel_open_session()
        .await
        .map_err(|e| anyhow!("打开 SFTP 通道失败：{e}"))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| anyhow!("请求 SFTP 子系统失败：{e}"))?;
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| anyhow!("初始化 SFTP 会话失败：{e}"))?;
    Ok((connected.handle, sftp, connected.host_key_outcome))
}

/// Executes a single remote command over a fresh SSH connection.
/// Strictly refuses untrusted hosts without a recorded host key (WP-61 §8).
pub async fn ssh_exec_target(target: &SshTarget, command: &str) -> Result<String> {
    let connected = connect_ssh(target, true)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let mut channel = connected
        .handle
        .channel_open_session()
        .await
        .map_err(|e| anyhow!("打开执行通道失败：{e}"))?;
    channel
        .exec(true, command)
        .await
        .map_err(|e| anyhow!("执行远程命令失败：{e}"))?;

    let mut output = Vec::new();
    let mut exit_status: Option<u32> = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                output.extend_from_slice(&data);
            }
            ChannelMsg::ExitStatus { exit_status: code } => {
                exit_status = Some(code);
            }
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    let _ = connected
        .handle
        .disconnect(Disconnect::ByApplication, "", "")
        .await;

    let text = String::from_utf8_lossy(&output).into_owned();
    if let Some(code) = exit_status
        && code != 0
    {
        bail!("远程命令退出码 {code}：{text}");
    }
    Ok(text)
}

/// One file to upload via [`ssh_push_target`].
#[derive(Clone, Debug)]
pub struct PushFile {
    /// Relative path inside `dir` (must not contain `..`).
    pub name: String,
    pub content: Vec<u8>,
    pub mode: Option<u32>,
}

/// Uploads files into `dir` over SFTP and optionally executes `command`.
/// Strictly refuses untrusted hosts without a recorded host key (WP-61 §8).
pub async fn ssh_push_target(
    target: &SshTarget,
    dir: &str,
    files: &[PushFile],
    command: &str,
) -> Result<String> {
    let (handle, sftp, _outcome) = open_sftp_session(target, true).await?;

    let base_dir = dir.trim_end_matches('/');
    if !base_dir.is_empty() {
        ensure_remote_dir(&sftp, base_dir).await?;
    }

    for file in files {
        let rel = validate_relative_push_path(&file.name)?;
        let full_path = if base_dir.is_empty() {
            format!("/{rel}")
        } else {
            format!("{base_dir}/{rel}")
        };
        if let Some((parent, _)) = full_path.rsplit_once('/')
            && !parent.is_empty()
        {
            ensure_remote_dir(&sftp, parent).await?;
        }
        sftp.write(&full_path, &file.content)
            .await
            .map_err(|e| anyhow!("上传文件 {full_path} 失败：{e}"))?;
        if let Some(mode) = file.mode {
            let mut attrs = russh_sftp::protocol::FileAttributes::empty();
            attrs.permissions = Some(mode & 0o777);
            let _ = sftp.set_metadata(&full_path, attrs).await;
        }
    }
    let _ = sftp.close().await;

    let mut out = String::new();
    if !command.trim().is_empty() {
        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|e| anyhow!("打开执行通道失败：{e}"))?;
        channel
            .exec(true, command)
            .await
            .map_err(|e| anyhow!("执行部署命令失败：{e}"))?;
        let mut buf = Vec::new();
        let mut exit_status: Option<u32> = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                    buf.extend_from_slice(&data);
                }
                ChannelMsg::ExitStatus { exit_status: code } => {
                    exit_status = Some(code);
                }
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        out = String::from_utf8_lossy(&buf).into_owned();
        if let Some(code) = exit_status
            && code != 0
        {
            let _ = handle.disconnect(Disconnect::ByApplication, "", "").await;
            bail!("部署命令退出码 {code}：{out}");
        }
    }

    let _ = handle.disconnect(Disconnect::ByApplication, "", "").await;
    Ok(out)
}

async fn ensure_remote_dir(sftp: &russh_sftp::client::SftpSession, dir: &str) -> Result<()> {
    let mut current = String::new();
    let absolute = dir.starts_with('/');
    for part in dir.split('/').filter(|p| !p.is_empty()) {
        if absolute || !current.is_empty() {
            current.push('/');
        }
        current.push_str(part);
        if !sftp.try_exists(&current).await.unwrap_or(false) {
            let _ = sftp.create_dir(&current).await;
        }
    }
    Ok(())
}

fn validate_relative_push_path(raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        bail!("上传文件名不能为空");
    }
    for comp in trimmed.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            bail!("上传文件路径包含非法片段：{raw}");
        }
    }
    Ok(trimmed.to_owned())
}

/// Single-quotes a POSIX shell argument safely.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
