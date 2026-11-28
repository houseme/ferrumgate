//! Persistent sessions (WP-61 §3.2/§3.3): server-side terminal sessions
//! with a bounded replay buffer, multi-client attach (shared input,
//! broadcast output) and the timeout rules — idle timeout, keep-alive
//! after the last client leaves, and the `maxSessions` ceiling answered
//! with HTTP 429.
//!
//! A session is a [`SessionInner`] record plus a pump task that owns the
//! [`Backend`]: input arrives on a control channel, output reaches the
//! session through the [`OutputSink`] the backend's reader was opened
//! with. When the backend exits, the pump broadcasts the `x` message and
//! removes the session, which closes every attached WebSocket.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::ws::ServerMsg;

/// Unix-seconds clock; injectable for the timeout tests.
pub type NowFn = Arc<dyn Fn() -> i64 + Send + Sync>;

/// The system UTC clock.
pub fn system_clock() -> NowFn {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_secs() as i64)
            .unwrap_or_default()
    })
}

/// A failed session operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// The `maxSessions` ceiling is reached (HTTP 429).
    TooMany,
    /// The session id is unknown (HTTP 404).
    NotFound,
    /// The backend could not be connected (HTTP 502).
    Connect(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooMany => write!(f, "并发会话已达上限"),
            Self::NotFound => write!(f, "会话不存在"),
            Self::Connect(detail) => write!(f, "连接失败：{detail}"),
        }
    }
}

/// Why a backend process ended; rendered into the `x` message's reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitReason {
    /// The channel closed without a report (connection dropped).
    Closed,
    /// The remote process exited with a status code.
    Exited(u32),
    /// The backend was terminated by FerrumGate (idle, keep-alive, user).
    Terminated,
    /// The backend reported an error condition.
    Failed(String),
}

impl ExitReason {
    /// The human readable reason sent in the `x` message.
    pub fn describe(&self) -> String {
        match self {
            Self::Closed => "连接已关闭".into(),
            Self::Exited(code) => format!("进程已退出（{code}）"),
            Self::Terminated => "会话已结束".into(),
            Self::Failed(detail) => format!("会话异常结束：{detail}"),
        }
    }
}

/// A write failure reported by a backend's input path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendError {
    /// The backend channel is already gone.
    Closed,
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "终端通道已关闭"),
        }
    }
}

/// A terminal backend: the process side of a session. Implementations are
/// constructed with an [`OutputSink`] (their reader forwards PTY output
/// into it) and only expose input, resize, termination and exit here.
/// Every method is called from the session pump task.
pub trait Backend: Send + 'static {
    /// Queues bytes of keyboard input. Never blocks: the pump must stay
    /// responsive to termination while the backend is stalled.
    fn write(&mut self, data: Vec<u8>) -> Result<(), BackendError>;
    /// Applies a terminal window resize.
    fn resize(&mut self, cols: u16, rows: u16);
    /// Asks the backend to end (channel close / process kill).
    fn terminate(&mut self);
    /// Resolves when the backend has exited; the pump awaits this to
    /// broadcast the `x` message and drop the session.
    fn wait_exit(&mut self) -> Pin<Box<dyn Future<Output = ExitReason> + Send + '_>>;
}

/// Terminal output sink a backend's reader pushes decoded PTY bytes into.
pub type OutputSink = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

/// One item on a client's live output stream: terminal data (with the
/// sequence number used to deduplicate against the replay snapshot) or a
/// protocol text message.
#[derive(Clone, Debug)]
pub enum LiveItem {
    Data { seq: u64, data: Arc<[u8]> },
    Server(ServerMsg),
}

/// Runtime ceilings derived from the settings (hot-updated by the
/// settings PUT).
#[derive(Clone, Debug)]
pub struct Caps {
    pub max_sessions: usize,
    pub buffer_bytes: usize,
    pub idle_timeout: Option<Duration>,
    pub keep_alive: Option<Duration>,
}

impl Caps {
    /// Builds the caps from normalized settings (WP-61 §3.4).
    pub fn from_settings(settings: &crate::model::Settings) -> Self {
        Self {
            max_sessions: settings.max_sessions as usize,
            buffer_bytes: settings.buffer_size as usize * 1024,
            idle_timeout: if settings.idle_timeout == 0 {
                None
            } else {
                Some(Duration::from_secs(u64::from(settings.idle_timeout) * 60))
            },
            keep_alive: if settings.session_keep_alive == 0 {
                None
            } else {
                Some(Duration::from_secs(
                    u64::from(settings.session_keep_alive) * 60,
                ))
            },
        }
    }
}

enum Control {
    Input(Vec<u8>),
    Resize(u16, u16),
    Terminate,
}

struct ReplayChunk {
    seq: u64,
    data: Arc<[u8]>,
}

struct ReplayBuffer {
    chunks: std::collections::VecDeque<ReplayChunk>,
    total: usize,
    cap: usize,
}

impl ReplayBuffer {
    fn new(cap: usize) -> Self {
        Self {
            chunks: std::collections::VecDeque::new(),
            total: 0,
            cap: cap.max(1024),
        }
    }

    /// Pushes one chunk, dropping the oldest until the buffer fits.
    fn push(&mut self, chunk: ReplayChunk) {
        self.total += chunk.data.len();
        self.chunks.push_back(chunk);
        while self.total > self.cap {
            let Some(oldest) = self.chunks.pop_front() else {
                break;
            };
            self.total = self.total.saturating_sub(oldest.data.len());
        }
    }

    fn snapshot(&self) -> Vec<(u64, Arc<[u8]>)> {
        self.chunks
            .iter()
            .map(|chunk| (chunk.seq, chunk.data.clone()))
            .collect()
    }
}

/// The shared session record.
pub struct SessionInner {
    pub id: String,
    pub conn_key: String,
    created_at: i64,
    last_active: AtomicI64,
    last_detached: AtomicI64,
    attached: AtomicUsize,
    cols: AtomicU16,
    rows: AtomicU16,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    next_seq: AtomicU64,
    remark: Mutex<String>,
    replay: Mutex<ReplayBuffer>,
    live_tx: broadcast::Sender<LiveItem>,
    control_tx: tokio::sync::mpsc::UnboundedSender<Control>,
    control_rx: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<Control>>>,
}

impl SessionInner {
    fn new(
        id: String,
        conn_key: String,
        cols: u16,
        rows: u16,
        buffer_bytes: usize,
        now: i64,
    ) -> Self {
        let (live_tx, _) = broadcast::channel(256);
        let (control_tx, control_rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            id,
            conn_key,
            created_at: now,
            last_active: AtomicI64::new(now),
            last_detached: AtomicI64::new(now),
            attached: AtomicUsize::new(0),
            cols: AtomicU16::new(cols),
            rows: AtomicU16::new(rows),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            next_seq: AtomicU64::new(0),
            remark: Mutex::new(String::new()),
            replay: Mutex::new(ReplayBuffer::new(buffer_bytes)),
            live_tx,
            control_tx,
            control_rx: Mutex::new(Some(control_rx)),
        }
    }

    /// The output sink handed to the backend's reader: chunks the output,
    /// appends it to the replay buffer, broadcasts it live and accounts
    /// the bytes.
    fn output_sink(self: &Arc<Self>, clock: NowFn) -> OutputSink {
        let inner = Arc::clone(self);
        Arc::new(move |bytes: Vec<u8>| {
            let now = (clock)();
            inner.last_active.store(now, Ordering::Relaxed);
            for chunk in chunk_output(bytes) {
                let seq = inner.next_seq.fetch_add(1, Ordering::Relaxed);
                let chunk: Arc<[u8]> = chunk.into();
                inner
                    .bytes_out
                    .fetch_add(chunk.len() as u64, Ordering::Relaxed);
                inner.replay.lock().expect("replay lock").push(ReplayChunk {
                    seq,
                    data: Arc::clone(&chunk),
                });
                let _ = inner.live_tx.send(LiveItem::Data { seq, data: chunk });
            }
        })
    }

    /// The replay snapshot with sequence numbers (for [`attach`]).
    fn replay_snapshot(&self) -> Vec<(u64, Arc<[u8]>)> {
        self.replay.lock().expect("replay lock").snapshot()
    }

    fn control(&self, message: Control) {
        // Unbounded sends only fail when the pump is gone; the session is
        // being torn down in that case and the message is dropped.
        let _ = self.control_tx.send(message);
    }

    /// The RFC 3339 creation time.
    pub fn created_at_rfc3339(&self) -> String {
        rfc3339(self.created_at)
    }

    /// The RFC 3339 last-activity time.
    pub fn last_active_rfc3339(&self) -> String {
        rfc3339(self.last_active.load(Ordering::Relaxed))
    }

    /// Seconds since the last input or output.
    pub fn idle_seconds(&self, now: i64) -> i64 {
        (now - self.last_active.load(Ordering::Relaxed)).max(0)
    }

    /// Seconds since the last client detached (or creation).
    pub fn detached_seconds(&self, now: i64) -> i64 {
        (now - self.last_detached.load(Ordering::Relaxed)).max(0)
    }

    /// The number of currently attached clients.
    pub fn attachers(&self) -> usize {
        self.attached.load(Ordering::Relaxed)
    }

    /// The current window size.
    pub fn window(&self) -> (u16, u16) {
        (
            self.cols.load(Ordering::Relaxed),
            self.rows.load(Ordering::Relaxed),
        )
    }

    /// The session remark.
    pub fn remark(&self) -> String {
        self.remark.lock().expect("remark lock").clone()
    }

    /// Replaces the session remark.
    pub fn set_remark(&self, remark: String) {
        *self.remark.lock().expect("remark lock") = remark;
    }
}

/// Splits backend output into replay chunks of at most
/// [`crate::model::limits::OUTPUT_CHUNK_MAX_BYTES`] bytes.
fn chunk_output(bytes: Vec<u8>) -> Vec<Vec<u8>> {
    if bytes.len() <= crate::model::limits::OUTPUT_CHUNK_MAX_BYTES {
        return vec![bytes];
    }
    bytes
        .chunks(crate::model::limits::OUTPUT_CHUNK_MAX_BYTES)
        .map(<[u8]>::to_vec)
        .collect()
}

fn rfc3339(unix_seconds: i64) -> String {
    let Ok(datetime) = time::OffsetDateTime::from_unix_timestamp(unix_seconds) else {
        return String::new();
    };
    datetime
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// The session as listed by the API.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionView {
    pub id: String,
    pub conn_key: String,
    pub remark: String,
    pub created_at: String,
    pub last_active: String,
    pub cols: u16,
    pub rows: u16,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub attachers: usize,
}

impl SessionView {
    fn of(inner: &SessionInner) -> Self {
        let (cols, rows) = inner.window();
        Self {
            id: inner.id.clone(),
            conn_key: inner.conn_key.clone(),
            remark: inner.remark(),
            created_at: inner.created_at_rfc3339(),
            last_active: inner.last_active_rfc3339(),
            cols,
            rows,
            bytes_in: inner.bytes_in.load(Ordering::Relaxed),
            bytes_out: inner.bytes_out.load(Ordering::Relaxed),
            attachers: inner.attachers(),
        }
    }
}

struct TableState {
    sessions: HashMap<String, Arc<SessionInner>>,
    caps: Caps,
}

/// The session table: creation, attach, input, timeouts. Cheap to share;
/// the module's run task owns the janitor loop over the same `Arc`.
pub struct SessionTable {
    state: Mutex<TableState>,
    clock: NowFn,
}

/// The result of [`SessionTable::attach`]: replay first, then live.
pub struct Attach {
    /// The buffered output as `(seq, bytes)` in order.
    pub replay: Vec<(u64, Arc<[u8]>)>,
    /// The highest sequence number already replayed.
    pub last_seq: u64,
    /// The live stream starting right now.
    pub live: broadcast::Receiver<LiveItem>,
    /// The session view at attach time.
    pub view: SessionView,
    _guard: AttachGuard,
}

impl std::fmt::Debug for Attach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attach")
            .field("id", &self.view.id)
            .field("last_seq", &self.last_seq)
            .finish()
    }
}

struct AttachGuard {
    inner: Arc<SessionInner>,
    table: Arc<SessionTable>,
}

impl Drop for AttachGuard {
    fn drop(&mut self) {
        let remaining = self.inner.attached.fetch_sub(1, Ordering::Relaxed);
        if remaining == 1 {
            let now = (self.table.clock)();
            self.inner.last_detached.store(now, Ordering::Relaxed);
            // keepAlive 0: the session ends as soon as its last client
            // leaves (WP-61 §3.3).
            let keep_alive = self.table.state.lock().expect("table lock").caps.keep_alive;
            if keep_alive.is_none() {
                self.table.close(&self.inner.id);
            }
        }
    }
}

impl SessionTable {
    /// A table with the given ceilings and the system clock.
    pub fn new(caps: Caps) -> Self {
        Self::with_clock(caps, system_clock())
    }

    /// A table with an injectable clock (timeout tests).
    pub fn with_clock(caps: Caps, clock: NowFn) -> Self {
        Self {
            state: Mutex::new(TableState {
                sessions: HashMap::new(),
                caps,
            }),
            clock,
        }
    }

    /// Hot-updates the ceilings (settings PUT); existing sessions keep
    /// their replay buffer size.
    pub fn set_caps(&self, caps: Caps) {
        self.state.lock().expect("table lock").caps = caps;
    }

    /// The current caps.
    pub fn caps(&self) -> Caps {
        self.state.lock().expect("table lock").caps.clone()
    }

    /// The number of live sessions.
    pub fn count(&self) -> usize {
        self.state.lock().expect("table lock").sessions.len()
    }

    /// Creates a session from an async backend opener. The opener receives
    /// the output sink and connects the backend (SSH connect + auth, PTY,
    /// shell); a failure removes the reserved slot again.
    pub async fn create_with<F, Fut>(
        self: &Arc<Self>,
        conn_key: &str,
        cols: u16,
        rows: u16,
        open: F,
    ) -> Result<String, SessionError>
    where
        F: FnOnce(OutputSink) -> Fut,
        Fut: Future<Output = Result<Box<dyn Backend>, String>>,
    {
        let (id, inner) = {
            let mut state = self.state.lock().expect("table lock");
            if state.sessions.len() >= state.caps.max_sessions {
                return Err(SessionError::TooMany);
            }
            let id = random_id();
            let now = (self.clock)();
            let buffer_bytes = state.caps.buffer_bytes;
            let inner = Arc::new(SessionInner::new(
                id.clone(),
                conn_key.to_owned(),
                cols,
                rows,
                buffer_bytes,
                now,
            ));
            state.sessions.insert(id.clone(), Arc::clone(&inner));
            (id, inner)
        };
        let sink = inner.output_sink(Arc::clone(&self.clock));
        let backend = match open(sink).await {
            Ok(backend) => backend,
            Err(error) => {
                // Roll the reserved slot back so a failed connect does not
                // consume a session.
                self.state.lock().expect("table lock").sessions.remove(&id);
                return Err(SessionError::Connect(error));
            }
        };
        self.start_pump(&inner, backend);
        Ok(id)
    }

    /// Creates a terminal session for any connection kind (SSH, Telnet, or Local).
    /// - SSH: applies TOFU host key policy before auth; returns any newly
    ///   observed or backfilled host key in the tuple so the caller can persist it.
    /// - Telnet: dials via optional proxy with minimal IAC & one-time auto-login.
    /// - Local: strictly gated behind `settings.allow_local_shell`.
    pub async fn create_for_connection(
        self: &Arc<Self>,
        conn: &crate::model::Connection,
        presets: &[crate::model::Preset],
        settings: &crate::model::Settings,
        cols: u16,
        rows: u16,
    ) -> Result<(String, Option<crate::model::HostKey>), SessionError> {
        let cols = if cols == 0 {
            crate::model::limits::DEFAULT_COLS
        } else {
            cols
        };
        let rows = if rows == 0 {
            crate::model::limits::DEFAULT_ROWS
        } else {
            rows
        };

        match conn.kind {
            crate::model::ConnKind::Ssh => {
                let target = crate::ssh::SshTarget::resolve_with_size(conn, presets, cols, rows)
                    .map_err(|error| SessionError::Connect(error.to_string()))?;
                let recorded: Arc<Mutex<Option<crate::model::HostKey>>> =
                    Arc::new(Mutex::new(None));
                let recorded_slot = Arc::clone(&recorded);
                let id = self
                    .create_with(&conn.key, cols, rows, move |sink| async move {
                        let (backend, outcome) = crate::ssh::open(&target, sink).await?;
                        if let Some(hk) = outcome.updated_key() {
                            *recorded_slot.lock().expect("hostkey slot") = Some(hk.clone());
                        }
                        Ok(Box::new(backend) as Box<dyn Backend>)
                    })
                    .await?;
                let updated_hk = recorded.lock().expect("hostkey slot").clone();
                Ok((id, updated_hk))
            }
            crate::model::ConnKind::Telnet => {
                let target = crate::telnet::TelnetTarget::resolve(conn, presets, cols, rows)
                    .map_err(SessionError::Connect)?;
                let id = self
                    .create_with(&conn.key, cols, rows, move |sink| async move {
                        let backend = crate::telnet::open(&target, sink).await?;
                        Ok(Box::new(backend) as Box<dyn Backend>)
                    })
                    .await?;
                Ok((id, None))
            }
            crate::model::ConnKind::Local => {
                let conn_cloned = conn.clone();
                let settings_cloned = settings.clone();
                let id = self
                    .create_with(&conn.key, cols, rows, move |sink| async move {
                        let backend = crate::local_shell::open(
                            &conn_cloned,
                            &settings_cloned,
                            cols,
                            rows,
                            sink,
                        )
                        .await?;
                        Ok(Box::new(backend) as Box<dyn Backend>)
                    })
                    .await?;
                Ok((id, None))
            }
        }
    }

    /// Creates an SSH terminal session for a connection (convenience wrapper).
    pub async fn create(
        self: &Arc<Self>,
        conn: &crate::model::Connection,
        presets: &[crate::model::Preset],
        cols: u16,
        rows: u16,
    ) -> Result<String, SessionError> {
        let (id, _) = self
            .create_for_connection(
                conn,
                presets,
                &crate::model::Settings::default(),
                cols,
                rows,
            )
            .await?;
        Ok(id)
    }

    /// Starts the pump task that owns the backend.
    fn start_pump(self: &Arc<Self>, inner: &Arc<SessionInner>, mut backend: Box<dyn Backend>) {
        let control_rx = inner
            .control_rx
            .lock()
            .expect("control lock")
            .take()
            .expect("pump started twice");
        let table = Arc::clone(self);
        let inner = Arc::clone(inner);
        let session_id = inner.id.clone();
        tokio::spawn(async move {
            let mut control_rx = control_rx;
            let reason = loop {
                let exit = backend.wait_exit();
                tokio::select! {
                    biased;
                    control = control_rx.recv() => match control {
                        Some(Control::Input(data)) => {
                            inner.bytes_in.fetch_add(data.len() as u64, Ordering::Relaxed);
                            if let Err(error) = backend.write(data) {
                                tracing::warn!(session = %session_id, %error, "writing terminal input failed");
                            }
                        }
                        Some(Control::Resize(cols, rows)) => {
                            inner.cols.store(cols, Ordering::Relaxed);
                            inner.rows.store(rows, Ordering::Relaxed);
                            backend.resize(cols, rows);
                        }
                        Some(Control::Terminate) | None => {
                            backend.terminate();
                            break ExitReason::Terminated;
                        }
                    },
                    reason = exit => break reason,
                }
            };
            // The backend exited: tell every attached client, then remove
            // the session (WP-61 §3.3: sends `x`, closes the WS, removes).
            let _ = inner
                .live_tx
                .send(LiveItem::Server(ServerMsg::Exit(reason.describe())));
            table.remove(&session_id);
        });
    }

    /// The session record, if live.
    pub fn session(&self, id: &str) -> Option<Arc<SessionInner>> {
        self.state
            .lock()
            .expect("table lock")
            .sessions
            .get(id)
            .cloned()
    }

    /// Attaches to a session: returns the replay snapshot followed by the
    /// live stream. Input from any attached client is shared.
    pub fn attach(self: &Arc<Self>, id: &str) -> Result<Attach, SessionError> {
        let inner = self.session(id).ok_or(SessionError::NotFound)?;
        let live = inner.live_tx.subscribe();
        let replay = inner.replay_snapshot();
        let last_seq = replay.last().map_or(0, |(seq, _)| *seq);
        inner.attached.fetch_add(1, Ordering::Relaxed);
        let view = SessionView::of(&inner);
        Ok(Attach {
            replay,
            last_seq,
            live,
            view,
            _guard: AttachGuard {
                inner,
                table: Arc::clone(self),
            },
        })
    }

    /// Sends keyboard input to a session; returns false when unknown.
    pub fn input(&self, id: &str, data: Vec<u8>) -> bool {
        let Some(inner) = self.session(id) else {
            return false;
        };
        // Input counts as activity (WP-61 §3.3: idle = no input/output).
        inner.last_active.store((self.clock)(), Ordering::Relaxed);
        inner.control(Control::Input(data));
        true
    }

    /// Resizes a session's terminal; returns false when unknown.
    pub fn resize(&self, id: &str, cols: u16, rows: u16) -> bool {
        let Some(inner) = self.session(id) else {
            return false;
        };
        if cols == 0 || rows == 0 {
            return false;
        }
        inner.control(Control::Resize(cols, rows));
        true
    }

    /// Closes a session (backend terminate → pump removes it); returns
    /// whether the session existed.
    pub fn close(&self, id: &str) -> bool {
        let Some(inner) = self.session(id) else {
            return false;
        };
        inner.control(Control::Terminate);
        true
    }

    /// The sessions list (newest first).
    pub fn list(&self) -> Vec<SessionView> {
        let state = self.state.lock().expect("table lock");
        let mut views: Vec<SessionView> = state
            .sessions
            .values()
            .map(|inner| SessionView::of(inner))
            .collect();
        views.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        views
    }

    /// One session's view, if live.
    pub fn view(&self, id: &str) -> Option<SessionView> {
        self.session(id).map(|inner| SessionView::of(&inner))
    }

    /// Replaces a session's remark; false when unknown.
    pub fn set_remark(&self, id: &str, remark: String) -> bool {
        let Some(inner) = self.session(id) else {
            return false;
        };
        inner.set_remark(remark);
        true
    }

    /// One janitor pass: closes sessions past their idle timeout or their
    /// keep-alive window. Returns the closed ids (tests assert on them).
    pub fn sweep(&self) -> Vec<String> {
        let (now, caps) = {
            let state = self.state.lock().expect("table lock");
            ((self.clock)(), state.caps.clone())
        };
        let mut expired = Vec::new();
        {
            let state = self.state.lock().expect("table lock");
            for (id, inner) in state.sessions.iter() {
                let idle_exceeded = caps
                    .idle_timeout
                    .is_some_and(|idle| inner.idle_seconds(now) >= idle.as_secs() as i64);
                // keepAlive 0 sessions are closed by the attach guard on
                // detach; the janitor only handles positive windows.
                let keep_alive_exceeded = caps.keep_alive.is_some_and(|keep| {
                    inner.attachers() == 0 && inner.detached_seconds(now) >= keep.as_secs() as i64
                });
                if idle_exceeded || keep_alive_exceeded {
                    expired.push(id.clone());
                }
            }
        }
        for id in &expired {
            tracing::info!(session = %id, "session expired; closing");
            self.close(id);
        }
        expired
    }

    /// Spawns the janitor loop with an explicit owner (the module run
    /// task) and a cancellation token; the loop stops with the token.
    pub fn spawn_janitor(
        self: &Arc<Self>,
        token: CancellationToken,
        tick: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let table = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tick);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => break,
                    _ = ticker.tick() => {
                        table.sweep();
                    }
                }
            }
        })
    }

    /// Removes a session immediately without touching the backend (used
    /// by the pump after the backend exited). Returns whether it existed.
    fn remove(&self, id: &str) -> bool {
        self.state
            .lock()
            .expect("table lock")
            .sessions
            .remove(id)
            .is_some()
    }
}

/// 12 lowercase hex characters (conventions §3.3: 6 random bytes).
pub fn random_id() -> String {
    let mut bytes = [0u8; 6];
    getrandom::fill(&mut bytes).expect("OS random source");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::limits;
    use std::sync::atomic::AtomicBool;
    use test_support::MutableClock;

    /// A backend that records every call and whose exit is controlled by
    /// the test through a watch channel.
    struct FakeBackend {
        log: Arc<Mutex<Vec<String>>>,
        exit_rx: tokio::sync::watch::Receiver<Option<ExitReason>>,
        exit_tx: tokio::sync::watch::Sender<Option<ExitReason>>,
        alive: Arc<AtomicBool>,
    }

    impl Backend for FakeBackend {
        fn write(&mut self, data: Vec<u8>) -> Result<(), BackendError> {
            self.log
                .lock()
                .expect("log")
                .push(format!("write:{}", String::from_utf8_lossy(&data)));
            Ok(())
        }

        fn resize(&mut self, cols: u16, rows: u16) {
            self.log
                .lock()
                .expect("log")
                .push(format!("resize:{cols}x{rows}"));
        }

        fn terminate(&mut self) {
            self.log.lock().expect("log").push("terminate".into());
            self.alive.store(false, Ordering::Relaxed);
            let _ = self.exit_tx.send_if_modified(|state| {
                if state.is_none() {
                    *state = Some(ExitReason::Terminated);
                    true
                } else {
                    false
                }
            });
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

    /// One live session created through the real create path.
    struct Fixture {
        table: Arc<SessionTable>,
        clock: Arc<MutableClock>,
        log: Arc<Mutex<Vec<String>>>,
        alive: Arc<AtomicBool>,
        exit_tx: tokio::sync::watch::Sender<Option<ExitReason>>,
        id: String,
    }

    impl Fixture {
        async fn new(caps: Caps) -> Self {
            let clock = Arc::new(MutableClock::at(1_000));
            let table = Arc::new(SessionTable::with_clock(caps, clock.fn_pointer()));
            let (exit_tx, exit_rx) = tokio::sync::watch::channel(None);
            let log = Arc::new(Mutex::new(Vec::new()));
            let alive = Arc::new(AtomicBool::new(true));
            let (log2, alive2, exit_rx2, exit_tx2) = (
                Arc::clone(&log),
                Arc::clone(&alive),
                exit_rx.clone(),
                exit_tx.clone(),
            );
            let id = table
                .create_with("conn", 80, 24, move |_sink| async move {
                    Ok(Box::new(FakeBackend {
                        log: log2,
                        exit_rx: exit_rx2,
                        exit_tx: exit_tx2,
                        alive: alive2,
                    }) as Box<dyn Backend>)
                })
                .await
                .expect("create session");
            Self {
                table,
                clock,
                log,
                alive,
                exit_tx,
                id,
            }
        }

        /// Pushes terminal output through the real sink path.
        fn emit(&self, bytes: &[u8]) {
            let inner = self.table.session(&self.id).expect("session");
            let sink = inner.output_sink(self.clock.fn_pointer());
            sink(bytes.to_vec());
        }
    }

    fn caps_default() -> Caps {
        Caps {
            max_sessions: 20,
            buffer_bytes: limits::BUFFER_SIZE_KB_DEFAULT as usize * 1024,
            idle_timeout: None,
            keep_alive: None,
        }
    }

    async fn wait_until(mut condition: impl FnMut() -> bool) {
        for _ in 0..400 {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("condition never became true");
    }

    #[tokio::test]
    async fn session_max_returns_429() {
        let clock = Arc::new(MutableClock::at(0));
        let table = Arc::new(SessionTable::with_clock(
            Caps {
                max_sessions: 2,
                ..caps_default()
            },
            clock.fn_pointer(),
        ));
        // A failed opener must roll its reserved slot back.
        let error = table
            .create_with("conn", 80, 24, |_sink| async {
                Err::<Box<dyn Backend>, _>("no backend".into())
            })
            .await
            .expect_err("opener fails");
        assert_eq!(
            error,
            SessionError::Connect("no backend".into()),
            "connect failures surface, not TooMany"
        );
        assert_eq!(table.count(), 0);
        // Two live sessions fill the cap.
        let first = table
            .create_with("conn", 80, 24, |_sink| async {
                Ok(Box::new(HeldBackend) as Box<dyn Backend>)
            })
            .await
            .expect("first");
        let second = table
            .create_with("conn", 80, 24, |_sink| async {
                Ok(Box::new(HeldBackend) as Box<dyn Backend>)
            })
            .await
            .expect("second");
        assert_ne!(first, second);
        let error = table
            .create_with("conn", 80, 24, |_sink| async {
                Ok(Box::new(HeldBackend) as Box<dyn Backend>)
            })
            .await
            .expect_err("third session must fail");
        assert_eq!(error, SessionError::TooMany);
        assert_eq!(table.count(), 2);
    }

    /// A backend that stays alive until the process ends.
    struct HeldBackend;
    impl Backend for HeldBackend {
        fn write(&mut self, _data: Vec<u8>) -> Result<(), BackendError> {
            Ok(())
        }
        fn resize(&mut self, _cols: u16, _rows: u16) {}
        fn terminate(&mut self) {}
        fn wait_exit(&mut self) -> Pin<Box<dyn Future<Output = ExitReason> + Send + '_>> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test]
    async fn session_replay_then_live_on_attach() {
        let fixture = Fixture::new(caps_default()).await;
        fixture.emit(b"hello ");
        fixture.emit(b"world");
        let mut attach = fixture.table.attach(&fixture.id).expect("attach");
        assert_eq!(
            attach
                .replay
                .iter()
                .map(|(_, data)| data.as_ref())
                .collect::<Vec<_>>(),
            vec![b"hello ".as_slice(), b"world".as_slice()]
        );
        assert_eq!(attach.last_seq, 1);
        assert_eq!(attach.view.attachers, 1);
        // Output emitted after the snapshot arrives live, exactly once.
        fixture.emit(b"!");
        let mut live_seen = 0;
        for _ in 0..10 {
            match attach.live.recv().await {
                Ok(LiveItem::Data { seq, data }) => {
                    assert!(seq > attach.last_seq, "no duplicate replay");
                    assert_eq!(&*data, b"!");
                    live_seen += 1;
                    break;
                }
                Ok(LiveItem::Server(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
        assert_eq!(live_seen, 1);
    }

    #[tokio::test]
    async fn session_multi_attach_broadcasts_output() {
        let fixture = Fixture::new(caps_default()).await;
        let mut first = fixture.table.attach(&fixture.id).expect("first attach");
        let mut second = fixture.table.attach(&fixture.id).expect("second attach");
        fixture.emit(b"shared");
        for (rx, name) in [(&mut first.live, "first"), (&mut second.live, "second")] {
            for _ in 0..10 {
                match rx.recv().await {
                    Ok(LiveItem::Data { data, .. }) => {
                        assert_eq!(&*data, b"shared", "{name} saw the broadcast");
                        break;
                    }
                    Ok(LiveItem::Server(_)) => continue,
                    Err(_) => continue,
                }
            }
        }
        // Input from either client reaches the same backend.
        assert!(fixture.table.input(&fixture.id, b"ls".to_vec()));
        wait_until(|| {
            fixture
                .log
                .lock()
                .expect("log")
                .contains(&"write:ls".into())
        })
        .await;
    }

    #[tokio::test]
    async fn session_idle_timeout_ends() {
        let fixture = Fixture::new(Caps {
            idle_timeout: Some(Duration::from_secs(60)),
            ..caps_default()
        })
        .await;
        // Not expired at t = 1000 + 59.
        fixture.clock.advance(59);
        assert!(fixture.table.sweep().is_empty());
        // Expired at t = 1000 + 60.
        fixture.clock.advance(1);
        let closed = fixture.table.sweep();
        assert_eq!(closed, vec![fixture.id.clone()]);
        wait_until(|| fixture.table.session(&fixture.id).is_none()).await;
        wait_until(|| {
            fixture
                .log
                .lock()
                .expect("log")
                .contains(&"terminate".into())
        })
        .await;
    }

    #[tokio::test]
    async fn session_keep_alive_then_close() {
        let fixture = Fixture::new(Caps {
            keep_alive: Some(Duration::from_secs(120)),
            ..caps_default()
        })
        .await;
        {
            let _attach = fixture.table.attach(&fixture.id).expect("attach");
        }
        wait_until(|| fixture.table.view(&fixture.id).map(|view| view.attachers) == Some(0)).await;
        assert!(
            fixture.table.session(&fixture.id).is_some(),
            "keepAlive keeps the session after detach"
        );
        fixture.clock.advance(119);
        assert!(fixture.table.sweep().is_empty());
        fixture.clock.advance(1);
        let closed = fixture.table.sweep();
        assert_eq!(closed, vec![fixture.id.clone()]);
        wait_until(|| fixture.table.session(&fixture.id).is_none()).await;
    }

    #[tokio::test]
    async fn session_keep_alive_zero_ends_on_detach() {
        let fixture = Fixture::new(caps_default()).await;
        {
            let _attach = fixture.table.attach(&fixture.id).expect("attach");
        }
        // keepAlive 0: closing happens on the last detach.
        wait_until(|| fixture.table.session(&fixture.id).is_none()).await;
        wait_until(|| {
            fixture
                .log
                .lock()
                .expect("log")
                .contains(&"terminate".into())
        })
        .await;
    }

    #[tokio::test]
    async fn session_replay_buffer_capped() {
        let fixture = Fixture::new(Caps {
            buffer_bytes: 256 * 1024,
            ..caps_default()
        })
        .await;
        // Push 300 KB through the sink in 10 KB chunks.
        let chunk = vec![b'x'; 10 * 1024];
        for _ in 0..30 {
            fixture.emit(&chunk);
        }
        let inner = fixture.table.session(&fixture.id).expect("session");
        let replay = inner.replay_snapshot();
        let total: usize = replay.iter().map(|(_, data)| data.len()).sum();
        let cap = 256 * 1024;
        assert!(total <= cap, "replay buffer stays under the cap ({total})");
        // Whole 10 KB chunks are kept; the oldest that would overflow are gone.
        assert!(total + chunk.len() > cap);
        assert_eq!(replay.len(), total / chunk.len());
        // The oldest remaining chunk is the first that still fits.
        let kept = total / chunk.len();
        assert_eq!(replay.first().expect("chunks").0, (30 - kept) as u64);
        // The newest chunk is still the last emit.
        assert_eq!(replay.last().expect("chunks").1.as_ref(), chunk.as_slice());
    }

    #[tokio::test]
    async fn session_backend_exit_sends_x() {
        let fixture = Fixture::new(caps_default()).await;
        let mut attach = fixture.table.attach(&fixture.id).expect("attach");
        // The backend exits on its own.
        let _ = fixture.exit_tx.send(Some(ExitReason::Exited(7)));
        loop {
            match attach.live.recv().await {
                Ok(LiveItem::Server(message)) => {
                    assert_eq!(message, ServerMsg::Exit("进程已退出（7）".into()));
                    break;
                }
                Ok(LiveItem::Data { .. }) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    panic!("channel closed before the x message")
                }
            }
        }
        wait_until(|| fixture.table.session(&fixture.id).is_none()).await;
    }

    #[tokio::test]
    async fn session_termination_removed_after_backend_exit() {
        let fixture = Fixture::new(caps_default()).await;
        assert!(fixture.table.close(&fixture.id));
        wait_until(|| fixture.table.session(&fixture.id).is_none()).await;
        assert!(!fixture.alive.load(Ordering::Relaxed));
        assert!(!fixture.table.close(&fixture.id));
        assert_eq!(
            fixture.table.attach(&fixture.id).unwrap_err(),
            SessionError::NotFound
        );
    }

    #[tokio::test]
    async fn session_remark_and_stats_round_trip() {
        let fixture = Fixture::new(caps_default()).await;
        fixture.emit(b"out");
        assert!(fixture.table.input(&fixture.id, b"in".to_vec()));
        fixture.table.set_remark(&fixture.id, "调试".into());
        wait_until(|| {
            let view = fixture.table.view(&fixture.id).expect("view");
            view.bytes_in > 0 && view.bytes_out > 0
        })
        .await;
        let view = fixture.table.view(&fixture.id).expect("view");
        assert_eq!(view.remark, "调试");
        assert_eq!(view.bytes_in, 2);
        assert_eq!(view.bytes_out, 3);
        assert_eq!(view.cols, 80);
        assert_eq!(view.rows, 24);
        assert!(!view.created_at.is_empty());
        assert!(!view.last_active.is_empty());
    }
}

/// Test support: a mutable unix-seconds clock shared with the table.
#[cfg(test)]
pub(crate) mod test_support {
    use super::NowFn;
    use std::sync::{Arc, Mutex};

    /// A clock whose reading the test advances manually.
    pub struct MutableClock {
        now: Mutex<i64>,
    }

    impl MutableClock {
        pub fn at(seconds: i64) -> Self {
            Self {
                now: Mutex::new(seconds),
            }
        }

        pub fn advance(&self, seconds: i64) {
            *self.now.lock().expect("clock") += seconds;
        }

        pub fn fn_pointer(self: &Arc<Self>) -> NowFn {
            let clock = Arc::clone(self);
            Arc::new(move || *clock.now.lock().expect("clock"))
        }
    }
}
