//! The management operation audit log.
//!
//! Records who did what from which address, appends the entries to
//! `audit.log` in the configuration directory through a bounded queue and a
//! dedicated writer thread, rotates at a size cap and serves newest-first
//! queries across the rotated files. Write failures drop the entry and are
//! counted; they never fail the audited request.

pub mod middleware;
pub mod rules;

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::Duration,
};

use anyhow::{Context, Result};
use axum::{
    Json,
    extract::{Query as RawQuery, rejection::QueryRejection},
    http::{Method, StatusCode},
    response::IntoResponse,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::Semaphore;

use crate::{ApiError, ApiRouter, RouteModels};

const MAX_BYTES: u64 = 5 << 20;
const KEEP: usize = 3;
const QUEUE_CAPACITY: usize = 1024;
const CHAIN: [&str; KEEP + 1] = ["audit.log", "audit.log.1", "audit.log.2", "audit.log.3"];
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;
const INVALID: ApiError = ApiError::new(StatusCode::BAD_REQUEST, "invalid audit query");
const BUSY: ApiError = ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "audit queries are busy");
const FAILED: ApiError = ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "audit query failed");

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Login,
    Change,
    Access,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    /// RFC 3339 UTC timestamp.
    pub time: String,
    /// Account name or `api-token:<name>`.
    pub actor: String,
    pub ip: IpAddr,
    /// Proxy that forwarded the request; absent for direct connections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<SocketAddr>,
    pub category: Category,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub module: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub status: u16,
    /// Supplementary explanation, an i18n key for login outcomes.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

fn is_zero(status: &u16) -> bool {
    *status == 0
}

fn timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("the current time formats as RFC 3339")
}

pub struct Query {
    pub category: Option<Category>,
    pub text: Option<String>,
    pub from: Option<OffsetDateTime>,
    pub to: Option<OffsetDateTime>,
    pub limit: usize,
}

pub struct Page {
    pub entries: Vec<Entry>,
    pub total: usize,
}

enum Message {
    Write(Entry),
    Fence(mpsc::Sender<()>),
}

/// Called by the writer thread after each entry is appended.
type Hook = Arc<dyn Fn(&Entry) + Send + Sync>;

struct Shared {
    dir: PathBuf,
    max_bytes: u64,
    dropped: AtomicU64,
    failed: AtomicU64,
    hook: RwLock<Option<Hook>>,
}

pub struct AuditLog {
    shared: Arc<Shared>,
    sender: Option<mpsc::SyncSender<Message>>,
    worker: Option<JoinHandle<()>>,
}

impl AuditLog {
    pub fn open(dir: &Path) -> Result<Arc<Self>> {
        Self::open_with(dir, MAX_BYTES)
    }

    /// Opens the log with a non-default main-file cap. Production callers use
    /// [`AuditLog::open`]; tests shrink the cap to exercise rotation.
    pub fn open_with(dir: &Path, max_bytes: u64) -> Result<Arc<Self>> {
        let shared = Arc::new(Shared {
            dir: dir.to_owned(),
            max_bytes,
            dropped: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            hook: RwLock::new(None),
        });
        let (sender, receiver) = mpsc::sync_channel::<Message>(QUEUE_CAPACITY);
        let worker = Shared::spawn_worker(&shared, receiver)?;
        Ok(Arc::new(Self {
            shared,
            sender: Some(sender),
            worker: Some(worker),
        }))
    }

    /// Queues one entry; a full queue drops the entry and counts it.
    pub fn record(&self, entry: Entry) {
        let send = self
            .sender
            .as_ref()
            .expect("the audit queue lives as long as the log");
        if send.try_send(Message::Write(entry)).is_err() {
            self.shared.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records a login outcome. `detail` carries the failure reason key.
    pub fn record_login(&self, ip: IpAddr, actor: &str, ok: bool, path: &str, detail: &str) {
        self.record(Entry {
            time: timestamp(),
            actor: actor.to_owned(),
            ip,
            via: None,
            category: Category::Login,
            module: String::new(),
            method: "POST".to_owned(),
            path: path.to_owned(),
            status: if ok { 200 } else { 401 },
            detail: detail.to_owned(),
        });
    }

    /// Blocks until every queued entry has been written (or dropped).
    pub fn flush(&self) {
        let Some(send) = self.sender.as_ref() else {
            return;
        };
        let (done, received) = mpsc::channel();
        if send.send(Message::Fence(done)).is_ok() {
            let _ = received.recv_timeout(Duration::from_secs(5));
        }
    }

    /// Installs a callback invoked after each entry is written. It must
    /// return quickly; the writer thread does not proceed while it runs.
    pub fn set_hook(&self, hook: Box<dyn Fn(&Entry) + Send + Sync>) {
        *self.shared.hook.write().expect("audit hook poisoned") = Some(Arc::from(hook));
    }

    pub fn dropped(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }

    pub fn failed(&self) -> u64 {
        self.shared.failed.load(Ordering::Relaxed)
    }

    /// Returns matching entries newest-first across the rotation chain.
    /// Call from a blocking context.
    pub fn search(&self, query: &Query) -> Result<Page> {
        let text = query
            .text
            .as_ref()
            .map(|text| text.to_ascii_lowercase())
            .filter(|text| !text.is_empty());
        let mut entries = Vec::new();
        let mut total = 0;
        for name in CHAIN {
            let content = match fs::read(self.shared.dir.join(name)) {
                Ok(content) => content,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error).with_context(|| format!("read the audit file {name}"));
                }
            };
            let mut matched = Vec::new();
            for line in content.split(|&byte| byte == b'\n') {
                if line.is_empty() {
                    continue;
                }
                let Ok(entry) = serde_json::from_slice::<Entry>(line) else {
                    continue;
                };
                if matches(&entry, query, text.as_deref()) {
                    total += 1;
                    matched.push(entry);
                }
            }
            for entry in matched.into_iter().rev() {
                if entries.len() < query.limit {
                    entries.push(entry);
                }
            }
        }
        Ok(Page { entries, total })
    }
}

impl Drop for AuditLog {
    fn drop(&mut self) {
        self.sender = None;
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Mounts `GET /api/audit`, restricted to administrator sessions by the
/// forbidden-prefix scope table. The audit log itself is never redacted.
pub(crate) fn mount_query(router: ApiRouter, audit: Arc<AuditLog>) -> ApiRouter {
    let budget = Arc::new(Semaphore::new(2));
    router.modeled_route(
        Method::GET,
        "/api/audit",
        "Query the operation audit log",
        RouteModels::default()
            .query::<AuditQuery>()
            .response::<AuditPage>(),
        move |query: Result<RawQuery<AuditQuery>, QueryRejection>| async move {
            let RawQuery(request) = query.map_err(|_| INVALID)?;
            let query = request.into_query()?;
            let permit = budget.clone().try_acquire_owned().map_err(|_| BUSY)?;
            let audit = audit.clone();
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                audit.search(&query)
            })
            .await
            .map_err(|_| FAILED)?
            .map(|page| {
                Json(AuditPage {
                    entries: page.entries,
                    total: page.total,
                })
                .into_response()
            })
            .map_err(|_| FAILED)
        },
    )
}

#[derive(Default, Deserialize, JsonSchema)]
#[serde(default)]
struct AuditQuery {
    category: String,
    q: String,
    from: String,
    to: String,
    limit: usize,
}

impl AuditQuery {
    fn into_query(self) -> Result<Query, ApiError> {
        let category = match self.category.trim() {
            "" => None,
            "login" => Some(Category::Login),
            "change" => Some(Category::Change),
            "access" => Some(Category::Access),
            _ => return Err(INVALID),
        };
        if self.limit > MAX_LIMIT {
            return Err(INVALID);
        }
        Ok(Query {
            category,
            text: (!self.q.trim().is_empty()).then(|| self.q.trim().to_owned()),
            from: audit_time(&self.from)?,
            to: audit_time(&self.to)?,
            limit: if self.limit == 0 {
                DEFAULT_LIMIT
            } else {
                self.limit
            },
        })
    }
}

#[derive(Serialize, JsonSchema)]
struct AuditPage {
    entries: Vec<Entry>,
    total: usize,
}

/// Accepts an RFC 3339 timestamp or epoch milliseconds with at least 12 digits.
fn audit_time(text: &str) -> Result<Option<OffsetDateTime>, ApiError> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    if let Ok(milliseconds) = text.parse::<i64>() {
        if text.trim_start_matches(['+', '-']).len() < 12 {
            return Err(INVALID);
        }
        return OffsetDateTime::from_unix_timestamp_nanos(i128::from(milliseconds) * 1_000_000)
            .map(Some)
            .map_err(|_| INVALID);
    }
    OffsetDateTime::parse(text, &Rfc3339)
        .map(Some)
        .map_err(|_| INVALID)
}

fn matches(entry: &Entry, query: &Query, text: Option<&str>) -> bool {
    if let Some(category) = query.category
        && category != entry.category
    {
        return false;
    }
    if let Some(text) = text
        && ![
            entry.actor.to_ascii_lowercase(),
            entry.path.to_ascii_lowercase(),
            entry.ip.to_string(),
        ]
        .iter()
        .any(|value| value.to_ascii_lowercase().contains(text))
    {
        return false;
    }
    if query.from.is_some() || query.to.is_some() {
        let Ok(time) = OffsetDateTime::parse(&entry.time, &Rfc3339) else {
            return false;
        };
        if query.from.is_some_and(|from| time < from) || query.to.is_some_and(|to| time > to) {
            return false;
        }
    }
    true
}

struct Writer {
    file: Option<File>,
    size: u64,
}

impl Shared {
    fn spawn_worker(self: &Arc<Self>, receiver: mpsc::Receiver<Message>) -> Result<JoinHandle<()>> {
        let shared = self.clone();
        let (file, size) = open_log(&shared.dir)?;
        let mut writer = Writer {
            file: Some(file),
            size,
        };
        std::thread::Builder::new()
            .name("fg-audit".to_owned())
            .spawn(move || {
                while let Ok(message) = receiver.recv() {
                    match message {
                        Message::Write(entry) => shared.write(&mut writer, entry),
                        Message::Fence(done) => {
                            let _ = done.send(());
                        }
                    }
                }
            })
            .context("spawn the audit writer")
    }

    fn write(&self, writer: &mut Writer, entry: Entry) {
        if writer.file.is_none() && !self.reopen(writer) {
            return;
        }
        let Ok(mut line) = serde_json::to_vec(&entry) else {
            self.note_failure();
            return;
        };
        line.push(b'\n');
        let written = writer
            .file
            .as_mut()
            .expect("the writer recovered an open file")
            .write_all(&line)
            .and_then(|()| writer.file.as_mut().expect("open file").flush());
        if let Err(error) = written {
            self.note_failure();
            tracing::debug!(target: "fg_admin::audit", %error, "audit entry dropped");
            return;
        }
        writer.size += line.len() as u64;
        if let Some(hook) = self.hook.read().expect("audit hook poisoned").clone() {
            hook(&entry);
        }
        if writer.size > self.max_bytes
            && let Err(error) = self.rotate(writer)
        {
            self.note_failure();
            tracing::debug!(target: "fg_admin::audit", %error, "audit rotation deferred");
        }
    }

    fn reopen(&self, writer: &mut Writer) -> bool {
        match open_log(&self.dir) {
            Ok((file, size)) => {
                writer.file = Some(file);
                writer.size = size;
                true
            }
            Err(error) => {
                self.note_failure();
                tracing::debug!(target: "fg_admin::audit", %error, "audit file unavailable");
                false
            }
        }
    }

    fn note_failure(&self) {
        let failures = self.failed.fetch_add(1, Ordering::Relaxed);
        if failures == 0 || failures % 64 == 63 {
            tracing::warn!(target: "fg_admin::audit", failures = failures + 1, "audit entries could not be written");
        }
    }

    fn rotate(&self, writer: &mut Writer) -> io::Result<()> {
        if let Some(file) = writer.file.as_mut() {
            file.flush()?;
        }
        writer.file = None; // release the handle before renaming
        let shifted = self.shift_chain();
        // Reopen regardless: a fresh file when the chain shifted, the
        // existing one when a rename failed and rotation stays pending.
        if !self.reopen(writer) {
            return Err(io::Error::last_os_error());
        }
        shifted
    }

    fn shift_chain(&self) -> io::Result<()> {
        let _ = fs::remove_file(self.dir.join(CHAIN[KEEP]));
        for index in (1..KEEP).rev() {
            let from = self.dir.join(CHAIN[index]);
            if from.exists() {
                fs::rename(from, self.dir.join(CHAIN[index + 1]))?;
            }
        }
        fs::rename(self.dir.join(CHAIN[0]), self.dir.join(CHAIN[1]))
    }
}

fn open_log(dir: &Path) -> io::Result<(File, u64)> {
    fs::create_dir_all(dir)?;
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(dir.join(CHAIN[0]))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    let size = file.metadata()?.len();
    Ok((file, size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn entry(actor: &str, path: &str) -> Entry {
        Entry {
            time: timestamp(),
            actor: actor.into(),
            ip: "127.0.0.1".parse().unwrap(),
            via: None,
            category: Category::Change,
            module: "ddns".into(),
            method: "PUT".into(),
            path: path.into(),
            status: 200,
            detail: String::new(),
        }
    }

    fn query() -> Query {
        Query {
            category: None,
            text: None,
            from: None,
            to: None,
            limit: 100,
        }
    }

    #[test]
    fn records_are_searchable_newest_first() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let audit = AuditLog::open_with(dir.path(), MAX_BYTES)?;
        for seq in 0..5 {
            audit.record(Entry {
                detail: seq.to_string(),
                ..entry("admin", "/api/ddns/rules")
            });
        }
        audit.flush();
        let page = audit.search(&query())?;
        assert_eq!(page.total, 5);
        let details: Vec<_> = page
            .entries
            .iter()
            .map(|entry| entry.detail.parse::<u8>().unwrap())
            .collect();
        assert_eq!(details, [4, 3, 2, 1, 0]);
        let limited = Query {
            limit: 2,
            ..query()
        };
        assert_eq!(audit.search(&limited)?.entries.len(), 2);
        Ok(())
    }

    #[test]
    fn search_filters_by_category_and_text() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let audit = AuditLog::open_with(dir.path(), MAX_BYTES)?;
        audit.record(entry("admin", "/api/ddns/rules"));
        audit.record(Entry {
            category: Category::Access,
            path: "/api/system/backup".into(),
            ..entry("admin", "/api/ddns/rules")
        });
        audit.record(Entry {
            actor: "api-token:ops".into(),
            ..entry("admin", "/api/ddns/rules")
        });
        audit.flush();
        let changes = Query {
            category: Some(Category::Change),
            ..query()
        };
        let page = audit.search(&changes)?;
        assert_eq!(page.total, 2);
        assert!(
            page.entries
                .iter()
                .all(|entry| entry.category == Category::Change)
        );
        let text = Query {
            text: Some("api-token:OPS".into()),
            ..query()
        };
        assert_eq!(audit.search(&text)?.total, 1);
        let by_path = Query {
            text: Some("system/backup".into()),
            ..query()
        };
        assert_eq!(audit.search(&by_path)?.total, 1);
        Ok(())
    }

    #[test]
    fn rotate_keeps_three_histories() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let audit = AuditLog::open_with(dir.path(), 600)?;
        for seq in 0..40 {
            audit.record(Entry {
                detail: format!("{seq:02}"),
                ..entry("admin", "/api/ddns/rules")
            });
        }
        audit.flush();
        for history in &CHAIN[1..] {
            assert!(dir.path().join(history).is_file(), "missing {history}");
        }
        assert!(!dir.path().join("audit.log.4").exists());
        let page = audit.search(&query())?;
        assert!(
            page.total < 40 && page.total > 0,
            "rotation retired the oldest entries, kept {}",
            page.total
        );
        let details: Vec<_> = page
            .entries
            .iter()
            .map(|entry| entry.detail.clone())
            .collect();
        let newest: i32 = details[0].parse().expect("surviving entry sequence");
        let expected: Vec<_> = (0..=newest)
            .rev()
            .take(details.len())
            .map(|seq| format!("{seq:02}"))
            .collect();
        assert_eq!(details, expected, "survivors are the newest, gapless run");
        assert_eq!(details[0], "39");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join(CHAIN[0]))?.permissions();
            assert_eq!(mode.mode() & 0o777, 0o600);
        }
        Ok(())
    }

    #[test]
    fn queue_overflow_is_counted() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let audit = AuditLog::open_with(dir.path(), MAX_BYTES)?;
        let brake = Arc::new(Mutex::new(()));
        let held = brake.lock().unwrap();
        let blocked = brake.clone();
        audit.set_hook(Box::new(move |_| {
            let _hold = blocked.lock().unwrap();
        }));
        for seq in 0..(QUEUE_CAPACITY + 8) {
            audit.record(Entry {
                detail: seq.to_string(),
                ..entry("admin", "/api/ddns/rules")
            });
        }
        assert!(audit.dropped() >= 1);
        drop(held);
        audit.flush();
        let page = audit.search(&query())?;
        assert_eq!(page.total, QUEUE_CAPACITY + 1);
        Ok(())
    }

    #[test]
    fn hook_sees_every_entry_in_write_order() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let audit = AuditLog::open_with(dir.path(), MAX_BYTES)?;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        audit.set_hook(Box::new(move |entry| {
            sink.lock().unwrap().push(entry.detail.clone());
        }));
        for seq in 0..3 {
            audit.record(Entry {
                detail: seq.to_string(),
                ..entry("admin", "/api/ddns/rules")
            });
        }
        audit.flush();
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            ["0", "1", "2"],
            "the hook runs after each write, in order"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn write_failures_are_counted_and_skipped() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir()?;
        let audit = AuditLog::open_with(dir.path(), 400)?;
        let original = fs::metadata(dir.path())?.permissions();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500))?;
        for seq in 0..12 {
            audit.record(Entry {
                detail: seq.to_string(),
                ..entry("admin", "/api/ddns/rules")
            });
        }
        audit.flush();
        assert!(audit.failed() >= 1, "rotation against a frozen directory");
        fs::set_permissions(dir.path(), original)?;
        audit.flush();
        let page = audit.search(&query())?;
        assert_eq!(
            page.total, 12,
            "entries keep appending after failed rotation"
        );
        Ok(())
    }
}
