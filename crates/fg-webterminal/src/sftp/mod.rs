//! SFTP and local filesystem manager (WP-61 §3.3 / §3.4):
//! - Remote SSH connections reuse a single SFTP session per connection key,
//!   evicted after 5 minutes of inactivity ([`limits::SFTP_IDLE_AFTER`]).
//! - Local connections operate directly on the host filesystem ONLY when
//!   `settings.allow_local_shell` is enabled, honoring `fg_core::fsperm`
//!   protected-path checks.
//! - Telnet connections do not support file management.
//! - Text preview > 1 MiB answers HTTP 413; root `/` is protected from deletion;
//!   archive compress/decompress/preview runs purely in Rust via [`archive`].

pub mod archive;

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::Disconnect;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

use crate::model::{ConnKind, Connection, HostKey, Preset, Settings, limits};
use crate::session::{NowFn, system_clock};
use crate::ssh::{self, SshClientHandler, SshTarget};

use self::archive::{
    ArchiveError, ArchiveFormat, ArchivePreview, CompressInput, ExtractLimits, compress_entries,
    extract_archive, preview_archive,
};

/// Errors returned by SFTP / local file operations (mapped to HTTP status codes by routes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SftpError {
    /// Connection kind does not support file management (e.g. Telnet) or invalid request (400).
    BadRequest(String),
    /// Local filesystem disabled or protected path / root deletion attempted (403).
    Forbidden(String),
    /// File or directory does not exist (404).
    NotFound(String),
    /// Text preview exceeds the 1 MiB ceiling (413).
    PayloadTooLarge(String),
    /// File appears to be binary and cannot be edited as text (415).
    UnsupportedMedia(String),
    /// Underlying SSH/SFTP/IO failure (502/500).
    Io(String),
}

impl std::fmt::Display for SftpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRequest(s)
            | Self::Forbidden(s)
            | Self::NotFound(s)
            | Self::PayloadTooLarge(s)
            | Self::UnsupportedMedia(s)
            | Self::Io(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for SftpError {}

impl From<ArchiveError> for SftpError {
    fn from(err: ArchiveError) -> Self {
        match err {
            ArchiveError::UnsupportedFormat(s) | ArchiveError::Corrupt(s) => Self::BadRequest(s),
            ArchiveError::PathTraversal(s) => Self::BadRequest(format!("归档包含非法路径：{s}")),
            ArchiveError::LimitExceeded(s) => Self::PayloadTooLarge(s),
        }
    }
}

/// One entry returned by `list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub mode: u32,
    pub mod_time: String,
    pub owner: String,
}

/// Text preview payload returned by `read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TextPreview {
    pub path: String,
    pub content: String,
    pub size: usize,
}

/// One uploaded file (preserving relative directory structure).
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadItem {
    /// Relative path inside target directory (e.g. `a.txt` or `sub/b.txt`).
    pub path: String,
    pub data: Vec<u8>,
}

/// Live pooled SSH + SFTP client pair.
pub struct RemoteClient {
    handle: russh::client::Handle<SshClientHandler>,
    sftp: russh_sftp::client::SftpSession,
}

impl RemoteClient {
    fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    async fn close(self) {
        let _ = self.sftp.close().await;
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "", "")
            .await;
    }
}

struct PooledEntry {
    /// `None` only in unit tests that test idle expiry without a real SSH socket.
    client: Option<Arc<AsyncMutex<RemoteClient>>>,
    last_used: AtomicI64,
}

/// Connection pool maintaining at most one SFTP session per SSH connection key
/// and closing sessions idle for >= 5 minutes (WP-61 §3.4).
pub struct SftpPool {
    entries: Mutex<HashMap<String, Arc<PooledEntry>>>,
    clock: NowFn,
    idle_after_secs: i64,
}

impl Default for SftpPool {
    fn default() -> Self {
        Self::new()
    }
}

impl SftpPool {
    /// Creates a pool with the system clock and the 5-minute idle timeout.
    pub fn new() -> Self {
        Self::with_clock(system_clock(), limits::SFTP_IDLE_AFTER)
    }

    /// Creates a pool with an injectable clock and idle duration (for unit tests).
    pub fn with_clock(clock: NowFn, idle_after: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            clock,
            idle_after_secs: idle_after.as_secs() as i64,
        }
    }

    /// Number of currently cached SFTP connections.
    pub fn len(&self) -> usize {
        self.entries.lock().expect("sftp pool lock").len()
    }

    /// Whether the pool has no cached connections.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a pooled remote SFTP client or dials a new one.
    /// Also returns any TOFU / backfill [`HostKey`] that should be persisted.
    pub async fn get_or_connect(
        &self,
        conn: &Connection,
        presets: &[Preset],
    ) -> Result<(Arc<AsyncMutex<RemoteClient>>, Option<HostKey>), SftpError> {
        let existing = self
            .entries
            .lock()
            .expect("sftp pool lock")
            .get(&conn.key)
            .cloned();

        if let Some(entry) = existing {
            if let Some(client) = &entry.client {
                let closed = client.lock().await.is_closed();
                if !closed {
                    entry.last_used.store((self.clock)(), Ordering::Relaxed);
                    return Ok((Arc::clone(client), None));
                }
            }
            self.evict(&conn.key);
        }

        let target =
            SshTarget::resolve(conn, presets).map_err(|e| SftpError::BadRequest(e.to_string()))?;
        let (handle, sftp, outcome) = ssh::open_sftp_session(&target, false)
            .await
            .map_err(|e| SftpError::Io(e.to_string()))?;
        let updated_hk = outcome.updated_key().cloned();

        let client = Arc::new(AsyncMutex::new(RemoteClient { handle, sftp }));
        let entry = Arc::new(PooledEntry {
            client: Some(Arc::clone(&client)),
            last_used: AtomicI64::new((self.clock)()),
        });
        let previous = self
            .entries
            .lock()
            .expect("sftp pool lock")
            .insert(conn.key.clone(), entry);
        if let Some(prev) = previous {
            close_entry_async(prev);
        }
        Ok((client, updated_hk))
    }

    /// Evicts and closes the pooled SFTP connection for `conn_key`.
    pub fn evict(&self, conn_key: &str) -> bool {
        let removed = self
            .entries
            .lock()
            .expect("sftp pool lock")
            .remove(conn_key);
        if let Some(entry) = removed {
            close_entry_async(entry);
            true
        } else {
            false
        }
    }

    /// Closes and removes all pooled connections whose idle time has reached
    /// `idle_after`. Returns the evicted connection keys.
    pub fn sweep(&self) -> Vec<String> {
        let now = (self.clock)();
        let mut evicted_keys = Vec::new();
        let mut evicted_entries = Vec::new();
        {
            let mut map = self.entries.lock().expect("sftp pool lock");
            let keys: Vec<String> = map
                .iter()
                .filter_map(|(k, entry)| {
                    let idle = now.saturating_sub(entry.last_used.load(Ordering::Relaxed));
                    (idle >= self.idle_after_secs).then(|| k.clone())
                })
                .collect();
            for key in keys {
                if let Some(entry) = map.remove(&key) {
                    evicted_keys.push(key);
                    evicted_entries.push(entry);
                }
            }
        }
        for entry in evicted_entries {
            close_entry_async(entry);
        }
        evicted_keys
    }

    /// Closes all pooled connections (module shutdown).
    pub fn close_all(&self) {
        let entries: Vec<Arc<PooledEntry>> = {
            let mut map = self.entries.lock().expect("sftp pool lock");
            map.drain().map(|(_, v)| v).collect()
        };
        for entry in entries {
            close_entry_async(entry);
        }
    }

    /// Spawns a background janitor that sweeps idle SFTP sessions until cancelled.
    pub fn spawn_janitor(
        self: &Arc<Self>,
        token: CancellationToken,
        tick: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tick);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => {
                        pool.close_all();
                        break;
                    }
                    _ = ticker.tick() => {
                        pool.sweep();
                    }
                }
            }
        })
    }

    #[cfg(test)]
    fn insert_dummy(&self, key: &str) {
        let entry = Arc::new(PooledEntry {
            client: None,
            last_used: AtomicI64::new((self.clock)()),
        });
        self.entries
            .lock()
            .expect("sftp pool lock")
            .insert(key.to_owned(), entry);
    }

    #[cfg(test)]
    fn touch_dummy(&self, key: &str) {
        if let Some(entry) = self.entries.lock().expect("sftp pool lock").get(key) {
            entry.last_used.store((self.clock)(), Ordering::Relaxed);
        }
    }
}

fn close_entry_async(entry: Arc<PooledEntry>) {
    if let Some(client_arc) = entry.client.clone()
        && tokio::runtime::Handle::try_current().is_ok()
    {
        tokio::spawn(async move {
            match Arc::try_unwrap(client_arc) {
                Ok(client) => client.into_inner().close().await,
                Err(client_arc) => {
                    let guard = client_arc.lock().await;
                    let _ = guard.sftp.close().await;
                    let _ = guard
                        .handle
                        .disconnect(Disconnect::ByApplication, "", "")
                        .await;
                }
            }
        });
    }
}

/// Resolves whether a connection operates on local FS or remote SFTP.
pub enum FileBackend {
    Local,
    Remote(Arc<AsyncMutex<RemoteClient>>),
}

/// Resolves the [`FileBackend`] for a connection, enforcing `allow_local_shell`
/// and refusing Telnet connections.
pub async fn resolve_backend(
    pool: &SftpPool,
    conn: &Connection,
    presets: &[Preset],
    settings: &Settings,
) -> Result<(FileBackend, Option<HostKey>), SftpError> {
    match conn.kind {
        ConnKind::Telnet => Err(SftpError::BadRequest("Telnet 连接不支持文件管理".into())),
        ConnKind::Local => {
            if !settings.allow_local_shell {
                return Err(SftpError::Forbidden(
                    "本机文件管理未开启（请在设置中启用 allowLocalShell）".into(),
                ));
            }
            Ok((FileBackend::Local, None))
        }
        ConnKind::Ssh => {
            let (client, updated_hk) = pool.get_or_connect(conn, presets).await?;
            Ok((FileBackend::Remote(client), updated_hk))
        }
    }
}

// --- Path validation & helpers -------------------------------------------

/// Checks whether `path` refers to the filesystem root `/` (protected from deletion).
pub fn is_root_path(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return true;
    }
    let normalized = normalize_posix_path(trimmed);
    normalized == "/"
}

/// Normalizes a POSIX path cleanly (collapsing `//`, `.`, and `..`).
pub fn normalize_posix_path(raw: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in raw.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// Joins a base directory and a relative name cleanly using POSIX separators.
pub fn join_posix(dir: &str, name: &str) -> String {
    let base = normalize_posix_path(dir);
    let clean_name = name.trim_start_matches('/');
    if base == "/" {
        format!("/{clean_name}")
    } else if clean_name.is_empty() {
        base
    } else {
        format!("{base}/{clean_name}")
    }
}

/// Ensures a local path is not protected by `fg_core::fsperm`.
fn check_local_path(path: &Path) -> Result<(), SftpError> {
    if fg_core::fsperm::protected(path).is_some() {
        return Err(SftpError::Forbidden(format!(
            "禁止访问受保护路径：{}",
            path.display()
        )));
    }
    Ok(())
}

/// Validates a relative subpath for uploads (must not escape target dir).
fn validate_upload_rel(raw: &str) -> Result<String, SftpError> {
    let unified = raw.replace('\\', "/");
    let trimmed = unified.trim().trim_start_matches('/');
    if trimmed.is_empty() || trimmed.contains('\0') {
        return Err(SftpError::BadRequest("上传文件路径无效".into()));
    }
    let mut parts = Vec::new();
    for comp in Path::new(trimmed).components() {
        match comp {
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(SftpError::BadRequest(format!("非法上传路径：{raw}")));
            }
        }
    }
    if parts.is_empty() {
        return Err(SftpError::BadRequest("上传文件路径无效".into()));
    }
    Ok(parts.join("/"))
}

/// Checks preview limits (<= 1 MiB) and UTF-8 / non-binary validity.
pub fn check_text_preview(path: &str, bytes: Vec<u8>) -> Result<TextPreview, SftpError> {
    if bytes.len() > limits::SFTP_PREVIEW_MAX_BYTES {
        return Err(SftpError::PayloadTooLarge(format!(
            "文件大小超过文本预览上限（{} 字节）",
            limits::SFTP_PREVIEW_MAX_BYTES
        )));
    }
    if bytes.contains(&0) {
        return Err(SftpError::UnsupportedMedia(
            "二进制文件不支持文本预览".into(),
        ));
    }
    let content = String::from_utf8(bytes)
        .map_err(|_| SftpError::UnsupportedMedia("非 UTF-8 文本文件不支持在线预览".into()))?;
    let size = content.len();
    Ok(TextPreview {
        path: path.to_owned(),
        content,
        size,
    })
}

/// Builds a copy destination name when copying into the same directory or when
/// a name collision occurs: `name 副本.ext`, `name 副本 2.ext`, `name 副本 3.ext`…
pub fn copy_collision_name(file_name: &str, index: usize) -> String {
    let suffix = if index <= 1 {
        " 副本".to_owned()
    } else {
        format!(" 副本 {index}")
    };
    if let Some((stem, ext)) = split_stem_ext(file_name) {
        format!("{stem}{suffix}.{ext}")
    } else {
        format!("{file_name}{suffix}")
    }
}

fn split_stem_ext(name: &str) -> Option<(&str, &str)> {
    // Handle dotfiles like `.env` (no extension).
    let (stem, ext) = name.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() {
        return None;
    }
    Some((stem, ext))
}

fn sort_entries(entries: &mut [FileEntry]) {
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.name.cmp(&b.name))
    });
}

fn format_unix_time(secs: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|dt| {
            dt.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

// --- Unified operations --------------------------------------------------

impl FileBackend {
    /// Lists directory entries sorted directories-first by name.
    pub async fn list(&self, dir: &str) -> Result<Vec<FileEntry>, SftpError> {
        let dir_norm = normalize_posix_path(dir);
        match self {
            Self::Local => {
                let path = PathBuf::from(&dir_norm);
                check_local_path(&path)?;
                let rd = std::fs::read_dir(&path).map_err(map_local_io_err)?;
                let mut entries = Vec::new();
                for item in rd {
                    let item = item.map_err(map_local_io_err)?;
                    let name = item.file_name().to_string_lossy().into_owned();
                    let full_path = join_posix(&dir_norm, &name);
                    let meta = match std::fs::symlink_metadata(item.path()) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    let is_symlink = meta.file_type().is_symlink();
                    let effective_meta = if is_symlink {
                        std::fs::metadata(item.path()).unwrap_or(meta)
                    } else {
                        meta
                    };
                    let is_dir = effective_meta.is_dir();
                    let size = if is_dir { 0 } else { effective_meta.len() };
                    let (mode, owner) = local_mode_and_owner(&effective_meta);
                    let mod_time = effective_meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| format_unix_time(d.as_secs() as i64))
                        .unwrap_or_default();
                    entries.push(FileEntry {
                        name,
                        path: full_path,
                        is_dir,
                        is_symlink,
                        size,
                        mode,
                        mod_time,
                        owner,
                    });
                }
                sort_entries(&mut entries);
                Ok(entries)
            }
            Self::Remote(client) => {
                let guard = client.lock().await;
                let rd = guard.sftp.read_dir(&dir_norm).await.map_err(map_sftp_err)?;
                let mut entries = Vec::new();
                for item in rd {
                    let name = item.file_name();
                    if name == "." || name == ".." {
                        continue;
                    }
                    let meta = item.metadata();
                    let is_dir = meta.is_dir();
                    let is_symlink = meta.is_symlink();
                    let size = if is_dir { 0 } else { meta.size.unwrap_or(0) };
                    let mode = meta.permissions.unwrap_or(0) & 0o7777;
                    let mod_time = meta
                        .mtime
                        .map(|m| format_unix_time(i64::from(m)))
                        .unwrap_or_default();
                    let owner = meta.uid.map(|u| u.to_string()).unwrap_or_default();
                    entries.push(FileEntry {
                        path: join_posix(&dir_norm, &name),
                        name,
                        is_dir,
                        is_symlink,
                        size,
                        mode,
                        mod_time,
                        owner,
                    });
                }
                sort_entries(&mut entries);
                Ok(entries)
            }
        }
    }

    /// Reads a file for online text preview (enforcing the 1 MiB ceiling -> 413).
    pub async fn read_text(&self, path: &str) -> Result<TextPreview, SftpError> {
        let norm = normalize_posix_path(path);
        match self {
            Self::Local => {
                let p = PathBuf::from(&norm);
                check_local_path(&p)?;
                let meta = std::fs::metadata(&p).map_err(map_local_io_err)?;
                if meta.len() as usize > limits::SFTP_PREVIEW_MAX_BYTES {
                    return Err(SftpError::PayloadTooLarge(format!(
                        "文件大小超过文本预览上限（{} 字节）",
                        limits::SFTP_PREVIEW_MAX_BYTES
                    )));
                }
                let bytes = std::fs::read(&p).map_err(map_local_io_err)?;
                check_text_preview(&norm, bytes)
            }
            Self::Remote(client) => {
                let guard = client.lock().await;
                let meta = guard.sftp.metadata(&norm).await.map_err(map_sftp_err)?;
                if meta.size.unwrap_or(0) as usize > limits::SFTP_PREVIEW_MAX_BYTES {
                    return Err(SftpError::PayloadTooLarge(format!(
                        "文件大小超过文本预览上限（{} 字节）",
                        limits::SFTP_PREVIEW_MAX_BYTES
                    )));
                }
                let bytes = guard.sftp.read(&norm).await.map_err(map_sftp_err)?;
                check_text_preview(&norm, bytes)
            }
        }
    }

    /// Reads raw file bytes (used for downloads and archive operations).
    pub async fn read_bytes(&self, path: &str) -> Result<Vec<u8>, SftpError> {
        let norm = normalize_posix_path(path);
        match self {
            Self::Local => {
                let p = PathBuf::from(&norm);
                check_local_path(&p)?;
                std::fs::read(&p).map_err(map_local_io_err)
            }
            Self::Remote(client) => {
                let guard = client.lock().await;
                guard.sftp.read(&norm).await.map_err(map_sftp_err)
            }
        }
    }

    /// Writes bytes to a file (creating or overwriting it).
    pub async fn write_bytes(&self, path: &str, data: &[u8]) -> Result<(), SftpError> {
        let norm = normalize_posix_path(path);
        if is_root_path(&norm) {
            return Err(SftpError::Forbidden("不能写入根目录".into()));
        }
        match self {
            Self::Local => {
                let p = PathBuf::from(&norm);
                check_local_path(&p)?;
                if let Some(parent) = p.parent() {
                    check_local_path(parent)?;
                    std::fs::create_dir_all(parent).map_err(map_local_io_err)?;
                }
                std::fs::write(&p, data).map_err(map_local_io_err)
            }
            Self::Remote(client) => {
                let guard = client.lock().await;
                if let Some((parent, _)) = norm.rsplit_once('/')
                    && !parent.is_empty()
                {
                    ensure_sftp_dir(&guard.sftp, parent).await?;
                }
                guard.sftp.write(&norm, data).await.map_err(map_sftp_err)
            }
        }
    }

    /// Uploads multiple files into `dir`, preserving relative directory structure
    /// and overwriting existing files.
    pub async fn upload(&self, dir: &str, items: &[UploadItem]) -> Result<usize, SftpError> {
        let base = normalize_posix_path(dir);
        let mut count = 0usize;
        for item in items {
            let rel = validate_upload_rel(&item.path)?;
            let dest = join_posix(&base, &rel);
            self.write_bytes(&dest, &item.data).await?;
            count += 1;
        }
        Ok(count)
    }

    /// Creates a directory (including missing parent directories).
    pub async fn mkdir(&self, path: &str) -> Result<(), SftpError> {
        let norm = normalize_posix_path(path);
        match self {
            Self::Local => {
                let p = PathBuf::from(&norm);
                check_local_path(&p)?;
                std::fs::create_dir_all(&p).map_err(map_local_io_err)
            }
            Self::Remote(client) => {
                let guard = client.lock().await;
                ensure_sftp_dir(&guard.sftp, &norm).await
            }
        }
    }

    /// Creates an empty file (or touches an existing one).
    pub async fn touch(&self, path: &str) -> Result<(), SftpError> {
        let norm = normalize_posix_path(path);
        if is_root_path(&norm) {
            return Err(SftpError::Forbidden("不能创建根目录文件".into()));
        }
        match self {
            Self::Local => {
                let p = PathBuf::from(&norm);
                check_local_path(&p)?;
                if !p.exists() {
                    std::fs::write(&p, b"").map_err(map_local_io_err)?;
                }
                Ok(())
            }
            Self::Remote(client) => {
                let guard = client.lock().await;
                if !guard.sftp.try_exists(&norm).await.unwrap_or(false) {
                    guard.sftp.write(&norm, b"").await.map_err(map_sftp_err)?;
                }
                Ok(())
            }
        }
    }

    /// Renames or moves a file/directory.
    pub async fn rename(&self, from: &str, to: &str) -> Result<(), SftpError> {
        let src = normalize_posix_path(from);
        let dst = normalize_posix_path(to);
        if is_root_path(&src) || is_root_path(&dst) {
            return Err(SftpError::Forbidden("不能重命名根目录".into()));
        }
        match self {
            Self::Local => {
                let src_p = PathBuf::from(&src);
                let dst_p = PathBuf::from(&dst);
                check_local_path(&src_p)?;
                check_local_path(&dst_p)?;
                std::fs::rename(&src_p, &dst_p).map_err(map_local_io_err)
            }
            Self::Remote(client) => {
                let guard = client.lock().await;
                guard.sftp.rename(&src, &dst).await.map_err(map_sftp_err)
            }
        }
    }

    /// Copies a file or directory into `dest_dir` (auto-renaming on collision
    /// to `name 副本.ext`, `name 副本 2.ext`, etc.). Returns the final created path.
    pub async fn copy(&self, from: &str, dest_dir: &str) -> Result<String, SftpError> {
        let src = normalize_posix_path(from);
        let target_dir = normalize_posix_path(dest_dir);
        if is_root_path(&src) {
            return Err(SftpError::Forbidden("不能复制根目录".into()));
        }
        let file_name = src
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SftpError::BadRequest("源路径无效".into()))?;

        // Choose a non-colliding destination name.
        let mut candidate = join_posix(&target_dir, file_name);
        let mut idx = 1usize;
        while self.exists(&candidate).await? {
            let alt = copy_collision_name(file_name, idx);
            candidate = join_posix(&target_dir, &alt);
            idx += 1;
            if idx > 10_000 {
                return Err(SftpError::Io("生成副本文件名次数超限".into()));
            }
        }

        self.copy_recursive(&src, &candidate).await?;
        Ok(candidate)
    }

    /// Deletes one or more files/directories recursively, protecting `/`!
    pub async fn remove(&self, paths: &[String]) -> Result<(), SftpError> {
        for raw in paths {
            if is_root_path(raw) {
                return Err(SftpError::Forbidden("根目录受保护，禁止删除".into()));
            }
        }
        for raw in paths {
            let norm = normalize_posix_path(raw);
            self.remove_one(&norm).await?;
        }
        Ok(())
    }

    /// Changes POSIX permissions (`0..=0o7777`), optionally recursing into subdirectories.
    pub async fn chmod(&self, path: &str, mode: u32, recursive: bool) -> Result<(), SftpError> {
        if mode > 0o7777 {
            return Err(SftpError::BadRequest(format!(
                "权限值无效（范围 0～7777）：{mode:o}"
            )));
        }
        let norm = normalize_posix_path(path);
        if is_root_path(&norm) {
            return Err(SftpError::Forbidden("禁止修改根目录权限".into()));
        }
        self.chmod_inner(&norm, mode, recursive).await
    }

    /// Compresses `paths` into `dest_archive` using `format` (`.zip` or `.tar.gz`).
    pub async fn compress(
        &self,
        paths: &[String],
        dest_archive: &str,
        format: ArchiveFormat,
    ) -> Result<(), SftpError> {
        if paths.is_empty() {
            return Err(SftpError::BadRequest(
                "请选择至少一个待压缩的文件或目录".into(),
            ));
        }
        let mut inputs = Vec::new();
        for raw in paths {
            let norm = normalize_posix_path(raw);
            if is_root_path(&norm) {
                return Err(SftpError::Forbidden("不能压缩根目录".into()));
            }
            let base_name = norm
                .rsplit('/')
                .next()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| SftpError::BadRequest(format!("无效路径：{raw}")))?;
            self.collect_for_compress(&norm, base_name, &mut inputs)
                .await?;
        }
        let archive_bytes = compress_entries(format, &inputs)?;
        self.write_bytes(dest_archive, &archive_bytes).await
    }

    /// Previews entries in an archive file (capped at 10,000 entries).
    pub async fn preview_archive(&self, archive_path: &str) -> Result<ArchivePreview, SftpError> {
        let format = ArchiveFormat::from_path(archive_path)
            .ok_or_else(|| SftpError::BadRequest("仅支持 .zip 和 .tar.gz/.tgz 格式".into()))?;
        let bytes = self.read_bytes(archive_path).await?;
        Ok(preview_archive(format, &bytes)?)
    }

    /// Decompresses an archive file into `dest_dir` with full security checks
    /// (rejects `..`, skips symlinks/hardlinks, keeps only `rwx` bits).
    pub async fn decompress(&self, archive_path: &str, dest_dir: &str) -> Result<usize, SftpError> {
        let format = ArchiveFormat::from_path(archive_path)
            .ok_or_else(|| SftpError::BadRequest("仅支持 .zip 和 .tar.gz/.tgz 格式".into()))?;
        let bytes = self.read_bytes(archive_path).await?;
        let extracted = extract_archive(format, &bytes, ExtractLimits::default())?;
        let base = normalize_posix_path(dest_dir);
        self.mkdir(&base).await?;

        let count = extracted.len();
        for entry in extracted {
            let full = join_posix(&base, &entry.rel_path);
            if entry.is_dir {
                self.mkdir(&full).await?;
                let _ = self.chmod(&full, entry.mode, false).await;
            } else {
                self.write_bytes(&full, &entry.data).await?;
                let _ = self.chmod(&full, entry.mode, false).await;
            }
        }
        Ok(count)
    }

    // --- Internal helpers ---

    async fn exists(&self, path: &str) -> Result<bool, SftpError> {
        match self {
            Self::Local => {
                let p = PathBuf::from(path);
                check_local_path(&p)?;
                Ok(p.exists())
            }
            Self::Remote(client) => {
                let guard = client.lock().await;
                Ok(guard.sftp.try_exists(path).await.unwrap_or(false))
            }
        }
    }

    async fn is_dir(&self, path: &str) -> Result<bool, SftpError> {
        match self {
            Self::Local => {
                let p = PathBuf::from(path);
                check_local_path(&p)?;
                let meta = std::fs::metadata(&p).map_err(map_local_io_err)?;
                Ok(meta.is_dir())
            }
            Self::Remote(client) => {
                let guard = client.lock().await;
                let meta = guard.sftp.metadata(path).await.map_err(map_sftp_err)?;
                Ok(meta.is_dir())
            }
        }
    }

    fn copy_recursive<'a>(
        &'a self,
        src: &'a str,
        dst: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SftpError>> + Send + 'a>>
    {
        Box::pin(async move {
            if self.is_dir(src).await? {
                self.mkdir(dst).await?;
                let children = self.list(src).await?;
                for child in children {
                    let child_dst = join_posix(dst, &child.name);
                    self.copy_recursive(&child.path, &child_dst).await?;
                }
            } else {
                let data = self.read_bytes(src).await?;
                self.write_bytes(dst, &data).await?;
            }
            Ok(())
        })
    }

    fn remove_one<'a>(
        &'a self,
        path: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SftpError>> + Send + 'a>>
    {
        Box::pin(async move {
            match self {
                Self::Local => {
                    let p = PathBuf::from(path);
                    check_local_path(&p)?;
                    let meta = std::fs::symlink_metadata(&p).map_err(map_local_io_err)?;
                    if meta.is_dir() && !meta.file_type().is_symlink() {
                        std::fs::remove_dir_all(&p).map_err(map_local_io_err)
                    } else {
                        std::fs::remove_file(&p).map_err(map_local_io_err)
                    }
                }
                Self::Remote(client) => {
                    let is_dir = {
                        let guard = client.lock().await;
                        let meta = guard
                            .sftp
                            .symlink_metadata(path)
                            .await
                            .map_err(map_sftp_err)?;
                        meta.is_dir() && !meta.is_symlink()
                    };
                    if is_dir {
                        let children = self.list(path).await?;
                        for child in children {
                            self.remove_one(&child.path).await?;
                        }
                        let guard = client.lock().await;
                        guard.sftp.remove_dir(path).await.map_err(map_sftp_err)
                    } else {
                        let guard = client.lock().await;
                        guard.sftp.remove_file(path).await.map_err(map_sftp_err)
                    }
                }
            }
        })
    }

    fn chmod_inner<'a>(
        &'a self,
        path: &'a str,
        mode: u32,
        recursive: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SftpError>> + Send + 'a>>
    {
        Box::pin(async move {
            match self {
                Self::Local => {
                    let p = PathBuf::from(path);
                    check_local_path(&p)?;
                    set_local_mode(&p, mode).await?;
                }
                Self::Remote(client) => {
                    let guard = client.lock().await;
                    let mut attrs = russh_sftp::protocol::FileAttributes::empty();
                    attrs.permissions = Some(mode);
                    guard
                        .sftp
                        .set_metadata(path, attrs)
                        .await
                        .map_err(map_sftp_err)?;
                }
            }
            if recursive && self.is_dir(path).await.unwrap_or(false) {
                let children = self.list(path).await?;
                for child in children {
                    if !child.is_symlink {
                        self.chmod_inner(&child.path, mode, true).await?;
                    }
                }
            }
            Ok(())
        })
    }

    fn collect_for_compress<'a>(
        &'a self,
        full_path: &'a str,
        rel_path: &'a str,
        out: &'a mut Vec<CompressInput>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SftpError>> + Send + 'a>>
    {
        Box::pin(async move {
            if self.is_dir(full_path).await? {
                out.push(CompressInput {
                    rel_path: rel_path.to_owned(),
                    is_dir: true,
                    mode: 0o755,
                    data: Vec::new(),
                });
                let children = self.list(full_path).await?;
                for child in children {
                    if child.is_symlink {
                        continue;
                    }
                    let child_rel = format!("{rel_path}/{}", child.name);
                    self.collect_for_compress(&child.path, &child_rel, out)
                        .await?;
                }
            } else {
                let data = self.read_bytes(full_path).await?;
                let mode = self.file_mode(full_path).await.unwrap_or(0o644);
                out.push(CompressInput {
                    rel_path: rel_path.to_owned(),
                    is_dir: false,
                    mode,
                    data,
                });
            }
            Ok(())
        })
    }

    async fn file_mode(&self, path: &str) -> Result<u32, SftpError> {
        match self {
            Self::Local => {
                let p = PathBuf::from(path);
                let meta = std::fs::metadata(&p).map_err(map_local_io_err)?;
                Ok(local_mode_and_owner(&meta).0)
            }
            Self::Remote(client) => {
                let guard = client.lock().await;
                let meta = guard.sftp.metadata(path).await.map_err(map_sftp_err)?;
                Ok(meta.permissions.unwrap_or(0o644) & 0o777)
            }
        }
    }
}

async fn ensure_sftp_dir(
    sftp: &russh_sftp::client::SftpSession,
    dir: &str,
) -> Result<(), SftpError> {
    let mut cur = String::new();
    for seg in dir.split('/').filter(|s| !s.is_empty()) {
        cur.push('/');
        cur.push_str(seg);
        if !sftp.try_exists(&cur).await.unwrap_or(false) {
            sftp.create_dir(&cur).await.map_err(map_sftp_err)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn local_mode_and_owner(meta: &std::fs::Metadata) -> (u32, String) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    (meta.permissions().mode() & 0o7777, meta.uid().to_string())
}

#[cfg(not(unix))]
fn local_mode_and_owner(meta: &std::fs::Metadata) -> (u32, String) {
    let mode = if meta.is_dir() { 0o755 } else { 0o644 };
    (mode, String::new())
}

#[cfg(unix)]
async fn set_local_mode(path: &Path, mode: u32) -> Result<(), SftpError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms).map_err(map_local_io_err)
}

#[cfg(not(unix))]
async fn set_local_mode(_path: &Path, _mode: u32) -> Result<(), SftpError> {
    Ok(())
}

fn map_local_io_err(err: std::io::Error) -> SftpError {
    match err.kind() {
        std::io::ErrorKind::NotFound => SftpError::NotFound(err.to_string()),
        std::io::ErrorKind::PermissionDenied => SftpError::Forbidden(err.to_string()),
        _ => SftpError::Io(err.to_string()),
    }
}

fn map_sftp_err(err: russh_sftp::client::error::Error) -> SftpError {
    use russh_sftp::protocol::StatusCode;
    match &err {
        russh_sftp::client::error::Error::Status(status) => match status.status_code {
            StatusCode::NoSuchFile => SftpError::NotFound(status.error_message.clone()),
            StatusCode::PermissionDenied => SftpError::Forbidden(status.error_message.clone()),
            _ => SftpError::Io(err.to_string()),
        },
        _ => SftpError::Io(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::test_support::MutableClock;

    #[test]
    fn sftp_read_over_1mb_413() {
        let oversized = vec![b'a'; limits::SFTP_PREVIEW_MAX_BYTES + 1];
        let err = check_text_preview("/tmp/big.txt", oversized).expect_err("over 1MB");
        assert!(matches!(err, SftpError::PayloadTooLarge(_)));

        let exact = vec![b'a'; limits::SFTP_PREVIEW_MAX_BYTES];
        let ok = check_text_preview("/tmp/exact.txt", exact).expect("exactly 1MB");
        assert_eq!(ok.size, limits::SFTP_PREVIEW_MAX_BYTES);

        let bin = vec![0u8, 1, 2, 3];
        let err = check_text_preview("/tmp/bin", bin).expect_err("binary");
        assert!(matches!(err, SftpError::UnsupportedMedia(_)));
    }

    #[test]
    fn sftp_idle_5min_closes() {
        let clock = Arc::new(MutableClock::at(1_000));
        let pool = SftpPool::with_clock(clock.fn_pointer(), limits::SFTP_IDLE_AFTER);
        pool.insert_dummy("conn_a");
        pool.insert_dummy("conn_b");
        assert_eq!(pool.len(), 2);

        // At +299s neither is expired.
        clock.advance(299);
        assert!(pool.sweep().is_empty());

        // Touch conn_b at t=1299 so only conn_a expires at t=1300.
        pool.touch_dummy("conn_b");
        clock.advance(1);
        let closed = pool.sweep();
        assert_eq!(closed, vec!["conn_a".to_owned()]);
        assert_eq!(pool.len(), 1);

        // At +300s after touch, conn_b expires too.
        clock.advance(300);
        let closed = pool.sweep();
        assert_eq!(closed, vec!["conn_b".to_owned()]);
        assert!(pool.is_empty());
    }

    #[test]
    fn copy_collision_names_follow_upstream_pattern() {
        assert_eq!(copy_collision_name("notes.txt", 1), "notes 副本.txt");
        assert_eq!(copy_collision_name("notes.txt", 2), "notes 副本 2.txt");
        assert_eq!(copy_collision_name("README", 1), "README 副本");
        assert_eq!(copy_collision_name(".env", 1), ".env 副本");
    }

    #[tokio::test]
    async fn sftp_root_protected_from_delete_unit() {
        let backend = FileBackend::Local;
        for root in ["/", "///", "/.", ""] {
            let err = backend
                .remove(&[root.to_owned()])
                .await
                .expect_err("root must be protected");
            assert!(matches!(err, SftpError::Forbidden(_)));
        }
    }
}
