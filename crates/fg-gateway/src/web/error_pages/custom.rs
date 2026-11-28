//! Custom error page library (WP-27 §3.3 & §4): up to 32 reusable pages
//! backed by inline HTML (≤ 256 KiB UTF-8) or server-side HTML files with live
//! mtime/size reload checking, symlink HTML-extension enforcement, automatic
//! fallback to the default built-in style when unavailable, and Axum management
//! routes under `/api/webservice/errorpages*`.

use std::{
    collections::HashMap,
    fmt, fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::SystemTime,
};

use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    builtin::{ErrorCtx, Lang, StyleId, render},
    sanitize::{ERROR_PAGE_CSP, MAX_CUSTOM_PAGE_BYTES, Sanitized, sanitize, sanitize_bytes},
};

/// Maximum number of custom error pages stored in the shared library.
pub const MAX_CUSTOM_PAGES: usize = 32;

/// Content source for a custom error page (WP-27 §3.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "sourceType", rename_all = "camelCase")]
pub enum Source {
    Inline { name: String, html: String },
    File { name: String, path: PathBuf },
}

impl Source {
    pub fn name(&self) -> &str {
        match self {
            Self::Inline { name, .. } | Self::File { name, .. } => name,
        }
    }
}

/// Public API view of one custom page in the library.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomPageView {
    pub key: String,
    pub name: String,
    pub source_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub removed: Vec<String>,
    pub warnings: Vec<String>,
}

/// Store error returned on CRUD mutations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    NotFound,
    LimitExceeded,
    Invalid(Vec<String>),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("custom error page not found"),
            Self::LimitExceeded => {
                write!(
                    f,
                    "custom error page library limit ({MAX_CUSTOM_PAGES}) exceeded"
                )
            }
            Self::Invalid(errs) => f.write_str(&errs.join("; ")),
        }
    }
}

impl std::error::Error for StoreError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileFingerprint {
    modified: Option<SystemTime>,
    len: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    ctime_sec: i64,
    #[cfg(unix)]
    ctime_nsec: i64,
}

impl FileFingerprint {
    fn from_meta(meta: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                modified: meta.modified().ok(),
                len: meta.len(),
                ino: meta.ino(),
                ctime_sec: meta.ctime(),
                ctime_nsec: meta.ctime_nsec(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                modified: meta.modified().ok(),
                len: meta.len(),
            }
        }
    }
}

#[derive(Clone, Debug)]
enum StoredState {
    Inline {
        name: String,
        sanitized: Sanitized,
    },
    File {
        name: String,
        path: PathBuf,
        fingerprint: Option<FileFingerprint>,
        sanitized: Option<Sanitized>,
        last_error: Option<String>,
    },
}

/// Thread-safe custom error page library shared across sites.
#[derive(Default)]
pub struct ErrorPageStore {
    entries: RwLock<HashMap<String, StoredState>>,
}

impl ErrorPageStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new custom error page and returns its view.
    ///
    /// Enforces the 32-page limit, runs HTML sanitization on inline pages, and
    /// validates + loads server-side HTML files.
    pub fn create(&self, source: Source) -> Result<CustomPageView, StoreError> {
        let state = build_stored_state(source)?;
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries.len() >= MAX_CUSTOM_PAGES {
            return Err(StoreError::LimitExceeded);
        }
        let key = generate_unique_key(&entries);
        let view = view_of(&key, &state);
        entries.insert(key, state);
        Ok(view)
    }

    /// Creates or inserts a page under an explicit key (validated to be
    /// non-empty ASCII alphanumeric/hyphen/underscore).
    pub fn insert_with_key(
        &self,
        key: impl Into<String>,
        source: Source,
    ) -> Result<CustomPageView, StoreError> {
        let key = key.into();
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(StoreError::Invalid(vec![
                "invalid custom page key".to_owned(),
            ]));
        }
        let state = build_stored_state(source)?;
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !entries.contains_key(&key) && entries.len() >= MAX_CUSTOM_PAGES {
            return Err(StoreError::LimitExceeded);
        }
        let view = view_of(&key, &state);
        entries.insert(key, state);
        Ok(view)
    }

    /// Replaces an existing custom error page by `key`.
    pub fn update(&self, key: &str, source: Source) -> Result<CustomPageView, StoreError> {
        let state = build_stored_state(source)?;
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !entries.contains_key(key) {
            return Err(StoreError::NotFound);
        }
        let view = view_of(key, &state);
        entries.insert(key.to_owned(), state);
        Ok(view)
    }

    /// Deletes a custom error page by `key`.
    pub fn delete(&self, key: &str) -> Result<(), StoreError> {
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.remove(key).map(|_| ()).ok_or(StoreError::NotFound)
    }

    /// Lists all custom pages, refreshing file-backed pages to reflect current
    /// availability.
    pub fn list(&self) -> Vec<CustomPageView> {
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out: Vec<CustomPageView> = entries
            .iter_mut()
            .map(|(key, state)| {
                refresh_if_file(state);
                view_of(key, state)
            })
            .collect();
        out.sort_by(|a, b| a.key.cmp(&b.key));
        out
    }

    /// Returns metadata for a single custom page, refreshing file status.
    pub fn get(&self, key: &str) -> Option<CustomPageView> {
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = entries.get_mut(key)?;
        refresh_if_file(state);
        Some(view_of(key, state))
    }

    /// Resolves the sanitized HTML template for `key`.
    ///
    /// For file-backed pages, checks whether the file changed on disk (mtime,
    /// size, inode/ctime) and reloads + re-sanitizes automatically. If the
    /// file was deleted or became invalid, marks it unavailable and returns
    /// `None` so callers fall back to the default built-in style.
    pub fn resolve_html(&self, key: &str) -> Option<String> {
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = entries.get_mut(key)?;
        refresh_if_file(state);
        match state {
            StoredState::Inline { sanitized, .. } => Some(sanitized.html.clone()),
            StoredState::File { sanitized, .. } => sanitized.as_ref().map(|s| s.html.clone()),
        }
    }
}

fn build_stored_state(source: Source) -> Result<StoredState, StoreError> {
    let name = source.name().trim().to_owned();
    if name.is_empty() {
        return Err(StoreError::Invalid(vec![
            "custom error page name cannot be empty".to_owned(),
        ]));
    }
    match source {
        Source::Inline { html, .. } => {
            let sanitized = sanitize(&html).map_err(StoreError::Invalid)?;
            Ok(StoredState::Inline { name, sanitized })
        }
        Source::File { path, .. } => {
            let (fp, sanitized) = load_html_file(&path).map_err(StoreError::Invalid)?;
            Ok(StoredState::File {
                name,
                path,
                fingerprint: Some(fp),
                sanitized: Some(sanitized),
                last_error: None,
            })
        }
    }
}

fn refresh_if_file(state: &mut StoredState) {
    let StoredState::File {
        path,
        fingerprint,
        sanitized,
        last_error,
        ..
    } = state
    else {
        return;
    };

    // Always resolve canonical target to ensure symlinks still point to a
    // regular `.html`/`.htm` file and check its current metadata.
    let canonical = match validate_file_path(path) {
        Ok(p) => p,
        Err(errs) => {
            *fingerprint = None;
            *sanitized = None;
            *last_error = Some(errs.join("; "));
            return;
        }
    };
    let meta = match fs::metadata(&canonical) {
        Ok(m) if m.is_file() => m,
        Ok(_) => {
            *fingerprint = None;
            *sanitized = None;
            *last_error = Some("error page path is not a regular file".to_owned());
            return;
        }
        Err(e) => {
            *fingerprint = None;
            *sanitized = None;
            *last_error = Some(format!("failed to stat error page file: {e}"));
            return;
        }
    };

    let current_fp = FileFingerprint::from_meta(&meta);
    if *fingerprint == Some(current_fp) && sanitized.is_some() {
        return;
    }

    match read_and_sanitize_file(&canonical, meta.len()) {
        Ok(s) => {
            *fingerprint = Some(current_fp);
            *sanitized = Some(s);
            *last_error = None;
        }
        Err(errs) => {
            *fingerprint = Some(current_fp);
            *sanitized = None;
            *last_error = Some(errs.join("; "));
        }
    }
}

fn load_html_file(path: &Path) -> Result<(FileFingerprint, Sanitized), Vec<String>> {
    let canonical = validate_file_path(path)?;
    let meta = fs::metadata(&canonical)
        .map_err(|e| vec![format!("failed to access error page file: {e}")])?;
    if !meta.is_file() {
        return Err(vec!["error page path must be a regular file".to_owned()]);
    }
    let fp = FileFingerprint::from_meta(&meta);
    let sanitized = read_and_sanitize_file(&canonical, meta.len())?;
    Ok((fp, sanitized))
}

fn validate_file_path(path: &Path) -> Result<PathBuf, Vec<String>> {
    if !path.is_absolute() {
        return Err(vec![
            "server error page path must be an absolute path".to_owned(),
        ]);
    }
    let canonical = fs::canonicalize(path)
        .map_err(|e| vec![format!("error page file cannot be resolved: {e}")])?;
    let ext_ok = canonical
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("html") || e.eq_ignore_ascii_case("htm"));
    if !ext_ok {
        return Err(vec![
            "error page file (including symlink target) must have .html or .htm extension"
                .to_owned(),
        ]);
    }
    Ok(canonical)
}

fn read_and_sanitize_file(canonical: &Path, len: u64) -> Result<Sanitized, Vec<String>> {
    if len as usize > MAX_CUSTOM_PAGE_BYTES {
        return Err(vec![format!(
            "error page file exceeds {} byte limit",
            MAX_CUSTOM_PAGE_BYTES
        )]);
    }
    let bytes =
        fs::read(canonical).map_err(|e| vec![format!("failed to read error page file: {e}")])?;
    sanitize_bytes(&bytes)
}

fn view_of(key: &str, state: &StoredState) -> CustomPageView {
    match state {
        StoredState::Inline { name, sanitized } => CustomPageView {
            key: key.to_owned(),
            name: name.clone(),
            source_type: "inline".to_owned(),
            path: None,
            available: true,
            error: None,
            removed: sanitized.removed.clone(),
            warnings: sanitized.warnings.clone(),
        },
        StoredState::File {
            name,
            path,
            sanitized,
            last_error,
            ..
        } => CustomPageView {
            key: key.to_owned(),
            name: name.clone(),
            source_type: "file".to_owned(),
            path: Some(path.display().to_string()),
            available: sanitized.is_some(),
            error: last_error.clone(),
            removed: sanitized
                .as_ref()
                .map_or_else(Vec::new, |s| s.removed.clone()),
            warnings: sanitized
                .as_ref()
                .map_or_else(Vec::new, |s| s.warnings.clone()),
        },
    }
}

fn generate_unique_key(existing: &HashMap<String, StoredState>) -> String {
    for _ in 0..32 {
        let mut bytes = [0u8; 6];
        getrandom::fill(&mut bytes).expect("OS randomness unavailable");
        let key: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        if !existing.contains_key(&key) {
            return key;
        }
    }
    format!("page{:08x}", existing.len() + 1)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckRequest {
    html: String,
}

/// Mounts the WP-27 custom error page management API routes:
/// - `GET  /api/webservice/errorpages`
/// - `POST /api/webservice/errorpages`
/// - `PUT  /api/webservice/errorpages/{key}`
/// - `DELETE /api/webservice/errorpages/{key}`
/// - `GET  /api/webservice/errorpages/styles`
/// - `POST /api/webservice/errorpages/check`
/// - `GET  /api/webservice/errorpages/{key}/preview`
pub fn mount_error_page_routes(router: Router, store: Arc<ErrorPageStore>) -> Router {
    let api = Router::new()
        .route(
            "/api/webservice/errorpages",
            get(handle_list).post(handle_create),
        )
        .route("/api/webservice/errorpages/styles", get(handle_styles))
        .route("/api/webservice/errorpages/check", post(handle_check))
        .route(
            "/api/webservice/errorpages/{key}",
            put(handle_update).delete(handle_delete),
        )
        .route(
            "/api/webservice/errorpages/{key}/preview",
            get(handle_preview),
        )
        .with_state(store);
    router.merge(api)
}

async fn handle_list(State(store): State<Arc<ErrorPageStore>>) -> Response {
    (StatusCode::OK, Json(store.list())).into_response()
}

async fn handle_create(
    State(store): State<Arc<ErrorPageStore>>,
    body: Result<Json<Source>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(source)) = body else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid custom error page payload" })),
        )
            .into_response();
    };
    match store.create(source) {
        Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Err(err) => store_error_response(err),
    }
}

async fn handle_update(
    State(store): State<Arc<ErrorPageStore>>,
    AxumPath(key): AxumPath<String>,
    body: Result<Json<Source>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(source)) = body else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid custom error page payload" })),
        )
            .into_response();
    };
    match store.update(&key, source) {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(err) => store_error_response(err),
    }
}

async fn handle_delete(
    State(store): State<Arc<ErrorPageStore>>,
    AxumPath(key): AxumPath<String>,
) -> Response {
    match store.delete(&key) {
        Ok(()) => (StatusCode::OK, Json(json!({ "removed": 1 }))).into_response(),
        Err(err) => store_error_response(err),
    }
}

async fn handle_styles() -> Response {
    let styles: Vec<_> = StyleId::ALL.into_iter().map(StyleId::info).collect();
    (StatusCode::OK, Json(styles)).into_response()
}

async fn handle_check(
    body: Result<Json<CheckRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(req)) = body else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid check payload" })),
        )
            .into_response();
    };
    match sanitize(&req.html) {
        Ok(sanitized) => (StatusCode::OK, Json(sanitized)).into_response(),
        Err(errors) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": errors.join("; "), "errors": errors })),
        )
            .into_response(),
    }
}

async fn handle_preview(
    State(store): State<Arc<ErrorPageStore>>,
    AxumPath(key): AxumPath<String>,
) -> Response {
    let Some(tpl) = store.resolve_html(&key) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "custom error page not found or unavailable" })),
        )
            .into_response();
    };
    let ctx = ErrorCtx::new(
        StatusCode::BAD_GATEWAY,
        "preview.example.com",
        "/example/path",
        Lang::En,
        SystemTime::now(),
    );
    let body = render(&tpl, &ctx);
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(ERROR_PAGE_CSP),
            ),
        ],
        body,
    )
        .into_response()
}

fn store_error_response(err: StoreError) -> Response {
    match err {
        StoreError::NotFound => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response(),
        StoreError::LimitExceeded => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response(),
        StoreError::Invalid(errors) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": errors.join("; "), "errors": errors })),
        )
            .into_response(),
    }
}
