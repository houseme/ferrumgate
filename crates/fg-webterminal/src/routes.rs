//! Axum HTTP and WebSocket routes for `/api/webterminal/*` (WP-61 §4).

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_RANGE, CONTENT_TYPE, RANGE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::WebTerminalHandle;
use crate::local_shell;
use crate::model::{Connection, Preset, Settings, Shortcut, limits};
use crate::security::{
    CallerContext, CallerRole, SecurityView, TwoFaSetupResponse, VerifyOutcome,
    connection_view_for, generate_totp_secret, otpauth_uri, preset_view_for, shortcuts_for,
    verify_totp,
};
use crate::session::{LiveItem, SessionError, random_id};
use crate::sftp::archive::ArchiveFormat;
use crate::sftp::{SftpError, UploadItem};
use crate::ssh;
use crate::validate::{
    ConnectionSecrets, PresetSecrets, clean_shortcuts, merge_connection, merge_preset, normalize,
    normalize_connection, preset_in_use, validate,
};
use crate::ws::{self, ClientMsg, ProtocolError, ServerMsg};

/// Standard JSON API error response (`{"error": "..."}`, conventions §3.3).
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, msg)
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, msg)
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, msg)
    }

    pub fn too_many(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, msg)
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, msg)
    }
}

impl From<SftpError> for ApiError {
    fn from(err: SftpError) -> Self {
        let status = match err {
            SftpError::BadRequest(_) => StatusCode::BAD_REQUEST,
            SftpError::Forbidden(_) => StatusCode::FORBIDDEN,
            SftpError::NotFound(_) => StatusCode::NOT_FOUND,
            SftpError::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            SftpError::UnsupportedMedia(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            SftpError::Io(_) => StatusCode::BAD_GATEWAY,
        };
        Self::new(status, err.to_string())
    }
}

impl From<SessionError> for ApiError {
    fn from(err: SessionError) -> Self {
        let status = match err {
            SessionError::TooMany => StatusCode::TOO_MANY_REQUESTS,
            SessionError::NotFound => StatusCode::NOT_FOUND,
            SessionError::Connect(_) => StatusCode::BAD_GATEWAY,
        };
        Self::new(status, err.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(json!({ "error": self.message }));
        let mut resp = (self.status, body).into_response();
        resp.headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        resp
    }
}

fn json_ok<T: Serialize>(value: T) -> Response {
    let mut resp = Json(value).into_response();
    resp.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// Extracts [`CallerContext`] from request extensions (set by auth middleware)
/// or from `x-fg-caller-role` / `x-fg-actor-id` headers when mounted standalone.
pub struct ExtractedCaller(pub CallerContext);

impl<S: Send + Sync> FromRequestParts<S> for ExtractedCaller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(ctx) = parts.extensions.get::<CallerContext>() {
            return Ok(Self(ctx.clone()));
        }
        let role = match parts
            .headers
            .get("x-fg-caller-role")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
        {
            Some("readonly") | Some("read_only") => CallerRole::ReadOnly,
            Some("api-write") | Some("api_write") | Some("token") => CallerRole::ApiWrite,
            _ => CallerRole::Session,
        };
        let actor_id = parts
            .headers
            .get("x-fg-actor-id")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("default-session")
            .to_owned();
        Ok(Self(CallerContext { role, actor_id }))
    }
}

fn require_write(caller: &CallerContext) -> Result<(), ApiError> {
    if !caller.can_write() {
        return Err(ApiError::forbidden("只读权限禁止执行写操作"));
    }
    Ok(())
}

fn require_session(caller: &CallerContext) -> Result<(), ApiError> {
    if !caller.can_manage_security() {
        return Err(ApiError::forbidden("该安全设置仅限登录会话操作"));
    }
    Ok(())
}

fn require_two_fa_if_enabled(
    handle: &WebTerminalHandle,
    caller: &CallerContext,
) -> Result<(), ApiError> {
    let cfg = handle.config_snapshot();
    if cfg.security.two_fa_enabled && !handle.two_fa.is_verified(&caller.actor_id) {
        return Err(ApiError::forbidden("需要完成两步验证确认后方可继续"));
    }
    Ok(())
}

/// Builds the `/api/webterminal/*` router backed by `handle`.
pub fn router(handle: Arc<WebTerminalHandle>) -> Router {
    Router::new()
        // Connections collection
        .route(
            "/api/webterminal/connections",
            get(list_connections).post(create_connection),
        )
        .route(
            "/api/webterminal/connections-delete",
            post(batch_delete_connections),
        )
        .route(
            "/api/webterminal/connections/batch-delete",
            post(batch_delete_connections),
        )
        .route(
            "/api/webterminal/connections-enable",
            put(batch_enable_connections),
        )
        .route(
            "/api/webterminal/connections-group",
            put(batch_group_connections),
        )
        .route("/api/webterminal/connections-order", put(order_connections))
        .route(
            "/api/webterminal/connections/test",
            post(test_draft_connection),
        )
        .route(
            "/api/webterminal/connections/{key}",
            put(update_connection).delete(delete_connection),
        )
        .route(
            "/api/webterminal/connections/{key}/copy",
            post(copy_connection),
        )
        .route(
            "/api/webterminal/connections/{key}/enable",
            put(enable_connection),
        )
        .route(
            "/api/webterminal/connections/{key}/secrets",
            get(get_connection_secrets),
        )
        .route(
            "/api/webterminal/connections/{key}/hostkey",
            delete(reset_connection_hostkey),
        )
        .route(
            "/api/webterminal/connections/{key}/quickaccess",
            put(update_quick_access),
        )
        .route(
            "/api/webterminal/connections/{key}/test",
            post(test_saved_connection),
        )
        // Sessions
        .route(
            "/api/webterminal/sessions",
            get(list_sessions).post(create_session),
        )
        .route(
            "/api/webterminal/sessions/{id}",
            get(get_session).delete(delete_session),
        )
        .route(
            "/api/webterminal/sessions/{id}/remark",
            put(update_session_remark),
        )
        .route(
            "/api/webterminal/sessions/{id}/stats",
            get(get_session_stats),
        )
        .route("/api/webterminal/sessions/{id}/ws", get(session_ws))
        // Credentials presets
        .route(
            "/api/webterminal/credentials",
            get(list_credentials).post(create_credential),
        )
        .route(
            "/api/webterminal/credentials-delete",
            post(batch_delete_credentials),
        )
        .route("/api/webterminal/credentials-order", put(order_credentials))
        .route(
            "/api/webterminal/credentials/{key}",
            put(update_credential).delete(delete_credential),
        )
        .route(
            "/api/webterminal/credentials/{key}/copy",
            post(copy_credential),
        )
        .route(
            "/api/webterminal/credentials/{key}/secrets",
            get(get_credential_secrets),
        )
        // Global shortcuts, shells, split layout
        .route(
            "/api/webterminal/globalshortcuts",
            get(get_global_shortcuts).put(put_global_shortcuts),
        )
        .route("/api/webterminal/shells", get(get_shells))
        .route(
            "/api/webterminal/splitlayout",
            get(get_split_layout)
                .put(put_split_layout)
                .delete(delete_split_layout),
        )
        // Security (login session only for mutations & 2FA)
        .route("/api/webterminal/security", get(get_security))
        .route(
            "/api/webterminal/security/agreement",
            post(accept_agreement),
        )
        .route("/api/webterminal/security/2fa/setup", post(setup_two_fa))
        .route("/api/webterminal/security/2fa/enable", post(enable_two_fa))
        .route(
            "/api/webterminal/security/2fa/disable",
            post(disable_two_fa),
        )
        .route("/api/webterminal/security/check2fa", get(check_two_fa))
        .route("/api/webterminal/security/verify2fa", post(verify_two_fa))
        // SFTP / file management
        .route("/api/webterminal/sftp/{key}/list", get(sftp_list))
        .route("/api/webterminal/sftp/{key}/read", get(sftp_read))
        .route("/api/webterminal/sftp/{key}/download", get(sftp_download))
        .route(
            "/api/webterminal/sftp/{key}/write",
            post(sftp_write).put(sftp_write),
        )
        .route("/api/webterminal/sftp/{key}/upload", post(sftp_upload))
        .route("/api/webterminal/sftp/{key}/mkdir", post(sftp_mkdir))
        .route("/api/webterminal/sftp/{key}/rename", post(sftp_rename))
        .route("/api/webterminal/sftp/{key}/copy", post(sftp_copy))
        .route("/api/webterminal/sftp/{key}/remove", delete(sftp_remove))
        .route("/api/webterminal/sftp/{key}/touch", post(sftp_touch))
        .route("/api/webterminal/sftp/{key}/chmod", post(sftp_chmod))
        .route("/api/webterminal/sftp/{key}/compress", post(sftp_compress))
        .route(
            "/api/webterminal/sftp/{key}/decompress",
            post(sftp_decompress),
        )
        .route(
            "/api/webterminal/sftp/{key}/preview-archive",
            get(sftp_preview_archive_get).post(sftp_preview_archive_post),
        )
        // Settings
        .route(
            "/api/webterminal/settings",
            get(get_settings).put(put_settings),
        )
        .with_state(handle)
}

// =========================================================================
// Connections
// =========================================================================

async fn list_connections(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
) -> Response {
    let cfg = handle.config_snapshot();
    let views: Vec<_> = cfg
        .connections
        .iter()
        .map(|c| connection_view_for(c, &caller))
        .collect();
    json_ok(views)
}

async fn create_connection(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Json(mut conn): Json<Connection>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    if conn.key.trim().is_empty() {
        conn.key = random_id();
    }
    normalize_connection(&mut conn);

    let created = handle.update_config(|cfg| {
        if cfg.connections.iter().any(|c| c.key == conn.key) {
            return Err(ApiError::conflict(format!("连接键 {} 已存在", conn.key)));
        }
        let mut next = cfg.clone();
        next.connections.push(conn.clone());
        let next = normalize(next);
        let problems = validate(&next);
        if let Some(first) = problems.first() {
            return Err(ApiError::bad_request(format!(
                "{}: {}",
                first.field, first.reason
            )));
        }
        let saved = next
            .connections
            .iter()
            .find(|c| c.key == conn.key)
            .cloned()
            .expect("inserted connection");
        *cfg = next;
        Ok(saved)
    })?;

    Ok((
        StatusCode::CREATED,
        json_ok(connection_view_for(&created, &caller)),
    )
        .into_response())
}

async fn update_connection(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    Json(mut incoming): Json<Connection>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    let updated = handle.update_config(|cfg| {
        let Some(existing) = cfg.connections.iter().find(|c| c.key == key).cloned() else {
            return Err(ApiError::not_found(format!("连接 {key} 不存在")));
        };
        incoming.key = key.clone();
        let mut merged = merge_connection(&existing, incoming);
        // Host/port change or manual fingerprint edit clears host_key.key_type (WP-61 §3.3).
        let endpoint_changed = merged.host.trim() != existing.host
            || merged.effective_port() != existing.effective_port();
        if endpoint_changed {
            merged.host_key = None;
        } else if let Some(hk) = &mut merged.host_key {
            let old_fp = existing.host_key.as_ref().map(|h| h.fingerprint.as_str());
            if old_fp != Some(hk.fingerprint.as_str()) {
                hk.key_type = None;
            }
        }
        let mut next = cfg.clone();
        if let Some(slot) = next.connections.iter_mut().find(|c| c.key == key) {
            *slot = merged;
        }
        let next = normalize(next);
        let problems = validate(&next);
        if let Some(first) = problems.first() {
            return Err(ApiError::bad_request(format!(
                "{}: {}",
                first.field, first.reason
            )));
        }
        let saved = next
            .connections
            .iter()
            .find(|c| c.key == key)
            .cloned()
            .expect("updated connection");
        *cfg = next;
        Ok(saved)
    })?;
    handle.sftp_pool.evict(&key);
    Ok(json_ok(connection_view_for(&updated, &caller)))
}

async fn delete_connection(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    handle.update_config(|cfg| {
        let before = cfg.connections.len();
        cfg.connections.retain(|c| c.key != key);
        if cfg.connections.len() == before {
            return Err(ApiError::not_found(format!("连接 {key} 不存在")));
        }
        Ok(())
    })?;
    handle.sftp_pool.evict(&key);
    Ok(json_ok(json!({ "ok": true })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct KeysBody {
    keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EnableBody {
    enable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BatchEnableBody {
    keys: Vec<String>,
    enable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BatchGroupBody {
    keys: Vec<String>,
    group: String,
}

fn validate_batch_keys(keys: &[String]) -> Result<(), ApiError> {
    if keys.is_empty() || keys.len() > limits::BATCH_KEYS_MAX {
        return Err(ApiError::bad_request(format!(
            "keys 数量须在 1～{} 之间",
            limits::BATCH_KEYS_MAX
        )));
    }
    Ok(())
}

async fn batch_delete_connections(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Json(body): Json<KeysBody>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    validate_batch_keys(&body.keys)?;
    let set: std::collections::HashSet<&str> = body.keys.iter().map(String::as_str).collect();
    handle.update_config(|cfg| {
        cfg.connections.retain(|c| !set.contains(c.key.as_str()));
        Ok(())
    })?;
    for key in &body.keys {
        handle.sftp_pool.evict(key);
    }
    Ok(json_ok(json!({ "ok": true })))
}

async fn batch_enable_connections(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Json(body): Json<BatchEnableBody>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    validate_batch_keys(&body.keys)?;
    let set: std::collections::HashSet<&str> = body.keys.iter().map(String::as_str).collect();
    handle.update_config(|cfg| {
        for c in &mut cfg.connections {
            if set.contains(c.key.as_str()) {
                c.enable = body.enable;
            }
        }
        Ok(())
    })?;
    Ok(json_ok(json!({ "ok": true })))
}

async fn batch_group_connections(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Json(body): Json<BatchGroupBody>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    validate_batch_keys(&body.keys)?;
    let group = body.group.trim().to_owned();
    if group.chars().count() > limits::GROUP_MAX_CHARS {
        return Err(ApiError::bad_request("分组名称过长"));
    }
    let set: std::collections::HashSet<&str> = body.keys.iter().map(String::as_str).collect();
    handle.update_config(|cfg| {
        for c in &mut cfg.connections {
            if set.contains(c.key.as_str()) {
                c.group = group.clone();
            }
        }
        Ok(())
    })?;
    Ok(json_ok(json!({ "ok": true })))
}

async fn order_connections(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Json(body): Json<KeysBody>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    validate_batch_keys(&body.keys)?;
    handle.update_config(|cfg| {
        let mut by_key: std::collections::HashMap<String, Connection> = cfg
            .connections
            .drain(..)
            .map(|c| (c.key.clone(), c))
            .collect();
        let mut ordered = Vec::with_capacity(by_key.len());
        for k in &body.keys {
            if let Some(c) = by_key.remove(k) {
                ordered.push(c);
            }
        }
        // Keep any remaining entries in deterministic key order.
        let mut rest: Vec<_> = by_key.into_values().collect();
        rest.sort_by(|a, b| a.key.cmp(&b.key));
        ordered.extend(rest);
        cfg.connections = ordered;
        Ok(())
    })?;
    Ok(json_ok(json!({ "ok": true })))
}

async fn enable_connection(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    Json(body): Json<EnableBody>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    let updated = handle.update_config(|cfg| {
        let Some(conn) = cfg.connections.iter_mut().find(|c| c.key == key) else {
            return Err(ApiError::not_found(format!("连接 {key} 不存在")));
        };
        conn.enable = body.enable;
        Ok(conn.clone())
    })?;
    Ok(json_ok(connection_view_for(&updated, &caller)))
}

async fn copy_connection(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    require_two_fa_if_enabled(&handle, &caller)?;
    let copied = handle.update_config(|cfg| {
        let Some(orig) = cfg.connections.iter().find(|c| c.key == key).cloned() else {
            return Err(ApiError::not_found(format!("连接 {key} 不存在")));
        };
        let mut dup = orig;
        dup.key = random_id();
        dup.name = format!("{} 副本", dup.name);
        cfg.connections.push(dup.clone());
        Ok(dup)
    })?;
    Ok((
        StatusCode::CREATED,
        json_ok(connection_view_for(&copied, &caller)),
    )
        .into_response())
}

async fn get_connection_secrets(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    require_two_fa_if_enabled(&handle, &caller)?;
    let cfg = handle.config_snapshot();
    let conn = cfg
        .connections
        .iter()
        .find(|c| c.key == key)
        .ok_or_else(|| ApiError::not_found(format!("连接 {key} 不存在")))?;
    Ok(json_ok(ConnectionSecrets::of(conn)))
}

async fn reset_connection_hostkey(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    handle.update_config(|cfg| {
        let Some(conn) = cfg.connections.iter_mut().find(|c| c.key == key) else {
            return Err(ApiError::not_found(format!("连接 {key} 不存在")));
        };
        conn.host_key = None;
        Ok(())
    })?;
    handle.sftp_pool.evict(&key);
    Ok(json_ok(json!({ "ok": true })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct QuickAccessBody {
    quick_access: Vec<String>,
}

async fn update_quick_access(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    Json(body): Json<QuickAccessBody>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    let updated = handle.update_config(|cfg| {
        let Some(conn) = cfg.connections.iter_mut().find(|c| c.key == key) else {
            return Err(ApiError::not_found(format!("连接 {key} 不存在")));
        };
        conn.quick_access = body
            .quick_access
            .into_iter()
            .map(|p| p.trim().to_owned())
            .filter(|p| !p.is_empty())
            .take(limits::QUICK_ACCESS_MAX)
            .collect();
        Ok(conn.quick_access.clone())
    })?;
    Ok(json_ok(json!({ "quickAccess": updated })))
}

async fn test_draft_connection(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Json(mut conn): Json<Connection>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    require_two_fa_if_enabled(&handle, &caller)?;
    normalize_connection(&mut conn);
    let cfg = handle.config_snapshot();
    // Test NEVER records host keys!
    let result = ssh::test_connection(&conn, &cfg.credentials)
        .await
        .map_err(ApiError::bad_request)?;
    Ok(json_ok(result))
}

async fn test_saved_connection(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    require_two_fa_if_enabled(&handle, &caller)?;
    let cfg = handle.config_snapshot();
    let conn = cfg
        .connections
        .iter()
        .find(|c| c.key == key)
        .cloned()
        .ok_or_else(|| ApiError::not_found(format!("连接 {key} 不存在")))?;
    // Test NEVER records host keys!
    let result = ssh::test_connection(&conn, &cfg.credentials)
        .await
        .map_err(ApiError::bad_request)?;
    Ok(json_ok(result))
}

// =========================================================================
// Sessions & WebSocket
// =========================================================================

async fn list_sessions(State(handle): State<Arc<WebTerminalHandle>>) -> Response {
    json_ok(handle.sessions.list())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CreateSessionBody {
    conn_key: String,
    #[serde(default)]
    cols: u16,
    #[serde(default)]
    rows: u16,
}

async fn create_session(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Json(body): Json<CreateSessionBody>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    require_two_fa_if_enabled(&handle, &caller)?;
    let cfg = handle.config_snapshot();
    let conn = cfg
        .connections
        .iter()
        .find(|c| c.key == body.conn_key)
        .cloned()
        .ok_or_else(|| ApiError::not_found(format!("连接 {} 不存在", body.conn_key)))?;
    if !conn.enable {
        return Err(ApiError::bad_request("该连接已禁用"));
    }

    let (id, updated_hk) = handle
        .sessions
        .create_for_connection(&conn, &cfg.credentials, &cfg.settings, body.cols, body.rows)
        .await
        .map_err(ApiError::from)?;

    if let Some(hk) = updated_hk {
        handle.record_host_key(&conn.key, hk);
    }

    let view = handle
        .sessions
        .view(&id)
        .ok_or_else(|| ApiError::internal("会话已创建但未找到"))?;
    Ok((StatusCode::CREATED, json_ok(view)).into_response())
}

async fn get_session(
    State(handle): State<Arc<WebTerminalHandle>>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let view = handle
        .sessions
        .view(&id)
        .ok_or_else(|| ApiError::not_found("会话不存在"))?;
    Ok(json_ok(view))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RemarkBody {
    remark: String,
}

async fn update_session_remark(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(id): Path<String>,
    Json(body): Json<RemarkBody>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    let trimmed: String = body
        .remark
        .trim()
        .chars()
        .take(limits::SESSION_REMARK_MAX_CHARS)
        .collect();
    if !handle.sessions.set_remark(&id, trimmed) {
        return Err(ApiError::not_found("会话不存在"));
    }
    let view = handle
        .sessions
        .view(&id)
        .ok_or_else(|| ApiError::not_found("会话不存在"))?;
    Ok(json_ok(view))
}

async fn get_session_stats(
    State(handle): State<Arc<WebTerminalHandle>>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let view = handle
        .sessions
        .view(&id)
        .ok_or_else(|| ApiError::not_found("会话不存在"))?;
    Ok(json_ok(view))
}

async fn delete_session(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    if !handle.sessions.close(&id) {
        return Err(ApiError::not_found("会话不存在"));
    }
    Ok(json_ok(json!({ "ok": true })))
}

async fn session_ws(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(id): Path<String>,
    ws_upgrade: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    // Verify session exists before upgrading.
    if handle.sessions.session(&id).is_none() {
        return Err(ApiError::not_found("会话不存在"));
    }
    let heartbeat_secs = handle.config_snapshot().settings.heartbeat_interval;
    Ok(ws_upgrade
        .on_upgrade(move |socket| run_session_ws(socket, handle, id, caller, heartbeat_secs)))
}

/// Reusable WebSocket pump for attaching a browser client to a session.
/// Shared protocol: binary frames for terminal output, text frames for JSON
/// control messages (`s`, `n`, `x`, `p`, `i`, `r`).
pub async fn run_session_ws(
    mut socket: WebSocket,
    handle: Arc<WebTerminalHandle>,
    session_id: String,
    caller: CallerContext,
    heartbeat_secs: u32,
) {
    let Ok(mut attach) = handle.sessions.attach(&session_id) else {
        let _ = socket
            .send(Message::Text(
                ws::encode(&ServerMsg::Exit("会话不存在".into())).into(),
            ))
            .await;
        let _ = socket.send(Message::Close(None)).await;
        return;
    };

    // 1. Send session started message (`{"t":"s","d":"<sessionId>"}`).
    if socket
        .send(Message::Text(
            ws::encode(&ServerMsg::Started(session_id.clone())).into(),
        ))
        .await
        .is_err()
    {
        return;
    }

    // 2. Replay buffered output as binary frames.
    for (_, chunk) in &attach.replay {
        if socket
            .send(Message::Binary(chunk.to_vec().into()))
            .await
            .is_err()
        {
            return;
        }
    }

    let hb_dur = Duration::from_secs(u64::from(heartbeat_secs.max(5)));
    let mut hb_ticker = tokio::time::interval(hb_dur);
    hb_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip immediate first tick.
    hb_ticker.tick().await;

    loop {
        tokio::select! {
            biased;
            live_item = attach.live.recv() => {
                match live_item {
                    Ok(LiveItem::Data { seq, data }) => {
                        if seq <= attach.last_seq && !attach.replay.is_empty() {
                            continue;
                        }
                        if socket.send(Message::Binary(data.to_vec().into())).await.is_err() {
                            break;
                        }
                    }
                    Ok(LiveItem::Server(msg)) => {
                        let is_exit = matches!(msg, ServerMsg::Exit(_));
                        let _ = socket.send(Message::Text(ws::encode(&msg).into())).await;
                        if is_exit {
                            let _ = socket.send(Message::Close(None)).await;
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        let _ = socket.send(Message::Close(None)).await;
                        break;
                    }
                }
            }
            _ = hb_ticker.tick() => {
                if socket.send(Message::Text(ws::encode(&ServerMsg::Pong).into())).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        match ws::decode(&text) {
                            Ok(ClientMsg::Input(data)) => {
                                // Read-only identity must NEVER send terminal input (WP-61 §3.3).
                                if caller.can_write() {
                                    handle.sessions.input(&session_id, data.into_bytes());
                                } else {
                                    let _ = socket.send(Message::Text(
                                        ws::encode(&ServerMsg::Notice("只读权限禁止终端输入".into())).into()
                                    )).await;
                                }
                            }
                            Ok(ClientMsg::Resize { cols, rows }) => {
                                if caller.can_write() {
                                    handle.sessions.resize(&session_id, cols, rows);
                                }
                            }
                            Ok(ClientMsg::Ping) => {
                                if socket.send(Message::Text(ws::encode(&ServerMsg::Pong).into())).await.is_err() {
                                    break;
                                }
                            }
                            Err(ProtocolError::UnknownType(_)) => {
                                // Ignore unknown control tags.
                            }
                            Err(ProtocolError::Malformed(_)) => {
                                let _ = socket.send(Message::Close(None)).await;
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        let _ = socket.send(Message::Pong(payload)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
        }
    }
}

// =========================================================================
// Credentials Presets
// =========================================================================

async fn list_credentials(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
) -> Response {
    let cfg = handle.config_snapshot();
    let list: Vec<_> = cfg
        .credentials
        .iter()
        .map(|p| preset_view_for(p, &caller))
        .collect();
    json_ok(list)
}

async fn create_credential(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Json(mut preset): Json<Preset>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    if preset.key.trim().is_empty() {
        preset.key = random_id();
    }
    let created = handle.update_config(|cfg| {
        if cfg.credentials.iter().any(|p| p.key == preset.key) {
            return Err(ApiError::conflict(format!(
                "凭据预设 {} 已存在",
                preset.key
            )));
        }
        let mut next = cfg.clone();
        next.credentials.push(preset.clone());
        let next = normalize(next);
        let problems = validate(&next);
        if let Some(first) = problems.first() {
            return Err(ApiError::bad_request(format!(
                "{}: {}",
                first.field, first.reason
            )));
        }
        let saved = next
            .credentials
            .iter()
            .find(|p| p.key == preset.key)
            .cloned()
            .expect("inserted preset");
        *cfg = next;
        Ok(saved)
    })?;
    Ok((
        StatusCode::CREATED,
        json_ok(preset_view_for(&created, &caller)),
    )
        .into_response())
}

async fn update_credential(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    Json(mut incoming): Json<Preset>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    let updated = handle.update_config(|cfg| {
        let Some(existing) = cfg.credentials.iter().find(|p| p.key == key).cloned() else {
            return Err(ApiError::not_found(format!("凭据预设 {key} 不存在")));
        };
        incoming.key = key.clone();
        let merged = merge_preset(&existing, incoming);
        let mut next = cfg.clone();
        if let Some(slot) = next.credentials.iter_mut().find(|p| p.key == key) {
            *slot = merged;
        }
        let next = normalize(next);
        let problems = validate(&next);
        if let Some(first) = problems.first() {
            return Err(ApiError::bad_request(format!(
                "{}: {}",
                first.field, first.reason
            )));
        }
        let saved = next
            .credentials
            .iter()
            .find(|p| p.key == key)
            .cloned()
            .expect("updated preset");
        *cfg = next;
        Ok(saved)
    })?;
    Ok(json_ok(preset_view_for(&updated, &caller)))
}

async fn delete_credential(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    handle.update_config(|cfg| {
        if !cfg.credentials.iter().any(|p| p.key == key) {
            return Err(ApiError::not_found(format!("凭据预设 {key} 不存在")));
        }
        if preset_in_use(cfg, &key) {
            return Err(ApiError::conflict("该凭据预设仍被连接引用，无法删除"));
        }
        cfg.credentials.retain(|p| p.key != key);
        Ok(())
    })?;
    Ok(json_ok(json!({ "ok": true })))
}

async fn batch_delete_credentials(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Json(body): Json<KeysBody>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    validate_batch_keys(&body.keys)?;
    handle.update_config(|cfg| {
        for key in &body.keys {
            if preset_in_use(cfg, key) {
                return Err(ApiError::conflict(format!(
                    "凭据预设 {key} 仍被连接引用，无法删除"
                )));
            }
        }
        let set: std::collections::HashSet<&str> = body.keys.iter().map(String::as_str).collect();
        cfg.credentials.retain(|p| !set.contains(p.key.as_str()));
        Ok(())
    })?;
    Ok(json_ok(json!({ "ok": true })))
}

async fn order_credentials(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Json(body): Json<KeysBody>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    validate_batch_keys(&body.keys)?;
    handle.update_config(|cfg| {
        let mut by_key: std::collections::HashMap<String, Preset> = cfg
            .credentials
            .drain(..)
            .map(|p| (p.key.clone(), p))
            .collect();
        let mut ordered = Vec::with_capacity(by_key.len());
        for k in &body.keys {
            if let Some(p) = by_key.remove(k) {
                ordered.push(p);
            }
        }
        let mut rest: Vec<_> = by_key.into_values().collect();
        rest.sort_by(|a, b| a.key.cmp(&b.key));
        ordered.extend(rest);
        cfg.credentials = ordered;
        Ok(())
    })?;
    Ok(json_ok(json!({ "ok": true })))
}

async fn copy_credential(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    require_two_fa_if_enabled(&handle, &caller)?;
    let copied = handle.update_config(|cfg| {
        let Some(orig) = cfg.credentials.iter().find(|p| p.key == key).cloned() else {
            return Err(ApiError::not_found(format!("凭据预设 {key} 不存在")));
        };
        let mut dup = orig;
        dup.key = random_id();
        dup.name = format!("{} 副本", dup.name);
        cfg.credentials.push(dup.clone());
        Ok(dup)
    })?;
    Ok((
        StatusCode::CREATED,
        json_ok(preset_view_for(&copied, &caller)),
    )
        .into_response())
}

async fn get_credential_secrets(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    require_two_fa_if_enabled(&handle, &caller)?;
    let cfg = handle.config_snapshot();
    let preset = cfg
        .credentials
        .iter()
        .find(|p| p.key == key)
        .ok_or_else(|| ApiError::not_found(format!("凭据预设 {key} 不存在")))?;
    Ok(json_ok(PresetSecrets::of(preset)))
}

// =========================================================================
// Global Shortcuts / Shells / Split Layout
// =========================================================================

async fn get_global_shortcuts(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
) -> Response {
    let cfg = handle.config_snapshot();
    json_ok(shortcuts_for(&cfg.global_shortcuts, &caller))
}

async fn put_global_shortcuts(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Json(shortcuts): Json<Vec<Shortcut>>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    let cleaned = handle.update_config(|cfg| {
        cfg.global_shortcuts = clean_shortcuts(shortcuts);
        Ok(cfg.global_shortcuts.clone())
    })?;
    Ok(json_ok(cleaned))
}

async fn get_shells(State(handle): State<Arc<WebTerminalHandle>>) -> Response {
    let cfg = handle.config_snapshot();
    if !cfg.settings.allow_local_shell {
        return json_ok(Vec::<String>::new());
    }
    json_ok(local_shell::available_shells())
}

async fn get_split_layout(State(handle): State<Arc<WebTerminalHandle>>) -> Response {
    let cfg = handle.config_snapshot();
    json_ok(cfg.split_layout.unwrap_or(Value::Null))
}

async fn put_split_layout(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Json(layout): Json<Value>,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    let serialized = serde_json::to_vec(&layout).unwrap_or_default();
    if serialized.len() > limits::SPLIT_LAYOUT_MAX_BYTES {
        return Err(ApiError::bad_request("分栏布局数据过大"));
    }
    handle.update_config(|cfg| {
        cfg.split_layout = Some(layout.clone());
        Ok(())
    })?;
    Ok(json_ok(layout))
}

async fn delete_split_layout(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
) -> Result<Response, ApiError> {
    require_write(&caller)?;
    handle.update_config(|cfg| {
        cfg.split_layout = None;
        Ok(())
    })?;
    Ok(json_ok(json!({ "ok": true })))
}

// =========================================================================
// Security (Agreement & TOTP 2FA — login session only for mutations)
// =========================================================================

async fn get_security(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
) -> Response {
    let cfg = handle.config_snapshot();
    let verified = !cfg.security.two_fa_enabled || handle.two_fa.is_verified(&caller.actor_id);
    json_ok(SecurityView {
        agreement_accepted: cfg.security.agreement_accepted,
        agreement_accepted_at: cfg.security.agreement_accepted_at,
        two_fa_enabled: cfg.security.two_fa_enabled,
        two_fa_verified: verified,
    })
}

async fn accept_agreement(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
) -> Result<Response, ApiError> {
    require_session(&caller)?;
    let now_rfc3339 = time::OffsetDateTime::from_unix_timestamp(handle.two_fa.now())
        .ok()
        .and_then(|dt| {
            dt.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default();
    handle.update_config(|cfg| {
        cfg.security.agreement_accepted = true;
        cfg.security.agreement_accepted_at = Some(now_rfc3339.clone());
        Ok(())
    })?;
    Ok(json_ok(json!({
        "agreementAccepted": true,
        "agreementAcceptedAt": now_rfc3339,
    })))
}

async fn setup_two_fa(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
) -> Result<Response, ApiError> {
    require_session(&caller)?;
    let secret = generate_totp_secret();
    let uri = otpauth_uri(&secret, "FerrumGate", "WebTerminal");
    handle.update_config(|cfg| {
        cfg.security.two_fa_pending_secret = secret.clone();
        Ok(())
    })?;
    Ok(json_ok(TwoFaSetupResponse {
        secret,
        otpauth_uri: uri,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TwoFaCodeBody {
    code: String,
}

async fn enable_two_fa(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Json(body): Json<TwoFaCodeBody>,
) -> Result<Response, ApiError> {
    require_session(&caller)?;
    let now = handle.two_fa.now();
    handle.update_config(|cfg| {
        let secret = cfg.security.two_fa_pending_secret.clone();
        if secret.is_empty() {
            return Err(ApiError::bad_request("请先初始化两步验证密钥（setup）"));
        }
        if !verify_totp(&secret, &body.code, now) {
            return Err(ApiError::bad_request("验证码无效"));
        }
        cfg.security.two_fa_secret = secret;
        cfg.security.two_fa_pending_secret.clear();
        cfg.security.two_fa_enabled = true;
        Ok(())
    })?;
    handle.two_fa.mark_verified(&caller.actor_id);
    Ok(json_ok(json!({ "twoFaEnabled": true })))
}

async fn disable_two_fa(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Json(body): Json<TwoFaCodeBody>,
) -> Result<Response, ApiError> {
    require_session(&caller)?;
    let cfg = handle.config_snapshot();
    if !cfg.security.two_fa_enabled {
        return Ok(json_ok(json!({ "twoFaEnabled": false })));
    }
    match handle
        .two_fa
        .verify(&caller.actor_id, &cfg.security.two_fa_secret, &body.code)
    {
        VerifyOutcome::Ok => {}
        VerifyOutcome::Invalid { remaining_attempts } => {
            return Err(ApiError::bad_request(format!(
                "验证码无效，剩余尝试次数：{remaining_attempts}"
            )));
        }
        VerifyOutcome::Locked { retry_after_secs } => {
            return Err(ApiError::too_many(format!(
                "验证失败次数过多，请 {retry_after_secs} 秒后重试"
            )));
        }
    }
    handle.update_config(|cfg| {
        cfg.security.two_fa_enabled = false;
        cfg.security.two_fa_secret.clear();
        cfg.security.two_fa_pending_secret.clear();
        Ok(())
    })?;
    handle.two_fa.clear_all();
    Ok(json_ok(json!({ "twoFaEnabled": false })))
}

async fn check_two_fa(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
) -> Result<Response, ApiError> {
    require_session(&caller)?;
    let cfg = handle.config_snapshot();
    let verified = !cfg.security.two_fa_enabled || handle.two_fa.is_verified(&caller.actor_id);
    Ok(json_ok(json!({
        "required": cfg.security.two_fa_enabled,
        "verified": verified,
    })))
}

async fn verify_two_fa(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Json(body): Json<TwoFaCodeBody>,
) -> Result<Response, ApiError> {
    require_session(&caller)?;
    let cfg = handle.config_snapshot();
    if !cfg.security.two_fa_enabled {
        return Ok(json_ok(json!({ "verified": true })));
    }
    match handle
        .two_fa
        .verify(&caller.actor_id, &cfg.security.two_fa_secret, &body.code)
    {
        VerifyOutcome::Ok => Ok(json_ok(json!({ "verified": true }))),
        VerifyOutcome::Invalid { remaining_attempts } => Err(ApiError::bad_request(format!(
            "验证码无效，剩余尝试次数：{remaining_attempts}"
        ))),
        VerifyOutcome::Locked { retry_after_secs } => Err(ApiError::too_many(format!(
            "验证失败次数过多，请 {retry_after_secs} 秒后重试"
        ))),
    }
}

// =========================================================================
// Settings (PUT requires login session per WP-61 §3.3)
// =========================================================================

async fn get_settings(State(handle): State<Arc<WebTerminalHandle>>) -> Response {
    json_ok(handle.config_snapshot().settings)
}

async fn put_settings(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Json(incoming): Json<Settings>,
) -> Result<Response, ApiError> {
    require_session(&caller)?;
    let saved = handle.update_config(|cfg| {
        let mut next = cfg.clone();
        next.settings = incoming;
        let next = normalize(next);
        let settings = next.settings.clone();
        *cfg = next;
        Ok(settings)
    })?;
    handle
        .sessions
        .set_caps(crate::session::Caps::from_settings(&saved));
    Ok(json_ok(saved))
}

// =========================================================================
// SFTP / File Management
// =========================================================================

async fn open_sftp_backend(
    handle: &WebTerminalHandle,
    caller: &CallerContext,
    key: &str,
) -> Result<crate::sftp::FileBackend, ApiError> {
    require_write(caller)?;
    require_two_fa_if_enabled(handle, caller)?;
    let cfg = handle.config_snapshot();
    let conn = cfg
        .connections
        .iter()
        .find(|c| c.key == key)
        .cloned()
        .ok_or_else(|| ApiError::not_found(format!("连接 {key} 不存在")))?;
    let (backend, updated_hk) =
        crate::sftp::resolve_backend(&handle.sftp_pool, &conn, &cfg.credentials, &cfg.settings)
            .await
            .map_err(ApiError::from)?;
    if let Some(hk) = updated_hk {
        handle.record_host_key(&conn.key, hk);
    }
    Ok(backend)
}

fn extract_path_param(uri: &Uri) -> String {
    let Some(q) = uri.query() else {
        return "/".to_owned();
    };
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == "path"
        {
            let decoded = percent_decode(v);
            return if decoded.is_empty() {
                "/".to_owned()
            } else {
                decoded
            };
        }
    }
    "/".to_owned()
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

async fn sftp_list(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let path = extract_path_param(&uri);
    let backend = open_sftp_backend(&handle, &caller, &key).await?;
    let entries = backend.list(&path).await.map_err(ApiError::from)?;
    Ok(json_ok(entries))
}

async fn sftp_read(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let path = extract_path_param(&uri);
    let backend = open_sftp_backend(&handle, &caller, &key).await?;
    let preview = backend.read_text(&path).await.map_err(ApiError::from)?;
    Ok(json_ok(preview))
}

async fn sftp_download(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let path = extract_path_param(&uri);
    let backend = open_sftp_backend(&handle, &caller, &key).await?;
    let data = backend.read_bytes(&path).await.map_err(ApiError::from)?;
    let total = data.len();
    let filename = path
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("download");
    let disp = format!("attachment; filename=\"{}\"", filename.replace('"', "_"));

    if let Some(range_val) = headers.get(RANGE).and_then(|v| v.to_str().ok())
        && let Some((start, end)) = parse_byte_range(range_val, total)
    {
        let slice = data[start..=end].to_vec();
        let mut resp = (StatusCode::PARTIAL_CONTENT, slice).into_response();
        let hdrs = resp.headers_mut();
        hdrs.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        hdrs.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if let Ok(val) = HeaderValue::from_str(&format!("bytes {start}-{end}/{total}")) {
            hdrs.insert(CONTENT_RANGE, val);
        }
        if let Ok(val) = HeaderValue::from_str(&disp) {
            hdrs.insert(CONTENT_DISPOSITION, val);
        }
        return Ok(resp);
    }

    let mut resp = (StatusCode::OK, data).into_response();
    let hdrs = resp.headers_mut();
    hdrs.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    hdrs.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(val) = HeaderValue::from_str(&disp) {
        hdrs.insert(CONTENT_DISPOSITION, val);
    }
    Ok(resp)
}

fn parse_byte_range(header: &str, total: usize) -> Option<(usize, usize)> {
    if total == 0 {
        return None;
    }
    let spec = header.trim().strip_prefix("bytes=")?;
    let (start_s, end_s) = spec.split_once('-')?;
    let start: usize = start_s.parse().ok()?;
    let end: usize = if end_s.is_empty() {
        total - 1
    } else {
        end_s.parse::<usize>().ok()?.min(total - 1)
    };
    if start <= end && start < total {
        Some((start, end))
    } else {
        None
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WriteFileBody {
    path: String,
    content: String,
}

async fn sftp_write(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    Json(body): Json<WriteFileBody>,
) -> Result<Response, ApiError> {
    let backend = open_sftp_backend(&handle, &caller, &key).await?;
    backend
        .write_bytes(&body.path, body.content.as_bytes())
        .await
        .map_err(ApiError::from)?;
    Ok(json_ok(json!({ "ok": true })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct UploadFileReq {
    path: String,
    #[serde(default)]
    data_base64: Option<String>,
    #[serde(default)]
    content: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct UploadBody {
    dir: String,
    files: Vec<UploadFileReq>,
}

async fn sftp_upload(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    Json(body): Json<UploadBody>,
) -> Result<Response, ApiError> {
    let backend = open_sftp_backend(&handle, &caller, &key).await?;
    let mut items = Vec::with_capacity(body.files.len());
    for f in body.files {
        let data = if let Some(b64) = f.data_base64 {
            base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .map_err(|e| ApiError::bad_request(format!("base64 解码失败：{e}")))?
        } else if let Some(text) = f.content {
            text.into_bytes()
        } else {
            Vec::new()
        };
        items.push(UploadItem { path: f.path, data });
    }
    let count = backend
        .upload(&body.dir, &items)
        .await
        .map_err(ApiError::from)?;
    Ok(json_ok(json!({ "uploaded": count })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PathBody {
    path: String,
}

async fn sftp_mkdir(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    Json(body): Json<PathBody>,
) -> Result<Response, ApiError> {
    let backend = open_sftp_backend(&handle, &caller, &key).await?;
    backend.mkdir(&body.path).await.map_err(ApiError::from)?;
    Ok(json_ok(json!({ "ok": true })))
}

async fn sftp_touch(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    Json(body): Json<PathBody>,
) -> Result<Response, ApiError> {
    let backend = open_sftp_backend(&handle, &caller, &key).await?;
    backend.touch(&body.path).await.map_err(ApiError::from)?;
    Ok(json_ok(json!({ "ok": true })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RenameBody {
    from: String,
    to: String,
}

async fn sftp_rename(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    Json(body): Json<RenameBody>,
) -> Result<Response, ApiError> {
    let backend = open_sftp_backend(&handle, &caller, &key).await?;
    backend
        .rename(&body.from, &body.to)
        .await
        .map_err(ApiError::from)?;
    Ok(json_ok(json!({ "ok": true })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CopyBody {
    from: String,
    to_dir: String,
}

async fn sftp_copy(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    Json(body): Json<CopyBody>,
) -> Result<Response, ApiError> {
    let backend = open_sftp_backend(&handle, &caller, &key).await?;
    let dest = backend
        .copy(&body.from, &body.to_dir)
        .await
        .map_err(ApiError::from)?;
    Ok(json_ok(json!({ "path": dest })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RemoveBody {
    paths: Vec<String>,
}

async fn sftp_remove(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    Json(body): Json<RemoveBody>,
) -> Result<Response, ApiError> {
    let backend = open_sftp_backend(&handle, &caller, &key).await?;
    backend.remove(&body.paths).await.map_err(ApiError::from)?;
    Ok(json_ok(json!({ "ok": true })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ChmodBody {
    path: String,
    mode: u32,
    #[serde(default)]
    recursive: bool,
}

async fn sftp_chmod(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    Json(body): Json<ChmodBody>,
) -> Result<Response, ApiError> {
    let backend = open_sftp_backend(&handle, &caller, &key).await?;
    backend
        .chmod(&body.path, body.mode, body.recursive)
        .await
        .map_err(ApiError::from)?;
    Ok(json_ok(json!({ "ok": true })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CompressBody {
    paths: Vec<String>,
    dest: String,
    #[serde(default)]
    format: Option<ArchiveFormat>,
}

async fn sftp_compress(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    Json(body): Json<CompressBody>,
) -> Result<Response, ApiError> {
    let backend = open_sftp_backend(&handle, &caller, &key).await?;
    let format = body
        .format
        .or_else(|| ArchiveFormat::from_path(&body.dest))
        .ok_or_else(|| ApiError::bad_request("无法识别压缩格式（支持 zip / tar.gz）"))?;
    backend
        .compress(&body.paths, &body.dest, format)
        .await
        .map_err(ApiError::from)?;
    Ok(json_ok(json!({ "ok": true })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DecompressBody {
    path: String,
    dest_dir: String,
}

async fn sftp_decompress(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    Json(body): Json<DecompressBody>,
) -> Result<Response, ApiError> {
    let backend = open_sftp_backend(&handle, &caller, &key).await?;
    let extracted = backend
        .decompress(&body.path, &body.dest_dir)
        .await
        .map_err(ApiError::from)?;
    Ok(json_ok(json!({ "extracted": extracted })))
}

async fn sftp_preview_archive_get(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let path = extract_path_param(&uri);
    let backend = open_sftp_backend(&handle, &caller, &key).await?;
    let preview = backend
        .preview_archive(&path)
        .await
        .map_err(ApiError::from)?;
    Ok(json_ok(preview))
}

async fn sftp_preview_archive_post(
    State(handle): State<Arc<WebTerminalHandle>>,
    ExtractedCaller(caller): ExtractedCaller,
    Path(key): Path<String>,
    Json(body): Json<PathBody>,
) -> Result<Response, ApiError> {
    let backend = open_sftp_backend(&handle, &caller, &key).await?;
    let preview = backend
        .preview_archive(&body.path)
        .await
        .map_err(ApiError::from)?;
    Ok(json_ok(preview))
}
