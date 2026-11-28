//! Management HTTP routes for WebDAV (`/api/webdav/*`) and shared file users
//! (`/api/fileusers`, `/api/fileusers/secrets`, WP-63 §4).

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use fg_files::{FileUsers, FileUsersStore, SaveError};
use serde_json::json;
use tokio::sync::RwLock;

use crate::{model::Settings, runtime::WebDavRuntime, validate};

/// Persistence callback saving `webdav.json`.
pub type PersistFn = Arc<dyn Fn(&Settings) -> anyhow::Result<()> + Send + Sync>;

/// Shared state for WebDAV management routes.
pub struct RoutesState {
    pub settings: Arc<RwLock<Settings>>,
    pub shared_users: Arc<FileUsersStore>,
    pub runtime: Arc<WebDavRuntime>,
    pub persist: PersistFn,
    pub bcrypt_cost: u32,
}

/// Mounts `/api/webdav/*` management endpoints onto `router`:
/// - `GET  /api/webdav/settings`
/// - `PUT  /api/webdav/settings`
/// - `GET  /api/webdav/settings/secrets`
/// - `GET  /api/webdav/status`
/// - `POST /api/webdav/restart`
/// - `GET  /api/webdav/shared-users` (deprecated alias for `/api/fileusers`)
/// - `PUT  /api/webdav/shared-users` (deprecated alias for `/api/fileusers`)
///
/// Combined with `fg-admin`'s 4 standard module log endpoints, this satisfies
/// WP-63's 9-operation WebDAV API parity.
pub fn mount(router: Router, state: Arc<RoutesState>) -> Router {
    let s_get = Arc::clone(&state);
    let s_put = Arc::clone(&state);
    let s_sec = Arc::clone(&state);
    let s_stat = Arc::clone(&state);
    let s_restart = Arc::clone(&state);
    let fu_get = Arc::clone(&state.shared_users);
    let fu_put = Arc::clone(&state.shared_users);

    router
        .route(
            "/api/webdav/settings",
            get(move || async move { get_settings(s_get).await })
                .put(move |body: Bytes| async move { put_settings(s_put, body).await }),
        )
        .route(
            "/api/webdav/settings/secrets",
            get(move || async move { get_settings_secrets(s_sec).await }),
        )
        .route(
            "/api/webdav/status",
            get(move || async move { get_status(s_stat).await }),
        )
        .route(
            "/api/webdav/restart",
            post(move || async move { restart(s_restart).await }),
        )
        .route(
            "/api/webdav/shared-users",
            get(move || async move { get_fileusers(fu_get).await })
                .put(move |body: Bytes| async move { put_fileusers(fu_put, body).await }),
        )
}

/// Mounts the standalone shared file-users management routes (permission domain
/// `fileusers`, WP-63 §4):
/// - `GET /api/fileusers`
/// - `PUT /api/fileusers`
/// - `GET /api/fileusers/secrets`
pub fn mount_fileusers(router: Router, shared_users: Arc<FileUsersStore>) -> Router {
    let get_store = Arc::clone(&shared_users);
    let put_store = Arc::clone(&shared_users);
    let sec_store = shared_users;

    router
        .route(
            "/api/fileusers",
            get(move || async move { get_fileusers(get_store).await })
                .put(move |body: Bytes| async move { put_fileusers(put_store, body).await }),
        )
        .route(
            "/api/fileusers/secrets",
            get(move || async move { get_fileusers_secrets(sec_store).await }),
        )
}

async fn get_settings(state: Arc<RoutesState>) -> Response {
    let settings = state.settings.read().await.clone();
    let masked = validate::mask_settings(&settings);
    let status = state.runtime.status();
    let mut val = serde_json::to_value(&masked).unwrap_or_else(|_| json!({}));
    if let Some(obj) = val.as_object_mut() {
        obj.insert("status".to_string(), json!(status));
    }
    Json(val).into_response()
}

async fn put_settings(state: Arc<RoutesState>, body: Bytes) -> Response {
    let mut submitted: Settings = match serde_json::from_slice(&body) {
        Ok(s) => s,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("invalid request payload: {err}") })),
            )
                .into_response();
        }
    };

    let mut guard = state.settings.write().await;
    if let Err(problems) =
        validate::merge_and_hash_passwords(&mut submitted, &guard, state.bcrypt_cost)
    {
        return problems_response("invalid webdav configuration", problems);
    }

    let usable_shared = state.shared_users.usable_user_count();
    let problems = validate::validate_settings(&submitted, usable_shared, true);
    if !problems.is_empty() {
        return problems_response("invalid webdav configuration", problems);
    }

    let persist = Arc::clone(&state.persist);
    let to_save = submitted.clone();
    let saved = tokio::task::spawn_blocking(move || persist(&to_save)).await;
    match saved {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::warn!(%err, "failed to persist webdav.json");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "failed to persist webdav configuration" })),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "configuration persistence task panicked" })),
            )
                .into_response();
        }
    }

    *guard = submitted.clone();
    drop(guard);

    if let Err(err) = state.runtime.apply(submitted).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response();
    }
    Json(json!({ "ok": true })).into_response()
}

async fn get_settings_secrets(state: Arc<RoutesState>) -> Response {
    let settings = state.settings.read().await;
    let users: Vec<_> = settings
        .users
        .iter()
        .map(|u| {
            json!({
                "name": u.name,
                "password": u.password,
                "hashed": fg_files::is_bcrypt_hash(&u.password),
            })
        })
        .collect();
    Json(json!({ "users": users })).into_response()
}

async fn get_status(state: Arc<RoutesState>) -> Response {
    Json(state.runtime.status()).into_response()
}

async fn restart(state: Arc<RoutesState>) -> Response {
    match state.runtime.restart().await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

async fn get_fileusers(store: Arc<FileUsersStore>) -> Response {
    Json(store.view()).into_response()
}

async fn get_fileusers_secrets(store: Arc<FileUsersStore>) -> Response {
    Json(store.secrets()).into_response()
}

async fn put_fileusers(store: Arc<FileUsersStore>, body: Bytes) -> Response {
    let incoming: FileUsers = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("invalid fileusers payload: {err}") })),
            )
                .into_response();
        }
    };

    let res = tokio::task::spawn_blocking(move || store.save_config(incoming)).await;
    match res {
        Ok(Ok(())) => Json(json!({ "ok": true })).into_response(),
        Ok(Err(SaveError::Validation(problems))) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid fileusers configuration",
                "problems": problems,
            })),
        )
            .into_response(),
        Ok(Err(SaveError::RequiredByService(services))) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "cannot remove last usable shared user while required by active services",
                "services": services,
            })),
        )
            .into_response(),
        Ok(Err(SaveError::Persist(msg))) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": msg })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "fileusers save task failed" })),
        )
            .into_response(),
    }
}

fn problems_response(message: &str, problems: Vec<validate::Problem>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": message,
            "problems": problems,
        })),
    )
        .into_response()
}
