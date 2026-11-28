//! NetBird management routes (WP-45 §4), served with plain axum while
//! mirroring the fg-admin collection contract, exactly like the fg-cron /
//! fg-guard module routes.
//!
//! Endpoints (permission domain `netbird`; the 4 generic log endpoints
//! are served by fg-admin and not mounted here — 24 module operations in
//! total, 28 including the logs):
//!
//! | Method | Path | Request | Response |
//! |---|---|---|---|
//! | GET | `/api/netbird/instances` | — | `[Instance]` (masked) |
//! | POST | `/api/netbird/instances` | `Instance` | created masked `Instance` |
//! | POST | `/api/netbird/instances-delete` | `{"keys":[…]}` | `{"removed":N}` |
//! | PUT | `/api/netbird/instances-enable` | `{"keys":[…],"enable":bool}` | `{"changed":N}` |
//! | PUT | `/api/netbird/instances-group` | `{"keys":[…],"group":"…"}` | `{"ok":true}` |
//! | PUT | `/api/netbird/instances-order` | `{"keys":[…]}` | `{"ok":true}` |
//! | PUT | `/api/netbird/instances/{key}` | `Instance` | replaced masked `Instance` |
//! | DELETE | `/api/netbird/instances/{key}` | — | `{"removed":1}` |
//! | POST | `/api/netbird/instances/{key}/copy` | `Instance` | created masked `Instance` |
//! | PUT | `/api/netbird/instances/{key}/enable` | `{"enable":bool}` | `{"ok":true}` |
//! | GET | `/api/netbird/instances/{key}/secrets` | — | `Instance` (plaintext secrets) |
//! | POST | `/api/netbird/instances/{key}/restart` | — | `{"ok":true}` |
//! | GET | `/api/netbird/instances/{key}/status` | — | runtime status + peers |
//! | POST | `/api/netbird/instances/{key}/logout` | — | `{"ok":true}` |
//! | GET | `/api/netbird/status` | — | module status (read-only snapshots) |
//! | GET | `/api/netbird/settings` | — | `ProgramSettings` |
//! | PUT | `/api/netbird/settings` | `ProgramSettings` | `ProgramSettings` |
//! | GET | `/api/netbird/install` | — | `{"stage","installed","backups"}` |
//! | POST | `/api/netbird/install` | `{"version"?}` | `{"ok":true}` |
//! | POST | `/api/netbird/install/check` | — | `{"latest","installed","updateAvailable"}` |
//! | POST | `/api/netbird/install/rollback` | `{"version"}` | `{"ok":true}` |
//! | DELETE | `/api/netbird/install` | — | `{"ok":true}` |
//! | DELETE | `/api/netbird/install/backups/{id}` | — | `{"ok":true}` |
//! | POST | `/api/netbird/reset` | — | `{"ok":true}` |
//!
//! Secrets: list and mutation responses carry masked secrets
//! (`********`); the plaintext only leaves through the `secrets`
//! endpoint. The settings endpoints must be mounted behind the
//! fg-admin session-only guard (WP-45 §8: the program path is an
//! arbitrary-program execution entry); no auth is applied here.
//!
//! Authentication is NOT performed here: routes are meant to be mounted
//! under the management router whose authorize layer maps
//! `/api/netbird/…` to domain `netbird` (GET → `netbird:read`,
//! every mutation → `netbird:write`).

use std::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::{Path, rejection::PathRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::RwLock;

use crate::{
    model::{FileConfig, Instance, ProgramSettings, limits},
    runtime::Runtime,
    validate::{self, Problem},
};

/// Writes the whole [`FileConfig`] to `netbird.json`.
pub type PersistFn = Arc<dyn Fn(&FileConfig) -> anyhow::Result<()> + Send + Sync>;

/// Shared state behind the management routes.
pub struct RoutesState {
    pub config: Arc<RwLock<FileConfig>>,
    pub persist: PersistFn,
    pub on_change: Arc<dyn Fn() + Send + Sync>,
    pub runtime: Arc<Runtime>,
}

pub fn mount(router: axum::Router, state: Arc<RoutesState>) -> axum::Router {
    let (list, create) = (state.clone(), state.clone());
    let (replace, remove) = (state.clone(), state.clone());
    let (copy, enable) = (state.clone(), state.clone());
    let (restart, status) = (state.clone(), state.clone());
    let (logout, secrets) = (state.clone(), state.clone());
    let (batch_delete, batch_enable) = (state.clone(), state.clone());
    let (group, order) = (state.clone(), state.clone());
    let (module_status, settings_get) = (state.clone(), state.clone());
    let (settings_put, install_get) = (state.clone(), state.clone());
    let (install_post, install_check) = (state.clone(), state.clone());
    let (install_rollback_state, install_delete) = (state.clone(), state.clone());
    let (backup_delete, reset_state) = (state.clone(), state);
    router
        .route(
            "/api/netbird/instances",
            get(move || async move { instances_list(list).await })
                .post(move |body: Bytes| async move { instances_create(create, body).await }),
        )
        .route(
            "/api/netbird/instances/{key}",
            put(move |path: PathResult, body: Bytes| async move {
                instances_update(replace, path, body).await
            })
            .delete(move |path: PathResult| async move { instances_remove(remove, path).await }),
        )
        .route(
            "/api/netbird/instances/{key}/copy",
            post(move |path: PathResult, body: Bytes| async move {
                instances_copy(copy, path, body).await
            }),
        )
        .route(
            "/api/netbird/instances/{key}/enable",
            put(move |path: PathResult, body: Bytes| async move {
                instances_enable(enable, path, body).await
            }),
        )
        .route(
            "/api/netbird/instances/{key}/secrets",
            get(move |path: PathResult| async move { instances_secrets(secrets, path).await }),
        )
        .route(
            "/api/netbird/instances/{key}/restart",
            post(move |path: PathResult| async move { instance_restart(restart, path).await }),
        )
        .route(
            "/api/netbird/instances/{key}/status",
            get(move |path: PathResult| async move { instance_status(status, path).await }),
        )
        .route(
            "/api/netbird/instances/{key}/logout",
            post(move |path: PathResult| async move { instance_logout(logout, path).await }),
        )
        .route(
            "/api/netbird/instances-delete",
            post(move |body: Bytes| async move { instances_batch_delete(batch_delete, body).await }),
        )
        .route(
            "/api/netbird/instances-enable",
            put(move |body: Bytes| async move {
                instances_batch_enable(batch_enable, body).await
            }),
        )
        .route(
            "/api/netbird/instances-group",
            put(move |body: Bytes| async move { instances_group(group, body).await }),
        )
        .route(
            "/api/netbird/instances-order",
            put(move |body: Bytes| async move { instances_order(order, body).await }),
        )
        .route(
            "/api/netbird/status",
            get(move || async move { module_status_view(module_status).await }),
        )
        .route(
            "/api/netbird/settings",
            get(move || async move { settings_view(settings_get).await })
                .put(move |body: Bytes| async move { settings_save(settings_put, body).await }),
        )
        .route(
            "/api/netbird/install",
            get(move || async move { install_view(install_get).await })
                .post(move |body: Bytes| async move { install_start(install_post, body).await })
                .delete(move || async move { install_uninstall(install_delete).await }),
        )
        .route(
            "/api/netbird/install/check",
            post(move || async move { install_check_view(install_check).await }),
        )
        .route(
            "/api/netbird/install/rollback",
            post(move |body: Bytes| async move {
                install_rollback(install_rollback_state, body).await
            }),
        )
        .route(
            "/api/netbird/install/backups/{id}",
            delete(move |path: PathResult| async move {
                install_backup_delete(backup_delete, path).await
            }),
        )
        .route(
            "/api/netbird/reset",
            post(move || async move { reset(reset_state).await }),
        )
}

type PathResult = Result<Path<String>, PathRejection>;

enum Failure {
    Api(StatusCode, String),
    Problems(Vec<Problem>),
}

impl From<Failure> for Response {
    fn from(failure: Failure) -> Response {
        match failure {
            Failure::Api(status, message) => {
                (status, Json(json!({ "error": message }))).into_response()
            }
            Failure::Problems(problems) => (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid netbird configuration",
                    "problems": problems
                        .iter()
                        .map(|problem| json!({"field": problem.field, "reason": problem.reason}))
                        .collect::<Vec<_>>(),
                })),
            )
                .into_response(),
        }
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        self.into()
    }
}

type Change<T> = Result<(T, bool), Failure>;

/// Serializes writers, applies the change to a candidate, persists the
/// normalized candidate before publishing it, and notifies afterwards.
#[allow(clippy::result_large_err)]
async fn mutate<T>(
    state: Arc<RoutesState>,
    change: impl FnOnce(&mut FileConfig) -> Change<T> + Send,
) -> Result<T, Response> {
    let mut guard = state.config.write().await;
    let mut candidate = guard.clone();
    let (value, changed) = change(&mut candidate).map_err(Response::from)?;
    if changed {
        let persist = state.persist.clone();
        let saved = candidate.clone();
        tokio::task::spawn_blocking(move || persist(&saved))
            .await
            .map_err(|_| internal())?
            .map_err(|error| {
                tracing::warn!(%error, "persisting netbird.json failed");
                internal()
            })?;
        *guard = candidate;
        drop(guard);
        (state.on_change)();
        return Ok(value);
    }
    drop(guard);
    Ok(value)
}

fn internal() -> Failure {
    Failure::Api(
        StatusCode::INTERNAL_SERVER_ERROR,
        "configuration operation failed".into(),
    )
}

fn decode_error() -> Response {
    Failure::Api(StatusCode::BAD_REQUEST, "invalid JSON body".into()).into_response()
}

/// Normalize → validate → conflict check. A validation problem or a
/// resource conflict rejects the whole candidate with a problem list. The
/// conflict check uses the runtime's effective socket / state-dir paths.
fn settle(state: &RoutesState, config: &mut FileConfig) -> Result<(), Failure> {
    *config = validate::normalize(std::mem::take(config));
    let mut problems = validate::validate(config);
    problems.extend(validate::warnings(config));
    let dir_of = |instance: &Instance| state.runtime.effective_state_dir(instance);
    for conflict in validate::conflicts(config.instances.as_slice(), &dir_of) {
        problems.push(Problem {
            field: "instances".into(),
            reason: crate::runtime::describe_conflict(&conflict),
        });
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(Failure::Problems(problems))
    }
}

fn item_key(path: PathResult) -> Result<String, Failure> {
    match path {
        Ok(Path(key)) if valid_key(&key) => Ok(key),
        _ => Err(Failure::Api(
            StatusCode::BAD_REQUEST,
            "invalid item key".into(),
        )),
    }
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key != "batch-delete"
        && key != "backups"
        && key.len() <= 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn batch_keys(mut keys: Vec<String>) -> Result<Vec<String>, Failure> {
    if keys.is_empty() || keys.len() > 500 || !keys.iter().all(|key| valid_key(key)) {
        return Err(Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys".into(),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    keys.retain(|key| seen.insert(key.clone()));
    Ok(keys)
}

fn locate(instances: &[Instance], key: &str) -> Result<usize, Failure> {
    instances
        .iter()
        .position(|instance| instance.key == key)
        .ok_or_else(|| Failure::Api(StatusCode::NOT_FOUND, "item not found".into()))
}

/// 12 lowercase hex characters, unique within the collection.
fn random_key(instances: &[Instance]) -> Result<String, Failure> {
    for _ in 0..8 {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes[2..]).map_err(|_| {
            Failure::Api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key generation failed".into(),
            )
        })?;
        let key = format!("{:012x}", u64::from_be_bytes(bytes));
        if !instances.iter().any(|instance| instance.key == key) {
            return Ok(key);
        }
    }
    Err(Failure::Api(
        StatusCode::INTERNAL_SERVER_ERROR,
        "unable to generate a unique instance key".into(),
    ))
}

fn masked_view(instance: Instance) -> Json<Instance> {
    Json(instance.masked())
}

async fn instances_list(state: Arc<RoutesState>) -> Response {
    let config = state.config.read().await;
    let views: Vec<Instance> = config
        .instances
        .clone()
        .into_iter()
        .map(Instance::masked)
        .collect();
    Json(views).into_response()
}

async fn instances_create(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(instance) = serde_json::from_slice::<Instance>(&body) else {
        return decode_error();
    };
    match mutate(Arc::clone(&state), move |config| {
        let mut instance = instance;
        if !valid_key(&instance.key) || config.instances.iter().any(|row| row.key == instance.key) {
            instance.key = random_key(&config.instances)?;
        }
        config.instances.push(instance);
        settle(&state, config)?;
        let created = config.instances.last().cloned().expect("just pushed");
        Ok((masked_view(created), true))
    })
    .await
    {
        Ok(view) => view.into_response(),
        Err(response) => response,
    }
}

async fn instances_copy(state: Arc<RoutesState>, path: PathResult, body: Bytes) -> Response {
    let Ok(instance) = serde_json::from_slice::<Instance>(&body) else {
        return decode_error();
    };
    let Ok(source) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    match mutate(Arc::clone(&state), move |config| {
        let index = locate(&config.instances, &source)?;
        let mut instance = instance;
        // Copies get a fresh key and start disabled until enabled
        // deliberately (conflicts are checked on enable).
        instance.key = random_key(&config.instances)?;
        instance.enable = false;
        config.instances.insert(index + 1, instance);
        settle(&state, config)?;
        let created = config.instances[index + 1].clone();
        Ok((masked_view(created), true))
    })
    .await
    {
        Ok(view) => view.into_response(),
        Err(response) => response,
    }
}

async fn instances_update(state: Arc<RoutesState>, path: PathResult, body: Bytes) -> Response {
    let Ok(mut instance) = serde_json::from_slice::<Instance>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    match mutate(Arc::clone(&state), move |config| {
        let index = locate(&config.instances, &key)?;
        instance.key = key.clone();
        instance.merge_masked(&config.instances[index]);
        config.instances[index] = instance;
        settle(&state, config)?;
        let replaced = config.instances[index].clone();
        Ok((masked_view(replaced), true))
    })
    .await
    {
        Ok(view) => view.into_response(),
        Err(response) => response,
    }
}

async fn instances_remove(state: Arc<RoutesState>, path: PathResult) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    match mutate(Arc::clone(&state), move |config| {
        let index = locate(&config.instances, &key)?;
        let instance = config.instances.remove(index);
        Ok((instance, true))
    })
    .await
    {
        Ok(instance) => {
            // Deletion cleanup after persist: logout (managed, default
            // dir) then remove the default dir; custom dirs are kept.
            state.runtime.delete_cleanup(&instance).await;
            Json(json!({ "removed": 1 })).into_response()
        }
        Err(response) => response,
    }
}

async fn instances_enable(state: Arc<RoutesState>, path: PathResult, body: Bytes) -> Response {
    let Ok(Enable { enable }) = serde_json::from_slice::<Enable>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    match mutate(Arc::clone(&state), move |config| {
        let index = locate(&config.instances, &key)?;
        let instance = &mut config.instances[index];
        let changed = instance.enable != enable;
        instance.enable = enable;
        settle(&state, config)?;
        Ok((Json(json!({ "ok": true })), changed))
    })
    .await
    {
        Ok(view) => view.into_response(),
        Err(response) => response,
    }
}

async fn instances_batch_delete(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Keys { keys }) = serde_json::from_slice::<Keys>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys".into(),
        )
        .into();
    };
    match mutate(Arc::clone(&state), move |config| {
        let mut removed = Vec::new();
        for key in &keys {
            let index = locate(&config.instances, key)?;
            removed.push(config.instances.remove(index));
        }
        Ok((removed, true))
    })
    .await
    {
        Ok(removed) => {
            let count = removed.len();
            for instance in removed {
                state.runtime.delete_cleanup(&instance).await;
            }
            Json(json!({ "removed": count })).into_response()
        }
        Err(response) => response,
    }
}

async fn instances_batch_enable(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(BatchEnable { keys, enable }) = serde_json::from_slice::<BatchEnable>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys".into(),
        )
        .into();
    };
    match mutate(Arc::clone(&state), move |config| {
        let mut indices = Vec::new();
        for key in &keys {
            indices.push(locate(&config.instances, key)?);
        }
        let mut changed = 0;
        for index in indices {
            let instance = &mut config.instances[index];
            if instance.enable != enable {
                instance.enable = enable;
                changed += 1;
            }
        }
        settle(&state, config)?;
        Ok((Json(json!({ "changed": changed })), changed > 0))
    })
    .await
    {
        Ok(view) => view.into_response(),
        Err(response) => response,
    }
}

async fn instances_order(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Keys { keys }) = serde_json::from_slice::<Keys>(&body) else {
        return decode_error();
    };
    match mutate(Arc::clone(&state), move |config| {
        if keys.len() != config.instances.len() {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                "order must include every item once".into(),
            ));
        }
        let Some(indices) = find_indices(&config.instances, &keys) else {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                "order contains an unknown or duplicate key".into(),
            ));
        };
        let unchanged = indices.iter().enumerate().all(|(index, &old)| index == old);
        if unchanged {
            return Ok((Json(json!({ "ok": true })), false));
        }
        let mut destination = vec![0; indices.len()];
        for (new, old) in indices.into_iter().enumerate() {
            destination[old] = new;
        }
        for index in 0..destination.len() {
            while destination[index] != index {
                let new = destination[index];
                config.instances.swap(index, new);
                destination.swap(index, new);
            }
        }
        Ok((Json(json!({ "ok": true })), true))
    })
    .await
    {
        Ok(view) => view.into_response(),
        Err(response) => response,
    }
}

async fn instances_group(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Group { keys, group }) = serde_json::from_slice::<Group>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys".into(),
        )
        .into();
    };
    let name = group.trim().to_owned();
    if name.chars().count() > limits::GROUP_MAX_CHARS {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            format!(
                "group name must have at most {} characters",
                limits::GROUP_MAX_CHARS
            ),
        )
        .into();
    }
    match mutate(Arc::clone(&state), move |config| {
        let mut indices = Vec::new();
        for key in &keys {
            indices.push(locate(&config.instances, key)?);
        }
        let mut changed = false;
        for index in indices {
            let field = &mut config.instances[index].group;
            if *field != name {
                field.clone_from(&name);
                changed = true;
            }
        }
        Ok((Json(json!({ "ok": true })), changed))
    })
    .await
    {
        Ok(view) => view.into_response(),
        Err(response) => response,
    }
}

/// The plaintext instance (write-permission path).
async fn instances_secrets(state: Arc<RoutesState>, path: PathResult) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let config = state.config.read().await;
    match config.instances.iter().find(|instance| instance.key == key) {
        Some(instance) => Json(instance.clone()).into_response(),
        None => Failure::Api(StatusCode::NOT_FOUND, "item not found".into()).into(),
    }
}

async fn instance_restart(state: Arc<RoutesState>, path: PathResult) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    match state.runtime.restart(&key).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(error) => {
            let message = error.to_string();
            let status = if message.contains("不存在") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::CONFLICT
            };
            Failure::Api(status, message).into()
        }
    }
}

async fn instance_status(state: Arc<RoutesState>, path: PathResult) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    match state.runtime.status(&key).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => Failure::Api(StatusCode::NOT_FOUND, error.to_string()).into(),
    }
}

/// `tailscale logout` for one instance (WP-45 §4: 退出登录).
async fn instance_logout(state: Arc<RoutesState>, path: PathResult) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    match state.runtime.logout(&key).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(error) => {
            let message = error.to_string();
            let status = if message.contains("不存在") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::CONFLICT
            };
            Failure::Api(status, message).into()
        }
    }
}

async fn module_status_view(state: Arc<RoutesState>) -> Response {
    let installer = state.runtime.installer();
    let snapshots = state.runtime.snapshot().await;
    Json(json!({
        "instances": snapshots,
        "program": program_view(&installer),
    }))
    .into_response()
}

async fn settings_view(state: Arc<RoutesState>) -> Response {
    let config = state.config.read().await;
    Json(config.settings.clone()).into_response()
}

async fn settings_save(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(settings) = serde_json::from_slice::<ProgramSettings>(&body) else {
        return decode_error();
    };
    match mutate(Arc::clone(&state), move |config| {
        config.settings = settings;
        *config = validate::normalize(std::mem::take(config));
        let problems = validate::validate(config);
        if !problems.is_empty() {
            return Err(Failure::Problems(problems));
        }
        Ok((Json(config.settings.clone()), true))
    })
    .await
    {
        Ok(view) => view.into_response(),
        Err(response) => response,
    }
}

fn program_view(installer: &Arc<fg_proc::install::Installer>) -> serde_json::Value {
    let installed = installer.installed().map(|installed| {
        json!({
            "version": installed.version,
            "at": crate::runtime::rfc3339(Some(installed.at)),
        })
    });
    let backups: Vec<serde_json::Value> = installer
        .backups()
        .iter()
        .map(|backup| {
            json!({
                "id": backup.version,
                "version": backup.version,
                "at": crate::runtime::rfc3339(Some(backup.at)),
            })
        })
        .collect();
    let stage = installer.stage().borrow().clone();
    json!({
        "installed": installed,
        "backups": backups,
        "stage": stage,
    })
}

async fn install_view(state: Arc<RoutesState>) -> Response {
    Json(program_view(&state.runtime.installer())).into_response()
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct InstallRequest {
    version: Option<String>,
}

async fn install_start(state: Arc<RoutesState>, body: Bytes) -> Response {
    let request = if body.is_empty() {
        InstallRequest { version: None }
    } else {
        match serde_json::from_slice::<InstallRequest>(&body) {
            Ok(request) => request,
            Err(_) => return decode_error(),
        }
    };
    let proxy = match download_proxy(&state).await {
        Ok(proxy) => proxy,
        Err(response) => return response,
    };
    let target = match request.version {
        Some(version) if !version.trim().is_empty() => {
            fg_proc::install::InstallTarget::Version(version.trim().to_owned())
        }
        _ => fg_proc::install::InstallTarget::Latest,
    };
    let installer = state.runtime.installer();
    let on_done = state.runtime.on_installed();
    match installer.start(target, proxy, Some(on_done)).await {
        Ok(_progress) => Json(json!({ "ok": true })).into_response(),
        Err(error) => Failure::Api(StatusCode::CONFLICT, error.to_string()).into(),
    }
}

#[allow(clippy::result_large_err)]
async fn download_proxy(
    state: &RoutesState,
) -> Result<Option<fg_proc::install::ProxyUrl>, Response> {
    let text = state.config.read().await.settings.download_proxy.clone();
    if text.trim().is_empty() {
        return Ok(None);
    }
    fg_proc::install::ProxyUrl::parse(text.trim())
        .map(Some)
        .map_err(|error| Failure::Api(StatusCode::BAD_REQUEST, error).into())
}

async fn install_check_view(state: Arc<RoutesState>) -> Response {
    let Some(fetch) = state.runtime.fetch().cloned() else {
        return Failure::Api(StatusCode::INTERNAL_SERVER_ERROR, "下载通道未配置".into()).into();
    };
    let proxy = match download_proxy(&state).await {
        Ok(proxy) => proxy,
        Err(response) => return response,
    };
    let installer = state.runtime.installer();
    let spec = installer.spec();
    match fg_proc::install::select_release(
        spec,
        &fetch,
        proxy.as_ref(),
        &fg_proc::install::InstallTarget::Latest,
    )
    .await
    {
        Ok(selected) => {
            let installed = installer.installed().map(|installed| installed.version);
            let update_available = installed
                .as_ref()
                .map(|current| !fg_proc::install::swap::version_eq(&selected.version, current))
                .unwrap_or(true);
            Json(json!({
                "latest": selected.version,
                "installed": installed,
                "updateAvailable": update_available,
            }))
            .into_response()
        }
        Err(error) => Failure::Api(StatusCode::BAD_GATEWAY, error.to_string()).into(),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RollbackRequest {
    version: String,
}

async fn install_rollback(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(RollbackRequest { version }) = serde_json::from_slice::<RollbackRequest>(&body) else {
        return decode_error();
    };
    match state.runtime.installer().rollback_to(version.trim()).await {
        Ok(installed) => {
            state.runtime.on_installed();
            Json(json!({ "ok": true, "version": installed.version })).into_response()
        }
        Err(error) => Failure::Api(StatusCode::CONFLICT, error.to_string()).into(),
    }
}

async fn install_uninstall(state: Arc<RoutesState>) -> Response {
    state.runtime.stop_all().await;
    match state.runtime.installer().uninstall().await {
        Ok(()) => {
            state.runtime.on_installed();
            Json(json!({ "ok": true })).into_response()
        }
        Err(error) => Failure::Api(StatusCode::CONFLICT, error.to_string()).into(),
    }
}

async fn install_backup_delete(state: Arc<RoutesState>, path: PathResult) -> Response {
    let Ok(id) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    match delete_backup(&state.runtime.installer(), &id) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(error) => Failure::Api(StatusCode::NOT_FOUND, error.to_string()).into(),
    }
}

/// Deletes one backup version directory under fg-proc's
/// `bin/.versions/<program>/<version>`; the id must be a safe single path
/// segment and the resolved directory must stay inside `bin/`.
fn delete_backup(installer: &Arc<fg_proc::install::Installer>, id: &str) -> anyhow::Result<()> {
    if sanitize_backup_id(id).is_empty() {
        anyhow::bail!("备份 ID 无效");
    }
    let dir = installer
        .bin_dir()
        .join(".versions")
        .join(installer.spec().name)
        .join(id);
    let dir = dir
        .canonicalize()
        .map_err(|_| anyhow::anyhow!("备份不存在"))?;
    let bin_dir = installer.bin_dir().canonicalize().ok();
    if let Some(bin_dir) = bin_dir
        && !dir.starts_with(&bin_dir)
    {
        anyhow::bail!("备份路径越界");
    }
    std::fs::remove_dir_all(&dir).map_err(|error| anyhow::anyhow!("删除备份失败：{error}"))?;
    tracing::info!(program = installer.spec().name, id, "已删除旧版本备份");
    Ok(())
}

fn sanitize_backup_id(id: &str) -> String {
    let ok = !id.is_empty()
        && id != "."
        && id != ".."
        && !id.contains('/')
        && !id.contains('\\')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'));
    if ok { id.to_owned() } else { String::new() }
}

async fn reset(state: Arc<RoutesState>) -> Response {
    match state.runtime.reset().await {
        Ok(()) => {
            (state.on_change)();
            Json(json!({ "ok": true })).into_response()
        }
        Err(error) => Failure::Api(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into(),
    }
}

fn find_indices(instances: &[Instance], keys: &[String]) -> Option<Vec<usize>> {
    let mut slots = keys
        .iter()
        .enumerate()
        .map(|(slot, key)| (key.as_str(), slot))
        .collect::<std::collections::HashMap<_, _>>();
    if slots.len() != keys.len() {
        return None;
    }
    let mut indices = vec![0; keys.len()];
    for (index, instance) in instances.iter().enumerate() {
        if let Some(slot) = slots.remove(instance.key.as_str()) {
            indices[slot] = index;
            if slots.is_empty() {
                break;
            }
        }
    }
    slots.is_empty().then_some(indices)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Keys {
    keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enable {
    enable: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BatchEnable {
    keys: Vec<String>,
    enable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    keys: Vec<String>,
    group: String,
}
