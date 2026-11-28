//! EasyTier management routes (WP-45 §4), served with plain axum while
//! mirroring the fg-admin collection contract (JSON shapes, status codes,
//! key handling), exactly like the fg-cron / fg-guard module routes.
//!
//! Endpoints (permission domain `easytier`; the 4 generic log endpoints
//! are served by fg-admin and not mounted here — 23 module operations in
//! total, 27 including the logs):
//!
//! | Method | Path | Request | Response |
//! |---|---|---|---|
//! | GET | `/api/easytier/instances` | — | `[Instance]` (masked) |
//! | POST | `/api/easytier/instances` | `Instance` | created masked `Instance` |
//! | POST | `/api/easytier/instances-delete` | `{"keys":[…]}` | `{"removed":N}` |
//! | PUT | `/api/easytier/instances-enable` | `{"keys":[…],"enable":bool}` | `{"changed":N}` |
//! | PUT | `/api/easytier/instances-group` | `{"keys":[…],"group":"…"}` | `{"ok":true}` |
//! | PUT | `/api/easytier/instances-order` | `{"keys":[…]}` | `{"ok":true}` |
//! | PUT | `/api/easytier/instances/{key}` | `Instance` | replaced masked `Instance` |
//! | DELETE | `/api/easytier/instances/{key}` | — | `{"removed":1}` |
//! | POST | `/api/easytier/instances/{key}/copy` | `Instance` | created masked `Instance` |
//! | PUT | `/api/easytier/instances/{key}/enable` | `{"enable":bool}` | `{"ok":true}` |
//! | GET | `/api/easytier/instances/{key}/secrets` | — | `Instance` (plaintext secrets) |
//! | POST | `/api/easytier/instances/{key}/restart` | — | `{"ok":true}` |
//! | GET | `/api/easytier/instances/{key}/status` | — | runtime status + peers |
//! | GET | `/api/easytier/status` | — | module status (read-only snapshots) |
//! | GET | `/api/easytier/settings` | — | `ProgramSettings` |
//! | PUT | `/api/easytier/settings` | `ProgramSettings` | `ProgramSettings` |
//! | GET | `/api/easytier/install` | — | `{"stage","installed","backups"}` |
//! | POST | `/api/easytier/install` | `{"version"?}` | `{"ok":true}` |
//! | POST | `/api/easytier/install/check` | — | `{"latest","installed","updateAvailable"}` |
//! | POST | `/api/easytier/install/rollback` | `{"version"}` | `{"ok":true}` |
//! | DELETE | `/api/easytier/install` | — | `{"ok":true}` |
//! | DELETE | `/api/easytier/install/backups/{id}` | — | `{"ok":true}` |
//! | POST | `/api/easytier/reset` | — | `{"ok":true}` |
//!
//! Secrets: list and mutation responses carry masked secrets
//! (`********`); the full plaintext is only returned by the `secrets`
//! endpoint (mounted behind a write-permission path in fg-admin).
//! Submitting the mask keeps the stored value.
//!
//! The settings endpoints carry no auth of their own. WP-45 §8 marks them
//! session-only (they select the program to execute); that restriction is
//! applied by the fg-admin authorize layer of the assembling router.
//!
//! Authentication is NOT performed here: routes are meant to be mounted
//! under the management router whose authorize layer maps
//! `/api/easytier/…` to domain `easytier` (GET → `easytier:read`, every
//! mutation → `easytier:write`).

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

/// Writes the whole [`FileConfig`] to `easytier.json`.
pub type PersistFn = Arc<dyn Fn(&FileConfig) -> anyhow::Result<()> + Send + Sync>;

/// Shared state behind the management routes.
pub struct RoutesState {
    /// The live desired config (already normalized once loaded).
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
    let (batch_delete, batch_enable) = (state.clone(), state.clone());
    let (group, order) = (state.clone(), state.clone());
    let (secrets, module_status) = (state.clone(), state.clone());
    let (settings_get, settings_put) = (state.clone(), state.clone());
    let (install_get, install_post) = (state.clone(), state.clone());
    let (install_check, install_rollback_state) = (state.clone(), state.clone());
    let (install_delete, backup_delete, reset_state) = (state.clone(), state.clone(), state);
    router
        .route(
            "/api/easytier/instances",
            get(move || async move { instances_list(list).await })
                .post(move |body: Bytes| async move { instances_create(create, body).await }),
        )
        .route(
            "/api/easytier/instances/{key}",
            put(move |path: PathResult, body: Bytes| async move {
                instances_update(replace, path, body).await
            })
            .delete(move |path: PathResult| async move { instances_remove(remove, path).await }),
        )
        .route(
            "/api/easytier/instances/{key}/copy",
            post(move |path: PathResult, body: Bytes| async move {
                instances_copy(copy, path, body).await
            }),
        )
        .route(
            "/api/easytier/instances/{key}/enable",
            put(move |path: PathResult, body: Bytes| async move {
                instances_enable(enable, path, body).await
            }),
        )
        .route(
            "/api/easytier/instances/{key}/secrets",
            get(move |path: PathResult| async move { instances_secrets(secrets, path).await }),
        )
        .route(
            "/api/easytier/instances/{key}/restart",
            post(move |path: PathResult| async move { instance_restart(restart, path).await }),
        )
        .route(
            "/api/easytier/instances/{key}/status",
            get(move |path: PathResult| async move { instance_status(status, path).await }),
        )
        .route(
            "/api/easytier/instances-delete",
            post(move |body: Bytes| async move { instances_batch_delete(batch_delete, body).await }),
        )
        .route(
            "/api/easytier/instances-enable",
            put(move |body: Bytes| async move {
                instances_batch_enable(batch_enable, body).await
            }),
        )
        .route(
            "/api/easytier/instances-group",
            put(move |body: Bytes| async move { instances_group(group, body).await }),
        )
        .route(
            "/api/easytier/instances-order",
            put(move |body: Bytes| async move { instances_order(order, body).await }),
        )
        .route(
            "/api/easytier/status",
            get(move || async move { module_status_view(module_status).await }),
        )
        .route(
            "/api/easytier/settings",
            get(move || async move { settings_view(settings_get).await })
                .put(move |body: Bytes| async move { settings_save(settings_put, body).await }),
        )
        .route(
            "/api/easytier/install",
            get(move || async move { install_view(install_get).await })
                .post(move |body: Bytes| async move { install_start(install_post, body).await })
                .delete(move || async move { install_uninstall(install_delete).await }),
        )
        .route(
            "/api/easytier/install/check",
            post(move || async move { install_check_view(install_check).await }),
        )
        .route(
            "/api/easytier/install/rollback",
            post(move |body: Bytes| async move {
                install_rollback(install_rollback_state, body).await
            }),
        )
        .route(
            "/api/easytier/install/backups/{id}",
            delete(move |path: PathResult| async move {
                install_backup_delete(backup_delete, path).await
            }),
        )
        .route(
            "/api/easytier/reset",
            post(move || async move { reset(reset_state).await }),
        )
}

/// The path extractor result; rejected paths become a 400.
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
                    "error": "invalid easytier configuration",
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
/// normalized candidate before publishing it, and notifies afterwards
/// (fg-admin collection commit order: persist first, snapshot second).
#[allow(clippy::result_large_err)]
async fn mutate<T>(
    state: &RoutesState,
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
                tracing::warn!(%error, "persisting easytier.json failed");
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

fn settle(config: &mut FileConfig) -> Result<(), Failure> {
    *config = validate::normalize(std::mem::take(config));
    let mut problems = validate::validate(config);
    for conflict in validate::conflicts(&config.instances) {
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

/// Same key contract as the fg-admin collections: short, URL-safe, and not
/// colliding with batch-style path suffixes.
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

/// 12 lowercase hex characters, unique within the collection (conventions
/// §3.3: 6 random bytes).
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
    match mutate(&state, move |config| {
        let mut instance = instance;
        if !valid_key(&instance.key) || config.instances.iter().any(|row| row.key == instance.key) {
            instance.key = random_key(&config.instances)?;
        }
        config.instances.push(instance);
        settle(config)?;
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
    match mutate(&state, move |config| {
        let index = locate(&config.instances, &source)?;
        let mut instance = instance;
        // Copies always receive a generated key and start disabled until
        // the conflict check passes (WP-45 §3.3: 复制时也检查冲突).
        instance.key = random_key(&config.instances)?;
        instance.enable = false;
        config.instances.insert(index + 1, instance);
        settle(config)?;
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
    match mutate(&state, move |config| {
        let index = locate(&config.instances, &key)?;
        instance.key = key.clone();
        instance.merge_masked(&config.instances[index]);
        config.instances[index] = instance;
        settle(config)?;
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
    match mutate(&state, move |config| {
        let index = locate(&config.instances, &key)?;
        let instance = config.instances.remove(index);
        Ok((instance, true))
    })
    .await
    {
        Ok(instance) => {
            // Deletion cleanup happens after persist: stop the process,
            // then remove the default state directory (WP-45 §3.3).
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
    match mutate(&state, move |config| {
        let index = locate(&config.instances, &key)?;
        let instance = &mut config.instances[index];
        let changed = instance.enable != enable;
        instance.enable = enable;
        settle(config)?;
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
    match mutate(&state, move |config| {
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
    match mutate(&state, move |config| {
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
        settle(config)?;
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
    match mutate(&state, move |config| {
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
    match mutate(&state, move |config| {
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

/// The plaintext instance (write-permission path, fg-admin guards it).
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

/// Module status (WP-45 §4): read-only instance snapshots plus the
/// program install summary — no paths, no arguments, no secrets.
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
    match mutate(&state, move |config| {
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
        // Progress stays readable through GET /install; the running
        // instances restart once the installer signals completion.
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
    // Stop every instance first: they hold the binaries we are about to
    // delete (the running images survive deletion, but the module should
    // not keep serving from removed files).
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

/// Deletes one backup version directory. The versioned layout lives under
/// fg-proc's `bin/.versions/<program>/<version>`; the id is validated to a
/// safe single path segment and the resolved directory must stay inside
/// `bin/` before anything is removed.
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

/// A backup id must be a safe single path segment (version strings like
/// `1.2.3` or `1.2.3-rc1`).
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

/// Maps requested keys (each once) onto positions; `None` when a key is
/// unknown or duplicated.
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
