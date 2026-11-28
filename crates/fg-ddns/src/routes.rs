//! DDNS management routes (WP-40 §4): the task collection, record-level
//! operations, sync, settings and the helper endpoints, served with plain
//! axum while mirroring the fg-admin `Collection<T>` contract (JSON
//! shapes, status codes, key handling) — the module cannot depend on
//! fg-admin, so the shapes are reimplemented here against
//! [`crate::model::FileConfig`] like the fg-cron module does.
//!
//! Endpoints (permission domain `ddns`, 21 of the upstream 25 operations;
//! the 4 generic log endpoints `GET|DELETE /api/ddns/logs`,
//! `GET /api/ddns/logs/export`, `GET /api/ddns/logs/sources` are served
//! by fg-admin and not mounted here):
//!
//! | Method | Path | Request | Response |
//! |---|---|---|---|
//! | GET | `/api/ddns/tasks` | — | `[TaskView]` (normalized, masked `credentials.secret`, read-only `status`) |
//! | POST | `/api/ddns/tasks` | `Task` | created `TaskView` |
//! | POST | `/api/ddns/tasks/{key}/copy` | `Task` | created `TaskView` (fresh key, secrets filled from the source) |
//! | PUT | `/api/ddns/tasks/{key}` | `Task` | replaced `TaskView` (`********`/empty secret values keep the stored ones) |
//! | DELETE | `/api/ddns/tasks/{key}` | — | `{"removed":1}` |
//! | PUT | `/api/ddns/tasks/{key}/enable` | `{"enable":bool}` | `{"ok":true}` |
//! | PUT | `/api/ddns/tasks-order` | `{"keys":[…]}` full ordered list | `{"ok":true}` |
//! | PUT | `/api/ddns/tasks-enable` | `{"keys":[…],"enable":bool}` | `{"changed":N}` |
//! | PUT | `/api/ddns/tasks-group` | `{"keys":[…],"group":"…"}` | `{"ok":true}` |
//! | POST | `/api/ddns/tasks-delete` | `{"keys":[…]}` | `{"removed":N}` |
//! | DELETE | `/api/ddns/tasks/{key}/records/{rec}` | — | `{"removed":1}` |
//! | POST | `/api/ddns/tasks/{key}/remote-delete` | `{"records":[recKey…]}` | `{"deleted":N}` — provider records first, all-or-nothing; local config untouched |
//! | PUT | `/api/ddns/tasks/{key}/records-layout` | `{"keys":[…]}` full record order, optional `{"groups":{recKey:group}}` | `{"ok":true}` |
//! | POST | `/api/ddns/tasks/{key}/sync` | — | `{"ok":true,"changed":N,"results":[…]}` or `{"ok":true,"skipped":true}` while a round runs, or `500 {"error":…}` |
//! | GET | `/api/ddns/tasks/{key}/secrets` | — | `{"credentials.id":…, "credentials.secret":…, "credentials.extra.<k>":…}` |
//! | GET | `/api/ddns/settings` | — | normalized `Settings` |
//! | PUT | `/api/ddns/settings` | `Settings` | normalized `Settings` |
//! | GET | `/api/ddns/providers` | — | provider list (`fg_dns::Meta` JSON + `available` flag) |
//! | GET | `/api/ddns/netinterfaces` | — | `{"interfaces":[{"name":…,"ipv4":[…],"ipv6":[…]}]}` |
//! | POST | `/api/ddns/iptest` | `{"family":"ipv4"|"ipv6","source":IpSource,"timeout":sec}` | `{"ip":"…"}` or `400 {"error":…}` |
//! | GET | `/api/ddns/defaults` | — | upstream defaults incl. the public IP query service lists |
//!
//! Every mutation runs normalize → validate → apply → persist →
//! on_change; validation problems are returned as `400` with the
//! collected list (`{"error":…,"problems":[…]}`). Batch bodies carry at
//! most 500 keys and all must exist before anything is saved. Task and
//! record keys are 12 lowercase hex characters generated on create/copy;
//! a client-supplied valid unique key is kept on create and always
//! regenerated on copy. `PUT /api/ddns/tasks/{key}` does not offer remote
//! deletion implicitly: the UI calls `remote-delete` for the removed
//! record keys first and saves only when that succeeded.
//!
//! Authentication is NOT performed here: [`mount`] routes are meant to be
//! mounted under the management router built by the assembler, whose
//! per-route `authorize` layer authenticates sessions/tokens and maps the
//! first path segment to the `ddns` domain (GET → `ddns:read`, every
//! mutation → `ddns:write`).

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
};

use axum::{
    Json,
    body::Bytes,
    extract::{Path, rejection::PathRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::RwLock;

use crate::{
    ip_source::{self, Family, SourceFilter},
    model::{FileConfig, IpSource, Settings, Task, limits},
    remote,
    runtime::{RoundOutcome, Scheduler, SyncNow, TaskStatus},
    validate::{self, Problem, merge_credentials},
};

/// Writes the whole [`FileConfig`] to `ddns.json`.
pub type PersistFn = Arc<dyn Fn(&FileConfig) -> anyhow::Result<()> + Send + Sync>;

/// Remote record deletion hook (see [`crate::runtime::DeleteRemoteFn`]).
pub type DeleteRemoteFn = crate::runtime::DeleteRemoteFn;

/// Shared state behind the DDNS management routes.
pub struct RoutesState {
    /// The live desired snapshot (already normalized once loaded).
    pub config: Arc<RwLock<FileConfig>>,
    pub scheduler: Arc<Scheduler>,
    pub persist: PersistFn,
    pub on_change: Arc<dyn Fn() + Send + Sync>,
    /// Remote deletion capability; `None` = unavailable in this build.
    pub delete_remote: Option<DeleteRemoteFn>,
}

/// A task as listed by the API: the stored task (secret masked) plus its
/// read-only status.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskView {
    #[serde(flatten)]
    pub task: Value,
    pub status: Option<TaskStatus>,
}

fn task_view(task: Task, scheduler: &Scheduler) -> TaskView {
    let mut value = serde_json::to_value(&task).expect("task serializes");
    if let Some(credentials) = value.get_mut("credentials").and_then(Value::as_object_mut) {
        credentials.insert("secret".to_owned(), Value::from(validate::SECRET_MASK));
    }
    TaskView {
        task: value,
        status: scheduler.status(&task.key),
    }
}

/// Adds the DDNS collection, record-level, sync, settings and helper
/// routes to `router`. See the module docs for the endpoint contract and
/// the authentication assumption.
pub fn mount(router: axum::Router, state: Arc<RoutesState>) -> axum::Router {
    let (list, create) = (state.clone(), state.clone());
    let (replace, remove) = (state.clone(), state.clone());
    let (copy, enable) = (state.clone(), state.clone());
    let (order, batch_enable) = (state.clone(), state.clone());
    let (group, batch_delete) = (state.clone(), state.clone());
    let (record_remove, remote_delete_state) = (state.clone(), state.clone());
    let (layout, sync) = (state.clone(), state.clone());
    let (secrets, settings_get) = (state.clone(), state.clone());
    let (settings_put, providers) = (state.clone(), state.clone());
    let (interfaces, iptest_state, defaults_state) = (state.clone(), state.clone(), state.clone());
    router
        .route(
            "/api/ddns/tasks",
            get(move || async move { tasks_list(list).await })
                .post(move |body: Bytes| async move { tasks_create(create, body).await }),
        )
        .route(
            "/api/ddns/tasks/{key}",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    tasks_update(replace, path, body).await
                },
            )
            .delete(
                move |path: Result<Path<String>, PathRejection>| async move {
                    tasks_delete(remove, path).await
                },
            ),
        )
        .route(
            "/api/ddns/tasks/{key}/copy",
            post(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    tasks_copy(copy, path, body).await
                },
            ),
        )
        .route(
            "/api/ddns/tasks/{key}/enable",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    tasks_enable(enable, path, body).await
                },
            ),
        )
        .route(
            "/api/ddns/tasks/{key}/records/{rec}",
            delete(
                move |path: Result<Path<(String, String)>, PathRejection>| async move {
                    record_delete(record_remove, path).await
                },
            ),
        )
        .route(
            "/api/ddns/tasks/{key}/remote-delete",
            post(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    remote_delete(remote_delete_state, path, body).await
                },
            ),
        )
        .route(
            "/api/ddns/tasks/{key}/records-layout",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    records_layout(layout, path, body).await
                },
            ),
        )
        .route(
            "/api/ddns/tasks/{key}/sync",
            post(
                move |path: Result<Path<String>, PathRejection>| async move {
                    tasks_sync(sync, path).await
                },
            ),
        )
        .route(
            "/api/ddns/tasks/{key}/secrets",
            get(
                move |path: Result<Path<String>, PathRejection>| async move {
                    task_secrets(secrets, path).await
                },
            ),
        )
        .route(
            "/api/ddns/tasks-order",
            put(move |body: Bytes| async move { tasks_order(order, body).await }),
        )
        .route(
            "/api/ddns/tasks-enable",
            put(move |body: Bytes| async move { tasks_batch_enable(batch_enable, body).await }),
        )
        .route(
            "/api/ddns/tasks-group",
            put(move |body: Bytes| async move { tasks_group(group, body).await }),
        )
        .route(
            "/api/ddns/tasks-delete",
            post(move |body: Bytes| async move { tasks_batch_delete(batch_delete, body).await }),
        )
        .route(
            "/api/ddns/settings",
            get(move || async move { settings_view(settings_get).await })
                .put(move |body: Bytes| async move { settings_save(settings_put, body).await }),
        )
        .route(
            "/api/ddns/providers",
            get(move || async move { providers_list(providers).await }),
        )
        .route(
            "/api/ddns/netinterfaces",
            get(move || async move { netinterfaces(interfaces).await }),
        )
        .route(
            "/api/ddns/iptest",
            post(move |body: Bytes| async move { iptest(iptest_state, body).await }),
        )
        .route(
            "/api/ddns/defaults",
            get(move || async move { defaults(defaults_state).await }),
        )
}

/// A failed mutation: either a plain status/message pair shaped like the
/// fg-admin `ApiError` body, or the collected validation problems.
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
                    "error": "invalid ddns configuration",
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
///
/// Mirrors the fg-admin `Collection::change` commit order: the file is
/// written first and the in-memory snapshot only advances once the persist
/// hook succeeded, so a failed write leaves the desired state untouched.
#[allow(clippy::result_large_err)]
async fn mutate<T>(
    state: &RoutesState,
    change: impl FnOnce(&mut FileConfig) -> Change<T> + Send + 'static,
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
                tracing::warn!(%error, "persisting ddns.json failed");
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

fn internal() -> Response {
    Failure::Api(
        StatusCode::INTERNAL_SERVER_ERROR,
        "configuration operation failed".into(),
    )
    .into_response()
}

/// Applies defaults and collects every validation problem.
fn settle(config: &mut FileConfig) -> Result<(), Failure> {
    *config = validate::normalize(std::mem::take(config));
    let problems = validate::validate(config);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(Failure::Problems(problems))
    }
}

fn item_key(path: Result<Path<String>, PathRejection>) -> Result<String, Failure> {
    match path {
        Ok(Path(key)) if valid_key(&key) => Ok(key),
        _ => Err(Failure::Api(
            StatusCode::BAD_REQUEST,
            "invalid item key".into(),
        )),
    }
}

/// Same key contract as the fg-admin collections: short, URL-safe, and
/// not colliding with batch-style path suffixes.
fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key != "batch-delete"
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
    let mut seen = HashSet::new();
    keys.retain(|key| seen.insert(key.clone()));
    Ok(keys)
}

fn locate(tasks: &[Task], key: &str) -> Result<usize, Failure> {
    tasks
        .iter()
        .position(|task| task.key == key)
        .ok_or_else(|| Failure::Api(StatusCode::NOT_FOUND, "item not found".into()))
}

fn missing_item() -> Failure {
    Failure::Api(StatusCode::NOT_FOUND, "item not found".into())
}

/// Maps requested keys (each once) onto task positions; `None` when a key
/// is unknown or duplicated.
fn find_indices(tasks: &[Task], keys: &[String]) -> Option<Vec<usize>> {
    let mut slots: HashMap<_, _> = keys
        .iter()
        .enumerate()
        .map(|(slot, key)| (key.as_str(), slot))
        .collect();
    if slots.len() != keys.len() {
        return None;
    }
    let mut indices = vec![0; keys.len()];
    for (index, task) in tasks.iter().enumerate() {
        if let Some(slot) = slots.remove(task.key.as_str()) {
            indices[slot] = index;
            if slots.is_empty() {
                break;
            }
        }
    }
    slots.is_empty().then_some(indices)
}

/// A generated key, unique within the collection (fg-admin collection
/// behavior).
fn random_key(tasks: &[Task]) -> Result<String, Failure> {
    for _ in 0..8 {
        let key = crate::model::new_key();
        if !tasks.iter().any(|task| task.key == key) {
            return Ok(key);
        }
    }
    Err(Failure::Api(
        StatusCode::INTERNAL_SERVER_ERROR,
        "unable to generate a unique task key".into(),
    ))
}

async fn tasks_list(state: Arc<RoutesState>) -> Response {
    let guard = state.config.read().await;
    let config = validate::normalize(guard.clone());
    let views: Vec<TaskView> = config
        .tasks
        .iter()
        .map(|task| task_view(task.clone(), &state.scheduler))
        .collect();
    Json(views).into_response()
}

async fn tasks_create(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(task) = serde_json::from_slice::<Task>(&body) else {
        return decode_error();
    };
    let scheduler = Arc::clone(&state.scheduler);
    match mutate(&state, move |config| {
        let mut task = task;
        // A client-supplied valid unique key is kept; anything else gets a
        // generated one (fg-admin collection behavior on create).
        if !valid_key(&task.key) || config.tasks.iter().any(|row| row.key == task.key) {
            task.key = random_key(&config.tasks)?;
        }
        config.tasks.push(task);
        settle(config)?;
        let created = config.tasks.last().cloned().expect("just pushed");
        let view = task_view(created, &scheduler);
        Ok((Json(view), true))
    })
    .await
    {
        Ok(created) => created.into_response(),
        Err(response) => response,
    }
}

async fn tasks_copy(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(mut task) = serde_json::from_slice::<Task>(&body) else {
        return decode_error();
    };
    let Ok(source) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let scheduler = Arc::clone(&state.scheduler);
    match mutate(&state, move |config| {
        let index = locate(&config.tasks, &source)?;
        // Copies always receive a generated key; masked secret values are
        // filled from the source task.
        task.key = random_key(&config.tasks)?;
        merge_credentials(&config.tasks[index].credentials, &mut task.credentials);
        config.tasks.insert(index + 1, task);
        settle(config)?;
        let created = config.tasks[index + 1].clone();
        let view = task_view(created, &scheduler);
        Ok((Json(view), true))
    })
    .await
    {
        Ok(created) => created.into_response(),
        Err(response) => response,
    }
}

async fn tasks_update(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(mut task) = serde_json::from_slice::<Task>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let scheduler = Arc::clone(&state.scheduler);
    match mutate(&state, move |config| {
        let index = locate(&config.tasks, &key)?;
        task.key = key.clone();
        // Masked or empty secret values keep the stored ones.
        merge_credentials(&config.tasks[index].credentials, &mut task.credentials);
        config.tasks[index] = task;
        settle(config)?;
        let replaced = config.tasks[index].clone();
        let view = task_view(replaced, &scheduler);
        Ok((Json(view), true))
    })
    .await
    {
        Ok(replaced) => replaced.into_response(),
        Err(response) => response,
    }
}

async fn tasks_delete(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let scheduler = Arc::clone(&state.scheduler);
    match mutate(&state, move |config| {
        let index = locate(&config.tasks, &key)?;
        config.tasks.remove(index);
        scheduler.forget(&key);
        Ok((Json(json!({ "removed": 1 })), true))
    })
    .await
    {
        Ok(removed) => removed.into_response(),
        Err(response) => response,
    }
}

async fn tasks_enable(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(Enable { enable }) = serde_json::from_slice::<Enable>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    match mutate(&state, move |config| {
        let index = locate(&config.tasks, &key)?;
        let task = &mut config.tasks[index];
        let changed = task.enable != enable;
        task.enable = enable;
        Ok((Json(json!({ "ok": true })), changed))
    })
    .await
    {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

async fn tasks_order(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Keys { keys }) = serde_json::from_slice::<Keys>(&body) else {
        return decode_error();
    };
    match mutate(&state, move |config| {
        if keys.len() != config.tasks.len() {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                "order must include every item once".into(),
            ));
        }
        let Some(indices) = find_indices(&config.tasks, &keys) else {
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
                config.tasks.swap(index, new);
                destination.swap(index, new);
            }
        }
        Ok((Json(json!({ "ok": true })), true))
    })
    .await
    {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

async fn tasks_batch_enable(state: Arc<RoutesState>, body: Bytes) -> Response {
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
        let indices = find_indices(&config.tasks, &keys).ok_or_else(missing_item)?;
        let mut changed = 0;
        for index in indices {
            let task = &mut config.tasks[index];
            if task.enable != enable {
                task.enable = enable;
                changed += 1;
            }
        }
        Ok((Json(json!({ "changed": changed })), changed > 0))
    })
    .await
    {
        Ok(changed) => changed.into_response(),
        Err(response) => response,
    }
}

async fn tasks_group(state: Arc<RoutesState>, body: Bytes) -> Response {
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
        let indices = find_indices(&config.tasks, &keys).ok_or_else(missing_item)?;
        let mut changed = false;
        for index in indices {
            let field = &mut config.tasks[index].group;
            if *field != name {
                field.clone_from(&name);
                changed = true;
            }
        }
        Ok((Json(json!({ "ok": true })), changed))
    })
    .await
    {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

async fn tasks_batch_delete(state: Arc<RoutesState>, body: Bytes) -> Response {
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
    let scheduler = Arc::clone(&state.scheduler);
    match mutate(&state, move |config| {
        // Every requested key must exist, mirroring the fg-admin batch
        // delete: no partial removals.
        find_indices(&config.tasks, &keys).ok_or_else(missing_item)?;
        let removed: HashSet<_> = keys.iter().map(String::as_str).collect();
        config
            .tasks
            .retain(|task| !removed.contains(task.key.as_str()));
        for key in &keys {
            scheduler.forget(key);
        }
        let count = keys.len();
        Ok((Json(json!({ "removed": count })), true))
    })
    .await
    {
        Ok(removed) => removed.into_response(),
        Err(response) => response,
    }
}

async fn record_delete(
    state: Arc<RoutesState>,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Response {
    let Ok(Path((task_key, rec_key))) = path else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    if !valid_key(&task_key) || !valid_key(&rec_key) {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    }
    match mutate(&state, move |config| {
        let index = locate(&config.tasks, &task_key)?;
        let records = &mut config.tasks[index].records;
        let at = records
            .iter()
            .position(|record| record.key == rec_key)
            .ok_or_else(missing_item)?;
        records.remove(at);
        Ok((Json(json!({ "removed": 1 })), true))
    })
    .await
    {
        Ok(removed) => removed.into_response(),
        Err(response) => response,
    }
}

async fn records_layout(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(Layout { keys, groups }) = serde_json::from_slice::<Layout>(&body) else {
        return decode_error();
    };
    let Ok(task_key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    match mutate(&state, move |config| {
        let index = locate(&config.tasks, &task_key)?;
        let task = &mut config.tasks[index];
        // The full ordered list of the task's record keys.
        let record_keys: Vec<String> = task.records.iter().map(|r| r.key.clone()).collect();
        if keys.len() != record_keys.len() {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                "layout must include every record once".into(),
            ));
        }
        let Some(indices) = find_record_indices(&record_keys, &keys) else {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                "layout contains an unknown or duplicate record key".into(),
            ));
        };
        let mut reordered = Vec::with_capacity(task.records.len());
        for position in indices {
            reordered.push(task.records[position].clone());
        }
        task.records = reordered;
        if let Some(groups) = &groups {
            for record in &mut task.records {
                if let Some(group) = groups.get(&record.key) {
                    record.group = group.trim().to_owned();
                }
            }
        }
        settle(config)?;
        Ok((Json(json!({ "ok": true })), true))
    })
    .await
    {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

/// Maps requested record keys (each once) onto positions; `None` when a
/// key is unknown or duplicated.
fn find_record_indices(records: &[String], keys: &[String]) -> Option<Vec<usize>> {
    let mut slots: HashMap<_, _> = keys
        .iter()
        .enumerate()
        .map(|(slot, key)| (key.as_str(), slot))
        .collect();
    if slots.len() != keys.len() {
        return None;
    }
    let mut indices = vec![0; keys.len()];
    for (index, key) in records.iter().enumerate() {
        if let Some(slot) = slots.remove(key.as_str()) {
            indices[slot] = index;
            if slots.is_empty() {
                break;
            }
        }
    }
    slots.is_empty().then_some(indices)
}

/// Deletes the provider records for the requested record keys (all-or-
/// nothing): the local configuration is never touched here — the UI only
/// removes the records/tasks after this succeeded.
async fn remote_delete(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(RecordKeys { records }) = serde_json::from_slice::<RecordKeys>(&body) else {
        return decode_error();
    };
    let Ok(task_key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    if records.is_empty() {
        return Failure::Api(StatusCode::BAD_REQUEST, "records 不能为空".into()).into();
    }
    let Some(hook) = state.delete_remote.clone() else {
        return Failure::Api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "此构建未包含 DNS 服务商删除能力".into(),
        )
        .into();
    };
    let (task, deleted_values) = {
        let config = state.config.read().await;
        let Some(task) = config
            .tasks
            .iter()
            .find(|task| task.key == task_key)
            .cloned()
        else {
            return missing_item().into();
        };
        let statuses = state.scheduler.statuses();
        let status = statuses.get(&task_key);
        let values: BTreeMap<String, String> = status
            .map(|status| {
                status
                    .records
                    .iter()
                    .map(|(key, record)| (key.clone(), record.value.clone()))
                    .collect()
            })
            .unwrap_or_default();
        (task, values)
    };
    let meta = remote::meta_for(&task.provider);
    let Some(meta) = meta.filter(|meta| meta.supports_delete) else {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            format!("DNS 服务商 {} 不支持删除解析", task.provider),
        )
        .into();
    };
    let mut deleted = 0;
    for rec_key in &records {
        let Some(record) = task.records.iter().find(|record| &record.key == rec_key) else {
            return missing_item().into();
        };
        let Some(value) = deleted_values
            .get(rec_key)
            .filter(|value| !value.is_empty())
        else {
            return Failure::Api(
                StatusCode::BAD_REQUEST,
                format!(
                    "{} {} 还没有同步过，无法确认服务商处的记录由本程序写入，未删除",
                    record.typ.as_str(),
                    remote::fqdn_of(record)
                ),
            )
            .into();
        };
        let dns_record = remote::build_record(Some(meta), &task, record, value);
        let hook = Arc::clone(&hook);
        match hook(
            task.provider.clone(),
            to_dns_creds(&task.credentials),
            dns_record,
        )
        .await
        {
            Ok(count) => deleted += count,
            Err(error) => {
                tracing::warn!(task = %task.name, provider = %task.provider, %error, "删除服务商解析失败");
                return Failure::Api(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into();
            }
        }
    }
    Json(json!({ "deleted": deleted })).into_response()
}

fn to_dns_creds(creds: &crate::model::Credentials) -> fg_dns::Credentials {
    fg_dns::Credentials {
        id: creds.id.clone(),
        secret: creds.secret.clone(),
        extra: creds.extra.clone(),
    }
}

async fn tasks_sync(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    // The stored (normalized) config decides existence.
    if !state
        .config
        .read()
        .await
        .tasks
        .iter()
        .any(|task| task.key == key)
    {
        return missing_item().into();
    }
    match state.scheduler.sync_now(&key).await {
        SyncNow::NotFound => missing_item().into(),
        SyncNow::Disabled => Failure::Api(StatusCode::CONFLICT, "DDNS 模块已停用".into()).into(),
        SyncNow::LoadError(errors) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "任务配置校验未通过，不会运行", "loadErr": errors })),
        )
            .into_response(),
        SyncNow::Busy => Json(json!({ "ok": true, "skipped": true })).into_response(),
        SyncNow::Done(outcome) => sync_response(outcome),
    }
}

fn sync_response(outcome: RoundOutcome) -> Response {
    let results: Vec<Value> = outcome
        .records
        .iter()
        .map(|record| {
            json!({
                "key": record.key,
                "fqdn": record.fqdn,
                "action": record.action.map(|action| action.as_str()).unwrap_or("none"),
                "skipReason": record.skip_reason,
                "error": record.error,
                "value": record.value,
            })
        })
        .collect();
    if outcome.failed {
        let message = outcome.failure.clone().unwrap_or_else(|| {
            outcome
                .records
                .iter()
                .find_map(|record| record.error.clone())
                .unwrap_or_else(|| "同步失败".to_owned())
        });
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": message, "results": results })),
        )
            .into_response();
    }
    let changed = outcome
        .records
        .iter()
        .filter(|record| {
            matches!(
                record.action,
                Some(fg_dns::UpsertAction::Created | fg_dns::UpsertAction::Updated)
            )
        })
        .count();
    Json(json!({ "ok": true, "changed": changed, "results": results })).into_response()
}

async fn task_secrets(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let config = state.config.read().await;
    let Some(task) = config.tasks.iter().find(|task| task.key == key) else {
        return missing_item().into();
    };
    let mut secrets = BTreeMap::new();
    secrets.insert("credentials.id".to_owned(), task.credentials.id.clone());
    secrets.insert(
        "credentials.secret".to_owned(),
        task.credentials.secret.clone(),
    );
    for (extra_key, value) in &task.credentials.extra {
        secrets.insert(format!("credentials.extra.{extra_key}"), value.clone());
    }
    Json(secrets).into_response()
}

async fn settings_view(state: Arc<RoutesState>) -> Response {
    let config = state.config.read().await;
    Json(validate::normalize(config.clone()).settings).into_response()
}

async fn settings_save(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(settings) = serde_json::from_slice::<Settings>(&body) else {
        return decode_error();
    };
    match mutate(&state, move |config| {
        let changed = config.settings != settings;
        config.settings = settings;
        settle(config)?;
        let saved = config.settings.clone();
        Ok((Json(saved), changed))
    })
    .await
    {
        Ok(saved) => saved.into_response(),
        Err(response) => response,
    }
}

async fn providers_list(_state: Arc<RoutesState>) -> Response {
    let registry = fg_dns::registry();
    let mut providers = Vec::new();
    for name in fg_dns::ALL_NAMES {
        let compiled = registry.iter().find(|(meta, _)| meta.name == *name);
        let Some((meta, _)) = compiled else {
            providers.push(json!({
                "name": name,
                "available": false,
            }));
            continue;
        };
        providers.push(json!({
            "name": meta.name,
            "title": meta.title,
            "idLabel": meta.id_label,
            "secretLabel": meta.secret_label,
            "extra": meta
                .extra
                .iter()
                .map(|field| json!({
                    "key": field.key,
                    "label": field.label,
                    "placeholder": field.placeholder,
                    "multiline": field.multiline,
                    "required": field.required,
                }))
                .collect::<Vec<_>>(),
            "supportsLine": meta.supports_line,
            "docUrl": meta.doc_url,
            "supportsAcme": meta.supports_acme,
            "supportsRemark": meta.supports_remark,
            "supportsDelete": meta.supports_delete,
            "available": true,
        }));
    }
    Json(providers).into_response()
}

async fn netinterfaces(_state: Arc<RoutesState>) -> Response {
    let mut interfaces: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();
    match if_addrs::get_if_addrs() {
        Ok(list) => {
            for iface in list {
                let name = iface.name.clone();
                let entry = interfaces.entry(name).or_default();
                match iface.ip() {
                    IpAddr::V4(v4) => entry.0.push(v4.to_string()),
                    IpAddr::V6(v6) => entry.1.push(v6.to_string()),
                }
            }
        }
        Err(error) => {
            return Failure::Api(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("读取网卡列表失败：{error}"),
            )
            .into();
        }
    }
    let list: Vec<Value> = interfaces
        .into_iter()
        .map(|(name, (ipv4, ipv6))| json!({ "name": name, "ipv4": ipv4, "ipv6": ipv6 }))
        .collect();
    Json(json!({ "interfaces": list })).into_response()
}

async fn iptest(_state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(IpTest {
        family,
        source,
        timeout,
    }) = serde_json::from_slice::<IpTest>(&body)
    else {
        return decode_error();
    };
    let Some(family) = (match family.as_str() {
        "ipv4" => Some(Family::V4),
        "ipv6" => Some(Family::V6),
        _ => None,
    }) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "family 只支持 ipv4 / ipv6".into()).into();
    };
    let timeout = std::time::Duration::from_secs(u64::from(if timeout == 0 {
        limits::HTTP_TIMEOUT_DEFAULT
    } else {
        timeout.min(limits::HTTP_TIMEOUT_MAX)
    }));
    let filter = match SourceFilter::new(&source) {
        Ok(filter) => filter,
        Err(error) => {
            return Failure::Api(StatusCode::BAD_REQUEST, error.to_string()).into();
        }
    };
    match ip_source::get(&source, family, timeout, &filter).await {
        Ok(ip) => Json(json!({ "ip": ip.to_string() })).into_response(),
        Err(error) => Failure::Api(StatusCode::BAD_REQUEST, error.to_string()).into(),
    }
}

async fn defaults(_state: Arc<RoutesState>) -> Response {
    Json(json!({
        "interval": limits::INTERVAL_DEFAULT,
        "intervalMin": limits::INTERVAL_MIN,
        "forceInterval": limits::FORCE_INTERVAL_DEFAULT,
        "httpTimeout": limits::HTTP_TIMEOUT_DEFAULT,
        "webhookTimeout": limits::WEBHOOK_TIMEOUT_DEFAULT,
        "remarkMaxChars": limits::REMARK_MAX_CHARS,
        "deleteRemote": false,
        "ipv4Urls": ip_source::DEFAULT_IPV4_URLS,
        "ipv6Urls": ip_source::DEFAULT_IPV6_URLS,
    }))
    .into_response()
}

fn decode_error() -> Response {
    Failure::Api(StatusCode::BAD_REQUEST, "invalid JSON body".into()).into_response()
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
#[serde(deny_unknown_fields)]
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Layout {
    keys: Vec<String>,
    #[serde(default)]
    groups: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordKeys {
    records: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IpTest {
    family: String,
    source: IpSource,
    #[serde(default)]
    timeout: u32,
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use hyper::header::CONTENT_TYPE;
    use hyper_util::rt::TokioIo;

    /// A mounted router over an in-memory store, counting persist calls
    /// and recording a fake provider's upserts.
    struct Harness {
        addr: std::net::SocketAddr,
        persists: Arc<AtomicUsize>,
        last_saved: Arc<Mutex<Option<FileConfig>>>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    async fn harness() -> Harness {
        let (provider_new, calls) = fake_provider_new();
        let deps = crate::runtime::Deps {
            provider_new,
            ..crate::runtime::Deps::default()
        };
        harness_with(deps, None, calls).await
    }

    async fn harness_with(
        deps: crate::runtime::Deps,
        delete_remote: Option<DeleteRemoteFn>,
        calls: Arc<Mutex<Vec<String>>>,
    ) -> Harness {
        let persists = Arc::new(AtomicUsize::new(0));
        let last_saved: Arc<Mutex<Option<FileConfig>>> = Arc::new(Mutex::new(None));
        let config = Arc::new(RwLock::new(FileConfig {
            settings: Settings {
                enable: true,
                ..Settings::default()
            },
            tasks: Vec::new(),
        }));
        let scheduler = Arc::new(Scheduler::new(config.clone(), deps));
        let (count_persist, slot) = (persists.clone(), last_saved.clone());
        let persist: PersistFn = Arc::new(move |config: &FileConfig| {
            serde_json::to_vec_pretty(config)?;
            *slot.lock().expect("slot") = Some(config.clone());
            count_persist.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let on_change = scheduler.on_change_handle();
        let state = Arc::new(RoutesState {
            config,
            scheduler,
            persist,
            on_change,
            delete_remote,
        });
        let app = mount(axum::Router::new(), state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        Harness {
            addr,
            persists,
            last_saved,
            calls,
        }
    }

    /// A fake provider whose `upsert` returns Created for the first value
    /// and Unchanged afterwards.
    fn fake_provider_new() -> (crate::runtime::ProviderNew, Arc<Mutex<Vec<String>>>) {
        let calls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let provider_new: crate::runtime::ProviderNew = {
            let calls = Arc::clone(&calls);
            let seen = Arc::clone(&seen);
            Arc::new(move |_name, _creds| {
                struct Fake {
                    calls: Arc<Mutex<Vec<String>>>,
                    seen: Arc<Mutex<Vec<String>>>,
                }
                static META: fg_dns::Meta = fg_dns::Meta::new("fake", "Fake");
                impl fg_dns::DnsProvider for Fake {
                    fn meta(&self) -> &'static fg_dns::Meta {
                        &META
                    }
                    fn upsert<'a>(
                        &'a self,
                        rec: &'a fg_dns::Record,
                    ) -> fg_dns::BoxFut<'a, Result<fg_dns::UpsertAction, fg_dns::ProviderError>>
                    {
                        Box::pin(async move {
                            let fingerprint =
                                format!("{} {} {}", rec.rr(), rec.typ.as_str(), rec.value);
                            let mut seen = self.seen.lock().expect("seen");
                            let action = if seen.contains(&fingerprint) {
                                fg_dns::UpsertAction::Unchanged
                            } else if seen.is_empty() {
                                fg_dns::UpsertAction::Created
                            } else {
                                fg_dns::UpsertAction::Updated
                            };
                            seen.push(fingerprint.clone());
                            self.calls.lock().expect("calls").push(fingerprint);
                            Ok(action)
                        })
                    }
                }
                Ok(Box::new(Fake {
                    calls: Arc::clone(&calls),
                    seen: Arc::clone(&seen),
                }))
            })
        };
        (provider_new, calls)
    }

    impl Harness {
        async fn send(
            &self,
            method: &str,
            path: &str,
            body: Option<serde_json::Value>,
        ) -> (StatusCode, serde_json::Value) {
            let stream = tokio::net::TcpStream::connect(self.addr)
                .await
                .expect("connect");
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .expect("handshake");
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let builder = hyper::Request::builder()
                .method(method)
                .uri(path)
                .header(CONTENT_TYPE, "application/json");
            let request = match body {
                Some(body) => builder.body(Body::from(body.to_string())).expect("body"),
                None => builder.body(Body::empty()).expect("body"),
            };
            let response = sender.send_request(request).await.expect("send");
            let status = response.status();
            let bytes = BodyExt::collect(response.into_body())
                .await
                .expect("collect")
                .to_bytes();
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
            )
        }

        async fn create(&self, task: serde_json::Value) -> serde_json::Value {
            let (status, body) = self.send("POST", "/api/ddns/tasks", Some(task)).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body
        }

        async fn keys(&self) -> Vec<String> {
            let (_, body) = self.send("GET", "/api/ddns/tasks", None).await;
            body.as_array()
                .expect("tasks array")
                .iter()
                .map(|task| task["key"].as_str().expect("key").to_owned())
                .collect()
        }
    }

    fn base_task(key: &str) -> serde_json::Value {
        json!({
            "key": key,
            "name": if key.is_empty() { "generated" } else { key },
            "group": "",
            "enable": false,
            "provider": "cloudflare",
            "credentials": {"id": "user@example.com", "secret": "token"},
            "ipv4": {"enable": true, "kind": "command", "command": "echo 1.2.3.4"},
            "ipv6": {"enable": false},
            "records": [
                {"key": "rec000000001", "enable": true, "zone": "example.com", "sub": "Home", "typ": "A"}
            ],
            "interval": 0,
            "forceInterval": 0,
            "httpTimeout": 0,
            "webhook": {"enable": false},
            "remark": ""
        })
    }

    fn is_generated_key(key: &str) -> bool {
        key.len() == 12
            && key
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }

    #[tokio::test]
    async fn create_normalizes_masks_and_lists() {
        let app = harness().await;
        let created = app.create(base_task("")).await;
        assert!(
            is_generated_key(created["key"].as_str().expect("key")),
            "{created}"
        );
        // Defaults are applied on save and the secret is masked in views.
        assert_eq!(created["interval"], 300);
        assert_eq!(created["forceInterval"], 3600);
        assert_eq!(created["httpTimeout"], 20);
        assert_eq!(created["records"][0]["sub"], "home");
        assert_eq!(created["credentials"]["secret"], validate::SECRET_MASK);
        assert_eq!(created["status"], serde_json::json!(null));
        let (status, tasks) = app.send("GET", "/api/ddns/tasks", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tasks.as_array().expect("array").len(), 1);
        assert_eq!(tasks[0]["credentials"]["secret"], validate::SECRET_MASK);
        assert_eq!(tasks[0]["ipv4"]["kind"], "command");

        // A valid unique client key is kept; a duplicate one is regenerated.
        let kept = app.create(base_task("web")).await;
        assert_eq!(kept["key"], "web");
        let clash = app.create(base_task("web")).await;
        assert!(is_generated_key(clash["key"].as_str().expect("key")));
        // The persist hook received the normalized candidate.
        let saved = app
            .last_saved
            .lock()
            .expect("slot")
            .clone()
            .expect("persisted");
        assert_eq!(saved.tasks.len(), 3);
        assert_eq!(saved.tasks[0].interval, 300);
        assert_eq!(saved.tasks[0].credentials.secret, "token");
    }

    #[tokio::test]
    async fn update_merges_masked_secret_and_missing_key_is_404() {
        let app = harness().await;
        app.create(base_task("task1")).await;
        let mut replacement = base_task("ignored");
        replacement["credentials"]["secret"] = validate::SECRET_MASK.into();
        replacement["name"] = "renamed".into();
        let (status, body) = app
            .send("PUT", "/api/ddns/tasks/task1", Some(replacement))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["key"], "task1", "the path key wins over the body key");
        assert_eq!(body["name"], "renamed");
        // The stored secret survives the mask.
        let saved = app
            .last_saved
            .lock()
            .expect("slot")
            .clone()
            .expect("persisted");
        assert_eq!(saved.tasks[0].credentials.secret, "token");
        let (status, body) = app
            .send("PUT", "/api/ddns/tasks/nope", Some(base_task("nope")))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "item not found");
    }

    #[tokio::test]
    async fn copy_assigns_fresh_key_and_fills_secrets() {
        let app = harness().await;
        app.create(base_task("first")).await;
        let mut template = base_task("first");
        template["credentials"]["secret"] = validate::SECRET_MASK.into();
        let (status, copied) = app
            .send("POST", "/api/ddns/tasks/first/copy", Some(template))
            .await;
        assert_eq!(status, StatusCode::OK, "{copied}");
        assert!(is_generated_key(copied["key"].as_str().expect("key")));
        let saved = app
            .last_saved
            .lock()
            .expect("slot")
            .clone()
            .expect("persisted");
        assert_eq!(
            saved.tasks[1].credentials.secret, "token",
            "the copy keeps the source's secret"
        );
        assert_eq!(app.keys().await[0], "first");
    }

    #[tokio::test]
    async fn enable_single_ok_and_batch_reports_changed() {
        let app = harness().await;
        app.create(base_task("a")).await;
        app.create(base_task("b")).await;
        let (status, body) = app
            .send(
                "PUT",
                "/api/ddns/tasks/a/enable",
                Some(json!({ "enable": true })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        // No-op enable: still ok, no persist.
        let persists_before = app.persists.load(Ordering::SeqCst);
        let (_, body) = app
            .send(
                "PUT",
                "/api/ddns/tasks/a/enable",
                Some(json!({ "enable": true })),
            )
            .await;
        assert_eq!(body["ok"], true);
        assert_eq!(app.persists.load(Ordering::SeqCst), persists_before);
        let (status, body) = app
            .send(
                "PUT",
                "/api/ddns/tasks-enable",
                Some(json!({ "keys": ["a", "b"], "enable": true })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["changed"], 1, "a was already on, b flipped");
        let (status, body) = app
            .send(
                "PUT",
                "/api/ddns/tasks-enable",
                Some(json!({ "keys": ["ghost"], "enable": true })),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "item not found");
    }

    #[tokio::test]
    async fn order_requires_every_item_once() {
        let app = harness().await;
        app.create(base_task("a")).await;
        app.create(base_task("b")).await;
        let (status, body) = app
            .send(
                "PUT",
                "/api/ddns/tasks-order",
                Some(json!({ "keys": ["b"] })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "order must include every item once");
        let (status, _) = app
            .send(
                "PUT",
                "/api/ddns/tasks-order",
                Some(json!({ "keys": ["b", "ghost"] })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = app
            .send(
                "PUT",
                "/api/ddns/tasks-order",
                Some(json!({ "keys": ["b", "a"] })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(app.keys().await, ["b", "a"]);
    }

    #[tokio::test]
    async fn group_and_batch_delete_follow_contract() {
        let app = harness().await;
        app.create(base_task("a")).await;
        app.create(base_task("b")).await;
        let (status, body) = app
            .send(
                "PUT",
                "/api/ddns/tasks-group",
                Some(json!({ "keys": ["a", "b"], "group": "夜间" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        let (status, _) = app
            .send(
                "POST",
                "/api/ddns/tasks-delete",
                Some(json!({ "keys": ["a", "ghost"] })),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "no partial removals");
        let (status, body) = app
            .send(
                "POST",
                "/api/ddns/tasks-delete",
                Some(json!({ "keys": ["a"] })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["removed"], 1);
        assert_eq!(app.keys().await, ["b"]);
        // Batch bodies over 500 keys are rejected.
        let many: Vec<String> = (0..501).map(|index| format!("k{index}")).collect();
        let (status, body) = app
            .send(
                "POST",
                "/api/ddns/tasks-delete",
                Some(json!({ "keys": many })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "expected between 1 and 500 valid keys");
    }

    #[tokio::test]
    async fn record_delete_and_layout_follow_contract() {
        let app = harness().await;
        app.create(base_task("task1")).await;
        // Layout reorders the records and sets groups.
        let with_two = json!({
            "key": "task1",
            "name": "task1",
            "enable": false,
            "provider": "cloudflare",
            "credentials": {"id": "user@example.com", "secret": "token"},
            "ipv4": {"enable": true, "kind": "command", "command": "echo 1.2.3.4"},
            "ipv6": {"enable": false},
            "records": [
                {"key": "rec000000001", "enable": true, "zone": "example.com", "sub": "Home", "typ": "A"},
                {"key": "rec000000002", "enable": true, "zone": "example.com", "sub": "www", "typ": "A"}
            ],
            "interval": 300,
            "forceInterval": 3600,
            "httpTimeout": 20,
            "webhook": {"enable": false},
            "remark": ""
        });
        let (status, _) = app
            .send("PUT", "/api/ddns/tasks/task1", Some(with_two))
            .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = app
            .send(
                "PUT",
                "/api/ddns/tasks/task1/records-layout",
                Some(json!({
                    "keys": ["rec000000002", "rec000000001"],
                    "groups": {"rec000000002": "内网"}
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (_, tasks) = app.send("GET", "/api/ddns/tasks", None).await;
        let records = tasks[0]["records"].as_array().expect("records");
        assert_eq!(records[0]["key"], "rec000000002");
        assert_eq!(records[0]["group"], "内网");
        // An incomplete layout list is rejected.
        let (status, _) = app
            .send(
                "PUT",
                "/api/ddns/tasks/task1/records-layout",
                Some(json!({ "keys": ["rec000000001"] })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Record delete.
        let (status, body) = app
            .send("DELETE", "/api/ddns/tasks/task1/records/rec000000001", None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["removed"], 1);
        let (status, _) = app
            .send("DELETE", "/api/ddns/tasks/task1/records/rec000000001", None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn sync_runs_round_and_records_status() {
        let app = harness().await;
        let created = app.create(base_task("task1")).await;
        let key = created["key"].as_str().expect("key").to_owned();
        let (status, body) = app
            .send("POST", &format!("/api/ddns/tasks/{key}/sync"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], true);
        assert_eq!(body["changed"], 1);
        assert_eq!(body["results"][0]["action"], "created");
        assert_eq!(body["results"][0]["value"], "1.2.3.4");
        // The status shows the synced value and the round timestamps.
        let (_, tasks) = app.send("GET", "/api/ddns/tasks", None).await;
        let status_view = &tasks[0]["status"];
        assert_eq!(status_view["records"]["rec000000001"]["value"], "1.2.3.4");
        assert_eq!(status_view["records"]["rec000000001"]["action"], "created");
        assert!(status_view["ipv4"].as_str().is_some());
        assert!(status_view["lastCheck"].as_str().is_some());
        assert!(status_view["nextCheck"].as_str().is_some());
        // A second sync skips the provider call (value unchanged).
        let (status, body) = app
            .send("POST", &format!("/api/ddns/tasks/{key}/sync"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["changed"], 0);
        assert_eq!(
            body["results"][0]["action"], "none",
            "no provider call this round"
        );
        assert_eq!(app.calls.lock().expect("calls").len(), 1);
        // Unknown task: 404.
        let (status, body) = app.send("POST", "/api/ddns/tasks/ghost/sync", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "item not found");
    }

    #[tokio::test]
    async fn secrets_endpoint_returns_plaintext() {
        let app = harness().await;
        app.create(base_task("task1")).await;
        let (status, secrets) = app.send("GET", "/api/ddns/tasks/task1/secrets", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(secrets["credentials.secret"], "token");
        assert_eq!(secrets["credentials.id"], "user@example.com");
        let (status, _) = app.send("GET", "/api/ddns/tasks/ghost/secrets", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn remote_delete_refuses_without_sync_or_delete_support() {
        // The fake hook records every call; the local config must stay
        // untouched on failures.
        let hook_calls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let hook: DeleteRemoteFn = {
            let hook_calls = Arc::clone(&hook_calls);
            Arc::new(move |_provider, _creds, rec| {
                let hook_calls = Arc::clone(&hook_calls);
                Box::pin(async move {
                    // Mirror fg_dns::delete::pick_targets: refuse when the
                    // record set has other values, else delete.
                    hook_calls.lock().expect("hook").push(rec.fqdn());
                    if rec.value == "9.9.9.9" {
                        return Err(fg_dns::ProviderError::invalid_input(
                            "fake",
                            "服务商处的记录值与最近同步的不一致，未删除",
                        ));
                    }
                    Ok(1)
                })
            })
        };
        // The sync in this test must not leave the test registry: use the
        // fake provider factory (the default factory would call the real
        // Cloudflare API for the configured credentials).
        let (provider_new, provider_calls) = fake_provider_new();
        let deps = crate::runtime::Deps {
            provider_new,
            ..crate::runtime::Deps::default()
        };
        let app = harness_with(deps, Some(hook), provider_calls).await;
        app.create(base_task("task1")).await;
        // Never synced: refused before any provider call.
        let (status, body) = app
            .send(
                "POST",
                "/api/ddns/tasks/task1/remote-delete",
                Some(json!({ "records": ["rec000000001"] })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body["error"].as_str().unwrap().contains("还没有同步过"));
        assert!(hook_calls.lock().expect("hook").is_empty());

        // Sync once, then delete succeeds and reports the count.
        let (_, body) = app.send("POST", "/api/ddns/tasks/task1/sync", None).await;
        assert_eq!(body["ok"], true);
        let (status, body) = app
            .send(
                "POST",
                "/api/ddns/tasks/task1/remote-delete",
                Some(json!({ "records": ["rec000000001"] })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["deleted"], 1);
        assert_eq!(hook_calls.lock().expect("hook").len(), 1);
        // The provider refuses a changed value; the endpoint surfaces the
        // reason and the local config stays unchanged.
        let mut override_value = base_task("task1");
        override_value["ipv4"]["command"] = "echo 9.9.9.9".into();
        let (status, _) = app
            .send("PUT", "/api/ddns/tasks/task1", Some(override_value))
            .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = app.send("POST", "/api/ddns/tasks/task1/sync", None).await;
        assert_eq!(status, StatusCode::OK);
        let saved_before = app.last_saved.lock().expect("slot").clone().expect("saved");
        let (status, body) = app
            .send(
                "POST",
                "/api/ddns/tasks/task1/remote-delete",
                Some(json!({ "records": ["rec000000001"] })),
            )
            .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body["error"].as_str().unwrap().contains("未删除"));
        let saved_after = app.last_saved.lock().expect("slot").clone().expect("saved");
        assert_eq!(
            saved_before, saved_after,
            "remote delete never touches ddns.json"
        );

        // Providers without delete support are refused up front.
        let mut no_delete = base_task("task1");
        no_delete["provider"] = "duckdns".into();
        no_delete["credentials"] = json!({"id": "", "secret": "duck-token"});
        let (status, body) = app
            .send("PUT", "/api/ddns/tasks/task1", Some(no_delete))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = app
            .send(
                "POST",
                "/api/ddns/tasks/task1/remote-delete",
                Some(json!({ "records": ["rec000000001"] })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("不支持删除"));
    }

    #[tokio::test]
    async fn remote_delete_without_capability_is_500() {
        let app = harness().await;
        app.create(base_task("task1")).await;
        let (status, body) = app
            .send(
                "POST",
                "/api/ddns/tasks/task1/remote-delete",
                Some(json!({ "records": ["rec000000001"] })),
            )
            .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body["error"].as_str().unwrap().contains("删除能力"));
    }

    #[tokio::test]
    async fn settings_roundtrip() {
        let app = harness().await;
        let (status, settings) = app.send("GET", "/api/ddns/settings", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(settings["enable"], true);
        assert_eq!(settings["deleteRemote"], false);
        let (status, saved) = app
            .send(
                "PUT",
                "/api/ddns/settings",
                Some(json!({"enable": true, "deleteRemote": true})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{saved}");
        assert_eq!(saved["deleteRemote"], true);
        let (status, body) = app
            .send(
                "PUT",
                "/api/ddns/settings",
                Some(json!({"enable": true, "nope": 1})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid JSON body");
    }

    #[tokio::test]
    async fn providers_defaults_netinterfaces_and_iptest() {
        let app = harness().await;
        let (_, providers) = app.send("GET", "/api/ddns/providers", None).await;
        let providers = providers.as_array().expect("providers");
        assert!(!providers.is_empty());
        let cloudflare = providers
            .iter()
            .find(|provider| provider["name"] == "cloudflare")
            .expect("cloudflare listed");
        assert_eq!(cloudflare["available"], true);
        assert_eq!(cloudflare["supportsDelete"], true);
        assert_eq!(cloudflare["supportsRemark"], true);
        let duckdns = providers
            .iter()
            .find(|provider| provider["name"] == "duckdns")
            .expect("duckdns listed");
        assert_eq!(duckdns["supportsDelete"], false);
        // Every upstream provider is listed exactly once; `available`
        // mirrors registry membership, which depends on the enabled
        // `dns-*` features — workspace-wide test runs unify features, so
        // do not assume any specific provider is unavailable here.
        assert_eq!(providers.len(), fg_dns::ALL_NAMES.len());
        let registry_names: std::collections::HashSet<&str> = fg_dns::registry()
            .iter()
            .map(|(meta, _)| meta.name)
            .collect();
        for provider in &providers {
            let name = provider["name"].as_str().expect("name");
            let expected = registry_names.contains(name);
            assert_eq!(
                provider["available"], expected,
                "availability must match the compiled registry for {name}"
            );
        }

        let (_, defaults) = app.send("GET", "/api/ddns/defaults", None).await;
        assert_eq!(defaults["interval"], 300);
        assert_eq!(defaults["forceInterval"], 3600);
        assert_eq!(defaults["httpTimeout"], 20);
        assert!(defaults["ipv4Urls"].as_array().expect("urls").len() >= 3);
        assert!(defaults["ipv6Urls"].as_array().expect("urls").len() >= 3);

        let (_, interfaces) = app.send("GET", "/api/ddns/netinterfaces", None).await;
        let list = interfaces["interfaces"].as_array().expect("interfaces");
        assert!(!list.is_empty(), "at least the loopback interface exists");

        // iptest runs a command source without touching the network.
        let (status, body) = app
            .send(
                "POST",
                "/api/ddns/iptest",
                Some(json!({
                    "family": "ipv4",
                    "source": {"enable": true, "kind": "command", "command": "echo 4.4.4.4"}
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ip"], "4.4.4.4");
        let (status, body) = app
            .send(
                "POST",
                "/api/ddns/iptest",
                Some(json!({
                    "family": "ipv4",
                    "source": {"enable": true, "kind": "command", "command": "echo nope"}
                })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!body["error"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn invalid_json_and_validation_problems() {
        let app = harness().await;
        let (status, body) = app
            .send("POST", "/api/ddns/tasks", Some(json!({ "nope": true })))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid JSON body");
        // Missing provider credentials surface as problems.
        let mut broken = base_task("bad");
        broken["credentials"]["secret"] = "".into();
        broken["records"][0]["zone"] = "".into();
        let (status, body) = app.send("POST", "/api/ddns/tasks", Some(broken)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid ddns configuration");
        let problems = body["problems"].as_array().expect("problems");
        assert!(problems.iter().any(|problem| {
            problem["field"]
                .as_str()
                .unwrap()
                .ends_with("credentials.secret")
        }));
        assert!(
            problems
                .iter()
                .any(|problem| problem["field"].as_str().unwrap().ends_with(".zone"))
        );
        // Invalid item keys (path shape) are rejected before lookup.
        let (status, body) = app
            .send("DELETE", "/api/ddns/tasks/batch-delete", None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid item key");
    }
}
