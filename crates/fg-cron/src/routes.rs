//! Cron management routes (WP-62 §4): the task collection, run-now and the
//! spec parser, served with plain axum while mirroring the fg-admin
//! `Collection<T>` contract (JSON shapes, status codes, key handling) —
//! the module cannot depend on fg-admin, so the shapes are reimplemented
//! here against [`crate::model::FileConfig`] instead of `ConfigStore`.
//!
//! Endpoints (permission domain `cron`; the 4 generic log endpoints
//! `GET|DELETE /api/cron/logs`, `GET /api/cron/logs/export`,
//! `GET /api/cron/logs/sources` are served by fg-admin and not mounted
//! here):
//!
//! | Method | Path | Request | Response |
//! |---|---|---|---|
//! | GET | `/api/cron/tasks` | — | `[TaskView]` (normalized, with read-only `history`) |
//! | POST | `/api/cron/tasks` | `Task` | created `TaskView` |
//! | POST | `/api/cron/tasks/{key}/copy` | `Task` | created `TaskView` (fresh key, inserted after the source) |
//! | PUT | `/api/cron/tasks/{key}` | `Task` | replaced `TaskView` |
//! | DELETE | `/api/cron/tasks/{key}` | — | `{"removed":1}` |
//! | PUT | `/api/cron/tasks/{key}/enable` | `{"enable":bool}` | `{"ok":true}` |
//! | PUT | `/api/cron/tasks-order` | `{"keys":[…]}` full ordered list | `{"ok":true}` |
//! | PUT | `/api/cron/tasks-enable` | `{"keys":[…],"enable":bool}` | `{"changed":N}` |
//! | PUT | `/api/cron/tasks-group` | `{"keys":[…],"group":"…"}` | `{"ok":true}` |
//! | POST | `/api/cron/tasks-delete` | `{"keys":[…]}` | `{"removed":N}` |
//! | POST | `/api/cron/tasks/{key}/run` | — | run `RecordView`, or `{"ok":true,"skipped":true}` when the previous run is still going, or `500 {"error":…}` on failure |
//! | POST | `/api/cron/parse` | `{"spec":"…"}` | `{"ok":true,"description":"…"}` |
//!
//! There is no settings endpoint and no standalone history endpoint: the
//! run history is a read-only `history` field on each listed task
//! (`started` in UTC RFC 3339, `durationMs`, `success`, `manual`,
//! `skipped`, `output`). Every mutation runs normalize → validate → apply
//! → persist → on_change; validation problems are returned as `400` with
//! the collected list (`{"error":…,"problems":[{"field":…,"reason":…}]}`).
//! Batch bodies carry at most 500 keys and all must exist before anything
//! is saved. Task keys follow the fg-admin collection convention: 12
//! lowercase hex characters generated on create/copy; a client-supplied
//! valid unique key is kept on create and always regenerated on copy.
//!
//! Authentication is NOT performed here: [`mount`] routes are meant to be
//! mounted under the management router built by the assembler, whose
//! per-route `authorize` layer authenticates sessions/tokens and maps the
//! first path segment to the `cron` domain (GET → `cron:read`, every
//! mutation → `cron:write`).

use std::{collections::HashMap, sync::Arc};

use axum::{
    Json,
    body::Bytes,
    extract::{Path, rejection::PathRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::Deserialize;
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use tokio::sync::RwLock;

use crate::{
    history::RunRecord,
    model::{FileConfig, Task, limits},
    runtime::{RunNow, Scheduler},
    schedule,
    validate::{normalize, validate},
};

/// Writes the whole [`FileConfig`] to `cron.json`.
pub type PersistFn = Arc<dyn Fn(&FileConfig) -> anyhow::Result<()> + Send + Sync>;

/// Shared state behind the cron management routes.
///
/// `config` is the live desired snapshot (already normalized once loaded);
/// `persist` writes it and is invoked with the normalized candidate before
/// the snapshot advances; `on_change` tells the scheduler to restart the
/// per-task loops; `scheduler` answers run-now and history reads.
pub struct RoutesState {
    pub config: Arc<RwLock<FileConfig>>,
    pub on_change: Arc<dyn Fn() + Send + Sync>,
    pub persist: PersistFn,
    pub scheduler: Arc<Scheduler>,
}

/// A task as listed by the API: the stored task plus its read-only run
/// history.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskView {
    #[serde(flatten)]
    pub task: Task,
    pub history: Vec<RecordView>,
}

/// One run-history entry (`started` in UTC RFC 3339).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordView {
    pub started: String,
    pub duration_ms: u64,
    pub success: bool,
    pub manual: bool,
    pub skipped: bool,
    pub output: String,
}

fn record_view(record: &RunRecord) -> RecordView {
    RecordView {
        started: record
            .started
            .format(&Rfc3339)
            .unwrap_or_else(|_| record.started.to_string()),
        duration_ms: u64::try_from(record.duration.as_millis()).unwrap_or(u64::MAX),
        success: record.success,
        manual: record.manual,
        skipped: record.skipped,
        output: record.output.clone(),
    }
}

fn task_view(task: Task, scheduler: &Scheduler) -> TaskView {
    let history = scheduler
        .history(&task.key)
        .iter()
        .map(record_view)
        .collect();
    TaskView { task, history }
}

/// Adds the cron collection, run-now and parser routes to `router`.
///
/// See the module docs for the endpoint contract and the authentication
/// assumption: the returned routes carry no auth of their own and rely on
/// the management router's authorize layer being applied to them.
pub fn mount(router: axum::Router, state: Arc<RoutesState>) -> axum::Router {
    let (list, create) = (state.clone(), state.clone());
    let (replace, remove) = (state.clone(), state.clone());
    let (copy, enable) = (state.clone(), state.clone());
    let (run, order) = (state.clone(), state.clone());
    let (batch_enable, group) = (state.clone(), state.clone());
    let (batch_delete, parse) = (state.clone(), state);
    router
        .route(
            "/api/cron/tasks",
            get(move || async move { tasks_list(list).await })
                .post(move |body: Bytes| async move { tasks_create(create, body).await }),
        )
        .route(
            "/api/cron/tasks/{key}",
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
            "/api/cron/tasks/{key}/copy",
            post(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    tasks_copy(copy, path, body).await
                },
            ),
        )
        .route(
            "/api/cron/tasks/{key}/enable",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    tasks_enable(enable, path, body).await
                },
            ),
        )
        .route(
            "/api/cron/tasks/{key}/run",
            post(
                move |path: Result<Path<String>, PathRejection>| async move {
                    tasks_run(run, path).await
                },
            ),
        )
        .route(
            "/api/cron/tasks-order",
            put(move |body: Bytes| async move { tasks_order(order, body).await }),
        )
        .route(
            "/api/cron/tasks-enable",
            put(move |body: Bytes| async move { tasks_batch_enable(batch_enable, body).await }),
        )
        .route(
            "/api/cron/tasks-group",
            put(move |body: Bytes| async move { tasks_group(group, body).await }),
        )
        .route(
            "/api/cron/tasks-delete",
            post(move |body: Bytes| async move { tasks_batch_delete(batch_delete, body).await }),
        )
        .route(
            "/api/cron/parse",
            post(move |body: Bytes| async move { parse_spec(parse, body).await }),
        )
}

/// A failed mutation: either a plain status/message pair shaped like the
/// fg-admin `ApiError` body, or the collected validation problems.
enum Failure {
    Api(StatusCode, String),
    Problems(Vec<crate::validate::Problem>),
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
                    "error": "invalid cron configuration",
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
                tracing::warn!(%error, "persisting cron.json failed");
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
    *config = normalize(std::mem::take(config));
    let problems = validate(config);
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

/// Same key contract as the fg-admin collections: short, URL-safe, and not
/// colliding with batch-style path suffixes.
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
    let mut seen = std::collections::HashSet::new();
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

/// 12 lowercase hex characters, unique within the collection — the same
/// shape the fg-admin collections generate.
fn random_key(tasks: &[Task]) -> Result<String, Failure> {
    for _ in 0..8 {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes[2..]).map_err(|_| {
            Failure::Api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key generation failed".into(),
            )
        })?;
        let key = format!("{:012x}", u64::from_be_bytes(bytes));
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
    let config = normalize(guard.clone());
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
        // Copies always receive a generated key (fg-admin collection
        // behavior): the template only determines the insertion position.
        task.key = random_key(&config.tasks)?;
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

async fn tasks_run(state: Arc<RoutesState>, path: Result<Path<String>, PathRejection>) -> Response {
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
    match state.scheduler.run_now(&key).await {
        RunNow::NotFound => missing_item().into(),
        RunNow::Busy => Json(json!({ "ok": true, "skipped": true })).into_response(),
        RunNow::Record(record) => {
            let view = record_view(&record);
            if record.success {
                Json(view).into_response()
            } else {
                let message = if record.output.is_empty() {
                    "任务执行失败".to_owned()
                } else {
                    record.output
                };
                Failure::Api(StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
        }
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
        let removed: std::collections::HashSet<_> = keys.iter().map(String::as_str).collect();
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

async fn parse_spec(_state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(ParseRequest { spec }) = serde_json::from_slice::<ParseRequest>(&body) else {
        return decode_error();
    };
    match schedule::parse(&spec) {
        Ok(parsed) => Json(json!({ "ok": true, "description": parsed.describe() })).into_response(),
        Err(error) => Failure::Api(StatusCode::BAD_REQUEST, error.0).into_response(),
    }
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
struct ParseRequest {
    spec: String,
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

    /// A mounted router over an in-memory store, counting persist calls.
    struct Harness {
        addr: std::net::SocketAddr,
        persists: Arc<AtomicUsize>,
        last_saved: Arc<Mutex<Option<FileConfig>>>,
    }

    async fn harness() -> Harness {
        let persists = Arc::new(AtomicUsize::new(0));
        let last_saved: Arc<Mutex<Option<FileConfig>>> = Arc::new(Mutex::new(None));
        let config = Arc::new(RwLock::new(FileConfig::default()));
        let scheduler = Arc::new(Scheduler::new(config.clone(), None));
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
            on_change,
            persist,
            scheduler,
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
        }
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
            let (status, body) = self.send("POST", "/api/cron/tasks", Some(task)).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body
        }

        async fn keys(&self) -> Vec<String> {
            let (_, body) = self.send("GET", "/api/cron/tasks", None).await;
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
            "spec": "@daily",
            "type": "command",
            "command": "echo ok",
            "remark": ""
        })
    }

    fn base_http_task(key: &str) -> serde_json::Value {
        json!({
            "key": key,
            "name": if key.is_empty() { "http task" } else { key },
            "group": "",
            "enable": false,
            "spec": "*/5 * * * *",
            "type": "http",
            "command": "",
            "http": {
                "url": "https://example.com/hook",
                "method": "POST",
                "headers": ["X-Token: abc"],
                "body": "",
                "successContent": ["ok"],
                "timeout": 0,
                "insecureSkipVerify": false
            },
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
    async fn create_keeps_valid_unique_key_and_lists_with_history() {
        let app = harness().await;
        let created = app.create(base_task("")).await;
        assert!(
            is_generated_key(created["key"].as_str().expect("key")),
            "{created}"
        );
        // The view carries the read-only history field.
        assert_eq!(created["history"], serde_json::json!([]));
        assert_eq!(created["spec"], "@daily");
        let (status, tasks) = app.send("GET", "/api/cron/tasks", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tasks.as_array().expect("array").len(), 1);
        assert_eq!(tasks[0]["key"], created["key"]);
        // A valid unique client key is kept; a duplicate one is regenerated.
        let kept = app.create(base_task("web")).await;
        assert_eq!(kept["key"], "web");
        let clash = app.create(base_task("web")).await;
        assert!(is_generated_key(clash["key"].as_str().expect("key")));
        // The persist hook received the normalized candidate (three tasks).
        let saved = app
            .last_saved
            .lock()
            .expect("slot")
            .clone()
            .expect("persisted");
        assert_eq!(saved.tasks.len(), 3);
        let app = harness().await;
        let created = app.create(base_http_task("")).await;
        assert_eq!(created["http"]["timeout"], 30, "timeout: 0 normalizes");
        assert_eq!(created["http"]["successContent"], serde_json::json!(["ok"]));
    }

    #[tokio::test]
    async fn update_replaces_and_missing_key_is_404() {
        let app = harness().await;
        let created = app.create(base_task("job")).await;
        let mut replacement = base_task("ignored");
        replacement["name"] = "renamed".into();
        replacement["spec"] = "0 9 * * *".into();
        let (status, body) = app
            .send("PUT", "/api/cron/tasks/job", Some(replacement))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["key"], "job", "the path key wins over the body key");
        assert_eq!(body["name"], "renamed");
        let (status, body) = app
            .send("PUT", "/api/cron/tasks/nope", Some(base_task("nope")))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "item not found");
        drop(created);
    }

    #[tokio::test]
    async fn copy_assigns_fresh_key_after_source() {
        let app = harness().await;
        app.create(base_task("first")).await;
        app.create(base_task("second")).await;
        let (status, copied) = app
            .send(
                "POST",
                "/api/cron/tasks/first/copy",
                Some(base_task("first")),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{copied}");
        assert!(is_generated_key(copied["key"].as_str().expect("key")));
        assert_eq!(
            app.keys().await,
            ["first", copied["key"].as_str().unwrap(), "second"]
        );
    }

    #[tokio::test]
    async fn enable_single_ok_and_batch_reports_changed() {
        let app = harness().await;
        app.create(base_task("a")).await;
        app.create(base_task("b")).await;
        let (status, body) = app
            .send(
                "PUT",
                "/api/cron/tasks/a/enable",
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
                "/api/cron/tasks/a/enable",
                Some(json!({ "enable": true })),
            )
            .await;
        assert_eq!(body["ok"], true);
        assert_eq!(app.persists.load(Ordering::SeqCst), persists_before);
        let (status, body) = app
            .send(
                "PUT",
                "/api/cron/tasks-enable",
                Some(json!({ "keys": ["a", "b"], "enable": true })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["changed"], 1, "a was already on, b flipped");
        let (_, body) = app
            .send(
                "PUT",
                "/api/cron/tasks-enable",
                Some(json!({ "keys": ["a", "b"], "enable": true })),
            )
            .await;
        assert_eq!(body["changed"], 0);
        let (status, body) = app
            .send(
                "PUT",
                "/api/cron/tasks-enable",
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
                "/api/cron/tasks-order",
                Some(json!({ "keys": ["b"] })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "order must include every item once");
        let (status, _) = app
            .send(
                "PUT",
                "/api/cron/tasks-order",
                Some(json!({ "keys": ["b", "ghost"] })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = app
            .send(
                "PUT",
                "/api/cron/tasks-order",
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
                "/api/cron/tasks-group",
                Some(json!({ "keys": ["a", "b"], "group": "夜间" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        let (_, tasks) = app.send("GET", "/api/cron/tasks", None).await;
        assert!(
            tasks
                .as_array()
                .unwrap()
                .iter()
                .all(|task| task["group"] == "夜间")
        );
        let (status, _) = app
            .send(
                "POST",
                "/api/cron/tasks-delete",
                Some(json!({ "keys": ["a", "ghost"] })),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "no partial removals");
        let (status, body) = app
            .send(
                "POST",
                "/api/cron/tasks-delete",
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
                "/api/cron/tasks-delete",
                Some(json!({ "keys": many })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "expected between 1 and 500 valid keys");
    }

    #[tokio::test]
    async fn parse_endpoint_returns_description_or_error() {
        let app = harness().await;
        let (status, body) = app
            .send(
                "POST",
                "/api/cron/parse",
                Some(json!({ "spec": "*/10 * * * *" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], true);
        assert_eq!(body["description"], "每 10 分钟");
        let (status, body) = app
            .send(
                "POST",
                "/api/cron/parse",
                Some(json!({ "spec": "61 * * * *" })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().expect("error").contains("范围"));
        let (status, _) = app
            .send("POST", "/api/cron/parse", Some(json!({ "nope": 1 })))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_now_returns_record_and_records_history() {
        let app = harness().await;
        let mut task = base_task("");
        task["enable"] = true.into();
        task["spec"] = "@daily".into();
        let created = app.create(task).await;
        let key = created["key"].as_str().expect("key").to_owned();
        let (status, body) = app
            .send("POST", &format!("/api/cron/tasks/{key}/run"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["manual"], true);
        assert_eq!(body["success"], true);
        assert_eq!(body["output"].as_str().expect("output").trim_end(), "ok");
        // The history is served with the task list.
        let (_, tasks) = app.send("GET", "/api/cron/tasks", None).await;
        assert_eq!(tasks[0]["history"].as_array().expect("history").len(), 1);
        assert_eq!(tasks[0]["history"][0]["manual"], true);
        assert_eq!(tasks[0]["history"][0]["skipped"], false);
        // Failures surface as errors but are recorded too.
        let mut failing = base_task("");
        failing["command"] = "exit 3".into();
        let failing = app.create(failing).await;
        let failing_key = failing["key"].as_str().expect("key").to_owned();
        let (status, _) = app
            .send("POST", &format!("/api/cron/tasks/{failing_key}/run"), None)
            .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let (_, tasks) = app.send("GET", "/api/cron/tasks", None).await;
        let failed = tasks
            .as_array()
            .unwrap()
            .iter()
            .find(|task| task["key"] == failing_key.as_str())
            .expect("task");
        assert_eq!(failed["history"][0]["success"], false);
        // Missing task: 404.
        let (status, body) = app.send("POST", "/api/cron/tasks/ghost/run", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "item not found");
    }

    #[tokio::test]
    async fn invalid_json_and_unknown_fields_are_rejected() {
        let app = harness().await;
        let (status, body) = app
            .send("POST", "/api/cron/tasks", Some(json!({ "nope": true })))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid JSON body");
        let (status, body) = app
            .send(
                "PUT",
                "/api/cron/tasks-order",
                Some(json!({ "keys": [], "extra": 1 })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid JSON body");
        let (status, _) = app
            .send(
                "PUT",
                "/api/cron/tasks/a/enable",
                Some(json!({ "enable": "yes" })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Invalid item keys (path shape) are rejected before lookup.
        let (status, body) = app
            .send("DELETE", "/api/cron/tasks/batch-delete", None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid item key");
    }

    #[tokio::test]
    async fn invalid_spec_is_rejected_with_problems() {
        let app = harness().await;
        let mut task = base_task("bad");
        task["spec"] = "* * * *".into();
        let (status, body) = app.send("POST", "/api/cron/tasks", Some(task)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid cron configuration");
        let problems = body["problems"].as_array().expect("problems");
        assert!(
            problems
                .iter()
                .any(|problem| problem["field"].as_str().unwrap().ends_with(".spec"))
        );
    }
}
