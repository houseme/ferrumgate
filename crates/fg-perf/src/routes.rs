//! Performance monitoring management routes (WP-69 §4): overview charts,
//! sites, managed processes, alert rule collection, active alerts, and
//! Prometheus metrics, served with plain axum while mirroring the fg-admin
//! `Collection<T>` contract (JSON shapes, status codes, key handling).
//!
//! Endpoints (permission domain `perf`; upstream carries 19 operations
//! including the 4 generic log endpoints served by fg-admin):
//!
//! | Method | Path | Request | Response |
//! |---|---|---|---|
//! | GET | `/api/perf/overview` | `?range=60s\|1h\|24h` | `{range,step,series,alerts}` |
//! | GET | `/api/perf/sites` | — | `[SiteView]` |
//! | GET | `/api/perf/processes` | `?scope=…` | `{processes,totalCpu,totalRss}` |
//! | GET | `/api/perf/rules` | — | `[AlertRule]` (normalized) |
//! | POST | `/api/perf/rules` | `AlertRule` | created `AlertRule` |
//! | PUT | `/api/perf/rules/{key}` | `AlertRule` | replaced `AlertRule` |
//! | DELETE | `/api/perf/rules/{key}` | — | `{"removed":1}` |
//! | POST | `/api/perf/rules/{key}/copy` | `AlertRule` | created `AlertRule` (fresh key, after source) |
//! | PUT | `/api/perf/rules/{key}/enable` | `{"enable":bool}` | `{"ok":true}` |
//! | POST | `/api/perf/rules-delete` | `{"keys":[…]}` | `{"removed":N}` |
//! | PUT | `/api/perf/rules-enable` | `{"keys":[…],"enable":bool}` | `{"changed":N}` |
//! | PUT | `/api/perf/rules-group` | `{"keys":[…],"group":"…"}` | `{"ok":true}` |
//! | PUT | `/api/perf/rules-order` | `{"keys":[…]}` | `{"ok":true}` |
//! | GET | `/api/perf/alerts` | — | `[ActiveAlertView]` |
//! | GET | `/api/perf/metrics` | — | Prometheus text 0.0.4 |

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::{Path, rejection::PathRejection},
    http::{HeaderValue, StatusCode, Uri, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    model::{AlertRule, FileConfig, Window, limits},
    runtime::PerfService,
    validate::{normalize, random_key, valid_key, validate},
};

/// Shared state behind the perf management routes.
pub struct RoutesState {
    pub service: Arc<PerfService>,
}

/// Adds the perf management routes (`/api/perf/…`) to `router`.
/// Authentication is applied by the surrounding management router
/// (permission domain `perf`).
pub fn mount(router: axum::Router, state: Arc<RoutesState>) -> axum::Router {
    let overview_state = Arc::clone(&state);
    let sites_state = Arc::clone(&state);
    let procs_state = Arc::clone(&state);
    let rules_list_state = Arc::clone(&state);
    let rules_create_state = Arc::clone(&state);
    let rule_replace_state = Arc::clone(&state);
    let rule_delete_state = Arc::clone(&state);
    let rule_copy_state = Arc::clone(&state);
    let rule_enable_state = Arc::clone(&state);
    let rules_order_state = Arc::clone(&state);
    let rules_enable_state = Arc::clone(&state);
    let rules_group_state = Arc::clone(&state);
    let rules_delete_state = Arc::clone(&state);
    let alerts_state = Arc::clone(&state);
    let metrics_state = state;

    router
        .route(
            "/api/perf/overview",
            get(move |uri: Uri| async move { overview_view(overview_state, uri).await }),
        )
        .route(
            "/api/perf/sites",
            get(move || async move { sites_view(sites_state).await }),
        )
        .route(
            "/api/perf/processes",
            get(move |uri: Uri| async move { processes_view(procs_state, uri).await }),
        )
        .route(
            "/api/perf/rules",
            get(move || async move { rules_list(rules_list_state).await }).post(
                move |body: Bytes| async move { rules_create(rules_create_state, body).await },
            ),
        )
        .route(
            "/api/perf/rules/{key}",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    rule_replace(rule_replace_state, path, body).await
                },
            )
            .delete(
                move |path: Result<Path<String>, PathRejection>| async move {
                    rule_delete(rule_delete_state, path).await
                },
            ),
        )
        .route(
            "/api/perf/rules/{key}/copy",
            post(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    rule_copy(rule_copy_state, path, body).await
                },
            ),
        )
        .route(
            "/api/perf/rules/{key}/enable",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    rule_enable(rule_enable_state, path, body).await
                },
            ),
        )
        .route(
            "/api/perf/rules-order",
            put(move |body: Bytes| async move { rules_order(rules_order_state, body).await }),
        )
        .route(
            "/api/perf/rules-enable",
            put(move |body: Bytes| async move {
                rules_batch_enable(rules_enable_state, body).await
            }),
        )
        .route(
            "/api/perf/rules-group",
            put(move |body: Bytes| async move { rules_group(rules_group_state, body).await }),
        )
        .route(
            "/api/perf/rules-delete",
            post(move |body: Bytes| async move {
                rules_batch_delete(rules_delete_state, body).await
            }),
        )
        .route(
            "/api/perf/alerts",
            get(move || async move { alerts_view(alerts_state).await }),
        )
        .route(
            "/api/perf/metrics",
            get(move || async move { metrics_view(metrics_state).await }),
        )
}

fn query_param<'a>(query: Option<&'a str>, name: &str) -> Option<&'a str> {
    query?.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then_some(value)
    })
}

async fn overview_view(state: Arc<RoutesState>, uri: Uri) -> Response {
    let range = query_param(uri.query(), "range").unwrap_or("60s");
    let window = match range {
        "60s" => Window::Min,
        "1h" => Window::Hour,
        "24h" => Window::Day,
        _ => {
            return Failure::Api(
                StatusCode::BAD_REQUEST,
                "invalid range; expected 60s, 1h or 24h".into(),
            )
            .into_response();
        }
    };
    Json(state.service.overview(window)).into_response()
}

async fn sites_view(state: Arc<RoutesState>) -> Response {
    Json(state.service.sites()).into_response()
}

async fn processes_view(state: Arc<RoutesState>, uri: Uri) -> Response {
    let scope = query_param(uri.query(), "scope");
    Json(state.service.processes(scope)).into_response()
}

async fn alerts_view(state: Arc<RoutesState>) -> Response {
    Json(state.service.active_alerts()).into_response()
}

async fn metrics_view(state: Arc<RoutesState>) -> Response {
    let body = state.service.render_metrics();
    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

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
                    "error": "invalid perf configuration",
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

#[allow(clippy::result_large_err)]
async fn mutate<T>(
    state: &RoutesState,
    change: impl FnOnce(&mut FileConfig) -> Change<T> + Send + 'static,
) -> Result<T, Response> {
    let config_lock = state.service.config();
    let mut guard = config_lock.write().await;
    let mut candidate = guard.clone();
    let (value, changed) = change(&mut candidate).map_err(Response::from)?;
    if changed {
        let persist = Arc::clone(state.service.persist());
        let saved = candidate.clone();
        tokio::task::spawn_blocking(move || persist(&saved))
            .await
            .map_err(|_| internal())?
            .map_err(|error| {
                tracing::warn!(%error, "persisting perf.json failed");
                internal()
            })?;
        let rules_snapshot = candidate.rules.clone();
        *guard = candidate;
        drop(guard);
        state.service.sync_rules(&rules_snapshot);
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

fn decode_error() -> Response {
    Failure::Api(StatusCode::BAD_REQUEST, "invalid JSON body".into()).into_response()
}

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

fn missing_item() -> Failure {
    Failure::Api(StatusCode::NOT_FOUND, "item not found".into())
}

fn generate_key(existing: &[AlertRule]) -> Result<String, Failure> {
    random_key(existing)
        .map_err(|error| Failure::Api(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))
}

fn locate(config: &FileConfig, key: &str) -> Result<usize, Failure> {
    config
        .rules
        .iter()
        .position(|rule| rule.key == key)
        .ok_or_else(missing_item)
}

fn find_indices(rules: &[AlertRule], keys: &[String]) -> Option<Vec<usize>> {
    let mut slots: HashMap<&str, usize> = keys
        .iter()
        .enumerate()
        .map(|(slot, key)| (key.as_str(), slot))
        .collect();
    if slots.len() != keys.len() {
        return None;
    }
    let mut indices = vec![0; keys.len()];
    for (index, rule) in rules.iter().enumerate() {
        if let Some(slot) = slots.remove(rule.key.as_str()) {
            indices[slot] = index;
            if slots.is_empty() {
                break;
            }
        }
    }
    slots.is_empty().then_some(indices)
}

async fn rules_list(state: Arc<RoutesState>) -> Response {
    let config_lock = state.service.config();
    let config = normalize(config_lock.read().await.clone());
    Json(config.rules).into_response()
}

async fn rules_create(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(mut rule) = serde_json::from_slice::<AlertRule>(&body) else {
        return decode_error();
    };
    match mutate(&state, move |config| {
        let key_normalized = rule.key.trim().to_lowercase();
        let duplicate = config.rules.iter().any(|item| item.key == key_normalized);
        if !valid_key(&key_normalized) || duplicate {
            rule.key = generate_key(&config.rules)?;
        } else {
            rule.key = key_normalized;
        }
        config.rules.push(rule);
        settle(config)?;
        let created = config.rules.last().cloned().ok_or_else(|| {
            Failure::Api(StatusCode::INTERNAL_SERVER_ERROR, "item missing".into())
        })?;
        Ok((Json(created), true))
    })
    .await
    {
        Ok(created) => created.into_response(),
        Err(response) => response,
    }
}

async fn rule_replace(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(mut rule) = serde_json::from_slice::<AlertRule>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into_response();
    };
    match mutate(&state, move |config| {
        let index = locate(config, &key)?;
        rule.key = key;
        config.rules[index] = rule;
        settle(config)?;
        let replaced = config.rules[index].clone();
        Ok((Json(replaced), true))
    })
    .await
    {
        Ok(replaced) => replaced.into_response(),
        Err(response) => response,
    }
}

async fn rule_delete(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into_response();
    };
    match mutate(&state, move |config| {
        let index = locate(config, &key)?;
        config.rules.remove(index);
        Ok((Json(json!({ "removed": 1 })), true))
    })
    .await
    {
        Ok(removed) => removed.into_response(),
        Err(response) => response,
    }
}

async fn rule_copy(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(mut copy) = serde_json::from_slice::<AlertRule>(&body) else {
        return decode_error();
    };
    let Ok(source) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into_response();
    };
    match mutate(&state, move |config| {
        let index = locate(config, &source)?;
        copy.key = generate_key(&config.rules)?;
        config.rules.insert(index + 1, copy);
        settle(config)?;
        let created = config.rules[index + 1].clone();
        Ok((Json(created), true))
    })
    .await
    {
        Ok(created) => created.into_response(),
        Err(response) => response,
    }
}

async fn rule_enable(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(Enable { enable }) = serde_json::from_slice::<Enable>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into_response();
    };
    match mutate(&state, move |config| {
        let index = locate(config, &key)?;
        let changed = config.rules[index].enable != enable;
        config.rules[index].enable = enable;
        Ok((Json(json!({ "ok": true })), changed))
    })
    .await
    {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

async fn rules_batch_enable(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(BatchEnable { keys, enable }) = serde_json::from_slice::<BatchEnable>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys".into(),
        )
        .into_response();
    };
    match mutate(&state, move |config| {
        let indices = find_indices(&config.rules, &keys).ok_or_else(missing_item)?;
        let mut changed = 0;
        for index in indices {
            if config.rules[index].enable != enable {
                config.rules[index].enable = enable;
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

async fn rules_order(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Keys { keys }) = serde_json::from_slice::<Keys>(&body) else {
        return decode_error();
    };
    match mutate(&state, move |config| {
        if keys.len() != config.rules.len() {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                "order must include every item once".into(),
            ));
        }
        let Some(indices) = find_indices(&config.rules, &keys) else {
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
                config.rules.swap(index, new);
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

async fn rules_group(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Group { keys, group }) = serde_json::from_slice::<Group>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys".into(),
        )
        .into_response();
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
        .into_response();
    }
    match mutate(&state, move |config| {
        let indices = find_indices(&config.rules, &keys).ok_or_else(missing_item)?;
        let mut changed = false;
        for index in indices {
            if config.rules[index].group != name {
                config.rules[index].group.clone_from(&name);
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

async fn rules_batch_delete(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Keys { keys }) = serde_json::from_slice::<Keys>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys".into(),
        )
        .into_response();
    };
    match mutate(&state, move |config| {
        find_indices(&config.rules, &keys).ok_or_else(missing_item)?;
        let removed: HashSet<&str> = keys.iter().map(String::as_str).collect();
        config
            .rules
            .retain(|rule| !removed.contains(rule.key.as_str()));
        let count = keys.len();
        Ok((Json(json!({ "removed": count })), true))
    })
    .await
    {
        Ok(removed) => removed.into_response(),
        Err(response) => response,
    }
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
