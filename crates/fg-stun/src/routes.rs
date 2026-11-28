//! STUN management routes (WP-42 §4): the rule collection, the settings
//! and the interface list, served with plain axum while mirroring the
//! fg-admin `Collection<T>` contract (JSON shapes, status codes, key
//! handling) — the module cannot depend on fg-admin, so the shapes are
//! reimplemented here against [`crate::model::FileConfig`].
//!
//! Endpoints (permission domain `stun`; the 4 generic log endpoints
//! `GET|DELETE /api/stun/logs`, `GET /api/stun/logs/export`,
//! `GET /api/stun/logs/sources` are served by fg-admin and not mounted
//! here — together they make up the upstream 18 operations):
//!
//! | Method | Path | Request | Response |
//! |---|---|---|---|
//! | GET | `/api/stun/rules` | — | `[RuleView]` (normalized, with read-only `status`) |
//! | POST | `/api/stun/rules` | `Rule` | created `RuleView` |
//! | POST | `/api/stun/rules/{key}/copy` | `Rule` | created `RuleView` (fresh key, inserted after the source) |
//! | PUT | `/api/stun/rules/{key}` | `Rule` | replaced `RuleView` |
//! | DELETE | `/api/stun/rules/{key}` | — | `{"removed":1}` |
//! | PUT | `/api/stun/rules/{key}/enable` | `{"enable":bool}` | `{"ok":true}` |
//! | POST | `/api/stun/rules/{key}/restart` | — | `{"ok":true,"started":bool}` |
//! | PUT | `/api/stun/rules-order` | `{"keys":[…]}` full ordered list | `{"ok":true}` |
//! | PUT | `/api/stun/rules-enable` | `{"keys":[…],"enable":bool}` | `{"changed":N}` |
//! | PUT | `/api/stun/rules-group` | `{"keys":[…],"group":"…"}` | `{"ok":true}` |
//! | POST | `/api/stun/rules-delete` | `{"keys":[…]}` | `{"removed":N}` |
//! | GET | `/api/stun/settings` | — | normalized `Settings` |
//! | PUT | `/api/stun/settings` | `Settings` | normalized `Settings` |
//! | GET | `/api/stun/netinterfaces` | — | `[{name, ip, loopback}]` |
//!
//! The channel status lives in the read-only `status` field of each listed
//! rule (public endpoint, state, NAT consistency, firewall text, last
//! error) — there is no separate status or module-metrics endpoint; the
//! metrics go through the global `GET /api/metrics`. Every mutation runs
//! normalize → validate → apply → persist → on_change; validation problems
//! are returned as `400` with the collected list. Batch bodies carry at
//! most 500 keys and all must exist before anything is saved. Rule keys
//! follow the fg-admin collection convention: 12 lowercase hex characters
//! generated on create/copy; a client-supplied valid unique key is kept on
//! create and always regenerated on copy.
//!
//! Authentication is NOT performed here: [`mount`] routes are meant to be
//! mounted under the management router built by the assembler, whose
//! per-route `authorize` layer authenticates sessions/tokens and maps the
//! first path segment to the `stun` domain (GET → `stun:read`, every
//! mutation → `stun:write`).

use std::sync::Arc;

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
use tokio::sync::RwLock as AsyncRwLock;

use crate::{
    model::{FileConfig, Rule, Settings, limits},
    runtime::Runtime,
    validate::{normalize, validate},
};

/// Writes the whole [`FileConfig`] to `stun.json`.
pub type PersistFn = Arc<dyn Fn(&FileConfig) -> anyhow::Result<()> + Send + Sync>;

/// Shared state behind the STUN management routes.
pub struct RoutesState {
    /// The live desired snapshot (already normalized once loaded).
    pub config: Arc<AsyncRwLock<FileConfig>>,
    pub on_change: Arc<dyn Fn() + Send + Sync>,
    pub persist: PersistFn,
    pub runtime: Arc<Runtime>,
}

/// A rule as listed by the API: the stored rule plus its read-only channel
/// status.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleView {
    #[serde(flatten)]
    pub rule: Rule,
    pub status: StatusView,
}

/// Read-only channel status of one rule (WP-42 §3.3 rule card data).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusView {
    pub state: String,
    pub local_addr: Option<String>,
    pub public_addr: Option<String>,
    pub since: Option<String>,
    pub nat_consistent: Option<bool>,
    pub firewall: String,
    pub last_error: Option<String>,
}

fn rule_view(rule: Rule, runtime: &Runtime) -> RuleView {
    let entry = runtime
        .snapshot()
        .entries
        .iter()
        .find(|entry| entry.key == rule.key)
        .cloned();
    let status = match entry {
        Some(entry) => StatusView {
            state: entry.state.to_owned(),
            local_addr: entry.local_addr.map(|addr| addr.to_string()),
            public_addr: entry.public_addr.map(|addr| addr.to_string()),
            since: entry.since.and_then(rfc3339),
            nat_consistent: entry.nat_consistent,
            firewall: entry.firewall,
            last_error: entry.last_error,
        },
        None => StatusView {
            state: if rule.enable { "stopped" } else { "disabled" }.to_owned(),
            local_addr: None,
            public_addr: None,
            since: None,
            nat_consistent: None,
            firewall: runtime.firewall_status(&rule.key),
            last_error: None,
        },
    };
    RuleView { rule, status }
}

/// UTC RFC 3339 rendering for status timestamps.
pub fn rfc3339(at: std::time::SystemTime) -> Option<String> {
    let datetime: time::OffsetDateTime = at.into();
    datetime.format(&Rfc3339).ok()
}

/// Adds the STUN collection, settings and helper routes to `router`.
///
/// See the module docs for the endpoint contract and the authentication
/// assumption: the returned routes carry no auth of their own and rely on
/// the management router's authorize layer being applied to them.
pub fn mount(router: axum::Router, state: Arc<RoutesState>) -> axum::Router {
    let (list, create) = (state.clone(), state.clone());
    let (replace, remove) = (state.clone(), state.clone());
    let (copy, enable) = (state.clone(), state.clone());
    let (restart, order) = (state.clone(), state.clone());
    let (batch_enable, group) = (state.clone(), state.clone());
    let (batch_delete, settings_get) = (state.clone(), state.clone());
    let (settings_put, interfaces) = (state.clone(), state);
    router
        .route(
            "/api/stun/rules",
            get(move || async move { rules_list(list).await })
                .post(move |body: Bytes| async move { rules_create(create, body).await }),
        )
        .route(
            "/api/stun/rules/{key}",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    rules_update(replace, path, body).await
                },
            )
            .delete(
                move |path: Result<Path<String>, PathRejection>| async move {
                    rules_delete(remove, path).await
                },
            ),
        )
        .route(
            "/api/stun/rules/{key}/copy",
            post(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    rules_copy(copy, path, body).await
                },
            ),
        )
        .route(
            "/api/stun/rules/{key}/enable",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    rules_enable(enable, path, body).await
                },
            ),
        )
        .route(
            "/api/stun/rules/{key}/restart",
            post(
                move |path: Result<Path<String>, PathRejection>| async move {
                    rules_restart(restart, path).await
                },
            ),
        )
        .route(
            "/api/stun/rules-order",
            put(move |body: Bytes| async move { rules_order(order, body).await }),
        )
        .route(
            "/api/stun/rules-enable",
            put(move |body: Bytes| async move { rules_batch_enable(batch_enable, body).await }),
        )
        .route(
            "/api/stun/rules-group",
            put(move |body: Bytes| async move { rules_group(group, body).await }),
        )
        .route(
            "/api/stun/rules-delete",
            post(move |body: Bytes| async move { rules_batch_delete(batch_delete, body).await }),
        )
        .route(
            "/api/stun/settings",
            get(move || async move { settings_view(settings_get).await })
                .put(move |body: Bytes| async move { settings_save(settings_put, body).await }),
        )
        .route(
            "/api/stun/netinterfaces",
            get(move || async move { netinterfaces(interfaces).await }),
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
                    "error": "invalid stun configuration",
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
                tracing::warn!(module = "stun", %error, "persisting stun.json failed");
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

fn locate(rules: &[Rule], key: &str) -> Result<usize, Failure> {
    rules
        .iter()
        .position(|rule| rule.key == key)
        .ok_or_else(|| Failure::Api(StatusCode::NOT_FOUND, "item not found".into()))
}

fn missing_item() -> Failure {
    Failure::Api(StatusCode::NOT_FOUND, "item not found".into())
}

/// Maps requested keys (each once) onto rule positions; `None` when a key
/// is unknown or duplicated.
fn find_indices(rules: &[Rule], keys: &[String]) -> Option<Vec<usize>> {
    let mut slots: std::collections::HashMap<_, _> = keys
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

/// 12 lowercase hex characters, unique within the collection — the same
/// shape the fg-admin collections generate.
fn random_key(rules: &[Rule]) -> Result<String, Failure> {
    for _ in 0..8 {
        let mut bytes = [0u8; 6];
        getrandom::fill(&mut bytes).map_err(|_| {
            Failure::Api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key generation failed".into(),
            )
        })?;
        let key: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        if !rules.iter().any(|rule| rule.key == key) {
            return Ok(key);
        }
    }
    Err(Failure::Api(
        StatusCode::INTERNAL_SERVER_ERROR,
        "unable to generate a unique rule key".into(),
    ))
}

async fn rules_list(state: Arc<RoutesState>) -> Response {
    let guard = state.config.read().await;
    let config = normalize(guard.clone());
    let views: Vec<RuleView> = config
        .rules
        .iter()
        .map(|rule| rule_view(rule.clone(), &state.runtime))
        .collect();
    Json(views).into_response()
}

async fn rules_create(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(rule) = serde_json::from_slice::<Rule>(&body) else {
        return decode_error();
    };
    let runtime = Arc::clone(&state.runtime);
    match mutate(&state, move |config| {
        let mut rule = rule;
        // A client-supplied valid unique key is kept; anything else gets a
        // generated one (fg-admin collection behavior on create).
        if !valid_key(&rule.key) || config.rules.iter().any(|row| row.key == rule.key) {
            rule.key = random_key(&config.rules)?;
        }
        config.rules.push(rule);
        settle(config)?;
        let created = config.rules.last().cloned().expect("just pushed");
        let view = rule_view(created, &runtime);
        Ok((Json(view), true))
    })
    .await
    {
        Ok(created) => created.into_response(),
        Err(response) => response,
    }
}

async fn rules_copy(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(mut rule) = serde_json::from_slice::<Rule>(&body) else {
        return decode_error();
    };
    let Ok(source) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let runtime = Arc::clone(&state.runtime);
    match mutate(&state, move |config| {
        let index = locate(&config.rules, &source)?;
        // Copies always receive a generated key (fg-admin collection
        // behavior): the template only determines the insertion position.
        rule.key = random_key(&config.rules)?;
        config.rules.insert(index + 1, rule);
        settle(config)?;
        let created = config.rules[index + 1].clone();
        let view = rule_view(created, &runtime);
        Ok((Json(view), true))
    })
    .await
    {
        Ok(created) => created.into_response(),
        Err(response) => response,
    }
}

async fn rules_update(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(mut rule) = serde_json::from_slice::<Rule>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let runtime = Arc::clone(&state.runtime);
    match mutate(&state, move |config| {
        let index = locate(&config.rules, &key)?;
        rule.key = key.clone();
        config.rules[index] = rule;
        settle(config)?;
        let replaced = config.rules[index].clone();
        let view = rule_view(replaced, &runtime);
        Ok((Json(view), true))
    })
    .await
    {
        Ok(replaced) => replaced.into_response(),
        Err(response) => response,
    }
}

async fn rules_delete(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    match mutate(&state, move |config| {
        let index = locate(&config.rules, &key)?;
        config.rules.remove(index);
        Ok((Json(json!({ "removed": 1 })), true))
    })
    .await
    {
        Ok(removed) => removed.into_response(),
        Err(response) => response,
    }
}

async fn rules_enable(
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
        let index = locate(&config.rules, &key)?;
        let rule = &mut config.rules[index];
        let changed = rule.enable != enable;
        rule.enable = enable;
        Ok((Json(json!({ "ok": true })), changed))
    })
    .await
    {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

async fn rules_restart(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    // The stored (normalized) config decides existence.
    let exists = state
        .config
        .read()
        .await
        .rules
        .iter()
        .any(|rule| rule.key == key);
    if !exists {
        return missing_item().into();
    }
    let started = state.runtime.restart(&key).await;
    Json(json!({ "ok": true, "started": started })).into_response()
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
        .into();
    };
    match mutate(&state, move |config| {
        // Every requested key must exist, mirroring the fg-admin batch
        // delete: no partial removals.
        find_indices(&config.rules, &keys).ok_or_else(missing_item)?;
        let removed: std::collections::HashSet<_> = keys.iter().map(String::as_str).collect();
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

async fn rules_batch_enable(state: Arc<RoutesState>, body: Bytes) -> Response {
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
        let indices = find_indices(&config.rules, &keys).ok_or_else(missing_item)?;
        let mut changed = 0;
        for index in indices {
            let rule = &mut config.rules[index];
            if rule.enable != enable {
                rule.enable = enable;
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
        let indices = find_indices(&config.rules, &keys).ok_or_else(missing_item)?;
        let mut changed = false;
        for index in indices {
            let field = &mut config.rules[index].group;
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

async fn settings_view(state: Arc<RoutesState>) -> Response {
    let config = state.config.read().await;
    Json(normalize(config.clone()).settings).into_response()
}

/// Normalize → validate → persist → on_change; a failed write leaves the
/// desired state untouched, matching the gateway module commit order.
async fn settings_save(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(settings) = serde_json::from_slice::<Settings>(&body) else {
        return decode_error();
    };
    let result = mutate(&state, move |config| {
        let changed = config.settings != settings;
        config.settings = settings;
        settle(config)?;
        Ok(((), changed))
    })
    .await;
    match result {
        Ok(()) => {
            let config = state.config.read().await;
            Json(config.settings.clone()).into_response()
        }
        Err(response) => response,
    }
}

/// The local interface addresses a rule's bind mode can select from.
async fn netinterfaces(_state: Arc<RoutesState>) -> Response {
    let list: Vec<serde_json::Value> = match if_addrs::get_if_addrs() {
        Ok(interfaces) => interfaces
            .iter()
            .map(|iface| {
                json!({
                    "name": iface.name,
                    "ip": iface.ip().to_string(),
                    "loopback": iface.ip().is_loopback(),
                })
            })
            .collect(),
        Err(error) => {
            tracing::warn!(module = "stun", %error, "enumerating interfaces failed");
            Vec::new()
        }
    };
    Json(list).into_response()
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
