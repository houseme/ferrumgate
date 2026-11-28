//! Notify management routes (WP-68 §4): the channel and rule collections,
//! test-send, the event-type catalog, recent deliveries, the pending queue
//! and the settings, served with plain axum while mirroring the fg-admin
//! `Collection<T>` contract (JSON shapes, status codes, key handling) —
//! the module cannot depend on fg-admin.
//!
//! Endpoints (permission domain `notify`; upstream carries 32 operations
//! for this path prefix including the 4 generic log endpoints
//! `GET|DELETE /api/notify/logs`, `GET /api/notify/logs/export`,
//! `GET /api/notify/logs/sources`, which are served by fg-admin and not
//! mounted here):
//!
//! | Method | Path | Request | Response |
//! |---|---|---|---|
//! | GET | `/api/notify/channels` | — | `[Channel]` (normalized, secrets `********`) |
//! | POST | `/api/notify/channels` | `Channel` | created `Channel` (masked) |
//! | POST | `/api/notify/channels-delete` | `{"keys":[…]}` | `{"removed":N}` |
//! | PUT | `/api/notify/channels-enable` | `{"keys":[…],"enable":bool}` | `{"changed":N}` (disabling also drops the backlog) |
//! | PUT | `/api/notify/channels-group` | `{"keys":[…],"group":"…"}` | `{"ok":true}` |
//! | PUT | `/api/notify/channels-order` | `{"keys":[…]}` full ordered list | `{"ok":true}` |
//! | PUT | `/api/notify/channels/{key}` | `Channel` | replaced `Channel` (`********`/empty secrets keep the stored ones) |
//! | DELETE | `/api/notify/channels/{key}` | — | `{"removed":1}` (backlog dropped too) |
//! | POST | `/api/notify/channels/{key}/copy` | `Channel` | created `Channel` (fresh key, secrets filled from the source) |
//! | PUT | `/api/notify/channels/{key}/enable` | `{"enable":bool}` | `{"ok":true}` |
//! | GET | `/api/notify/channels/{key}/secrets` | — | `{"config.<field>": value, …}` unmasked |
//! | POST | `/api/notify/channels/{key}/test` | — | `{"ok":true}` or `500 {"error":…}`; single send, no retry/pending |
//! | GET | `/api/notify/rules` | — | `[Rule]` (normalized) |
//! | POST | `/api/notify/rules` | `Rule` | created `Rule` |
//! | POST | `/api/notify/rules-delete` | `{"keys":[…]}` | `{"removed":N}` |
//! | PUT | `/api/notify/rules-enable` | `{"keys":[…],"enable":bool}` | `{"changed":N}` |
//! | PUT | `/api/notify/rules-group` | `{"keys":[…],"group":"…"}` | `{"ok":true}` |
//! | PUT | `/api/notify/rules-order` | `{"keys":[…]}` | `{"ok":true}` |
//! | PUT | `/api/notify/rules/{key}` | `Rule` | replaced `Rule` |
//! | DELETE | `/api/notify/rules/{key}` | — | `{"removed":1}` |
//! | POST | `/api/notify/rules/{key}/copy` | `Rule` | created `Rule` (fresh key, after the source) |
//! | PUT | `/api/notify/rules/{key}/enable` | `{"enable":bool}` | `{"ok":true}` |
//! | GET | `/api/notify/event-types` | — | `[{"name","defaultLevel","titleKey"}]` (fg-core kinds) |
//! | GET | `/api/notify/history` | — | `[{"at","event","channel","outcome","attempts","error"}]` |
//! | GET | `/api/notify/pending` | — | `{"channels":[{key,count,waitSeconds,nextAttempt,messages}],"total":N}` (read identities may view) |
//! | DELETE | `/api/notify/pending` | — | `{"ok":true,"cleared":N}` |
//! | GET | `/api/notify/settings` | — | normalized `Settings` |
//! | PUT | `/api/notify/settings` | `Settings` | normalized `Settings` |
//!
//! Every mutation runs normalize → validate → apply → persist → on_change;
//! validation problems are returned as `400` with the collected list
//! (`{"error":…,"problems":[{"field":…,"reason":…}]}`). Batch bodies carry
//! at most 500 keys and all must exist before anything is saved. Keys
//! follow the fg-admin collection convention: 12 lowercase hex characters
//! generated on create/copy; a client-supplied valid unique key is kept on
//! create and always regenerated on copy.
//!
//! Authentication is NOT performed here: [`mount`] routes are meant to be
//! mounted under the management router whose authorize layer maps
//! `/api/notify/…` to domain `notify` (GET → `notify:read`, every mutation
//! → `notify:write`).

use std::collections::HashMap;
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
use tokio::sync::RwLock;

use crate::{
    Dispatcher,
    model::{Channel, FileConfig, Rule, Settings, limits},
    rfc3339,
    validate::{merge_channel, normalize, validate},
};

/// Writes the whole [`FileConfig`] to `notify.json`.
pub type PersistFn = Arc<dyn Fn(&FileConfig) -> anyhow::Result<()> + Send + Sync>;

/// Shared state behind the notify management routes.
pub struct RoutesState {
    /// The live desired snapshot (already normalized once loaded).
    pub config: Arc<RwLock<FileConfig>>,
    pub persist: PersistFn,
    pub on_change: Arc<dyn Fn() + Send + Sync>,
    /// Answers history/pending reads and the test send.
    pub dispatcher: Arc<Dispatcher>,
}

/// Adds the notify management routes to `router`. See the module docs for
/// the endpoint contract and the authentication assumption.
pub fn mount(router: axum::Router, state: Arc<RoutesState>) -> axum::Router {
    let (channels_list, channels_create) = (state.clone(), state.clone());
    let (channel_replace, channel_remove) = (state.clone(), state.clone());
    let (channel_copy, channel_enable) = (state.clone(), state.clone());
    let (channel_secrets, channel_test) = (state.clone(), state.clone());
    let (channels_order, channels_enable) = (state.clone(), state.clone());
    let (channels_group, channels_delete) = (state.clone(), state.clone());
    let (rules_list, rules_create) = (state.clone(), state.clone());
    let (rule_replace, rule_remove) = (state.clone(), state.clone());
    let (rule_copy, rule_enable) = (state.clone(), state.clone());
    let (rules_order, rules_enable) = (state.clone(), state.clone());
    let (rules_group, rules_delete) = (state.clone(), state.clone());
    let (event_types, history) = (state.clone(), state.clone());
    let (pending, pending_clear) = (state.clone(), state.clone());
    let (settings_get, settings_put) = (state.clone(), state.clone());
    router
        .route(
            "/api/notify/channels",
            get(move || async move { collection_list(channels_list, Which::Channels).await }).post(
                move |body: Bytes| async move {
                    collection_create(channels_create, body, Which::Channels).await
                },
            ),
        )
        .route(
            "/api/notify/channels/{key}",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    collection_replace(channel_replace, path, body, Which::Channels).await
                },
            )
            .delete(
                move |path: Result<Path<String>, PathRejection>| async move {
                    collection_delete(channel_remove, path, Which::Channels).await
                },
            ),
        )
        .route(
            "/api/notify/channels/{key}/copy",
            post(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    collection_copy(channel_copy, path, body, Which::Channels).await
                },
            ),
        )
        .route(
            "/api/notify/channels/{key}/enable",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    collection_enable(channel_enable, path, body, Which::Channels).await
                },
            ),
        )
        .route(
            "/api/notify/channels/{key}/secrets",
            get(
                move |path: Result<Path<String>, PathRejection>| async move {
                    channel_secrets_view(channel_secrets, path).await
                },
            ),
        )
        .route(
            "/api/notify/channels/{key}/test",
            post(
                move |path: Result<Path<String>, PathRejection>| async move {
                    channel_test_send(channel_test, path).await
                },
            ),
        )
        .route(
            "/api/notify/channels-order",
            put(move |body: Bytes| async move {
                collection_order(channels_order, body, Which::Channels).await
            }),
        )
        .route(
            "/api/notify/channels-enable",
            put(move |body: Bytes| async move {
                collection_batch_enable(channels_enable, body, Which::Channels).await
            }),
        )
        .route(
            "/api/notify/channels-group",
            put(move |body: Bytes| async move {
                collection_group(channels_group, body, Which::Channels).await
            }),
        )
        .route(
            "/api/notify/channels-delete",
            post(move |body: Bytes| async move {
                collection_batch_delete(channels_delete, body, Which::Channels).await
            }),
        )
        .route(
            "/api/notify/rules",
            get(move || async move { collection_list(rules_list, Which::Rules).await }).post(
                move |body: Bytes| async move {
                    collection_create(rules_create, body, Which::Rules).await
                },
            ),
        )
        .route(
            "/api/notify/rules/{key}",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    collection_replace(rule_replace, path, body, Which::Rules).await
                },
            )
            .delete(
                move |path: Result<Path<String>, PathRejection>| async move {
                    collection_delete(rule_remove, path, Which::Rules).await
                },
            ),
        )
        .route(
            "/api/notify/rules/{key}/copy",
            post(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    collection_copy(rule_copy, path, body, Which::Rules).await
                },
            ),
        )
        .route(
            "/api/notify/rules/{key}/enable",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    collection_enable(rule_enable, path, body, Which::Rules).await
                },
            ),
        )
        .route(
            "/api/notify/rules-order",
            put(move |body: Bytes| async move {
                collection_order(rules_order, body, Which::Rules).await
            }),
        )
        .route(
            "/api/notify/rules-enable",
            put(move |body: Bytes| async move {
                collection_batch_enable(rules_enable, body, Which::Rules).await
            }),
        )
        .route(
            "/api/notify/rules-group",
            put(move |body: Bytes| async move {
                collection_group(rules_group, body, Which::Rules).await
            }),
        )
        .route(
            "/api/notify/rules-delete",
            post(move |body: Bytes| async move {
                collection_batch_delete(rules_delete, body, Which::Rules).await
            }),
        )
        .route(
            "/api/notify/event-types",
            get(move || async move { event_types_view(event_types).await }),
        )
        .route(
            "/api/notify/history",
            get(move || async move { history_view(history).await }),
        )
        .route(
            "/api/notify/pending",
            get(move || async move { pending_view(pending).await })
                .delete(move || async move { pending_clear_view(pending_clear).await }),
        )
        .route(
            "/api/notify/settings",
            get(move || async move { settings_view(settings_get).await })
                .put(move |body: Bytes| async move { settings_save(settings_put, body).await }),
        )
}

/// Which collection a handler works on; keeps the shared handlers generic
/// over channels vs rules without traits.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Which {
    Channels,
    Rules,
}

impl Which {
    /// The list as JSON values (channels masked, rules verbatim).
    fn get(self, config: &FileConfig) -> Vec<serde_json::Value> {
        match self {
            Which::Channels => config
                .channels
                .iter()
                .map(|channel| channel.masked_value())
                .collect(),
            Which::Rules => config
                .rules
                .iter()
                .map(|rule| serde_json::to_value(rule).expect("rule serializes"))
                .collect(),
        }
    }
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
                    "error": "invalid notify configuration",
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
/// (the fg-admin `Collection::change` commit order: a failed write leaves
/// the desired state untouched).
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
                tracing::warn!(%error, "persisting notify.json failed");
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
    let mut seen = std::collections::HashSet::new();
    keys.retain(|key| seen.insert(key.clone()));
    Ok(keys)
}

fn missing_item() -> Failure {
    Failure::Api(StatusCode::NOT_FOUND, "item not found".into())
}

/// 12 lowercase hex characters, unique within the collection — the same
/// shape the fg-admin collections generate.
fn random_key(existing: &[&str]) -> Result<String, Failure> {
    for _ in 0..8 {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes[2..]).map_err(|_| {
            Failure::Api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key generation failed".into(),
            )
        })?;
        let candidate = format!("{:012x}", u64::from_be_bytes(bytes));
        if !existing.contains(&candidate.as_str()) {
            return Ok(candidate);
        }
    }
    Err(Failure::Api(
        StatusCode::INTERNAL_SERVER_ERROR,
        "unable to generate a unique key".into(),
    ))
}

fn item_keys(config: &FileConfig, which: Which) -> Vec<&str> {
    match which {
        Which::Channels => config
            .channels
            .iter()
            .map(|channel| channel.key.as_str())
            .collect(),
        Which::Rules => config.rules.iter().map(|rule| rule.key.as_str()).collect(),
    }
}

fn locate(config: &FileConfig, which: Which, key: &str) -> Result<usize, Failure> {
    let position = match which {
        Which::Channels => config.channels.iter().position(|item| item.key == key),
        Which::Rules => config.rules.iter().position(|item| item.key == key),
    };
    position.ok_or_else(missing_item)
}

/// Maps requested keys (each once) onto positions in `items`; `None` when
/// a key is unknown or duplicated.
fn find_indices(items: &[&str], keys: &[String]) -> Option<Vec<usize>> {
    let mut slots: HashMap<_, _> = keys
        .iter()
        .enumerate()
        .map(|(slot, key)| (key.as_str(), slot))
        .collect();
    if slots.len() != keys.len() {
        return None;
    }
    let mut indices = vec![0; keys.len()];
    for (index, item) in items.iter().enumerate() {
        if let Some(slot) = slots.remove(item) {
            indices[slot] = index;
            if slots.is_empty() {
                break;
            }
        }
    }
    slots.is_empty().then_some(indices)
}

/// Removes every occurrence (channel or rule) with one of the keys.
fn remove_items(config: &mut FileConfig, which: Which, keys: &std::collections::HashSet<&str>) {
    match which {
        Which::Channels => config
            .channels
            .retain(|channel| !keys.contains(channel.key.as_str())),
        Which::Rules => config
            .rules
            .retain(|rule| !keys.contains(rule.key.as_str())),
    }
}

fn decode_error() -> Response {
    Failure::Api(StatusCode::BAD_REQUEST, "invalid JSON body".into()).into_response()
}

async fn collection_list(state: Arc<RoutesState>, which: Which) -> Response {
    let config = normalize(state.config.read().await.clone());
    Json(which.get(&config)).into_response()
}

async fn collection_create(state: Arc<RoutesState>, body: Bytes, which: Which) -> Response {
    let parsed = match which {
        Which::Channels => serde_json::from_slice::<Channel>(&body)
            .map(|channel| Parsed::Channel(Box::new(channel))),
        Which::Rules => serde_json::from_slice::<Rule>(&body).map(Parsed::Rule),
    };
    let mut item = match parsed {
        Ok(item) => item,
        Err(_) => return decode_error(),
    };
    match mutate(&state, move |config| {
        let keys = item_keys(config, which);
        // A client-supplied valid unique key is kept; anything else gets a
        // generated one (fg-admin collection behavior on create).
        if !valid_key(item.key()) || keys.contains(&item.key()) {
            let generated = random_key(&keys)?;
            item.set_key(generated);
        }
        match (item, which) {
            (Parsed::Channel(channel), Which::Channels) => config.channels.push(*channel),
            (Parsed::Rule(rule), Which::Rules) => config.rules.push(rule),
            _ => unreachable!("parsed per collection"),
        }
        settle(config)?;
        let view = which.view_last(config)?;
        Ok((Json(view), true))
    })
    .await
    {
        Ok(created) => created.into_response(),
        Err(response) => response,
    }
}

/// A parsed collection item of either kind (the channel is boxed: the
/// fat config would otherwise dominate the enum size).
enum Parsed {
    Channel(Box<Channel>),
    Rule(Rule),
}

impl Parsed {
    fn key(&self) -> &str {
        match self {
            Parsed::Channel(channel) => &channel.key,
            Parsed::Rule(rule) => &rule.key,
        }
    }

    fn set_key(&mut self, key: String) {
        match self {
            Parsed::Channel(channel) => channel.key = key,
            Parsed::Rule(rule) => rule.key = key,
        }
    }
}

impl Which {
    fn view_last(&self, config: &FileConfig) -> Result<serde_json::Value, Failure> {
        let view = match self {
            Which::Channels => config.channels.last().map(|channel| channel.masked_value()),
            Which::Rules => config
                .rules
                .last()
                .map(|rule| serde_json::to_value(rule).expect("rule serializes")),
        };
        view.ok_or_else(|| Failure::Api(StatusCode::INTERNAL_SERVER_ERROR, "item missing".into()))
    }

    fn view_at(&self, config: &FileConfig, index: usize) -> Result<serde_json::Value, Failure> {
        let view = match self {
            Which::Channels => config
                .channels
                .get(index)
                .map(|channel| channel.masked_value()),
            Which::Rules => config
                .rules
                .get(index)
                .map(|rule| serde_json::to_value(rule).expect("rule serializes")),
        };
        view.ok_or_else(|| Failure::Api(StatusCode::INTERNAL_SERVER_ERROR, "item missing".into()))
    }
}

async fn collection_replace(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
    which: Which,
) -> Response {
    let parse = match which {
        Which::Channels => serde_json::from_slice::<Channel>(&body)
            .map(|channel| Parsed::Channel(Box::new(channel))),
        Which::Rules => serde_json::from_slice::<Rule>(&body).map(Parsed::Rule),
    };
    let mut item = match parse {
        Ok(item) => item,
        Err(_) => return decode_error(),
    };
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    match mutate(&state, move |config| {
        let index = locate(config, which, &key)?;
        item.set_key(key.clone());
        match (&mut item, which) {
            (Parsed::Channel(channel), Which::Channels) => {
                // Masked or empty secrets keep the stored values.
                let mut merged = std::mem::take(channel);
                merge_channel(&config.channels[index], &mut merged);
                config.channels[index] = *merged;
            }
            (Parsed::Rule(rule), Which::Rules) => {
                config.rules[index] = std::mem::take(rule);
            }
            _ => {
                return Err(Failure::Api(
                    StatusCode::BAD_REQUEST,
                    "kind mismatch".into(),
                ));
            }
        }
        settle(config)?;
        let view = which.view_at(config, index)?;
        Ok((Json(view), true))
    })
    .await
    {
        Ok(replaced) => replaced.into_response(),
        Err(response) => response,
    }
}

async fn collection_delete(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    which: Which,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let deleted_key = key.clone();
    match mutate(&state, move |config| {
        let index = locate(config, which, &key)?;
        match which {
            Which::Channels => {
                config.channels.remove(index);
            }
            Which::Rules => {
                config.rules.remove(index);
            }
        }
        Ok((Json(json!({ "removed": 1 })), true))
    })
    .await
    {
        Ok(removed) => {
            // A deleted channel also loses its pending backlog (with a
            // failure record each).
            if which == Which::Channels {
                state.dispatcher.drop_channel_backlog(&deleted_key);
            }
            removed.into_response()
        }
        Err(response) => response,
    }
}

async fn collection_copy(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
    which: Which,
) -> Response {
    let parse = match which {
        Which::Channels => serde_json::from_slice::<Channel>(&body)
            .map(|channel| Parsed::Channel(Box::new(channel))),
        Which::Rules => serde_json::from_slice::<Rule>(&body).map(Parsed::Rule),
    };
    let item = match parse {
        Ok(item) => item,
        Err(_) => return decode_error(),
    };
    let Ok(source) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    match mutate(&state, move |config| {
        let index = locate(config, which, &source)?;
        let keys = item_keys(config, which);
        match (item, which) {
            (Parsed::Channel(mut copy), Which::Channels) => {
                // Copies always receive a generated key and resolve masked
                // secrets against the source (fg-admin collection
                // behavior on copy).
                let stored = config.channels[index].clone();
                merge_channel(&stored, &mut copy);
                copy.key = random_key(&keys)?;
                config.channels.insert(index + 1, *copy);
            }
            (Parsed::Rule(mut copy), Which::Rules) => {
                copy.key = random_key(&keys)?;
                config.rules.insert(index + 1, copy);
            }
            _ => unreachable!("parsed per collection"),
        }
        settle(config)?;
        let view = which.view_at(config, index + 1)?;
        Ok((Json(view), true))
    })
    .await
    {
        Ok(created) => created.into_response(),
        Err(response) => response,
    }
}

async fn collection_enable(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
    which: Which,
) -> Response {
    let Ok(Enable { enable }) = serde_json::from_slice::<Enable>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let backlog_key = key.clone();
    match mutate(&state, move |config| {
        let index = locate(config, which, &key)?;
        let changed = *enable_of(which, config, index) != enable;
        *enable_of(which, config, index) = enable;
        Ok((Json(json!({ "ok": true })), changed))
    })
    .await
    {
        Ok(ok) => {
            if which == Which::Channels && !enable {
                state.dispatcher.drop_channel_backlog(&backlog_key);
            }
            ok.into_response()
        }
        Err(response) => response,
    }
}

/// The enable flag of an item, per collection (a free fn keeps one
/// lifetime for the returned reference).
fn enable_of(which: Which, config: &mut FileConfig, index: usize) -> &mut bool {
    match which {
        Which::Channels => &mut config.channels[index].enable,
        Which::Rules => &mut config.rules[index].enable,
    }
}

async fn collection_batch_enable(state: Arc<RoutesState>, body: Bytes, which: Which) -> Response {
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
    let keys_for_drop = keys.clone();
    match mutate(&state, move |config| {
        let indices = find_indices(&item_keys(config, which), &keys).ok_or_else(missing_item)?;
        let mut changed = 0;
        for index in indices {
            if *enable_of(which, config, index) != enable {
                *enable_of(which, config, index) = enable;
                changed += 1;
            }
        }
        Ok((Json(json!({ "changed": changed })), changed > 0))
    })
    .await
    {
        Ok(changed) => {
            if which == Which::Channels && !enable {
                for key in &keys_for_drop {
                    state.dispatcher.drop_channel_backlog(key);
                }
            }
            changed.into_response()
        }
        Err(response) => response,
    }
}

async fn collection_order(state: Arc<RoutesState>, body: Bytes, which: Which) -> Response {
    let Ok(Keys { keys }) = serde_json::from_slice::<Keys>(&body) else {
        return decode_error();
    };
    match mutate(&state, move |config| {
        let total = match which {
            Which::Channels => config.channels.len(),
            Which::Rules => config.rules.len(),
        };
        if keys.len() != total {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                "order must include every item once".into(),
            ));
        }
        let Some(indices) = find_indices(&item_keys(config, which), &keys) else {
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
                match which {
                    Which::Channels => config.channels.swap(index, new),
                    Which::Rules => config.rules.swap(index, new),
                }
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

async fn collection_group(state: Arc<RoutesState>, body: Bytes, which: Which) -> Response {
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
        let indices = find_indices(&item_keys(config, which), &keys).ok_or_else(missing_item)?;
        let mut changed = false;
        for index in indices {
            let field = match which {
                Which::Channels => &mut config.channels[index].group,
                Which::Rules => &mut config.rules[index].group,
            };
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

async fn collection_batch_delete(state: Arc<RoutesState>, body: Bytes, which: Which) -> Response {
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
    let keys_for_drop = keys.clone();
    match mutate(&state, move |config| {
        // Every requested key must exist, mirroring the fg-admin batch
        // delete: no partial removals.
        find_indices(&item_keys(config, which), &keys).ok_or_else(missing_item)?;
        let removed: std::collections::HashSet<_> = keys.iter().map(String::as_str).collect();
        remove_items(config, which, &removed);
        let count = keys.len();
        Ok((Json(json!({ "removed": count })), true))
    })
    .await
    {
        Ok(removed) => {
            if which == Which::Channels {
                for key in &keys_for_drop {
                    state.dispatcher.drop_channel_backlog(key);
                }
            }
            removed.into_response()
        }
        Err(response) => response,
    }
}

/// The unmasked secret fields of one channel (fg-admin `secrets` view).
async fn channel_secrets_view(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    let config = state.config.read().await;
    let Some(channel) = config.channels.iter().find(|channel| channel.key == key) else {
        return missing_item().into();
    };
    let value = serde_json::to_value(&channel.config).expect("config serializes");
    let mut secrets = std::collections::BTreeMap::new();
    if let Some(fields) = value.as_object() {
        for field in channel.secret_fields() {
            if let Some(item) = fields.get(*field) {
                secrets.insert(format!("config.{field}"), item.clone());
            }
        }
    }
    Json(secrets).into_response()
}

/// One test send (no retry, no pending; the outcome is recorded).
async fn channel_test_send(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".into()).into();
    };
    // The stored config carries the real secrets (the masked form exists
    // only in API output), so the test send uses it as-is.
    let channel = {
        let config = state.config.read().await;
        config
            .channels
            .iter()
            .find(|channel| channel.key == key)
            .cloned()
    };
    let Some(channel) = channel else {
        return missing_item().into();
    };
    match state.dispatcher.test_send(&channel).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(error) => Failure::Api(StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    }
}

/// The event-type catalog (fg-core kinds).
async fn event_types_view(_state: Arc<RoutesState>) -> Response {
    let kinds: Vec<serde_json::Value> = fg_core::events::KINDS
        .iter()
        .map(|info| {
            json!({
                "name": info.name,
                "defaultLevel": crate::model::level_json::label(info.default_level),
                "titleKey": info.title_key,
            })
        })
        .collect();
    Json(kinds).into_response()
}

/// The bounded recent-deliveries list.
async fn history_view(state: Arc<RoutesState>) -> Response {
    let records: Vec<serde_json::Value> = state
        .dispatcher
        .history()
        .into_iter()
        .map(|record| {
            json!({
                "at": rfc3339(record.at),
                "event": record.event,
                "channel": record.channel,
                "outcome": record.outcome.as_str(),
                "attempts": record.attempts,
                "error": record.error,
            })
        })
        .collect();
    Json(records).into_response()
}

/// The pending queue view (titles only).
async fn pending_view(state: Arc<RoutesState>) -> Response {
    Json(state.dispatcher.pending_view()).into_response()
}

/// Drops every backlog entry.
async fn pending_clear_view(state: Arc<RoutesState>) -> Response {
    let cleared = state.dispatcher.clear_pending();
    Json(json!({ "ok": true, "cleared": cleared })).into_response()
}

async fn settings_view(state: Arc<RoutesState>) -> Response {
    let config = state.config.read().await;
    Json(normalize(config.clone()).settings).into_response()
}

/// Normalize → validate → persist → publish, echoing the settings; a
/// no-op save echoes the settings without persisting.
async fn settings_save(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(settings) = serde_json::from_slice::<Settings>(&body) else {
        return decode_error();
    };
    let current = state.config.read().await.settings.clone();
    match mutate(&state, move |config| {
        config.settings = settings;
        settle(config)?;
        let changed = config.settings != current;
        Ok((Json(config.settings.clone()), changed))
    })
    .await
    {
        Ok(saved) => saved.into_response(),
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

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use axum::body::Body;
    use serde_json::json;
    use tokio::sync::RwLock;

    use super::*;

    /// A mounted router over an in-memory store, counting persist calls.
    struct Harness {
        addr: std::net::SocketAddr,
        persists: Arc<AtomicUsize>,
        dispatcher: Arc<Dispatcher>,
    }

    async fn harness() -> Harness {
        let persists = Arc::new(AtomicUsize::new(0));
        let config = Arc::new(RwLock::new(FileConfig::default()));
        let dispatcher = Dispatcher::for_tests(config.clone());
        let count_persist = persists.clone();
        let persist: PersistFn = Arc::new(move |config: &FileConfig| {
            serde_json::to_vec_pretty(config)?;
            count_persist.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let on_change: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
        let state = Arc::new(RoutesState {
            config,
            persist,
            on_change,
            dispatcher: Arc::clone(&dispatcher),
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
            dispatcher,
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
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                    .await
                    .expect("handshake");
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let builder = hyper::Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json");
            let request = match body {
                Some(body) => builder.body(Body::from(body.to_string())).expect("body"),
                None => builder.body(Body::empty()).expect("body"),
            };
            let response = sender.send_request(request).await.expect("send");
            let status = response.status();
            let bytes = http_body_util::BodyExt::collect(response.into_body())
                .await
                .expect("collect")
                .to_bytes();
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
            )
        }

        async fn create(&self, item: serde_json::Value) -> serde_json::Value {
            let (status, body) = self.send("POST", "/api/notify/channels", Some(item)).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body
        }
    }

    fn telegram(key: &str) -> serde_json::Value {
        json!({
            "key": key,
            "name": "ops",
            "enable": true,
            "kind": "telegram",
            "config": { "token": "secret-token", "chatId": "-42" },
        })
    }

    fn is_generated_key(key: &str) -> bool {
        key.len() == 12
            && key
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }

    #[tokio::test]
    async fn secrets_masked_in_api() {
        let app = harness().await;
        let created = app.create(telegram("chan000000001")).await;
        // The created view masks the token; the key is kept.
        assert_eq!(created["key"], "chan000000001");
        assert_eq!(created["config"]["token"], "********", "{created}");
        assert_eq!(created["config"]["chatId"], "-42");
        // The list masks too.
        let (_, list) = app.send("GET", "/api/notify/channels", None).await;
        assert_eq!(list[0]["config"]["token"], "********");
        // The secrets view reveals the stored value.
        let (status, secrets) = app
            .send("GET", "/api/notify/channels/chan000000001/secrets", None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(secrets["config.token"], "secret-token", "{secrets}");
        // A masked submission keeps the stored token; a new value replaces
        // it.
        let mut update = telegram("ignored");
        update["config"]["chatId"] = "-43".into();
        let (status, replaced) = app
            .send("PUT", "/api/notify/channels/chan000000001", Some(update))
            .await;
        assert_eq!(status, StatusCode::OK, "{replaced}");
        assert_eq!(replaced["config"]["token"], "********");
        let (_, secrets) = app
            .send("GET", "/api/notify/channels/chan000000001/secrets", None)
            .await;
        assert_eq!(secrets["config.token"], "secret-token", "mask keeps stored");
        let (_, list) = app.send("GET", "/api/notify/channels", None).await;
        assert_eq!(
            list[0]["config"]["chatId"], "-43",
            "non-secret fields are updated"
        );
        let mut update = telegram("ignored");
        update["config"]["token"] = "rotated-token".into();
        let _ = app
            .send("PUT", "/api/notify/channels/chan000000001", Some(update))
            .await;
        let (_, secrets) = app
            .send("GET", "/api/notify/channels/chan000000001/secrets", None)
            .await;
        assert_eq!(secrets["config.token"], "rotated-token");
    }

    #[tokio::test]
    async fn collection_contract_for_channels() {
        let app = harness().await;
        // Create with a valid unique key keeps it; a duplicate is
        // regenerated.
        let created = app.create(telegram("chan000000001")).await;
        assert_eq!(created["key"], "chan000000001");
        let clash = app.create(telegram("chan000000001")).await;
        assert!(is_generated_key(clash["key"].as_str().expect("key")));
        let generated = app.create(telegram("")).await;
        assert!(is_generated_key(generated["key"].as_str().expect("key")));
        // Copy inserts after the source with a fresh key, secrets filled
        // from the source.
        let (status, copied) = app
            .send(
                "POST",
                "/api/notify/channels/chan000000001/copy",
                Some(telegram("chan000000001")),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{copied}");
        let copied_key = copied["key"].as_str().expect("key").to_owned();
        assert!(is_generated_key(&copied_key));
        assert_eq!(copied["config"]["token"], "********");
        let (_, secrets) = app
            .send(
                "GET",
                &format!("/api/notify/channels/{copied_key}/secrets"),
                None,
            )
            .await;
        assert_eq!(
            secrets["config.token"], "secret-token",
            "copy fills from source"
        );
        // Enable single + batch semantics.
        let (status, body) = app
            .send(
                "PUT",
                "/api/notify/channels/chan000000001/enable",
                Some(json!({ "enable": false })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        let (_, body) = app
            .send(
                "PUT",
                "/api/notify/channels-enable",
                Some(json!({ "keys": [copied_key], "enable": false })),
            )
            .await;
        assert_eq!(body["changed"], 1);
        // Order requires every key once.
        let (_, list) = app.send("GET", "/api/notify/channels", None).await;
        let keys: Vec<String> = list
            .as_array()
            .expect("array")
            .iter()
            .map(|item| item["key"].as_str().expect("key").to_owned())
            .collect();
        let mut reversed = keys.clone();
        reversed.reverse();
        let (status, body) = app
            .send(
                "PUT",
                "/api/notify/channels-order",
                Some(json!({ "keys": reversed })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = app
            .send(
                "PUT",
                "/api/notify/channels-order",
                Some(json!({ "keys": [keys[0].clone()] })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "order must include every item once");
        // Group + batch delete (the order was reversed above, so apply to
        // the whole current list and expect every entry grouped).
        let (_, list) = app.send("GET", "/api/notify/channels", None).await;
        let current: Vec<String> = list
            .as_array()
            .expect("array")
            .iter()
            .map(|item| item["key"].as_str().expect("key").to_owned())
            .collect();
        let (status, body) = app
            .send(
                "PUT",
                "/api/notify/channels-group",
                Some(json!({ "keys": current, "group": "运维" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (_, list) = app.send("GET", "/api/notify/channels", None).await;
        assert!(
            list.as_array()
                .expect("array")
                .iter()
                .all(|item| item["group"] == "运维"),
            "{list}"
        );
        let (status, _) = app
            .send(
                "POST",
                "/api/notify/channels-delete",
                Some(json!({ "keys": [keys[0], "ghost"] })),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "no partial removals");
        let (status, body) = app
            .send(
                "POST",
                "/api/notify/channels-delete",
                Some(json!({ "keys": [keys[0], keys[1], keys[2]] })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["removed"], 3);
        // Unknown fields are rejected.
        let (status, body) = app
            .send("POST", "/api/notify/channels", Some(json!({ "nope": 1 })))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid JSON body");
    }

    #[tokio::test]
    async fn rule_collection_and_validation_problems() {
        let app = harness().await;
        app.create(telegram("chan000000001")).await;
        let rule = json!({
            "name": "auth",
            "enable": true,
            "events": ["auth.*"],
            "minLevel": "warn",
            "channels": ["chan000000001"],
        });
        let (status, created) = app.send("POST", "/api/notify/rules", Some(rule)).await;
        assert_eq!(status, StatusCode::OK, "{created}");
        let key = created["key"].as_str().expect("key").to_owned();
        assert!(is_generated_key(&key));
        assert_eq!(created["minLevel"], "warn");
        // A rule referencing an unknown channel is rejected with problems.
        let bad = json!({
            "name": "bad",
            "events": ["*"],
            "channels": ["ghost"],
        });
        let (status, body) = app.send("POST", "/api/notify/rules", Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid notify configuration");
        let problems = body["problems"].as_array().expect("problems");
        assert!(
            problems
                .iter()
                .any(|problem| problem["field"].as_str().unwrap().contains("channels")),
            "{problems:?}"
        );
        // Replace + enable + delete on the rule.
        let mut replacement = json!({
            "name": "renamed",
            "events": ["*"],
            "minLevel": "error",
            "channels": ["chan000000001"],
        });
        replacement["name"] = "renamed".into();
        let (status, replaced) = app
            .send(
                "PUT",
                &format!("/api/notify/rules/{key}"),
                Some(replacement),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{replaced}");
        assert_eq!(replaced["key"], key);
        assert_eq!(replaced["name"], "renamed");
        let (status, _) = app
            .send(
                "PUT",
                &format!("/api/notify/rules/{key}/enable"),
                Some(json!({ "enable": false })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = app
            .send("DELETE", &format!("/api/notify/rules/{key}"), None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["removed"], 1);
    }

    #[tokio::test]
    async fn settings_and_read_endpoints() {
        let app = harness().await;
        let (_, settings) = app.send("GET", "/api/notify/settings", None).await;
        assert_eq!(settings["retries"], serde_json::Value::Null);
        assert_eq!(settings["proxy"], "none");
        let (status, saved) = app
            .send(
                "PUT",
                "/api/notify/settings",
                Some(json!({
                    "language": "zh-CN",
                    "serverName": " home-gate ",
                    "retries": 5,
                    "pendingHours": 48,
                    "proxy": { "custom": "http://gate:8080" },
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{saved}");
        assert_eq!(saved["serverName"], "home-gate", "normalized");
        assert_eq!(saved["retries"], 5);
        // Out-of-range values are rejected with problems.
        let (status, body) = app
            .send(
                "PUT",
                "/api/notify/settings",
                Some(json!({ "retries": 99 })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().expect("error").contains("notify"));
        // Event types list the fg-core kinds.
        let (_, kinds) = app.send("GET", "/api/notify/event-types", None).await;
        let kinds = kinds.as_array().expect("kinds array");
        assert_eq!(kinds.len(), fg_core::events::KINDS.len());
        assert!(kinds.iter().any(|kind| kind["name"] == "auth.failed"));
        // History and pending start empty; pending clear is a no-op.
        let (_, history) = app.send("GET", "/api/notify/history", None).await;
        assert_eq!(history, serde_json::json!([]));
        let (_, pending) = app.send("GET", "/api/notify/pending", None).await;
        assert_eq!(pending["total"], 0);
        let (status, cleared) = app.send("DELETE", "/api/notify/pending", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(cleared["ok"], true);
        assert_eq!(cleared["cleared"], 0);
        // Unknown channel: 404 on secrets and test.
        let (status, body) = app
            .send("GET", "/api/notify/channels/ghost/secrets", None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "item not found");
        let (status, _) = app
            .send("POST", "/api/notify/channels/ghost/test", None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // Invalid item keys are rejected before lookup.
        let (status, _) = app
            .send("DELETE", "/api/notify/channels/batch-delete", None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn channel_delete_clears_backlog_state() {
        // Deleting a channel leaves no dangling dispatcher state and
        // persists the config change exactly once.
        let app = harness().await;
        let created = app
            .send(
                "POST",
                "/api/notify/channels",
                Some(json!({
                    "name": "hook",
                    "enable": true,
                    "kind": "webhook",
                    "config": { "url": "https://example.com/hook" },
                })),
            )
            .await
            .1;
        let key = created["key"].as_str().expect("key").to_owned();
        let (status, body) = app
            .send("DELETE", &format!("/api/notify/channels/{key}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["removed"], 1);
        assert_eq!(app.dispatcher.pending_total(), 0);
        assert!(app.dispatcher.history().is_empty());
        assert_eq!(
            app.persists.load(Ordering::SeqCst),
            2,
            "create + delete each persist"
        );
        let (_, list) = app.send("GET", "/api/notify/channels", None).await;
        assert_eq!(list.as_array().expect("array").len(), 0);
    }
}
