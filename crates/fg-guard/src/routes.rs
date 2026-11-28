//! Guard management routes (WP-50 §4 / WP-52 §4): the ban list, the
//! module settings, the jail rule collection (with presets and the
//! rule-test endpoint), served with plain axum while mirroring the
//! fg-admin contract (JSON shapes, status codes, problem lists) exactly
//! like the fg-gateway module routes do — fg-guard cannot depend on
//! fg-admin. The 4 generic module-log operations are part of the module
//! log framework (WP-09) and intentionally absent here.
//!
//! Endpoints (permission domain `guard`):
//!
//! | Method | Path | Request | Response |
//! |---|---|---|---|
//! | GET | `/api/guard/bans` | query: `source`, `search`, `includeExpired`, `offset`, `limit` | `{"bans":[Entry],"total":N}` |
//! | POST | `/api/guard/bans` | `{"target":"1.2.3.4","seconds":86400}` (`-1` permanent, default 86400) | created `Entry` |
//! | DELETE | `/api/guard/bans` | query: `target` (IP or CIDR) | `{"removed":N}` |
//! | GET | `/api/guard/settings` | — | normalized `Settings` |
//! | PUT | `/api/guard/settings` | `Settings` | normalized `Settings` |
//! | GET | `/api/guard/status` | — | `{"enable","firewall","firewallSync","bans","offenses","loginTrusted","limit"}` |
//! | GET | `/api/guard/firewall/rules` | — | `{"backend":…,"rules":…}` (WP-51 §4 "查看规则") |
//! | GET | `/api/guard/jails` | — | `[Jail]` (normalized) |
//! | POST | `/api/guard/jails` | `Jail` | created `Jail` |
//! | POST | `/api/guard/jails/{key}/copy` | `Jail` | created `Jail` (fresh key, inserted after the source) |
//! | PUT | `/api/guard/jails/{key}` | `Jail` | replaced `Jail` |
//! | DELETE | `/api/guard/jails/{key}` | — | `{"removed":1}` |
//! | PUT | `/api/guard/jails/{key}/enable` | `{"enable":bool}` | `{"ok":true}` |
//! | PUT | `/api/guard/jails-order` | `{"keys":[…]}` full ordered list | `{"ok":true}` |
//! | PUT | `/api/guard/jails-enable` | `{"keys":[…],"enable":bool}` | `{"changed":N}` |
//! | PUT | `/api/guard/jails-group` | `{"keys":[…],"group":"…"}` | `{"ok":true}` |
//! | POST | `/api/guard/jails-delete` | `{"keys":[…]}` | `{"removed":N}` |
//! | GET | `/api/guard/presets` | — | `[{"id",…jail fields}]` |
//! | POST | `/api/guard/jails/test` | `{"source":"file"\|"journal"\|"command"\|"docker",filter,ignore,lines:[…]}` / `{"source":"web",filter,ignore,anyStatus,unknownHost,samples:[…]}` / `{"source":"tls",filter,samples:[…]}` | `{"results":[…]}` |
//!
//! Every mutation runs normalize → validate → persist → engine reload →
//! source reconcile, mirroring the fg-admin `Collection::change` commit
//! order (the file is written before the snapshot advances; a failed
//! write leaves the desired state untouched). Validation problems are
//! returned as `400` `{"error":…,"problems":[{"field":…,"reason":…}]}`.
//! A `docker` jail saved without a compiled docker module is refused
//! (WP-52 §3.3). Jail keys follow the fg-admin collection convention:
//! 12 lowercase hex characters generated on create/copy; a
//! client-supplied valid unique key is kept on create.
//!
//! Authentication is NOT performed here: [`mount`] routes are meant to be
//! mounted under the management router whose authorize layer maps
//! `/api/guard/…` to domain `guard` (GET → `guard:read`, every mutation →
//! `guard:write`). Mounted outside that router, callers must apply their
//! own authentication layers.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use axum::{
    Json,
    body::Bytes,
    extract::{
        Path, Query,
        rejection::{PathRejection, QueryRejection},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::RwLock;

use crate::bans::{GuardBanError, GuardService};
use crate::jail::{
    self, JailSource,
    model::Jail,
    validate::{self as jail_validate},
};
use crate::model::{FileConfig, Settings};
use crate::validate::{self, Problem};

/// Writes the whole [`FileConfig`] to `guard.json`.
pub type PersistFn = Arc<dyn Fn(&FileConfig) -> anyhow::Result<()> + Send + Sync>;

/// Shared state behind the guard management routes.
pub struct RoutesState {
    /// The live desired configuration (already normalized once loaded).
    pub config: Arc<RwLock<FileConfig>>,
    pub service: Arc<GuardService>,
    /// The jail engine: jail mutations reload its snapshot and reconcile
    /// the source tasks after a successful persist.
    pub engine: Arc<jail::JailEngine>,
    pub persist: PersistFn,
}

/// Adds the guard ban list, settings and jail routes to `router`.
pub fn mount(router: axum::Router, state: Arc<RoutesState>) -> axum::Router {
    let (list, create, remove) = (state.clone(), state.clone(), state.clone());
    let (settings_get, settings_put, status) = (state.clone(), state.clone(), state.clone());
    let (rules, jails_list_st) = (state.clone(), state.clone());
    let (jails_create_st, jails_replace_st, jails_remove_st) =
        (state.clone(), state.clone(), state.clone());
    let (jails_copy_st, jails_enable_st, jails_order_st) =
        (state.clone(), state.clone(), state.clone());
    let (jails_batch_enable_st, jails_group_st, jails_batch_delete_st) =
        (state.clone(), state.clone(), state.clone());
    let presets = state.clone();
    router
        .route(
            "/api/guard/bans",
            get(
                move |query: Result<Query<BansQuery>, QueryRejection>| async move {
                    bans_list(list, query).await
                },
            )
            .post(move |body: Bytes| async move { bans_create(create, body).await })
            .delete(
                move |query: Result<Query<TargetQuery>, QueryRejection>| async move {
                    bans_delete(remove, query).await
                },
            ),
        )
        .route(
            "/api/guard/settings",
            get(move || async move { settings_view(settings_get).await })
                .put(move |body: Bytes| async move { settings_save(settings_put, body).await }),
        )
        .route(
            "/api/guard/status",
            get(move || async move { status_view(status).await }),
        )
        .route(
            "/api/guard/firewall/rules",
            get(move || async move { firewall_rules_view(rules).await }),
        )
        .route(
            "/api/guard/jails",
            get(move || async move { jails_list_view(jails_list_st).await })
                .post(move |body: Bytes| async move { jails_create(jails_create_st, body).await }),
        )
        .route(
            "/api/guard/jails/{key}",
            put(
                move |path: Result<Path<String>, PathRejection>,
                      body: Bytes| async move { jails_update(jails_replace_st, path, body).await },
            )
            .delete(
                move |path: Result<Path<String>, PathRejection>| async move {
                    jails_delete(jails_remove_st, path).await
                },
            ),
        )
        .route(
            "/api/guard/jails/{key}/copy",
            post(
                move |path: Result<Path<String>, PathRejection>,
                      body: Bytes| async move { jails_copy(jails_copy_st, path, body).await },
            ),
        )
        .route(
            "/api/guard/jails/{key}/enable",
            put(
                move |path: Result<Path<String>, PathRejection>,
                      body: Bytes| async move { jails_enable(jails_enable_st, path, body).await },
            ),
        )
        .route(
            "/api/guard/jails-order",
            put(move |body: Bytes| async move { jails_order(jails_order_st, body).await }),
        )
        .route(
            "/api/guard/jails-enable",
            put(move |body: Bytes| async move {
                jails_batch_enable(jails_batch_enable_st, body).await
            }),
        )
        .route(
            "/api/guard/jails-group",
            put(move |body: Bytes| async move { jails_group(jails_group_st, body).await }),
        )
        .route(
            "/api/guard/jails-delete",
            post(move |body: Bytes| async move {
                jails_batch_delete(jails_batch_delete_st, body).await
            }),
        )
        .route(
            "/api/guard/presets",
            get(move || async move { presets_view(presets).await }),
        )
        .route(
            "/api/guard/jails/test",
            post(move |body: Bytes| async move { jails_test(body).await }),
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
                    "error": "invalid guard configuration",
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
/// normalized candidate before publishing it, reloads the jail engine and
/// reconciles the source tasks afterwards.
///
/// Mirrors the fg-admin `Collection::change` commit order: the file is
/// written first and the in-memory snapshot only advances once the
/// persist hook succeeded, so a failed write leaves the desired state
/// untouched.
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
                tracing::warn!(%error, "persisting guard.json failed");
                internal()
            })?;
        state
            .engine
            .reload(&candidate)
            .map_err(|error| Failure::Api(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))
            .map_err(Response::from)?;
        *guard = candidate;
        drop(guard);
        state.engine.reconcile_sources();
        return Ok(value);
    }
    drop(guard);
    Ok(value)
}

async fn bans_list(
    state: Arc<RoutesState>,
    query: Result<Query<BansQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(params)) = query else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid query".to_owned()).into();
    };
    let filter = fg_net::banlist::BanFilter {
        source: params.source,
        search: params.search,
        include_expired: params.include_expired.unwrap_or(false),
        offset: params.offset.unwrap_or(0),
        limit: params.limit.unwrap_or(0),
    };
    let bans = state.service.list(&filter);
    let total = state.service.count(&filter);
    Json(json!({ "bans": bans, "total": total })).into_response()
}

async fn bans_create(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(request) = serde_json::from_slice::<ManualBan>(&body) else {
        return decode_error();
    };
    let seconds = request.seconds.unwrap_or(validate::MANUAL_DEFAULT_SECONDS);
    match state.service.ban_manual(&request.target, seconds) {
        Ok(entry) => Json(entry).into_response(),
        Err(error) => Failure::Api(status_for(error), error.to_string()).into(),
    }
}

async fn bans_delete(
    state: Arc<RoutesState>,
    query: Result<Query<TargetQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(params)) = query else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid query".to_owned()).into();
    };
    match state.service.unban(&params.target) {
        Ok(removed) => Json(json!({ "removed": removed })).into_response(),
        Err(error) => Failure::Api(status_for(error), error.to_string()).into(),
    }
}

fn status_for(error: GuardBanError) -> StatusCode {
    match error {
        GuardBanError::InvalidTarget | GuardBanError::InvalidDuration | GuardBanError::Loopback => {
            StatusCode::BAD_REQUEST
        }
        GuardBanError::AlreadyPermanent | GuardBanError::Full => StatusCode::CONFLICT,
    }
}

async fn settings_view(state: Arc<RoutesState>) -> Response {
    let config = state.config.read().await;
    Json(crate::validate::normalize(config.clone()).settings).into_response()
}

/// Normalize → validate → apply to the policy → persist → reload; a
/// failed write leaves the desired state untouched, matching the gateway
/// module commit order.
async fn settings_save(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(settings) = serde_json::from_slice::<Settings>(&body) else {
        return decode_error();
    };
    let current = state.config.read().await.clone();
    let mut candidate = current.clone();
    candidate.settings = settings;
    let candidate = crate::validate::normalize(candidate);
    let problems = validate::validate(&candidate);
    if !problems.is_empty() {
        return Failure::Problems(problems).into();
    }
    // A no-op save echoes the settings but skips the policy application,
    // the persist and the reload, like the fg-admin collections.
    let changed = candidate.settings != current.settings;
    if changed {
        state.service.apply_settings(&candidate.settings);
        let persist = state.persist.clone();
        let saved = candidate.clone();
        let persisted = tokio::task::spawn_blocking(move || persist(&saved))
            .await
            .map_err(|_| internal())
            .and_then(|result| {
                result.map_err(|error| {
                    tracing::warn!(%error, "persisting guard.json failed");
                    internal()
                })
            });
        if let Err(failure) = persisted {
            return failure.into();
        }
        // The ignore set (whitelist) follows the settings; the jail
        // snapshot rebuild is cheap and keeps both in sync.
        let _ = state.engine.reload(&candidate);
        *state.config.write().await = candidate;
    }
    Json(state.service.settings()).into_response()
}

fn internal() -> Failure {
    Failure::Api(
        StatusCode::INTERNAL_SERVER_ERROR,
        "configuration operation failed".to_owned(),
    )
}

fn decode_error() -> Response {
    Failure::Api(StatusCode::BAD_REQUEST, "invalid JSON body".to_owned()).into_response()
}

async fn status_view(state: Arc<RoutesState>) -> Response {
    let service = &state.service;
    let counts = service.counts();
    let settings = service.settings();
    // The firewall sync lives inside the module status (WP-51 §4: backend,
    // unavailable reason, statistics). Firewall problems never fail the
    // endpoint — the application layer keeps answering.
    let firewall_status = service
        .firewall()
        .map(|sync| sync.status())
        .unwrap_or_else(|| crate::firewall::FwStatus {
            enabled: settings.firewall,
            ..crate::firewall::FwStatus::default()
        });
    let mut firewall = serde_json::to_value(&firewall_status)
        .unwrap_or_else(|_| json!({ "enabled": settings.firewall }));
    firewall["text"] = json!(crate::firewall::status_text(&firewall_status));
    Json(json!({
        "enable": settings.enable,
        "firewall": settings.firewall,
        "firewallSync": firewall,
        "bans": counts.bans,
        "offenses": counts.offenses,
        "loginTrusted": counts.login_trusted,
        "limit": service.limit(),
        "jails": jail_status(&state).await,
    }))
    .into_response()
}

/// The jail summary inside the module status: rule counts and the live
/// engine counters (WP-52 status surface).
async fn jail_status(state: &RoutesState) -> serde_json::Value {
    let config = state.config.read().await;
    let enabled = config.jails.iter().filter(|jail| jail.enable).count();
    let stats = state.engine.stats();
    json!({
        "total": config.jails.len(),
        "enabled": enabled,
        "bans": stats.bans.load(std::sync::atomic::Ordering::Relaxed),
        "linesMatched": stats.lines_matched.load(std::sync::atomic::Ordering::Relaxed),
        "eventsMatched": stats.events_matched.load(std::sync::atomic::Ordering::Relaxed),
    })
}

/// The full rule text the sync last wrote ("view rules", WP-51 §4).
async fn firewall_rules_view(state: Arc<RoutesState>) -> Response {
    let sync = state.service.firewall();
    let status = sync.as_ref().map(|sync| sync.status());
    let rules = sync.as_ref().and_then(|sync| sync.rules_text());
    Json(json!({
        "backend": status
            .as_ref()
            .and_then(|status| status.backend)
            .map(|backend| backend.as_str()),
        "rules": rules,
    }))
    .into_response()
}

// ---------------------------------------------------------------- jails

async fn jails_list_view(state: Arc<RoutesState>) -> Response {
    let config = state.config.read().await;
    Json(crate::validate::normalize(config.clone()).jails).into_response()
}

/// Applies upstream defaults and collects every validation problem of a
/// candidate; docker jails without a compiled docker module are refused
/// (WP-52 §3.3).
fn settle(state: &RoutesState, config: &mut FileConfig) -> Result<(), Failure> {
    *config = validate::normalize(std::mem::take(config));
    let problems = validate::validate(config);
    if !problems.is_empty() {
        return Err(Failure::Problems(problems));
    }
    if config
        .jails
        .iter()
        .any(|jail| jail.source == JailSource::Docker && state.engine.docker().is_none())
    {
        return Err(Failure::Api(
            StatusCode::BAD_REQUEST,
            "docker module is not included in this build; docker jails are unavailable".to_owned(),
        ));
    }
    Ok(())
}

async fn jails_create(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(mut jail) = serde_json::from_slice::<Jail>(&body) else {
        return decode_error();
    };
    let settle_state = Arc::clone(&state);
    match mutate(&state, move |config| {
        // A client-supplied valid unique key is kept; anything else gets
        // a generated one (fg-admin collection behavior on create).
        if !jail_validate::valid_key(&jail.key)
            || config.jails.iter().any(|row| row.key == jail.key)
        {
            jail.key = random_jail_key(&config.jails)?;
        }
        config.jails.push(jail);
        settle(&settle_state, config)?;
        let created = config.jails.last().cloned().expect("just pushed");
        Ok((Json(created), true))
    })
    .await
    {
        Ok(created) => created.into_response(),
        Err(response) => response,
    }
}

async fn jails_copy(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(mut jail) = serde_json::from_slice::<Jail>(&body) else {
        return decode_error();
    };
    let Ok(source) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".to_owned()).into();
    };
    let settle_state = Arc::clone(&state);
    match mutate(&state, move |config| {
        let index = locate(&config.jails, &source)?;
        // Copies always receive a generated key (fg-admin collection
        // behavior): the template only determines the insertion position.
        jail.key = random_jail_key(&config.jails)?;
        config.jails.insert(index + 1, jail);
        settle(&settle_state, config)?;
        let created = config.jails[index + 1].clone();
        Ok((Json(created), true))
    })
    .await
    {
        Ok(created) => created.into_response(),
        Err(response) => response,
    }
}

async fn jails_update(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(mut jail) = serde_json::from_slice::<Jail>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".to_owned()).into();
    };
    let settle_state = Arc::clone(&state);
    match mutate(&state, move |config| {
        let index = locate(&config.jails, &key)?;
        jail.key = key.clone();
        config.jails[index] = jail;
        settle(&settle_state, config)?;
        let replaced = config.jails[index].clone();
        Ok((Json(replaced), true))
    })
    .await
    {
        Ok(replaced) => replaced.into_response(),
        Err(response) => response,
    }
}

async fn jails_delete(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".to_owned()).into();
    };
    match mutate(&state, move |config| {
        let index = locate(&config.jails, &key)?;
        config.jails.remove(index);
        Ok((Json(json!({ "removed": 1 })), true))
    })
    .await
    {
        Ok(removed) => removed.into_response(),
        Err(response) => response,
    }
}

async fn jails_batch_delete(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Keys { keys }) = serde_json::from_slice::<Keys>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys".to_owned(),
        )
        .into();
    };
    match mutate(&state, move |config| {
        // Every requested key must exist, mirroring the fg-admin batch
        // delete: no partial removals.
        find_indices(&config.jails, &keys).ok_or_else(missing_item)?;
        let removed: HashSet<_> = keys.iter().map(String::as_str).collect();
        config
            .jails
            .retain(|jail| !removed.contains(jail.key.as_str()));
        let count = keys.len();
        Ok((Json(json!({ "removed": count })), true))
    })
    .await
    {
        Ok(removed) => removed.into_response(),
        Err(response) => response,
    }
}

async fn jails_enable(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(Enable { enable }) = serde_json::from_slice::<Enable>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::Api(StatusCode::BAD_REQUEST, "invalid item key".to_owned()).into();
    };
    match mutate(&state, move |config| {
        let index = locate(&config.jails, &key)?;
        let jail = &mut config.jails[index];
        let changed = jail.enable != enable;
        jail.enable = enable;
        Ok((Json(json!({ "ok": true })), changed))
    })
    .await
    {
        Ok(ok) => ok.into_response(),
        Err(response) => response,
    }
}

async fn jails_batch_enable(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(BatchEnable { keys, enable }) = serde_json::from_slice::<BatchEnable>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys".to_owned(),
        )
        .into();
    };
    match mutate(&state, move |config| {
        let indices = find_indices(&config.jails, &keys).ok_or_else(missing_item)?;
        let mut changed = 0;
        for index in indices {
            let jail = &mut config.jails[index];
            if jail.enable != enable {
                jail.enable = enable;
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

async fn jails_order(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Keys { keys }) = serde_json::from_slice::<Keys>(&body) else {
        return decode_error();
    };
    match mutate(&state, move |config| {
        if keys.len() != config.jails.len() {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                "order must include every item once".to_owned(),
            ));
        }
        let Some(indices) = find_indices(&config.jails, &keys) else {
            return Err(Failure::Api(
                StatusCode::BAD_REQUEST,
                "order contains an unknown or duplicate key".to_owned(),
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
                config.jails.swap(index, new);
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

async fn jails_group(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Group { keys, group }) = serde_json::from_slice::<Group>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys".to_owned(),
        )
        .into();
    };
    let name = group.trim().to_owned();
    if name.chars().count() > 64 {
        return Failure::Api(
            StatusCode::BAD_REQUEST,
            "group name must have at most 64 characters".to_owned(),
        )
        .into();
    }
    match mutate(&state, move |config| {
        let indices = find_indices(&config.jails, &keys).ok_or_else(missing_item)?;
        let mut changed = false;
        for index in indices {
            let field = &mut config.jails[index].group;
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

async fn presets_view(_state: Arc<RoutesState>) -> Response {
    Json(&*crate::presets::PRESETS).into_response()
}

// ------------------------------------------------------- test endpoint

/// The `jails/test` request: tagged by the rule's source type. Log
/// sources test filter/ignore lines against pasted log lines; `web`
/// tests path rules against sample requests; `tls` classifies pasted
/// handshake failure reasons or tests kind selections (WP-52 §4).
#[derive(Deserialize)]
#[serde(tag = "source", rename_all = "lowercase", deny_unknown_fields)]
enum TestRequest {
    File(LogTest),
    Journal(LogTest),
    Command(LogTest),
    Docker(LogTest),
    Web(WebTest),
    Tls(TlsTest),
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct LogTest {
    filter: String,
    ignore: String,
    lines: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct WebTest {
    filter: String,
    ignore: String,
    any_status: bool,
    unknown_host: bool,
    target: Option<String>,
    samples: Vec<WebSample>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct WebSample {
    path: String,
    listener: Option<String>,
    host: Option<String>,
    status: u16,
    ip: Option<String>,
    unknown_host: bool,
    default_site: bool,
    trusted_user: bool,
    access_denied: bool,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct TlsTest {
    filter: String,
    samples: Vec<TlsSample>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct TlsSample {
    /// A pasted rustls-style error; classified like the web service does.
    reason: Option<String>,
    /// An explicit kind tag to test a selection.
    kind: Option<String>,
    listener: Option<String>,
}

async fn jails_test(body: Bytes) -> Response {
    let Ok(request) = serde_json::from_slice::<TestRequest>(&body) else {
        return decode_error();
    };
    let results = match request {
        TestRequest::File(test)
        | TestRequest::Journal(test)
        | TestRequest::Command(test)
        | TestRequest::Docker(test) => {
            let Ok(matchers) = jail::compile_filter(&test.filter) else {
                return Failure::Api(
                    StatusCode::BAD_REQUEST,
                    "the filter does not compile".to_owned(),
                )
                .into();
            };
            let ignores = match jail::compile_ignore(&test.ignore) {
                Ok(ignores) => ignores,
                Err(errors) => {
                    return Failure::Api(StatusCode::BAD_REQUEST, errors.join("; ")).into();
                }
            };
            test.lines
                .iter()
                .map(|line| {
                    let ignored = ignores.iter().any(|regex| regex.is_match(line));
                    let ip = matchers.iter().find_map(|matcher| matcher.match_host(line));
                    let hit = matchers.iter().any(|matcher| matcher.is_match(line)) && !ignored;
                    json!({
                        "line": line,
                        "hit": hit,
                        "ignored": ignored,
                        "ip": ip.map(|ip| ip.to_string()),
                    })
                })
                .collect::<Vec<_>>()
        }
        TestRequest::Web(test) => {
            let rules = match crate::webprobe::compile_paths(&test.filter) {
                Ok(rules) => rules,
                Err(error) => {
                    return Failure::Api(StatusCode::BAD_REQUEST, error.to_string()).into();
                }
            };
            let ignores = match crate::webprobe::compile_paths(&test.ignore) {
                Ok(ignores) => ignores,
                Err(error) => {
                    return Failure::Api(StatusCode::BAD_REQUEST, error.to_string()).into();
                }
            };
            test.samples
                .iter()
                .map(|sample| {
                    let listener: &str = sample.listener.as_deref().unwrap_or("");
                    let summary = crate::webprobe::WebRequestSummary {
                        listener,
                        path: &sample.path,
                        host: sample.host.as_deref().unwrap_or("example.test"),
                        status: sample.status,
                        ip: sample
                            .ip
                            .as_deref()
                            .and_then(|ip| ip.parse().ok())
                            .unwrap_or_else(|| "203.0.113.1".parse().expect("constant")),
                        unknown_host: sample.unknown_host,
                        default_site: sample.default_site,
                        trusted_user: sample.trusted_user,
                        access_denied: sample.access_denied,
                    };
                    let counted = crate::webprobe::web_jail_counts(
                        test.target.as_deref().unwrap_or(""),
                        &rules,
                        &ignores,
                        test.any_status,
                        test.unknown_host,
                        &summary,
                    );
                    json!({
                        "path": sample.path,
                        "status": crate::webprobe::effective_status(&summary),
                        "counted": counted,
                    })
                })
                .collect::<Vec<_>>()
        }
        TestRequest::Tls(test) => {
            let kinds: Vec<_> = jail::split_lines(&test.filter)
                .into_iter()
                .filter_map(|line| crate::webprobe::TlsFailKind::from_tag(&line))
                .collect();
            test.samples
                .iter()
                .map(|sample| {
                    let kind = sample
                        .kind
                        .as_deref()
                        .and_then(crate::webprobe::TlsFailKind::from_tag)
                        .unwrap_or_else(|| {
                            crate::webprobe::classify(sample.reason.as_deref().unwrap_or(""))
                        });
                    let fail = crate::webprobe::TlsFail {
                        listener: sample.listener.as_deref().unwrap_or("web"),
                        ip: "203.0.113.1".parse().expect("constant"),
                        kind,
                        reason: sample.reason.as_deref().unwrap_or(""),
                        trusted_proxy: false,
                    };
                    json!({
                        "kind": kind.tag(),
                        "counted": crate::webprobe::tls_jail_counts("", &kinds, &fail, false, false),
                    })
                })
                .collect::<Vec<_>>()
        }
    };
    Json(json!({ "results": results })).into_response()
}

// ------------------------------------------------- collection helpers

fn item_key(path: Result<Path<String>, PathRejection>) -> Result<String, Failure> {
    match path {
        Ok(Path(key)) if jail_validate::valid_key(&key) => Ok(key),
        _ => Err(Failure::Api(
            StatusCode::BAD_REQUEST,
            "invalid item key".to_owned(),
        )),
    }
}

fn batch_keys(mut keys: Vec<String>) -> Result<Vec<String>, Failure> {
    if keys.is_empty() || keys.len() > 500 || !keys.iter().all(|key| jail_validate::valid_key(key))
    {
        return Err(Failure::Api(
            StatusCode::BAD_REQUEST,
            "expected between 1 and 500 valid keys".to_owned(),
        ));
    }
    let mut seen = HashSet::with_capacity(keys.len());
    keys.retain(|key| seen.insert(key.clone()));
    Ok(keys)
}

fn locate(jails: &[Jail], key: &str) -> Result<usize, Failure> {
    jails
        .iter()
        .position(|jail| jail.key == key)
        .ok_or(Failure::Api(
            StatusCode::NOT_FOUND,
            "item not found".to_owned(),
        ))
}

fn missing_item() -> Failure {
    Failure::Api(StatusCode::NOT_FOUND, "item not found".to_owned())
}

/// Maps requested keys (each once) onto jail positions; `None` when a
/// key is unknown or duplicated.
fn find_indices(jails: &[Jail], keys: &[String]) -> Option<Vec<usize>> {
    let mut slots: HashMap<_, _> = keys
        .iter()
        .enumerate()
        .map(|(slot, key)| (key.as_str(), slot))
        .collect();
    if slots.len() != keys.len() {
        return None;
    }
    let mut indices = vec![0; keys.len()];
    for (index, jail) in jails.iter().enumerate() {
        if let Some(slot) = slots.remove(jail.key.as_str()) {
            indices[slot] = index;
            if slots.is_empty() {
                break;
            }
        }
    }
    slots.is_empty().then_some(indices)
}

/// 12 lowercase hex characters, unique within the collection — the same
/// shape the fg-admin collections generate (6 random bytes).
fn random_jail_key(jails: &[Jail]) -> Result<String, Failure> {
    for _ in 0..8 {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes[2..]).map_err(|_| {
            Failure::Api(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key generation failed".to_owned(),
            )
        })?;
        let key = format!("{:012x}", u64::from_be_bytes(bytes));
        if !jails.iter().any(|jail| jail.key == key) {
            return Ok(key);
        }
    }
    Err(Failure::Api(
        StatusCode::INTERNAL_SERVER_ERROR,
        "unable to generate a unique jail key".to_owned(),
    ))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct BansQuery {
    source: Option<String>,
    search: Option<String>,
    include_expired: Option<bool>,
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetQuery {
    target: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManualBan {
    target: String,
    /// `-1` permanent, otherwise 1..=720 hours (default 24 hours).
    seconds: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Keys {
    keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Group {
    keys: Vec<String>,
    group: String,
}
