//! Guard management routes (WP-50 §4): the ban list and the module
//! settings, served with plain axum while mirroring the fg-admin contract
//! (JSON shapes, status codes, problem lists) exactly like the
//! fg-gateway module routes do — fg-guard cannot depend on fg-admin.
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
//! | GET | `/api/guard/status` | — | `{"enable","firewall","bans","offenses","loginTrusted","limit"}` |
//!
//! Manual bans and unbans are written through to the shared table
//! immediately (the delayed saver persists them); the settings PUT follows
//! the gateway module contract: normalize → validate → apply to the
//! policy → persist `guard.json` → publish, with validation problems
//! returned as `400` `{"error":…,"problems":[…]}`. Write operations are
//! meant to run behind the management router's audit layer (WP-11 wiring).
//!
//! Authentication is NOT performed here: [`mount`] routes are meant to be
//! mounted under the management router whose authorize layer maps
//! `/api/guard/…` to domain `guard` (GET → `guard:read`, every mutation →
//! `guard:write`). Mounted outside that router, callers must apply their
//! own authentication layers.

use std::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::{Query, rejection::QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::RwLock;

use crate::bans::{GuardBanError, GuardService};
use crate::model::{FileConfig, Settings};
use crate::validate::{self, Problem};

/// Writes the whole [`FileConfig`] to `guard.json`.
pub type PersistFn = Arc<dyn Fn(&FileConfig) -> anyhow::Result<()> + Send + Sync>;

/// Shared state behind the guard management routes.
pub struct RoutesState {
    /// The live desired settings (already normalized once loaded).
    pub config: Arc<RwLock<FileConfig>>,
    pub service: Arc<GuardService>,
    pub persist: PersistFn,
}

/// Adds the guard ban list and settings routes to `router`.
pub fn mount(router: axum::Router, state: Arc<RoutesState>) -> axum::Router {
    let (list, create, remove) = (state.clone(), state.clone(), state.clone());
    let (settings_get, settings_put, status) = (state.clone(), state.clone(), state);
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

/// Normalize → validate → apply to the policy → persist → publish; a
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
    // the persist and the publish, like the fg-admin collections.
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
    Json(json!({
        "enable": settings.enable,
        "firewall": settings.firewall,
        "bans": counts.bans,
        "offenses": counts.offenses,
        "loginTrusted": counts.login_trusted,
        "limit": service.limit(),
    }))
    .into_response()
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
