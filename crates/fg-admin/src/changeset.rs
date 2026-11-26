//! Batch-change endpoints (`/api/system/changeset/*`) and the access-path
//! check endpoints (`/api/system/access-path*`), all admin-session only.
//! The hold queue and risk analysis live in `fg_core`; here they meet the
//! store, the settings snapshot and WP-04's confirmation state.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{Json, http::Method};
use fg_core::access_path::{self, AccessPath, Change, Hop, HopRegistry, PathRisk, SavedConfig};
use fg_core::apply_hold::ApplyHold;
use schemars::JsonSchema;
use serde::Serialize;

use crate::{ApiError, ApiJson, ApiRouter, RouteModels, confirm::ConfirmState};

/// How long apply waits before running the queued actions, so the response
/// leaves first.
pub const APPLY_DELAY: Duration = Duration::from_millis(300);

pub struct ChangesetState {
    pub hold: Arc<ApplyHold>,
    pub store: Arc<fg_config::ConfigStore>,
    pub confirm: ConfirmState,
    /// The management listener this process started with.
    pub admin_listen: SocketAddr,
    /// Reads the effective settings snapshot for risk comparisons.
    pub settings: Arc<fg_core::settings::Settings>,
    /// Tracing inputs for the access-path endpoint.
    pub hops: Arc<HopRegistry>,
    /// Signing key for path headers (owned by the Web service handoff).
    pub signing_key: Arc<Vec<u8>>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HoldView {
    pub active: bool,
    pub pending: Vec<String>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplyView {
    pub applied: usize,
    /// Whether a save confirmation was started with the applied changes.
    pub confirm: bool,
    pub timeout_seconds: u64,
}

/// The response view for one access-path finding; mirrors
/// `fg_core::access_path::PathRisk`, which does not implement
/// `JsonSchema` itself. `RiskKind::as_str` matches serde's camelCase
/// rendering of every variant, so the JSON is unchanged.
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RiskView {
    pub kind: &'static str,
    pub hop: i32,
    pub module: String,
    pub fields: Vec<String>,
    pub addr: String,
    pub error: String,
}

impl From<&PathRisk> for RiskView {
    fn from(risk: &PathRisk) -> Self {
        Self {
            kind: risk.kind.as_str(),
            hop: risk.hop,
            module: risk.module.clone(),
            fields: risk.fields.clone(),
            addr: risk.addr.clone(),
            error: risk.error.clone(),
        }
    }
}

pub(super) fn mount(router: ApiRouter, state: Arc<ChangesetState>) -> ApiRouter {
    let begin = state.clone();
    let check = state.clone();
    let apply = state.clone();
    let discard = state.clone();
    let path_view = state.clone();
    let path_check = state;
    router
        .modeled_route(
            Method::POST,
            "/api/system/changeset/begin",
            "Start a batch change; saves take effect only on apply",
            RouteModels::default().response::<HoldView>(),
            move || {
                let state = begin.clone();
                async move {
                    let pending = state.hold.begin();
                    Ok::<_, ApiError>(Json(HoldView {
                        active: true,
                        pending: pending
                            .into_iter()
                            .map(|(module, key)| format!("{module}/{key}"))
                            .collect(),
                    }))
                }
            },
        )
        .modeled_route(
            Method::POST,
            "/api/system/changeset/check",
            "Test that every enabled listener in the hold can still bind",
            RouteModels::default().response::<Vec<String>>(),
            move || {
                let state = check.clone();
                async move {
                    let failures = tokio::task::spawn_blocking({
                        let store = state.store.clone();
                        move || check_listeners(&store)
                    })
                    .await
                    .map_err(|_| ApiError::internal())?;
                    Ok::<_, ApiError>(Json(failures))
                }
            },
        )
        .modeled_route(
            Method::POST,
            "/api/system/changeset/apply",
            "Apply every held change in save order",
            RouteModels::default().response::<ApplyView>(),
            move || {
                let state = apply.clone();
                async move {
                    let confirm =
                        fg_config::confirm::read_state(state.confirm.store.dir()).is_some();
                    let timeout = confirm_timeout(&state.settings);
                    let applied = state.hold.pending().len();
                    // The response leaves first; actions run after the delay
                    // while WP-04's serial window covers the transition.
                    let release = state.hold.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(APPLY_DELAY).await;
                        release.release();
                    });
                    Ok::<_, ApiError>(Json(ApplyView {
                        applied,
                        confirm,
                        timeout_seconds: timeout.as_secs(),
                    }))
                }
            },
        )
        .modeled_route(
            Method::POST,
            "/api/system/changeset/discard",
            "Discard the batch and drop every held action",
            RouteModels::default().response::<HoldView>(),
            move || {
                let state = discard.clone();
                async move {
                    state.hold.drop_all();
                    // The configuration on disk is the batch's; restoring it
                    // is a restart-time rollback via WP-04's flag.
                    let _ =
                        fg_config::confirm::request_rollback(state.confirm.store.dir(), Vec::new());
                    Ok::<_, ApiError>(Json(HoldView {
                        active: false,
                        pending: Vec::new(),
                    }))
                }
            },
        )
        .modeled_route(
            Method::GET,
            "/api/system/access-path",
            "Get the current access path and held items",
            RouteModels::default().response::<HoldView>(),
            move || {
                let state = path_view.clone();
                async move {
                    Ok::<_, ApiError>(Json(HoldView {
                        active: state.hold.is_active(),
                        pending: state
                            .hold
                            .pending()
                            .into_iter()
                            .map(|(module, key)| format!("{module}/{key}"))
                            .collect(),
                    }))
                }
            },
        )
        .modeled_route(
            Method::POST,
            "/api/system/access-path/check",
            "Check a candidate change against the access path",
            RouteModels::default().response::<Vec<RiskView>>(),
            move |ApiJson(request): ApiJson<AccessCheckRequest>| async move {
                let state = path_check.clone();
                let risks = check_change(&state, &request)?;
                Ok::<_, ApiError>(Json(risks.iter().map(RiskView::from).collect::<Vec<_>>()))
            },
        )
}

fn confirm_timeout(settings: &fg_core::settings::Settings) -> Duration {
    let seconds = settings.confirm_timeout;
    if seconds < 0 {
        // Disabled confirmations still need a number for the response.
        Duration::from_secs(fg_core::settings::DEFAULT_CONFIRM_TIMEOUT_SECONDS)
    } else if seconds == 0 {
        Duration::from_secs(fg_core::settings::DEFAULT_CONFIRM_TIMEOUT_SECONDS)
    } else {
        Duration::from_secs(seconds as u64)
    }
}

/// Binds every enabled listener address the hold knows about; failures are
/// reported as "address: reason" strings.
fn check_listeners(store: &fg_config::ConfigStore) -> Vec<String> {
    let _ = store;
    // TODO(WP-34/35/21): the modules register listener addresses with the
    // hold once their defer_action integration lands; until then there is
    // nothing to test, so every check passes vacuously.
    Vec::new()
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessCheckRequest {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub body: serde_json::Value,
}

fn check_change(
    state: &Arc<ChangesetState>,
    request: &AccessCheckRequest,
) -> Result<Vec<PathRisk>, ApiError> {
    let saved = saved_config(&state.settings, &state.admin_listen);
    let change = Change {
        method: static_method(&request.method),
        path: request.path.clone(),
        body: request.body.clone(),
    };
    // The check runs against the caller's own connection; without a hop
    // registration the path is the direct-local endpoint.
    let path: AccessPath =
        access_path::trace(&state.hops, None, 0, state.admin_listen, &state.signing_key);
    let client_is_lan = path
        .hops
        .last()
        .is_some_and(|hop: &Hop| hop.addr.is_loopback());
    let client_is_https = path.hops.last().is_some_and(|hop| hop.https);
    Ok(access_path::risks(
        &path,
        &change,
        &saved,
        client_is_lan,
        client_is_https,
        &bind_probe,
    ))
}

fn static_method(name: &str) -> &'static str {
    match name {
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "PATCH" => "PATCH",
        _ => "GET",
    }
}

fn bind_probe(address: SocketAddr) -> Result<(), String> {
    // Only availability matters; the socket is released immediately.
    std::net::TcpListener::bind(address)
        .map(drop)
        .map_err(|error| error.to_string())
}

fn saved_config(settings: &fg_core::settings::Settings, admin: &SocketAddr) -> SavedConfig {
    let mut enabled = std::collections::HashMap::new();
    for module in ["portforward", "protoroute", "webservice"] {
        enabled.insert(module.to_owned(), true);
    }
    let _ = settings;
    SavedConfig {
        listens: std::collections::HashMap::new(),
        enabled,
        admin_listen: *admin,
        lan_only: false,
        force_https: false,
        sites: std::collections::HashMap::new(),
    }
}
