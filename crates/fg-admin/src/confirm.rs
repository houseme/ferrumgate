//! Save-confirmation endpoints: status, WebSocket confirmation and manual
//! rollback, all admin-session only. The state machine lives in
//! `fg_config::confirm`; this module wires it to HTTP.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{
    Json,
    extract::WebSocketUpgrade,
    http::{HeaderMap, Method, StatusCode},
};
use schemars::JsonSchema;
use serde::Serialize;
use time::OffsetDateTime;

use crate::{
    ApiError, ApiRouter, RouteModels,
    login::{COOKIE_NAME, cookie},
};
use fg_auth::AccountManager;
use fg_config::{ConfigStore, confirm as confirm_state};

/// Configuration names whose saves participate in confirmation.
pub const CONFIRM_MODULES: [&str; 3] = ["portforward", "protoroute", "webservice"];
pub const CONFIRM_HEADER: &str = "x-gately-confirm";

#[derive(Clone)]
pub struct ConfirmState {
    pub store: Arc<ConfigStore>,
    pub accounts: Arc<AccountManager>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmView {
    /// Whether a pending change exists.
    pub active: bool,
    pub id: String,
    pub deadline: String,
    pub seconds_left: u64,
    pub status: &'static str,
    pub modules: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

/// Wires the three confirmation endpoints. Mounted by the management
/// assembly once the store and accounts exist.
#[allow(dead_code)]
pub(super) fn mount(router: ApiRouter, state: ConfirmState) -> ApiRouter {
    let status_state = state.clone();
    let socket_state = state.clone();
    let rollback_state = state;
    router
        .modeled_route(
            Method::GET,
            "/api/system/confirm",
            "Get the pending save confirmation",
            RouteModels::default().response::<ConfirmView>(),
            move || {
                let state = status_state.clone();
                async move { Json(status(&state)) }
            },
        )
        .route(
            Method::GET,
            "/api/system/confirm/connect",
            "Confirm the pending change over a fresh connection",
            {
                let state = socket_state.clone();
                move |_headers: HeaderMap, upgrade: WebSocketUpgrade| async move {
                    upgrade.on_upgrade(move |socket| async move {
                        handle_socket(state, socket).await;
                    })
                }
            },
        )
        .modeled_route(
            Method::POST,
            "/api/system/confirm/rollback",
            "Roll back the pending change",
            RouteModels::default().response::<ConfirmView>(),
            move || {
                let state = rollback_state.clone();
                async move {
                    let store = state.store.clone();
                    tokio::task::spawn_blocking(move || {
                        confirm_state::request_rollback(store.dir(), Vec::new()).map_err(
                            |_: anyhow::Error| {
                                ApiError::new(StatusCode::CONFLICT, "没有待确认的变更")
                            },
                        )
                    })
                    .await
                    .map_err(|_| ApiError::internal())??;
                    Ok::<_, ApiError>(Json(status(&state)))
                }
            },
        )
}

fn status(state: &ConfirmState) -> ConfirmView {
    let pending = confirm_state::read_state(state.store.dir());
    match pending {
        Some(pending) => {
            let now = std::time::SystemTime::now();
            let seconds_left = pending
                .deadline
                .duration_since(now)
                .map(|left| left.as_secs())
                .unwrap_or(0);
            let status = if pending.rollback {
                "rollingBack"
            } else if pending.hold {
                "hold"
            } else if pending.wait_restart {
                "waitRestart"
            } else {
                "applying"
            };
            ConfirmView {
                active: true,
                id: pending.id,
                deadline: OffsetDateTime::from(pending.deadline)
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                seconds_left,
                status,
                modules: pending.files.keys().cloned().collect(),
                errors: (!pending.errors.is_empty()).then(|| pending.errors.clone()),
            }
        }
        None => ConfirmView {
            active: false,
            id: String::new(),
            deadline: String::new(),
            seconds_left: 0,
            status: "none",
            modules: Vec::new(),
            errors: None,
        },
    }
}

async fn handle_socket(state: ConfirmState, mut socket: axum::extract::ws::WebSocket) {
    // Any message on this fresh connection confirms; the browser always
    // opens a new TCP connection for WebSocket, which is the whole point:
    // keep-alive paths cannot replay it. The whole exchange is bounded.
    let outcome = match tokio::time::timeout(Duration::from_secs(10), socket.recv()).await {
        Err(_) | Ok(None) => Err(ApiError::new(StatusCode::REQUEST_TIMEOUT, "确认连接超时")),
        Ok(Some(_)) => Ok(()),
    };
    let payload = match outcome {
        Err(_) => {
            // Dropping the socket closes it; the client surfaces the timeout.
            return;
        }
        Ok(()) => confirm_now(&state),
    };
    let text = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_owned());
    let _ = socket.send(axum::extract::ws::Message::text(text)).await;
    // Dropping the socket closes the connection.
}

fn confirm_now(state: &ConfirmState) -> serde_json::Value {
    let pending = confirm_state::read_state(state.store.dir());
    let Some(pending) = pending else {
        return serde_json::json!({"result": "none"});
    };
    if pending.rollback {
        return serde_json::json!({"result": "rollingBack"});
    }
    if pending.hold {
        return serde_json::json!({"result": "hold"});
    }
    if pending.wait_restart {
        return serde_json::json!({"result": "waitRestart"});
    }
    // The confirmation must arrive after the change took effect; a
    // connection established before `applied` may have travelled the old
    // path, so it cannot confirm.
    let arrived = std::time::SystemTime::now();
    if arrived < pending.applied {
        return serde_json::json!({"result": "applying"});
    }
    match confirm_state::confirm(state.store.dir()) {
        confirm_state::ConfirmResult::Confirmed => serde_json::json!({"result": "confirmed"}),
        _ => serde_json::json!({"result": "none"}),
    }
}

/// Registers a save through the confirm workflow: reads the involved
/// configuration files before the handler runs and registers only when the
/// contents changed afterwards. Returns the pre-save snapshot for tests.
pub fn capture_before(store: &ConfigStore, paths: &[&str]) -> BTreeMap<String, Option<String>> {
    let mut before = BTreeMap::new();
    for name in paths {
        let contents = store
            .load_raw(name)
            .ok()
            .flatten()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
        before.insert((*name).to_owned(), contents);
    }
    before
}

/// Compares after-save contents and registers the change when they differ.
pub fn register_after(
    store: &ConfigStore,
    before: BTreeMap<String, Option<String>>,
    timeout: Duration,
) -> Result<bool, anyhow::Error> {
    let mut files = BTreeMap::new();
    for (name, previous) in &before {
        let current = store
            .load_raw(name)
            .ok()
            .flatten()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
        if current != *previous {
            files.insert(name.clone(), previous.clone());
        }
    }
    if files.is_empty() {
        return Ok(false);
    }
    confirm_state::begin(store.dir(), files, timeout, std::time::SystemTime::now())?;
    Ok(true)
}

/// Session-only check mirroring login::admin_token, kept local so the
/// confirm endpoints do not depend on login module plumbing.
pub fn has_admin_session(headers: &HeaderMap) -> bool {
    cookie(headers, COOKIE_NAME).is_some()
}
