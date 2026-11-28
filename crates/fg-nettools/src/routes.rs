//! Nettools management routes (WP-71 §4): the tool runner and its task
//! list, the local networks for the LAN scan and the module settings,
//! served with plain axum while mirroring the fg-admin contract (JSON
//! shapes, status codes) — the module cannot depend on fg-admin.
//!
//! Endpoints (permission domain `nettools`; the 4 generic log endpoints
//! `GET|DELETE /api/nettools/logs`, `GET /api/nettools/logs/export`,
//! `GET /api/nettools/logs/sources` are served by fg-logging/fg-admin and
//! not mounted here):
//!
//! | Method | Path | Request | Response |
//! |---|---|---|---|
//! | POST | `/api/nettools/run` | `{"tool":"ping",…params}` (internally tagged) | created `JobView` |
//! | GET | `/api/nettools/tasks` | — | `{"tasks":[JobView]}` (running newest first, then history) |
//! | GET | `/api/nettools/tasks/{id}` | — | `JobView` or `404 {"error":…}` |
//! | DELETE | `/api/nettools/tasks/{id}` | — | `{"ok":true}` (cancels a running job, removes a finished one) or `404` |
//! | GET | `/api/nettools/networks` | — | `{"networks":["192.168.1.0/24",…]}` |
//! | GET | `/api/nettools/settings` | — | normalized `Settings` |
//! | PUT | `/api/nettools/settings` | `Settings` | normalized `Settings` |
//!
//! `POST /api/nettools/run` answers immediately with the task view (the
//! UI polls `tasks/{id}` for output); too many running jobs answer `429`.
//! The settings PUT follows the gateway module contract: normalize →
//! validate → persist `nettools.json` → apply the registry caps, with
//! validation problems returned as `400`
//! `{"error":…,"problems":[{"field":…,"reason":…}]}`.
//!
//! Every tool is open only to write-scope identities (WP-71 §3.3): the
//! surrounding management router's authorize layer maps `/api/nettools/…`
//! to domain `nettools` (GET → `nettools:read`, every mutation →
//! `nettools:write`); nettools writes are audited (not on the read-only
//! skip list). Authentication is NOT performed here.

use std::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::{Path, rejection::PathRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::RwLock;

use crate::PingParams;
use crate::jobs::{Caps, JobError, JobRegistry};
use crate::model::{
    DnsParams, FileConfig, LanScanParams, PortProbeParams, Settings, SpeedParams, Tool,
    TracerouteParams,
};
use crate::validate;

/// Writes the whole [`FileConfig`] to `nettools.json`.
pub type PersistFn = Arc<dyn Fn(&FileConfig) -> anyhow::Result<()> + Send + Sync>;

/// Shared state behind the nettools management routes.
pub struct RoutesState {
    /// The live desired settings (already normalized once loaded).
    pub config: Arc<RwLock<FileConfig>>,
    pub registry: Arc<JobRegistry>,
    pub persist: PersistFn,
    /// Global custom DNS servers (WP-07) for the "empty server" case.
    pub dns_servers: Option<crate::dns_lookup::DnsProvider>,
}

/// One tool run request: the `tool` tag selects the variant.
#[derive(Debug, Deserialize)]
#[serde(tag = "tool", rename_all = "lowercase")]
enum RunRequest {
    Ping(crate::model::PingParams),
    Traceroute(crate::model::TracerouteParams),
    PortProbe(crate::model::PortProbeParams),
    Dns(crate::model::DnsParams),
    Speed(crate::model::SpeedParams),
    LanScan(crate::model::LanScanParams),
}

/// Adds the nettools routes to `router`. See the module docs for the
/// endpoint contract and the authentication assumption.
pub fn mount(router: axum::Router, state: Arc<RoutesState>) -> axum::Router {
    let (run, list) = (state.clone(), state.clone());
    let (view, stop) = (state.clone(), state.clone());
    let (settings_get, settings_put) = (state.clone(), state.clone());
    router
        .route(
            "/api/nettools/run",
            post(move |body: Bytes| async move { run_tool(run, body).await }),
        )
        .route(
            "/api/nettools/tasks",
            get(move || async move { tasks_list(list).await }),
        )
        .route(
            "/api/nettools/tasks/{id}",
            get(
                move |path: Result<Path<String>, PathRejection>| async move {
                    task_view(view, path).await
                },
            )
            .delete(
                move |path: Result<Path<String>, PathRejection>| async move {
                    task_stop(stop, path).await
                },
            ),
        )
        .route(
            "/api/nettools/networks",
            get(move || async move { networks_view().await }),
        )
        .route(
            "/api/nettools/settings",
            get(move || async move { settings_view(settings_get).await })
                .put(move |body: Bytes| async move { settings_save(settings_put, body).await }),
        )
}

fn api_error(status: StatusCode, message: impl std::fmt::Display) -> Response {
    (status, Json(json!({ "error": message.to_string() }))).into_response()
}

fn decode_error() -> Response {
    api_error(StatusCode::BAD_REQUEST, "invalid JSON body")
}

/// Starts one tool run. The deny list comes from the current settings; the
/// future is spawned immediately and the view returned while running.
async fn run_tool(state: Arc<RoutesState>, body: Bytes) -> Response {
    // fg-admin enables serde_json's `arbitrary_precision`, which feature
    // unification shares with this crate; under it, numbers inside a
    // `serde_json::Value` deserialize through the private Content path and
    // break both internally-tagged enums and `from_value` of float fields.
    // The `tool` tag is therefore read from a `Value` peek and each params
    // struct is deserialized typed from the raw bytes, which
    // arbitrary_precision handles correctly.
    let peek: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(peek) => peek,
        Err(_) => return decode_error(),
    };
    let parsed = match peek.get("tool").and_then(|tool| tool.as_str()) {
        Some("ping") => serde_json::from_slice::<PingParams>(&body).map(RunRequest::Ping),
        Some("traceroute") => {
            serde_json::from_slice::<TracerouteParams>(&body).map(RunRequest::Traceroute)
        }
        Some("portprobe") => {
            serde_json::from_slice::<PortProbeParams>(&body).map(RunRequest::PortProbe)
        }
        Some("dns") => serde_json::from_slice::<DnsParams>(&body).map(RunRequest::Dns),
        Some("speed") => serde_json::from_slice::<SpeedParams>(&body).map(RunRequest::Speed),
        Some("lanscan") => serde_json::from_slice::<LanScanParams>(&body).map(RunRequest::LanScan),
        _ => Err(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unknown tool",
        ))),
    };
    let Ok(request) = parsed else {
        return decode_error();
    };
    let config = state.config.read().await.clone();
    let deny = validate::parse_deny_list(&config.settings.deny_list);
    let registry = Arc::clone(&state.registry);
    let spawned: Result<String, JobError> = match request {
        RunRequest::Ping(params) => {
            let target = params.target.trim().to_owned();
            if target.is_empty() {
                return api_error(StatusCode::BAD_REQUEST, "target 不能为空");
            }
            let deny = deny.clone();
            registry.spawn(
                Tool::Ping.kind(),
                &format!("ping {target}"),
                move |handle| crate::ping::run(&params, handle, &deny),
            )
        }
        RunRequest::Traceroute(params) => {
            let target = params.target.trim().to_owned();
            if target.is_empty() {
                return api_error(StatusCode::BAD_REQUEST, "target 不能为空");
            }
            let deny = deny.clone();
            registry.spawn(
                Tool::Traceroute.kind(),
                &format!("traceroute {target}"),
                move |handle| crate::traceroute::run(&params, handle, &deny),
            )
        }
        RunRequest::PortProbe(params) => {
            let target = params.target.trim().to_owned();
            if target.is_empty() {
                return api_error(StatusCode::BAD_REQUEST, "target 不能为空");
            }
            let deny = deny.clone();
            registry.spawn(
                Tool::PortProbe.kind(),
                &format!("端口探测 {target}"),
                move |handle| crate::port_probe::run(&params, handle, &deny),
            )
        }
        RunRequest::Dns(params) => {
            let name = params.name.trim().to_owned();
            if name.is_empty() {
                return api_error(StatusCode::BAD_REQUEST, "name 不能为空");
            }
            let deny = deny.clone();
            let servers = state.dns_servers.clone();
            registry.spawn(Tool::Dns.kind(), &format!("DNS {name}"), move |handle| {
                crate::dns_lookup::run(&params, handle, &deny, servers.clone())
            })
        }
        RunRequest::Speed(params) => {
            let deny = deny.clone();
            let default_url = config.settings.default_speed_url.clone();
            let title = format!(
                "测速 {}",
                params
                    .url
                    .as_deref()
                    .map(str::trim)
                    .filter(|text| !text.is_empty())
                    .unwrap_or(&default_url)
            );
            registry.spawn(Tool::Speed.kind(), &title, move |handle| {
                crate::speed_test::run(&params, handle, &deny, &default_url)
            })
        }
        RunRequest::LanScan(params) => {
            let deny = deny.clone();
            let title = format!(
                "局域网扫描 {}",
                params
                    .cidr
                    .as_deref()
                    .map(str::trim)
                    .filter(|text| !text.is_empty())
                    .unwrap_or("本机网段")
            );
            registry.spawn(Tool::LanScan.kind(), &title, move |handle| {
                crate::lan_scan::run(&params, handle, &deny)
            })
        }
    };
    match spawned {
        Ok(id) => match registry.get(&id) {
            Some(view) => Json(view.to_json()).into_response(),
            None => api_error(StatusCode::INTERNAL_SERVER_ERROR, "任务启动后丢失"),
        },
        Err(JobError::TooMany) => api_error(
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "同时运行的任务已达上限（{}），请稍后再试",
                registry.caps().max_running
            ),
        ),
        Err(JobError::Message(message)) => api_error(StatusCode::INTERNAL_SERVER_ERROR, message),
    }
}

async fn tasks_list(state: Arc<RoutesState>) -> Response {
    let tasks: Vec<serde_json::Value> = state
        .registry
        .list()
        .iter()
        .map(crate::jobs::JobView::to_json)
        .collect();
    Json(json!({ "tasks": tasks })).into_response()
}

async fn task_view(state: Arc<RoutesState>, path: Result<Path<String>, PathRejection>) -> Response {
    let Ok(Path(id)) = path else {
        return api_error(StatusCode::BAD_REQUEST, "invalid task id");
    };
    match state.registry.get(&id) {
        Some(view) => Json(view.to_json()).into_response(),
        None => api_error(StatusCode::NOT_FOUND, format!("任务 {id} 不存在")),
    }
}

async fn task_stop(state: Arc<RoutesState>, path: Result<Path<String>, PathRejection>) -> Response {
    let Ok(Path(id)) = path else {
        return api_error(StatusCode::BAD_REQUEST, "invalid task id");
    };
    if state.registry.cancel(&id) {
        Json(json!({ "ok": true })).into_response()
    } else {
        api_error(StatusCode::NOT_FOUND, format!("任务 {id} 不存在"))
    }
}

async fn networks_view() -> Response {
    match crate::lan_scan::discover_networks() {
        Ok(networks) => Json(json!({
            "networks": networks
                .iter()
                .map(|network| network.to_string())
                .collect::<Vec<_>>()
        }))
        .into_response(),
        Err(error) => api_error(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

async fn settings_view(state: Arc<RoutesState>) -> Response {
    let config = state.config.read().await.clone();
    Json(validate::normalize(config).settings).into_response()
}

/// Normalize → validate → persist → apply the registry caps; a failed
/// write leaves the desired state untouched, matching the gateway module
/// commit order.
async fn settings_save(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(settings) = serde_json::from_slice::<Settings>(&body) else {
        return decode_error();
    };
    let candidate = validate::normalize(FileConfig { settings });
    let problems = validate::validate(&candidate);
    if !problems.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid nettools settings",
                "problems": problems
                    .iter()
                    .map(|problem| json!({"field": problem.field, "reason": problem.reason}))
                    .collect::<Vec<_>>(),
            })),
        )
            .into_response();
    }
    let changed = *state.config.read().await != candidate;
    if changed {
        let persist = Arc::clone(&state.persist);
        let saved = candidate.clone();
        let persisted = match tokio::task::spawn_blocking(move || persist(&saved)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                tracing::warn!(%error, "persisting nettools.json failed");
                Err(internal())
            }
            Err(_) => Err(internal()),
        };
        if let Err(failure) = persisted {
            return failure;
        }
        *state.config.write().await = candidate;
    }
    state
        .registry
        .set_caps(Caps::from_settings(&state.config.read().await.settings));
    Json(state.config.read().await.settings.clone()).into_response()
}

fn internal() -> Response {
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "configuration operation failed",
    )
}
