//! Web service observability management API routes (WP-28 §4).
//!
//! Endpoints (permission domain `webservice`, auth enforced by management router):
//! - `GET  /api/webservice/stats`
//! - `GET  /api/webservice/connections`
//! - `POST /api/webservice/connections/close`
//! - `GET  /api/webservice/topology`
//! - `GET  /api/webservice/topology/replay`
//! - `GET  /api/webservice/topology/replay/frame`
//! - `PUT  /api/webservice/topology/replay/settings`
//! - `GET  /api/webservice/visitors`
//! - `GET  /api/webservice/visitors/detail`
//! - `POST /api/webservice/visitors/delete`
//! - `GET  /api/webservice/visitors/settings`
//! - `PUT  /api/webservice/visitors/settings`
//! - `GET  /api/webservice/metrics`
//!
//! Query parameters are parsed directly from [`Uri`] because `fg-gateway`
//! enables `axum` with `features = ["json"]` only.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    body::Bytes,
    http::{HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    ObsHub,
    connections::{CloseBanError, ConnView, FinishedReq},
    metrics::PROMETHEUS_CONTENT_TYPE,
    minute_ring::{WindowSummary, unix_minute},
    replay::ReplaySettings,
    topology::DEFAULT_RATE_WINDOW_SECS,
    visitors::{VisitorQuery, VisitorsConfig},
};

/// Mounts all WP-28 observability routes onto `router`.
pub fn mount(router: axum::Router, hub: Arc<ObsHub>) -> axum::Router {
    let s_stats = Arc::clone(&hub);
    let s_conns = Arc::clone(&hub);
    let s_close = Arc::clone(&hub);
    let s_topo = Arc::clone(&hub);
    let s_replay = Arc::clone(&hub);
    let s_frame = Arc::clone(&hub);
    let s_replay_set = Arc::clone(&hub);
    let s_visitors = Arc::clone(&hub);
    let s_vdetail = Arc::clone(&hub);
    let s_vdel = Arc::clone(&hub);
    let s_vset_get = Arc::clone(&hub);
    let s_vset_put = Arc::clone(&hub);
    let s_metrics = hub;

    router
        .route(
            "/api/webservice/stats",
            get(move |uri: Uri| async move { handle_stats(s_stats, uri) }),
        )
        .route(
            "/api/webservice/connections",
            get(move |uri: Uri| async move { handle_connections(s_conns, uri) }),
        )
        .route(
            "/api/webservice/connections/close",
            post(move |body: Bytes| async move { handle_connections_close(s_close, body) }),
        )
        .route(
            "/api/webservice/topology",
            get(move |uri: Uri| async move { handle_topology(s_topo, uri) }),
        )
        .route(
            "/api/webservice/topology/replay",
            get(move |uri: Uri| async move { handle_replay_overview(s_replay, uri) }),
        )
        .route(
            "/api/webservice/topology/replay/frame",
            get(move |uri: Uri| async move { handle_replay_frame(s_frame, uri) }),
        )
        .route(
            "/api/webservice/topology/replay/settings",
            put(move |body: Bytes| async move { handle_replay_settings(s_replay_set, body) }),
        )
        .route(
            "/api/webservice/visitors",
            get(move |uri: Uri| async move { handle_visitors_list(s_visitors, uri) }),
        )
        .route(
            "/api/webservice/visitors/detail",
            get(move |uri: Uri| async move { handle_visitors_detail(s_vdetail, uri) }),
        )
        .route(
            "/api/webservice/visitors/delete",
            post(move |body: Bytes| async move { handle_visitors_delete(s_vdel, body) }),
        )
        .route(
            "/api/webservice/visitors/settings",
            get(move || async move { handle_visitors_settings_get(s_vset_get) }).put(
                move |body: Bytes| async move { handle_visitors_settings_put(s_vset_put, body) },
            ),
        )
        .route(
            "/api/webservice/metrics",
            get(move || async move { handle_metrics(s_metrics) }),
        )
}

fn json_ok<T: Serialize>(value: &T) -> Response {
    let mut resp = (StatusCode::OK, Json(value)).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn json_err(status: StatusCode, message: impl Into<String>) -> Response {
    let msg = message.into();
    let mut resp = (status, Json(json!({ "error": msg }))).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn parse_query(uri: &Uri) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(raw) = uri.query() else {
        return map;
    };
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let key = percent_decode_str(&k.replace('+', " "))
            .decode_utf8_lossy()
            .into_owned();
        let val = percent_decode_str(&v.replace('+', " "))
            .decode_utf8_lossy()
            .into_owned();
        map.insert(key, val);
    }
    map
}

fn now_unix_secs() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => 0,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SiteBackendStats {
    url: String,
    route: String,
    healthy: bool,
    weight: u32,
    backup: bool,
    conns: u32,
    requests: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SiteStatsResponse {
    listener: String,
    site: String,
    site_name: String,
    range: String,
    summary: WindowSummary,
    backends: Vec<SiteBackendStats>,
}

fn handle_stats(hub: Arc<ObsHub>, uri: Uri) -> Response {
    let q = parse_query(&uri);
    let Some(listener_key) = q.get("listener").filter(|s| !s.is_empty()) else {
        return json_err(StatusCode::BAD_REQUEST, "missing listener parameter");
    };
    let Some(site_key) = q.get("site").filter(|s| !s.is_empty()) else {
        return json_err(StatusCode::BAD_REQUEST, "missing site parameter");
    };
    let Some(site) = hub.site(listener_key, site_key) else {
        return json_err(StatusCode::NOT_FOUND, "site not found");
    };

    let (range_label, minutes) = match q.get("range").map(String::as_str).unwrap_or("1h") {
        "6h" | "360m" => ("6h", 6 * 60i64),
        "24h" | "1440m" => ("24h", 24 * 60i64),
        _ => ("1h", 60i64),
    };
    let to_min = unix_minute(SystemTime::now());
    let from_min = to_min - minutes + 1;
    let summary = site.minute_ring.summary(from_min, to_min);
    let meta = site.meta_snapshot();
    let backends = site
        .upstreams_snapshot()
        .into_iter()
        .map(|u| SiteBackendStats {
            url: u.url.clone(),
            route: u.route.clone(),
            healthy: u.is_healthy(),
            weight: u.weight,
            backup: u.backup,
            conns: u.topo.active.load(std::sync::atomic::Ordering::Relaxed),
            requests: u
                .topo
                .cum_requests
                .load(std::sync::atomic::Ordering::Relaxed),
        })
        .collect();

    json_ok(&SiteStatsResponse {
        listener: listener_key.clone(),
        site: site_key.clone(),
        site_name: meta.display_name(),
        range: range_label.to_owned(),
        summary,
        backends,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionsResponse {
    active: Vec<ConnView>,
    total_active: usize,
    history: Vec<FinishedReq>,
}

fn handle_connections(hub: Arc<ObsHub>, uri: Uri) -> Response {
    let q = parse_query(&uri);
    let site = q.get("site").map(String::as_str).filter(|s| !s.is_empty());
    let search = q
        .get("search")
        .or_else(|| q.get("q"))
        .map(String::as_str)
        .filter(|s| !s.is_empty());
    let ip_filter = match q.get("ip").filter(|s| !s.is_empty()) {
        Some(raw) => match raw.parse::<IpAddr>() {
            Ok(ip) => Some(ip),
            Err(_) => return json_err(StatusCode::BAD_REQUEST, "invalid ip parameter"),
        },
        None => None,
    };
    let include_history = q
        .get("includeHistory")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);

    let active = hub
        .connections
        .list_filtered(site, ip_filter, search, std::time::Instant::now());
    let total_active = hub.connections.active_count();
    let history = if include_history {
        hub.connections.history(site, search)
    } else {
        Vec::new()
    };

    json_ok(&ConnectionsResponse {
        active,
        total_active,
        history,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CloseConnRequest {
    id: u64,
    #[serde(default)]
    ban: bool,
}

fn handle_connections_close(hub: Arc<ObsHub>, body: Bytes) -> Response {
    let req: CloseConnRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(err) => return json_err(StatusCode::BAD_REQUEST, format!("invalid request: {err}")),
    };
    if req.ban {
        match hub.connections.close_and_ban(req.id) {
            Ok(res) => json_ok(&res),
            Err(CloseBanError::NotFound) => json_err(StatusCode::NOT_FOUND, "connection not found"),
            Err(CloseBanError::LoopbackRefused) => json_err(
                StatusCode::BAD_REQUEST,
                "loopback addresses cannot be banned",
            ),
            Err(CloseBanError::TrustedProxyRefused) => json_err(
                StatusCode::BAD_REQUEST,
                "trusted proxy addresses cannot be banned",
            ),
            Err(CloseBanError::BanFailed(msg)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, msg),
        }
    } else if hub.connections.close(req.id) {
        json_ok(&json!({ "closed": true, "id": req.id }))
    } else {
        json_err(StatusCode::NOT_FOUND, "connection not found")
    }
}

fn handle_topology(hub: Arc<ObsHub>, uri: Uri) -> Response {
    let q = parse_query(&uri);
    let window = q
        .get("window")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_RATE_WINDOW_SECS);
    let snap = hub.build_topology_snapshot(window, now_unix_secs());
    json_ok(&snap)
}

fn handle_replay_overview(hub: Arc<ObsHub>, uri: Uri) -> Response {
    let q = parse_query(&uri);
    let from = q.get("from").and_then(|v| v.parse::<i64>().ok());
    let to = q.get("to").and_then(|v| v.parse::<i64>().ok());
    let points = q.get("points").and_then(|v| v.parse::<usize>().ok());
    let overview = hub.replay.overview(from, to, points, now_unix_secs());
    json_ok(&overview)
}

fn handle_replay_frame(hub: Arc<ObsHub>, uri: Uri) -> Response {
    let q = parse_query(&uri);
    let Some(ts) = q.get("ts").and_then(|v| v.parse::<i64>().ok()) else {
        return json_err(StatusCode::BAD_REQUEST, "missing or invalid ts parameter");
    };
    match hub.replay.frame_at(ts) {
        Some(frame) => json_ok(&frame),
        None => json_err(StatusCode::NOT_FOUND, "replay frame not found"),
    }
}

fn handle_replay_settings(hub: Arc<ObsHub>, body: Bytes) -> Response {
    let settings: ReplaySettings = match serde_json::from_slice(&body) {
        Ok(s) => s,
        Err(err) => return json_err(StatusCode::BAD_REQUEST, format!("invalid settings: {err}")),
    };
    let updated = hub.replay.update_settings(settings);
    json_ok(&updated)
}

fn handle_visitors_list(hub: Arc<ObsHub>, uri: Uri) -> Response {
    let q = parse_query(&uri);
    let query = VisitorQuery {
        search: q.get("q").or_else(|| q.get("search")).cloned(),
        site: q.get("site").cloned(),
        filter: q.get("filter").cloned(),
        sort: q.get("sort").cloned(),
        offset: q
            .get("offset")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0),
        limit: q
            .get("limit")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(100),
    };
    let resp = hub.visitors.query(&query, SystemTime::now());
    json_ok(&resp)
}

fn handle_visitors_detail(hub: Arc<ObsHub>, uri: Uri) -> Response {
    let q = parse_query(&uri);
    let Some(raw_ip) = q.get("ip").filter(|s| !s.is_empty()) else {
        return json_err(StatusCode::BAD_REQUEST, "missing ip parameter");
    };
    let Ok(ip) = raw_ip.parse::<IpAddr>() else {
        return json_err(StatusCode::BAD_REQUEST, "invalid ip parameter");
    };
    match hub.visitors.detail(ip, SystemTime::now()) {
        Some(detail) => json_ok(&detail),
        None => json_err(StatusCode::NOT_FOUND, "visitor not found"),
    }
}

#[derive(Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct DeleteVisitorsRequest {
    ips: Vec<String>,
    clear_all: bool,
}

impl Default for DeleteVisitorsRequest {
    fn default() -> Self {
        Self {
            ips: Vec::new(),
            clear_all: false,
        }
    }
}

fn handle_visitors_delete(hub: Arc<ObsHub>, body: Bytes) -> Response {
    let req: DeleteVisitorsRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(err) => return json_err(StatusCode::BAD_REQUEST, format!("invalid request: {err}")),
    };
    if req.clear_all {
        let removed = hub.visitors.clear();
        return json_ok(&json!({ "removed": removed }));
    }
    let mut parsed = Vec::with_capacity(req.ips.len());
    for raw in &req.ips {
        match raw.parse::<IpAddr>() {
            Ok(ip) => parsed.push(ip),
            Err(_) => {
                return json_err(StatusCode::BAD_REQUEST, format!("invalid ip: {raw}"));
            }
        }
    }
    let removed = hub.visitors.delete(&parsed);
    json_ok(&json!({ "removed": removed }))
}

fn handle_visitors_settings_get(hub: Arc<ObsHub>) -> Response {
    json_ok(&hub.visitors.settings())
}

fn handle_visitors_settings_put(hub: Arc<ObsHub>, body: Bytes) -> Response {
    let cfg: VisitorsConfig = match serde_json::from_slice(&body) {
        Ok(c) => c,
        Err(err) => return json_err(StatusCode::BAD_REQUEST, format!("invalid settings: {err}")),
    };
    let updated = hub.visitors.update_settings(cfg, SystemTime::now());
    json_ok(&updated)
}

fn handle_metrics(hub: Arc<ObsHub>) -> Response {
    let text = hub.render_metrics();
    let mut resp = (StatusCode::OK, text).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(PROMETHEUS_CONTENT_TYPE),
    );
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}
