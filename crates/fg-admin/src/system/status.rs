//! `GET /api/status`: runtime state the overview page polls.

use std::sync::Arc;

use axum::{Json, http::Method};
use schemars::JsonSchema;
use serde::Serialize;
use time::OffsetDateTime;

use super::{ModuleState, SummarySource};
use crate::{ApiRouter, RouteModels};

pub(super) fn mount(router: ApiRouter, source: &Arc<SummarySource>) -> ApiRouter {
    let status = source.clone();
    router.modeled_route(
        Method::GET,
        "/api/status",
        "Get runtime status",
        RouteModels::default().response::<StatusView>(),
        move || {
            let source = status.clone();
            async move { Json(source.status_view()) }
        },
    )
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StatusView {
    pub version: &'static str,
    /// RFC 3339 process start time.
    pub started_at: String,
    pub uptime_seconds: u64,
    pub os: &'static str,
    pub arch: &'static str,
    pub config_dir: String,
    pub proc_rss_bytes: u64,
    pub timezone: String,
    pub modules: Vec<ModuleState>,
}

impl SummarySource {
    pub(super) fn status_view(&self) -> StatusView {
        StatusView {
            version: env!("CARGO_PKG_VERSION"),
            started_at: OffsetDateTime::from(self.started_at)
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            uptime_seconds: self.uptime_seconds(),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            config_dir: self.config_dir.display().to_string(),
            proc_rss_bytes: self.proc_rss_bytes,
            timezone: self.settings.time_zone.clone(),
            modules: self.module_states(),
        }
    }
}
