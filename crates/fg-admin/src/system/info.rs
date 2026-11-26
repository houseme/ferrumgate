//! `GET /api/system/info`: build contents and compile-time capabilities.

use std::sync::Arc;

use axum::{Json, http::Method};
use schemars::JsonSchema;
use serde::Serialize;

use super::SummarySource;
use crate::{ApiRouter, RouteModels};

pub(super) fn mount(router: ApiRouter, source: &Arc<SummarySource>) -> ApiRouter {
    let info = source.clone();
    router.modeled_route(
        Method::GET,
        "/api/system/info",
        "Get build and system information",
        RouteModels::default().response::<InfoView>(),
        move || {
            let source = info.clone();
            async move { Json(source.info_view()) }
        },
    )
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct InfoView {
    pub version: &'static str,
    /// Rust compiler version when the build injected it, else empty.
    pub rustc: &'static str,
    pub os: &'static str,
    pub arch: &'static str,
    pub config_dir: String,
    /// Modules compiled into this binary.
    pub included_modules: Vec<&'static str>,
    /// Known modules not present in this build.
    pub absent_modules: Vec<&'static str>,
    /// Language tier, a WP-90 concept reported as full for now.
    pub languages: &'static str,
}

impl SummarySource {
    pub(super) fn info_view(&self) -> InfoView {
        let (registry, _) = &*self.modules;
        // `absent()` yields the catalog modules missing from this build;
        // everything else in the catalog is compiled in.
        let absent: Vec<&'static str> = registry.absent().map(|module| module.id).collect();
        let included: Vec<&'static str> = fg_core::registry::CATALOG
            .iter()
            .map(|module| module.id)
            .filter(|id| !absent.contains(id))
            .collect();
        InfoView {
            version: env!("CARGO_PKG_VERSION"),
            rustc: option_env!("FERRUMGATE_RUSTC_VERSION").unwrap_or(""),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            config_dir: self.config_dir.display().to_string(),
            included_modules: included,
            absent_modules: absent,
            languages: "full",
        }
    }
}
