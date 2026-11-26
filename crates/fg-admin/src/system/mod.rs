//! System-level routes: status, build information and module states.

mod info;
mod status;

use std::{path::PathBuf, sync::Arc, time::SystemTime};

use crate::ApiRouter;
use fg_core::{registry::CATALOG, settings::Settings, sysstat::Procfs};

/// Inputs for the system routes: configuration directory, module
/// resolution, process start time and the effective settings snapshot.
pub struct SystemRoutes {
    pub config_dir: PathBuf,
    pub modules: Arc<(fg_core::registry::Registry, fg_core::registry::Enabled)>,
    pub started_at: SystemTime,
    pub settings: Arc<Settings>,
}

/// The immutable snapshot behind the status and info responses.
pub struct SummarySource {
    pub config_dir: PathBuf,
    pub modules: Arc<(fg_core::registry::Registry, fg_core::registry::Enabled)>,
    pub started_at: SystemTime,
    pub proc_rss_bytes: u64,
    pub settings: Arc<Settings>,
}

impl SystemRoutes {
    /// Wires `GET /api/status` and `GET /api/system/info`, both scoped to
    /// `status:read`. Call before `finish`.
    pub fn register(self, router: ApiRouter) -> ApiRouter {
        let source = Arc::new(SummarySource {
            proc_rss_bytes: <Procfs as fg_core::sysstat::Sysstat>::proc(&Procfs).rss_bytes,
            config_dir: self.config_dir,
            modules: self.modules,
            started_at: self.started_at,
            settings: self.settings,
        });
        info::mount(status::mount(router, &source), &source)
    }
}

impl SummarySource {
    pub fn uptime_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.started_at)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0)
    }

    pub fn module_states(&self) -> Vec<ModuleState> {
        let (registry, enabled) = &*self.modules;
        CATALOG
            .iter()
            .map(|entry| ModuleState {
                id: entry.id,
                group: entry.group,
                status: match registry.status(enabled, entry.id) {
                    Some(fg_core::registry::Status::Enabled) => "enabled",
                    Some(fg_core::registry::Status::Disabled) => "disabled",
                    _ => "absent",
                },
            })
            .collect()
    }
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ModuleState {
    pub id: &'static str,
    pub group: &'static str,
    pub status: &'static str,
}

use serde::Serialize;
