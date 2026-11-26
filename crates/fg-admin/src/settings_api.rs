use std::{collections::BTreeMap, fs::DirBuilder, path::Path, sync::Arc};

use anyhow::{Context, Result, ensure};
use axum::{
    Json,
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use fg_auth::{AccountManager, MAX_SESSION_HOURS};
use fg_config::{ConfigStore, Loaded};
use fg_core::{
    registry::{CATALOG, Registry},
    settings::{Effect, Settings},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, watch};

use crate::{
    ApiError, ApiRouter, RouteModels, SECRET_MASK,
    http::{JsonBody, invalid_json, run_blocking},
    item_json, keep_secret,
};

const FILE: &str = "ferrumgate";
const PATH: &str = "/api/system/settings";
const VIEW_ONLY: &[&str] = &[
    "sessionHours",
    "restartRequired",
    "gatewayAvailable",
    "modules",
    "effects",
];

/// Owns the desired settings snapshot for one management service.
pub struct SettingsState {
    store: Arc<ConfigStore>,
    registry: Registry,
    started: Arc<Settings>,
    current: watch::Sender<Arc<Settings>>,
    writer: Arc<Semaphore>,
    modules: Arc<Vec<ModuleOption>>,
    effects: Arc<BTreeMap<String, Effect>>,
}

impl SettingsState {
    /// Opens settings after the startup migrations have run.
    pub fn open(store: Arc<ConfigStore>, registry: Registry) -> Result<Self> {
        let mut settings = match store.load(FILE)? {
            Loaded::Found(settings) => settings,
            Loaded::Missing => Settings::default(),
        };
        ensure!(
            settings.legacy_api_token.is_empty(),
            "legacy API token must be migrated before loading settings"
        );
        settings.normalize();
        settings.validate(&registry).map_err(|errors| {
            let details = errors
                .into_iter()
                .map(|error| format!("{}: {}", error.field, error.message))
                .collect::<Vec<_>>();
            anyhow::anyhow!("invalid global settings: {}", details.join(", "))
        })?;
        let modules = CATALOG
            .iter()
            .filter(|module| !registry.absent().any(|absent| absent.id == module.id))
            .map(|module| ModuleOption {
                id: module.id.to_owned(),
                title: module.title.en.to_owned(),
                requires: registry.requires(module.id).map(str::to_owned).collect(),
            })
            .collect();
        let started = Arc::new(settings);
        Ok(Self {
            store,
            registry,
            current: watch::Sender::new(started.clone()),
            started,
            writer: Arc::new(Semaphore::new(1)),
            modules: Arc::new(modules),
            effects: Arc::new(
                Settings::effects()
                    .map(|(field, effect)| (field.into(), effect))
                    .collect(),
            ),
        })
    }

    pub fn subscribe(&self) -> watch::Receiver<Arc<Settings>> {
        self.current.subscribe()
    }

    pub fn snapshot(&self) -> Arc<Settings> {
        self.current.borrow().clone()
    }

    pub fn directory(&self) -> &Path {
        self.store.dir()
    }

    fn view(&self, current: &Settings, accounts: &AccountManager) -> SettingsView {
        let mut settings = current.clone();
        for provider in &mut settings.third_login.providers {
            if !provider.client_secret.is_empty() {
                provider.client_secret = SECRET_MASK.into();
            }
        }
        SettingsView {
            restart_required: current.changed_with_effect(&self.started, Effect::NeedsRestart),
            settings,
            session_hours: accounts.session_hours(),
            gateway_available: false,
            modules: self.modules.clone(),
            effects: self.effects.clone(),
        }
    }

    fn save(&self, mut next: Settings, session_hours: u64, accounts: &AccountManager) -> Response {
        if session_hours > MAX_SESSION_HOURS && session_hours != accounts.session_hours() {
            return ApiError::new(
                StatusCode::BAD_REQUEST,
                "sessionHours must be zero or between 1 and 8760",
            )
            .into_response();
        }
        let old = self.snapshot();
        next.legacy_api_token.clear();
        next.ui_language.clone_from(&old.ui_language);
        self.registry
            .keep_absent_disabled(&old.disabled_modules, &mut next.disabled_modules);
        next.normalize();
        for provider in &mut next.third_login.providers {
            let previous = old
                .third_login
                .providers
                .iter()
                .find(|previous| previous.key == provider.key);
            keep_secret(
                previous.map_or("", |previous| &previous.client_secret),
                &mut provider.client_secret,
            );
        }
        if let Err(errors) = next.validate(&self.registry) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid global settings", "fields": errors })),
            )
                .into_response();
        }
        if !next.disable_log_persist
            && !next.log_dir.is_empty()
            && (next.log_dir != old.log_dir || old.disable_log_persist)
            && check_log_directory(Path::new(&next.log_dir), self.store.dir()).is_err()
        {
            return ApiError::new(
                StatusCode::BAD_REQUEST,
                "logDir must be writable and separate from static roots and the configuration directory",
            )
            .into_response();
        }
        let changed = next != *old;
        let next = if changed {
            let Ok(mut bytes) = serde_json::to_vec_pretty(&next) else {
                return ApiError::internal().into_response();
            };
            bytes.push(b'\n');
            let saved = self.store.write_raw(FILE, &bytes);
            let next = Arc::new(next);
            // A directory sync error can occur after the new file becomes visible.
            if saved.is_ok() || self.store.load_raw(FILE).ok().flatten().as_deref() == Some(&bytes)
            {
                self.current.send_replace(next.clone());
            }
            if saved.is_err() {
                return ApiError::internal().into_response();
            }
            next
        } else {
            old
        };
        let change_hours = session_hours != 0 && session_hours != accounts.session_hours();
        if change_hours && accounts.set_session_hours(session_hours).is_err() {
            let message = if changed {
                "global settings saved; sessionHours update failed"
            } else {
                "sessionHours update failed"
            };
            return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, message).into_response();
        }
        if changed || change_hours {
            tracing::info!(target: "fg_core::settings", "global settings updated");
        }
        Json(self.view(&next, accounts)).into_response()
    }
}

impl ApiRouter {
    pub fn with_settings(self, state: Arc<SettingsState>, accounts: Arc<AccountManager>) -> Self {
        let get = state.clone();
        let get_accounts = accounts.clone();
        let put = state.clone();
        self.modeled_route(
            Method::GET,
            PATH,
            "Get global settings",
            RouteModels::default().response::<SettingsView>(),
            move || async move {
                let settings = get.snapshot();
                Json(get.view(&settings, &get_accounts))
            },
        )
        .modeled_route(
            Method::PUT,
            PATH,
            "Save global settings",
            RouteModels::default()
                .request::<Settings>()
                .ignored_request_fields(VIEW_ONLY)
                .response::<SettingsView>(),
            move |JsonBody(bytes): JsonBody| async move {
                let writer = put.writer.clone();
                run_blocking(
                    &writer,
                    ApiError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "global settings writes are busy",
                    ),
                    move || {
                        let Ok(input) = item_json::decode(&bytes, VIEW_ONLY) else {
                            return invalid_json().into_response();
                        };
                        let Ok(session) = serde_json::from_slice::<SessionUpdate>(&bytes) else {
                            return invalid_json().into_response();
                        };
                        put.save(input, session.session_hours, &accounts)
                    },
                )
                .await
            },
        )
        .modeled_route(
            Method::GET,
            "/api/system/settings/secrets",
            "Get third-party login client secrets",
            RouteModels::default().response::<BTreeMap<String, String>>(),
            move || async move {
                let settings = state.snapshot();
                Json(
                    settings
                        .third_login
                        .providers
                        .iter()
                        .map(|provider| (provider.key.clone(), provider.client_secret.clone()))
                        .collect::<BTreeMap<_, _>>(),
                )
            },
        )
    }
}

#[derive(Deserialize)]
struct SessionUpdate {
    #[serde(default, rename = "sessionHours")]
    session_hours: u64,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct SettingsView {
    #[serde(flatten)]
    settings: Settings,
    session_hours: u64,
    restart_required: bool,
    gateway_available: bool,
    modules: Arc<Vec<ModuleOption>>,
    effects: Arc<BTreeMap<String, Effect>>,
}

#[derive(Serialize, JsonSchema)]
struct ModuleOption {
    id: String,
    title: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    requires: Vec<String>,
}

fn check_log_directory(directory: &Path, config: &Path) -> Result<()> {
    fg_core::fsperm::check_log_directory(directory)?;
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(directory)?;
    ensure!(
        std::fs::symlink_metadata(directory)?.is_dir(),
        "expected a regular log directory"
    );
    let directory = directory.canonicalize()?;
    ensure!(
        directory != config && directory.parent().is_some(),
        "invalid log directory"
    );
    tempfile::NamedTempFile::new_in(directory)?
        .close()
        .context("remove log directory write probe")
}
