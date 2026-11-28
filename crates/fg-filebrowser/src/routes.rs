//! The instance collection and settings API under `/api/filebrowser`
//! (WP-66 step 5; upstream 25 operations minus the 4 generic log
//! endpoints fg-admin carries). Contract mirrors the fg-cron / fg-guard
//! routes: `{"error":…}` failures, validation `problems`, batch `{"keys"}`
//! up to 500, `{"changed":N}` / `{"removed":N}` / `{"ok":true}`, 12-hex
//! keys, secrets masked in every read and restored on masked submits.
//! Authentication comes from the surrounding management router (domain
//! `filebrowser`).

use std::{path::PathBuf, sync::Arc};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, rejection::PathRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::RwLock;

use crate::{
    model::{FileConfig, Instance, limits},
    validate,
};

/// Writes the whole [`FileConfig`] to `filebrowser.json`.
pub type PersistFn = Arc<dyn Fn(&FileConfig) -> anyhow::Result<()> + Send + Sync>;

/// Shared state behind the filebrowser management routes.
pub struct RoutesState {
    pub config_dir: PathBuf,
    pub config: Arc<RwLock<FileConfig>>,
    pub runtime: Arc<crate::InstanceRuntime>,
    /// `(installer, fetch)`; `fetch: None` reports 「下载通道未配置」.
    pub installer: Option<(
        Arc<fg_proc::install::Installer>,
        Option<fg_proc::install::HttpGetter>,
    )>,
    pub persist: PersistFn,
}

/// The response projection of one instance: the password masked, plus the
/// effective port and access URL. Card status rides on top in
/// `list_instances`.
pub fn view_instance(instance: &Instance) -> serde_json::Value {
    let effective_url = instance.access_urls.first().cloned().unwrap_or_else(|| {
        format!(
            "http://{}:{}",
            listen_display(instance),
            instance.effective_port()
        )
    });
    json!({
        "key": instance.key,
        "name": instance.name,
        "group": instance.group,
        "enable": instance.enable,
        "listenIp": instance.listen_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        "port": instance.effective_port(),
        "baseUrl": instance.base_url,
        "accessUrls": instance.access_urls,
        "sources": instance.sources,
        "authMethod": instance.auth_method,
        "proxyHeader": instance.proxy_header,
        "adminUser": instance.admin_user,
        "adminPassword": masked(&instance.admin_password),
        "trustProxyHeaders": instance.trust_proxy_headers,
        "disableWebDav": instance.disable_web_dav,
        "locale": instance.locale,
        "tokenHours": instance.effective_token_hours(),
        "remark": instance.remark,
        "effectiveUrl": effective_url,
    })
}

fn listen_display(instance: &Instance) -> String {
    instance
        .listen_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "0.0.0.0".to_string())
}

fn masked(value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        limits::SECRET_MASK.to_string()
    }
}

/// A failed mutation shaped like the fg-admin `ApiError` body.
struct Failure {
    status: StatusCode,
    message: String,
}

impl Failure {
    fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.to_owned(),
        }
    }

    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: "item not found".to_owned(),
        }
    }

    fn problems(problems: Vec<validate::Problem>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: serde_json::to_string(&json!({
                "error": "invalid filebrowser configuration",
                "problems": problems
                    .iter()
                    .map(|p| json!({"field": p.field, "reason": p.reason}))
                    .collect::<Vec<_>>(),
            }))
            .unwrap_or_else(|_| "invalid filebrowser configuration".to_string()),
        }
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        // `problems` payloads already carry their own JSON body.
        if self.message.starts_with("{\"error\"") {
            (self.status, self.message).into_response()
        } else {
            (self.status, Json(json!({ "error": self.message }))).into_response()
        }
    }
}

type Change<T> = Result<(T, bool), Failure>;

pub fn mount(router: Router, state: Arc<RoutesState>) -> Router {
    let (list, create, batch_delete) = (state.clone(), state.clone(), state.clone());
    let (replace, remove, copy) = (state.clone(), state.clone(), state.clone());
    let (enable, batch_enable, order) = (state.clone(), state.clone(), state.clone());
    let (group, restart, secrets) = (state.clone(), state.clone(), state.clone());
    let (settings_get, settings_put, reset) = (state.clone(), state.clone(), state.clone());
    let (install_get, install_post, install_check) = (state.clone(), state.clone(), state.clone());
    let (install_rollback, install_delete, backup_delete) = (state.clone(), state.clone(), state);
    router
        .route(
            "/api/filebrowser/instances",
            get(move || async move { list_instances(list).await })
                .post(move |body: Bytes| async move { create_instance(create, body).await }),
        )
        .route(
            "/api/filebrowser/instances/{key}",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    replace_instance(replace, path, body).await
                },
            )
            .delete(
                move |path: Result<Path<String>, PathRejection>| async move {
                    remove_instance(remove, path).await
                },
            ),
        )
        .route(
            "/api/filebrowser/instances/{key}/copy",
            post(
                move |path: Result<Path<String>, PathRejection>| async move {
                    copy_instance(copy, path).await
                },
            ),
        )
        .route(
            "/api/filebrowser/instances/{key}/enable",
            put(
                move |path: Result<Path<String>, PathRejection>, body: Bytes| async move {
                    enable_instance(enable, path, body).await
                },
            ),
        )
        .route(
            "/api/filebrowser/instances/{key}/restart",
            post(
                move |path: Result<Path<String>, PathRejection>| async move {
                    restart_instance(restart, path).await
                },
            ),
        )
        .route(
            "/api/filebrowser/instances/{key}/secrets",
            get(
                move |path: Result<Path<String>, PathRejection>| async move {
                    instance_secrets(secrets, path).await
                },
            ),
        )
        .route(
            "/api/filebrowser/instances-delete",
            post(move |body: Bytes| async move { batch_remove(batch_delete, body).await }),
        )
        .route(
            "/api/filebrowser/instances-enable",
            put(move |body: Bytes| async move { batch_toggle(batch_enable, body).await }),
        )
        .route(
            "/api/filebrowser/instances-order",
            put(move |body: Bytes| async move { reorder(order, body).await }),
        )
        .route(
            "/api/filebrowser/instances-group",
            put(move |body: Bytes| async move { regroup(group, body).await }),
        )
        .route(
            "/api/filebrowser/settings",
            get(move || async move { settings_view(settings_get).await })
                .put(move |body: Bytes| async move { settings_save(settings_put, body).await }),
        )
        .route(
            "/api/filebrowser/install",
            get(move || async move { install_status(install_get).await })
                .post(move |body: Bytes| async move { install_start(install_post, body).await })
                .delete(move || async move { install_uninstall(install_delete).await }),
        )
        .route(
            "/api/filebrowser/install/check",
            post(move || async move { install_check_updates(install_check).await }),
        )
        .route(
            "/api/filebrowser/install/rollback",
            post(
                move |body: Bytes| async move { install_rollback_to(install_rollback, body).await },
            ),
        )
        .route(
            "/api/filebrowser/install/backups/{id}",
            axum::routing::delete(
                move |path: Result<Path<String>, PathRejection>| async move {
                    backup_remove(backup_delete, path).await
                },
            ),
        )
        .route(
            "/api/filebrowser/reset",
            post(move || async move { reset_all(reset).await }),
        )
}

/// Serializes writers, applies the change to the live config, persists and
/// only then publishes. Mutations restart the owning instance on change.
#[allow(clippy::result_large_err)]
async fn mutate<T>(
    state: &RoutesState,
    change: impl FnOnce(&mut FileConfig) -> Change<T> + Send,
) -> Result<T, Response> {
    let mut guard = state.config.write().await;
    let mut candidate = guard.clone();
    let (value, changed) = change(&mut candidate).map_err(IntoResponse::into_response)?;
    if changed {
        if let Err(problem) = validate::normalize(&mut candidate) {
            return Err(Failure::problems(vec![problem]).into_response());
        }
        let persist = state.persist.clone();
        let saved = candidate.clone();
        tokio::task::spawn_blocking(move || persist(&saved))
            .await
            .map_err(|_| internal())?
            .map_err(|error| {
                tracing::warn!(%error, "persisting filebrowser.json failed");
                internal()
            })?;
        *guard = candidate;
        drop(guard);
        return Ok(value);
    }
    drop(guard);
    Ok(value)
}

fn internal() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": "configuration operation failed" })),
    )
        .into_response()
}

async fn list_instances(state: Arc<RoutesState>) -> Response {
    let config = state.config.read().await;
    let views: Vec<serde_json::Value> = config
        .instances
        .iter()
        .map(|instance| {
            let mut view = view_instance(instance);
            let status = state.runtime.status(instance);
            view["running"] = json!(status.running);
            view["pid"] = json!(status.pid);
            view["since"] = json!(status.since);
            view["restarts"] = json!(status.restarts);
            view["failed"] = json!(status.failed);
            view
        })
        .collect();
    Json(json!({ "instances": views })).into_response()
}

async fn create_instance(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(instance) = serde_json::from_slice::<Instance>(&body) else {
        return decode_error();
    };
    let config_dir = state.config_dir.clone();
    match mutate(&state, move |config| {
        validate::validate_instance(&instance).map_err(|p| Failure::problems(vec![p]))?;
        for (index, source) in instance.sources.iter().enumerate() {
            if validate::source_overlaps_config_dir(std::path::Path::new(&source.path), &config_dir)
            {
                return Err(Failure::problems(vec![validate::Problem {
                    field: format!("instances.sources[{index}].path"),
                    reason: "共享目录不能与 Gately 配置目录重叠".to_string(),
                }]));
            }
        }
        config.instances.push(instance);
        validate::normalize(config).map_err(|p| Failure::problems(vec![p]))?;
        let created = config.instances.last().cloned().expect("just pushed");
        Ok((json!({ "key": created.key, "ok": true }), true))
    })
    .await
    {
        Ok(value) => Json(value).into_response(),
        Err(response) => response,
    }
}

async fn replace_instance(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(submitted) = serde_json::from_slice::<Instance>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::bad_request("invalid item key").into_response();
    };
    match mutate(&state, move |config| {
        let index = locate(config, &key)?;
        let mut replacement = submitted;
        replacement.key = key.clone();
        validate::validate_instance(&replacement).map_err(|p| Failure::problems(vec![p]))?;
        config.instances[index] = replacement;
        validate::normalize(config).map_err(|p| Failure::problems(vec![p]))?;
        Ok((json!({ "ok": true }), true))
    })
    .await
    {
        Ok(value) => Json(value).into_response(),
        Err(response) => response,
    }
}

async fn copy_instance(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::bad_request("invalid item key").into_response();
    };
    match mutate(&state, move |config| {
        let index = locate(config, &key)?;
        let mut copy: Instance = serde_json::to_value(&config.instances[index])
            .ok()
            .and_then(|value| serde_json::from_value(value).ok())
            .ok_or(Failure {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "copy failed".to_string(),
            })?;
        copy.key = String::new();
        copy.name = format!("{}-copy", config.instances[index].name);
        // The copy starts disabled and keeps the share layout; the admin
        // password is kept (the operator may want the same access).
        copy.enable = false;
        config.instances.push(copy);
        validate::normalize(config).map_err(|p| Failure::problems(vec![p]))?;
        let created = config.instances.last().cloned().expect("just pushed");
        Ok((json!({ "key": created.key, "ok": true }), true))
    })
    .await
    {
        Ok(value) => Json(value).into_response(),
        Err(response) => response,
    }
}

async fn remove_instance(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::bad_request("invalid item key").into_response();
    };
    let removed_key = key.clone();
    match mutate(&state, move |config| {
        let index = locate(config, &key)?;
        config.instances.remove(index);
        Ok((json!({ "removed": 1 }), true))
    })
    .await
    {
        Ok(value) => {
            // The data directory goes with the instance.
            state.runtime.reset_data(&[removed_key]);
            Json(value).into_response()
        }
        Err(response) => response,
    }
}

async fn enable_instance(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(payload) = serde_json::from_slice::<Enable>(&body) else {
        return decode_error();
    };
    let Ok(key) = item_key(path) else {
        return Failure::bad_request("invalid item key").into_response();
    };
    let enabled = payload.enable;
    match mutate(&state, move |config| {
        let index = locate(config, &key)?;
        let instance = &mut config.instances[index];
        let changed = instance.enable != enabled;
        instance.enable = enabled;
        let snapshot = instance.clone();
        Ok((snapshot, changed))
    })
    .await
    {
        Ok(snapshot) => {
            if enabled {
                if let Err(reason) = state.runtime.start(&snapshot).await {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": reason })),
                    )
                        .into_response();
                }
            } else {
                state.runtime.stop(&snapshot.key).await;
            }
            (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
        }
        Err(response) => response,
    }
}

async fn restart_instance(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::bad_request("invalid item key").into_response();
    };
    let snapshot = {
        let config = state.config.read().await;
        match config.instances.iter().find(|row| row.key == key) {
            Some(instance) => instance.clone(),
            None => return Failure::not_found().into_response(),
        }
    };
    match state.runtime.restart(&snapshot).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(reason) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": reason })),
        )
            .into_response(),
    }
}

/// The plaintext admin password endpoint (write-scoped via the
/// management router's sensitive-path rules).
async fn instance_secrets(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(key) = item_key(path) else {
        return Failure::bad_request("invalid item key").into_response();
    };
    let config = state.config.read().await;
    match config.instances.iter().find(|row| row.key == key) {
        Some(instance) => Json(json!({ "adminPassword": instance.admin_password })).into_response(),
        None => Failure::not_found().into_response(),
    }
}

async fn batch_remove(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Keys { keys }) = serde_json::from_slice::<Keys>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::bad_request("expected between 1 and 500 valid keys").into_response();
    };
    let removed_keys = keys.clone();
    match mutate(&state, move |config| {
        for key in &keys {
            locate(config, key)?;
        }
        let removed: std::collections::HashSet<_> = keys.iter().map(String::as_str).collect();
        config
            .instances
            .retain(|instance| !removed.contains(instance.key.as_str()));
        Ok((json!({ "removed": keys.len() }), true))
    })
    .await
    {
        Ok(value) => {
            state.runtime.reset_data(&removed_keys);
            Json(value).into_response()
        }
        Err(response) => response,
    }
}

async fn batch_toggle(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(EnableKeys { keys, enable }) = serde_json::from_slice::<EnableKeys>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::bad_request("expected between 1 and 500 valid keys").into_response();
    };
    match mutate(&state, move |config| {
        for key in &keys {
            locate(config, key)?;
        }
        let mut changed = 0;
        for instance in &mut config.instances {
            if keys.contains(&instance.key) && instance.enable != enable {
                instance.enable = enable;
                changed += 1;
            }
        }
        Ok((json!({ "changed": changed }), changed > 0))
    })
    .await
    {
        Ok(value) => Json(value).into_response(),
        Err(response) => response,
    }
}

async fn reorder(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Keys { keys }) = serde_json::from_slice::<Keys>(&body) else {
        return decode_error();
    };
    match mutate(&state, move |config| {
        if keys.len() != config.instances.len() {
            return Err(Failure::bad_request("order must include every item once"));
        }
        let indices: Vec<usize> = keys
            .iter()
            .map(|key| locate(config, key))
            .collect::<Result<Vec<_>, _>>()?;
        let unchanged = indices.iter().enumerate().all(|(index, &old)| index == old);
        if unchanged {
            return Ok((json!({ "ok": true }), false));
        }
        let mut destination = vec![0; indices.len()];
        for (new, old) in indices.into_iter().enumerate() {
            destination[old] = new;
        }
        for index in 0..destination.len() {
            while destination[index] != index {
                let new = destination[index];
                config.instances.swap(index, new);
                destination.swap(index, new);
            }
        }
        Ok((json!({ "ok": true }), true))
    })
    .await
    {
        Ok(value) => Json(value).into_response(),
        Err(response) => response,
    }
}

async fn regroup(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(Groups { keys, group }) = serde_json::from_slice::<Groups>(&body) else {
        return decode_error();
    };
    let Ok(keys) = batch_keys(keys) else {
        return Failure::bad_request("expected between 1 and 500 valid keys").into_response();
    };
    match mutate(&state, move |config| {
        for key in &keys {
            locate(config, key)?;
        }
        let mut changed = 0;
        for instance in &mut config.instances {
            if keys.contains(&instance.key) && instance.group != group {
                instance.group = group.clone();
                changed += 1;
            }
        }
        Ok((json!({ "changed": changed }), changed > 0))
    })
    .await
    {
        Ok(value) => Json(value).into_response(),
        Err(response) => response,
    }
}

async fn settings_view(state: Arc<RoutesState>) -> Response {
    let config = state.config.read().await;
    Json(json!({
        "settings": config.settings,
        "install": { "proxy": config.install.proxy },
    }))
    .into_response()
}

async fn settings_save(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(SettingsBody { bin_path, proxy }) = serde_json::from_slice::<SettingsBody>(&body) else {
        return decode_error();
    };
    let settings = crate::Settings {
        program_path: bin_path.unwrap_or_default(),
    };
    let proxy = proxy.unwrap_or_default();
    match mutate(&state, move |config| {
        let changed =
            config.settings.program_path != settings.program_path || config.install.proxy != proxy;
        config.settings = settings;
        config.install.proxy = proxy;
        Ok((json!({ "ok": true }), changed))
    })
    .await
    {
        Ok(value) => Json(value).into_response(),
        Err(response) => response,
    }
}

async fn install_status(state: Arc<RoutesState>) -> Response {
    let Some((installer, fetch)) = state.installer.as_ref() else {
        return Json(json!({ "installed": null, "stage": "Idle" })).into_response();
    };
    let stage = stage_name(&installer.stage().borrow().clone());
    Json(json!({
        "installed": installer.installed().map(|installed| json!({
            "version": installed.version,
            "files": installed.files,
        })),
        "stage": stage,
        "fetchConfigured": fetch.is_some(),
        "backups": installer.backups().iter().map(|backup| json!({
            "id": backup.version,
            "version": backup.version,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

fn stage_name(stage: &fg_proc::install::Stage) -> &'static str {
    match stage {
        fg_proc::install::Stage::Idle => "Idle",
        fg_proc::install::Stage::Checking => "Checking",
        fg_proc::install::Stage::Downloading { .. } => "Downloading",
        fg_proc::install::Stage::Verifying => "Verifying",
        fg_proc::install::Stage::Extracting => "Extracting",
        fg_proc::install::Stage::Done => "Done",
        fg_proc::install::Stage::UpToDate => "UpToDate",
        fg_proc::install::Stage::Failed(_) => "Failed",
    }
}

async fn install_start(state: Arc<RoutesState>, _body: Bytes) -> Response {
    let Some((installer, fetch)) = state.installer.clone() else {
        return internal();
    };
    let Some(_) = fetch else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "下载通道未配置" })),
        )
            .into_response();
    };
    // Download proxy from the module settings; empty follows the global
    // update proxy (the assembler's getter already applies it).
    let proxy = {
        let config = state.config.read().await;
        crate::InstallConfig {
            proxy: config.install.proxy.clone(),
        }
        .proxy
    };
    let proxy = if proxy.is_empty() {
        None
    } else {
        match fg_proc::install::ProxyUrl::parse(&proxy) {
            Ok(proxy) => Some(proxy),
            Err(reason) => {
                return (StatusCode::BAD_REQUEST, Json(json!({ "error": reason }))).into_response();
            }
        }
    };
    // Kick the install off detached; progress polls via GET /install, and
    // enabled instances restart once the new binary lands (doc §3.3).
    let on_done_state = Arc::clone(&state);
    let on_done: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        let state = Arc::clone(&on_done_state);
        tokio::spawn(async move {
            let enabled: Vec<Instance> = {
                let config = state.config.read().await;
                config
                    .instances
                    .iter()
                    .filter(|instance| instance.enable)
                    .cloned()
                    .collect()
            };
            for instance in enabled {
                let _ = state.runtime.restart(&instance).await;
            }
        });
    });
    tokio::spawn(async move {
        let _ = installer
            .start(
                fg_proc::install::InstallTarget::Latest,
                proxy,
                Some(on_done),
            )
            .await;
    });
    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}

async fn install_check_updates(state: Arc<RoutesState>) -> Response {
    let Some((installer, fetch)) = state.installer.clone() else {
        return internal();
    };
    let Some(fetch) = fetch else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "下载通道未配置" })),
        )
            .into_response();
    };
    let installed = installer.installed();
    let latest = fg_proc::install::select_release(
        installer.spec(),
        &fetch,
        None,
        &fg_proc::install::InstallTarget::Latest,
    )
    .await;
    let body = match (&installed, latest) {
        (Some(current), Ok(selected)) => json!({
            "installed": current.version,
            "latest": selected.version,
            "update": selected.version != current.version,
        }),
        (Some(current), Err(error)) => json!({
            "installed": current.version,
            "error": format!("{error:?}"),
        }),
        (None, Ok(selected)) => json!({ "installed": null, "latest": selected.version }),
        (None, Err(error)) => json!({ "installed": null, "error": format!("{error:?}") }),
    };
    (StatusCode::OK, Json(body)).into_response()
}

async fn install_rollback_to(state: Arc<RoutesState>, body: Bytes) -> Response {
    let Ok(payload) = serde_json::from_slice::<RollbackBody>(&body) else {
        return decode_error();
    };
    let Some((installer, _)) = state.installer.clone() else {
        return internal();
    };
    match installer.rollback_to(&payload.version).await {
        Ok(installed) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "version": installed.version })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": install_error_text(&error) })),
        )
            .into_response(),
    }
}

async fn install_uninstall(state: Arc<RoutesState>) -> Response {
    let Some((installer, _)) = state.installer.clone() else {
        return internal();
    };
    match installer.uninstall().await {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": install_error_text(&error) })),
        )
            .into_response(),
    }
}

async fn backup_remove(
    state: Arc<RoutesState>,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(id) = path.map(|Path(id)| id) else {
        return Failure::bad_request("invalid item key").into_response();
    };
    let Some((installer, _)) = state.installer.as_ref() else {
        return internal();
    };
    // Backup ids are their version strings (fg-proc keeps one directory
    // per version under bin/versions/).
    let known = installer
        .backups()
        .iter()
        .any(|backup| fg_proc::install::swap::version_eq(&backup.version, id.trim()));
    if !known {
        return Failure::not_found().into_response();
    }
    let dir = fg_proc::install::swap::versions_dir(installer.bin_dir(), installer.spec().name)
        .join(id.trim());
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("删除备份失败：{error}") })),
        )
            .into_response(),
    }
}

/// 「恢复默认配置」: stop everything, delete every instance and its data,
/// keep the installed program.
async fn reset_all(state: Arc<RoutesState>) -> Response {
    let keys: Vec<String> = {
        let config = state.config.read().await;
        config
            .instances
            .iter()
            .map(|instance| instance.key.clone())
            .collect()
    };
    match mutate(&state, move |config| {
        config.instances.clear();
        Ok((json!({ "ok": true }), true))
    })
    .await
    {
        Ok(value) => {
            state.runtime.stop_all().await;
            state.runtime.reset_data(&keys);
            Json(value).into_response()
        }
        Err(response) => response,
    }
}

fn install_error_text(error: &fg_proc::install::InstallError) -> String {
    match error {
        fg_proc::install::InstallError::Busy => "已有安装操作进行中".to_string(),
        fg_proc::install::InstallError::Unsupported(_) => "当前平台不受支持".to_string(),
        other => format!("安装失败：{other:?}"),
    }
}

fn locate(config: &FileConfig, key: &str) -> Result<usize, Failure> {
    config
        .instances
        .iter()
        .position(|instance| instance.key == key)
        .ok_or(Failure::not_found())
}

fn item_key(path: Result<Path<String>, PathRejection>) -> Result<String, Failure> {
    match path {
        Ok(Path(key)) if valid_key(&key) => Ok(key),
        _ => Err(Failure::bad_request("invalid item key")),
    }
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn batch_keys(keys: Vec<String>) -> Result<Vec<String>, Failure> {
    if keys.is_empty() || keys.len() > 500 || !keys.iter().all(|key| valid_key(key)) {
        return Err(Failure::bad_request(
            "expected between 1 and 500 valid keys",
        ));
    }
    Ok(keys)
}

fn decode_error() -> Response {
    Failure::bad_request("invalid JSON body").into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Keys {
    keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enable {
    enable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnableKeys {
    keys: Vec<String>,
    enable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Groups {
    keys: Vec<String>,
    group: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsBody {
    #[serde(rename = "binPath")]
    bin_path: Option<String>,
    proxy: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackBody {
    version: String,
}
