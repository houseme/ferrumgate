//! First-run onboarding state: `onboarding.json` in the configuration
//! directory with `scenePending`, `scenes` and `done`. The state is read
//! and written through the config store so the declarative apply and the
//! confirm/rollback flows see it.

use std::{path::Path, sync::Arc};

use axum::{Json, http::Method};
use fg_config::ConfigStore;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ApiError, ApiJson, ApiRouter, RouteModels};

const STORE: &str = "onboarding";
const MAX_DONE: usize = 32;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct OnboardingState {
    scene_pending: bool,
    scenes: Vec<String>,
    done: Vec<String>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OnboardingView {
    pub pending: bool,
    pub scene_pending: bool,
    pub scenes: Vec<String>,
    pub done: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScenesRequest {
    pub scenes: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DoneRequest {
    pub item: String,
}

/// Known usage scenes; the interface maps them to module switches via the
/// settings API, never this endpoint.
const SCENES: [&str; 7] = ["web", "forward", "ddns", "mesh", "files", "vps", "all"];

pub(super) fn mount(router: ApiRouter, store: Arc<ConfigStore>) -> ApiRouter {
    let get = store.clone();
    let scenes = store.clone();
    let done = store.clone();
    let dismiss = store;
    router
        .modeled_route(
            Method::GET,
            "/api/system/onboarding",
            "Get onboarding progress",
            RouteModels::default().response::<OnboardingView>(),
            move || {
                let store = get.clone();
                async move { Json(view(&store)) }
            },
        )
        .modeled_route(
            Method::POST,
            "/api/system/onboarding/scenes",
            "Record chosen usage scenes and finish scene selection",
            RouteModels::default()
                .request::<ScenesRequest>()
                .response::<OnboardingView>(),
            move |ApiJson(request): ApiJson<ScenesRequest>| async move {
                let store = scenes.clone();
                let blocked = store.clone();
                tokio::task::spawn_blocking(move || record_scenes(&blocked, request.scenes))
                    .await
                    .map_err(|_| ApiError::internal())??;
                let view: OnboardingView = view(&store);
                Ok::<_, ApiError>(Json(view))
            },
        )
        .modeled_route(
            Method::POST,
            "/api/system/onboarding/done",
            "Mark one checklist item as done",
            RouteModels::default()
                .request::<DoneRequest>()
                .response::<OnboardingView>(),
            move |ApiJson(request): ApiJson<DoneRequest>| async move {
                let store = done.clone();
                let blocked = store.clone();
                tokio::task::spawn_blocking(move || record_done(&blocked, &request.item))
                    .await
                    .map_err(|_| ApiError::internal())??;
                let view: OnboardingView = view(&store);
                Ok::<_, ApiError>(Json(view))
            },
        )
        .modeled_route(
            Method::POST,
            "/api/system/onboarding/dismiss",
            "Finish or skip onboarding",
            RouteModels::default().response::<OnboardingView>(),
            move || {
                let store = dismiss.clone();
                async move {
                    let blocked = store.clone();
                    tokio::task::spawn_blocking(move || {
                        update(&blocked, |state| state.scene_pending = false)
                    })
                    .await
                    .map_err(|_| ApiError::internal())??;
                    let view: OnboardingView = view(&store);
                    Ok::<_, ApiError>(Json(view))
                }
            },
        )
}

/// Marks a fresh install so the interface can offer scene selection. Call
/// before any configuration file is written; directories that already hold
/// configuration stay untouched. Wired by the bootstrap start sequence; the
/// unit test below pins the semantics.
#[allow(dead_code)]
pub fn mark_fresh_install(dir: &Path) {
    let fresh = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .all(|entry| entry.path().extension() != Some(std::ffi::OsStr::new("json")))
        })
        .unwrap_or(false);
    if !fresh {
        return;
    }
    if let Ok(store) = ConfigStore::open(dir) {
        let _ = update(&store, |state| state.scene_pending = true);
    }
}

fn view(store: &ConfigStore) -> OnboardingView {
    let state = found(store.load::<OnboardingState>(STORE)).unwrap_or_default();
    // `pending` mirrors scenePending: the checklist stage is over once the
    // scenes are recorded, and `done` survives dismiss as history.
    OnboardingView {
        pending: state.scene_pending,
        scene_pending: state.scene_pending,
        scenes: state.scenes,
        done: state.done,
    }
}

fn update(store: &ConfigStore, apply: impl FnOnce(&mut OnboardingState)) -> Result<(), ApiError> {
    let mut state = found(store.load::<OnboardingState>(STORE)).unwrap_or_default();
    apply(&mut state);
    store
        .save(STORE, &state)
        .map_err(|_: anyhow::Error| ApiError::internal())
        .map(|_: fg_config::Saved| ())
}

fn found<T>(result: Result<fg_config::Loaded<T>, anyhow::Error>) -> Option<T> {
    match result {
        Ok(fg_config::Loaded::Found(value)) => Some(value),
        _ => None,
    }
}

fn record_scenes(store: &ConfigStore, scenes: Vec<String>) -> Result<(), ApiError> {
    let mut picked = Vec::new();
    for scene in scenes {
        let scene = scene.trim().to_ascii_lowercase();
        if scene.is_empty() {
            continue;
        }
        if !SCENES.contains(&scene.as_str()) {
            return Err(ApiError::new(
                axum::http::StatusCode::BAD_REQUEST,
                "未知的使用场景",
            ));
        }
        if !picked.contains(&scene) {
            picked.push(scene);
        }
    }
    update(store, |state| {
        state.scenes = picked;
        state.scene_pending = false;
    })
}

fn record_done(store: &ConfigStore, item: &str) -> Result<(), ApiError> {
    let valid = item.len() <= 32
        && item.starts_with(|c: char| c.is_ascii_lowercase())
        && item
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !valid {
        return Err(ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "清单项编号无效",
        ));
    }
    let mut rejected = None;
    update(store, |state| {
        if state.done.len() >= MAX_DONE && !state.done.iter().any(|existing| existing == item) {
            rejected = Some(());
            return;
        }
        if !state.done.iter().any(|existing| existing == item) {
            state.done.push(item.to_owned());
        }
    })?;
    if rejected.is_some() {
        return Err(ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "清单项过多",
        ));
    }
    Ok(())
}

// The Loaded helper above keeps the store's Result/enum shape internal.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_install_gets_scene_pending_and_used_ones_do_not() {
        let fresh = tempfile::tempdir().unwrap();
        mark_fresh_install(fresh.path());
        let store = ConfigStore::open(fresh.path()).unwrap();
        assert!(
            view(&store).scene_pending,
            "a fresh directory asks for scenes"
        );

        let used = tempfile::tempdir().unwrap();
        std::fs::write(used.path().join("ddns.json"), "{}").unwrap();
        mark_fresh_install(used.path());
        let store = ConfigStore::open(used.path()).unwrap();
        assert!(
            !view(&store).scene_pending,
            "an existing deployment is untouched"
        );
    }
}
