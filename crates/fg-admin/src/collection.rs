use std::{collections::HashSet, sync::Arc};

use anyhow::{Result, ensure};
use arc_swap::ArcSwap;
use axum::{
    Json,
    extract::{Path, rejection::PathRejection},
    http::{Method, StatusCode},
};
use fg_config::{ConfigStore, Loaded};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tokio::sync::Semaphore;

use crate::{ApiError, ApiJson, ApiRouter};

type ApiResult<T> = Result<T, ApiError>;

pub struct CollectionPaths {
    pub list: &'static str,
    pub item: &'static str,
    pub batch_delete: &'static str,
}

/// One collection owns the named configuration file and serves immutable read snapshots.
pub struct Collection<T> {
    store: Arc<ConfigStore>,
    name: String,
    rows: ArcSwap<Vec<T>>,
    writer: Arc<Semaphore>,
    key: fn(&T) -> &str,
    set_key: fn(&mut T, String),
    validate: fn(&mut T) -> ApiResult<()>,
    view: fn(&T) -> Value,
    limit: usize,
}

impl<T> Collection<T>
where
    T: DeserializeOwned + Serialize + Clone + Send + Sync + 'static,
{
    pub fn open(
        store: Arc<ConfigStore>,
        name: impl Into<String>,
        limit: usize,
        key: fn(&T) -> &str,
        set_key: fn(&mut T, String),
        validate: fn(&mut T) -> ApiResult<()>,
        view: fn(&T) -> Value,
    ) -> Result<Self> {
        ensure!(limit > 0, "collection requires a positive item limit");
        let name = name.into();
        let rows = match store.load::<Vec<T>>(&name)? {
            Loaded::Found(rows) => rows,
            Loaded::Missing => Vec::new(),
        };
        let mut keys = HashSet::new();
        ensure!(
            rows.iter()
                .all(|row| valid_key(key(row)) && keys.insert(key(row))),
            "invalid or duplicate item key in {name}"
        );
        Ok(Self {
            store,
            name,
            rows: ArcSwap::from_pointee(rows),
            writer: Arc::new(Semaphore::new(1)),
            key,
            set_key,
            validate,
            view,
            limit,
        })
    }

    pub fn register(self, router: ApiRouter, paths: CollectionPaths) -> ApiRouter {
        assert_eq!(paths.item.strip_suffix("/{key}"), Some(paths.list));
        assert_eq!(
            paths.batch_delete.strip_suffix("/batch-delete"),
            Some(paths.list)
        );
        let state = Arc::new(self);
        let list = state.clone();
        let insert = state.clone();
        let update = state.clone();
        let delete = state.clone();
        router
            .route(Method::GET, paths.list, "List items", move || async move {
                Json(list.rows.load().iter().map(list.view).collect::<Vec<_>>())
            })
            .route(
                Method::POST,
                paths.list,
                "Add an item",
                move |ApiJson(mut item): ApiJson<T>| async move {
                    insert
                        .change(move |state, items| {
                            if items.len() >= state.limit {
                                return Err(ApiError::new(
                                    StatusCode::CONFLICT,
                                    "collection item limit reached",
                                ));
                            }
                            (state.validate)(&mut item)?;
                            let key = (state.key)(&item);
                            if !valid_key(key) || items.iter().any(|row| (state.key)(row) == key) {
                                let key = random_key(items, state.key)?;
                                (state.set_key)(&mut item, key);
                            }
                            let view = (state.view)(&item);
                            items.push(item);
                            Ok(Json(view))
                        })
                        .await
                },
            )
            .route(
                Method::PUT,
                paths.item,
                "Replace an item",
                move |path: Result<Path<String>, PathRejection>, ApiJson(mut item): ApiJson<T>| async move {
                    let key = item_key(path)?;
                    update
                        .change(move |state, items| {
                            let row = items
                                .iter_mut()
                                .find(|row| (state.key)(row) == key)
                                .ok_or_else(missing_item)?;
                            (state.set_key)(&mut item, key.clone());
                            (state.validate)(&mut item)?;
                            (state.set_key)(&mut item, key);
                            let view = (state.view)(&item);
                            *row = item;
                            Ok(Json(view))
                        })
                        .await
                },
            )
            .route(
                Method::DELETE,
                paths.item,
                "Remove an item",
                move |path: Result<Path<String>, PathRejection>| async move { delete.remove(vec![item_key(path)?]).await },
            )
            .route(
                Method::POST,
                paths.batch_delete,
                "Remove multiple items",
                move |ApiJson(batch): ApiJson<Batch>| async move { state.remove(batch.keys).await },
            )
    }

    async fn remove(self: Arc<Self>, keys: Vec<String>) -> ApiResult<Json<Value>> {
        if keys.is_empty() || keys.len() > 500 || !keys.iter().all(|key| valid_key(key)) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "expected between 1 and 500 valid keys",
            ));
        }
        let keys: HashSet<_> = keys.into_iter().collect();
        self.change(move |state, items| {
            let matching = items
                .iter()
                .filter(|item| keys.contains((state.key)(item)))
                .count();
            if matching != keys.len() {
                return Err(missing_item());
            }
            items.retain(|item| !keys.contains((state.key)(item)));
            Ok(Json(json!({"removed": matching})))
        })
        .await
    }

    async fn change<R: Send + 'static>(
        self: Arc<Self>,
        change: impl FnOnce(&Self, &mut Vec<T>) -> ApiResult<R> + Send + 'static,
    ) -> ApiResult<R> {
        let permit = self.writer.clone().try_acquire_owned().map_err(|_| {
            ApiError::new(
                StatusCode::CONFLICT,
                "another collection write is in progress",
            )
        })?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut candidate = self.rows.load_full().as_ref().clone();
            let result = change(&self, &mut candidate)?;
            let mut bytes =
                serde_json::to_vec_pretty(&candidate).map_err(|_| ApiError::internal())?;
            bytes.push(b'\n');
            let saved = self.store.write_raw(&self.name, &bytes);
            // Directory sync or history pruning can fail after replacement became visible.
            if saved.is_ok()
                || self.store.load_raw(&self.name).ok().flatten().as_deref()
                    == Some(bytes.as_slice())
            {
                self.rows.store(Arc::new(candidate));
            }
            saved.map_err(|_| ApiError::internal())?;
            Ok(result)
        })
        .await
        .map_err(|_| ApiError::internal())?
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    keys: Vec<String>,
}

fn missing_item() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "item not found")
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key != "batch-delete"
        && key.len() <= 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn item_key(path: Result<Path<String>, PathRejection>) -> ApiResult<String> {
    match path {
        Ok(Path(key)) if valid_key(&key) => Ok(key),
        _ => Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid item key")),
    }
}

fn random_key<T>(rows: &[T], key: fn(&T) -> &str) -> ApiResult<String> {
    for _ in 0..8 {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes[2..]).map_err(|_| ApiError::internal())?;
        let next = format!("{:012x}", u64::from_be_bytes(bytes));
        if !rows.iter().any(|row| key(row) == next) {
            return Ok(next);
        }
    }
    Err(ApiError::internal())
}
