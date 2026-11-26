use std::sync::Arc;

use axum::{
    Json,
    extract::Path,
    http::{Method, StatusCode},
};
use fg_auth::token::{TokenChangeError, TokenInput, TokenManager, TokenView};
use fg_core::registry::{CATALOG, Enabled, Registry, Status};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::Semaphore;

use crate::{ApiError, ApiJson, ApiRouter, RouteModels, http::run_blocking, models::OkResponse};

#[derive(Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct Domain {
    pub id: &'static str,
    title: &'static str,
    builtin: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    read_only: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    write_only: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    can_exec: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    can_files: bool,
}

pub(super) fn domains(modules: Option<&(Registry, Enabled)>, tokens: &TokenManager) -> Vec<Domain> {
    let explicit = modules.is_none().then(|| tokens.domains());
    let catalog = CATALOG
        .iter()
        .filter(|module| {
            if let Some((registry, enabled)) = modules {
                matches!(
                    registry.status(enabled, module.id),
                    Some(Status::Enabled | Status::Disabled)
                )
            } else {
                explicit
                    .as_ref()
                    .is_some_and(|domains| domains.iter().any(|id| id == module.id))
            }
        })
        .map(|module| Domain {
            id: module.id,
            title: module.title.en,
            builtin: false,
            read_only: false,
            write_only: false,
            can_exec: matches!(
                module.id,
                "ddns"
                    | "cron"
                    | "guard"
                    | "stun"
                    | "ssl"
                    | "webterminal"
                    | "docker"
                    | "frp"
                    | "filebrowser"
                    | "cloudflared"
                    | "tailscale"
                    | "netbird"
            ),
            can_files: matches!(
                module.id,
                "storage" | "webservice" | "webdav" | "ftp" | "smb" | "backup"
            ),
        });
    catalog
        .chain(
            [
                ("status", "System status", true, false, false),
                ("logs", "System logs", true, false, false),
                ("metrics", "Metrics", true, false, false),
                ("import", "Lucky configuration import", false, true, false),
                ("fileusers", "Shared file-service users", false, false, true),
            ]
            .into_iter()
            .map(|(id, title, read_only, write_only, can_files)| Domain {
                id,
                title,
                builtin: true,
                read_only,
                write_only,
                can_exec: false,
                can_files,
            }),
        )
        .collect()
}

struct Writes {
    tokens: Arc<TokenManager>,
    slots: Arc<Semaphore>,
}

impl Writes {
    async fn run<T: Serialize + Send + 'static>(
        self: Arc<Self>,
        edit: impl FnOnce(&TokenManager) -> anyhow::Result<T> + Send + 'static,
    ) -> Result<Json<T>, ApiError> {
        let tokens = self.tokens.clone();
        run_blocking(
            &self.slots,
            ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "API token writes are busy"),
            move || edit(&tokens),
        )
        .await?
        .map(Json)
        .map_err(|error| match error.downcast_ref::<TokenChangeError>() {
            Some(TokenChangeError::Invalid(message)) => {
                ApiError::new(StatusCode::BAD_REQUEST, message)
            }
            Some(TokenChangeError::NotFound) => {
                ApiError::new(StatusCode::NOT_FOUND, "API token was not found")
            }
            None => ApiError::internal(),
        })
    }
}

pub(super) fn mount(
    router: ApiRouter,
    tokens: Arc<TokenManager>,
    domains: Vec<Domain>,
) -> ApiRouter {
    let list = tokens.clone();
    let domains = Arc::new(domains);
    let writes = Arc::new(Writes {
        tokens,
        slots: Arc::new(Semaphore::new(1)),
    });
    let create = writes.clone();
    let update = writes.clone();
    let rotate = writes.clone();
    let order = writes.clone();
    let group = writes.clone();
    router
        .modeled_route(
            Method::GET,
            "/api/tokens",
            "List API tokens",
            RouteModels::default().response::<Vec<TokenView>>(),
            move || async move { Json(list.list(OffsetDateTime::now_utc())) },
        )
        .modeled_route(
            Method::GET,
            "/api/tokens/scopes",
            "List available token scope domains",
            RouteModels::default().response::<Vec<Domain>>(),
            move || async move { Json(domains) },
        )
        .modeled_route(
            Method::POST,
            "/api/tokens",
            "Create an API token",
            RouteModels::default()
                .request::<TokenInput>()
                .response::<Issued>(),
            move |ApiJson(input): ApiJson<TokenInput>| async move {
                create
                    .run(move |tokens| {
                        let (token, secret) = tokens.create(input, OffsetDateTime::now_utc())?;
                        Ok(Issued { token, secret })
                    })
                    .await
            },
        )
        .modeled_route(
            Method::PUT,
            "/api/tokens/{id}",
            "Update an API token",
            RouteModels::default()
                .request::<TokenInput>()
                .response::<TokenView>(),
            move |Path(id): Path<String>, ApiJson(input): ApiJson<TokenInput>| async move {
                update
                    .run(move |tokens| tokens.update(&id, input, OffsetDateTime::now_utc()))
                    .await
            },
        )
        .modeled_route(
            Method::POST,
            "/api/tokens/{id}/regenerate",
            "Rotate an API token",
            RouteModels::default().response::<Issued>(),
            move |Path(id): Path<String>| async move {
                rotate
                    .run(move |tokens| {
                        let (token, secret) =
                            tokens.regenerate_with_view(&id, OffsetDateTime::now_utc())?;
                        Ok(Issued { token, secret })
                    })
                    .await
            },
        )
        .modeled_route(
            Method::PUT,
            "/api/tokens/order",
            "Reorder API tokens",
            RouteModels::default()
                .request::<Keys>()
                .response::<OkResponse>(),
            move |ApiJson(input): ApiJson<Keys>| async move {
                order
                    .run(move |tokens| {
                        tokens.order(&input.keys)?;
                        Ok(OkResponse { ok: true })
                    })
                    .await
            },
        )
        .modeled_route(
            Method::PUT,
            "/api/tokens/group",
            "Set API token groups",
            RouteModels::default()
                .request::<Group>()
                .response::<OkResponse>(),
            move |ApiJson(input): ApiJson<Group>| async move {
                group
                    .run(move |tokens| {
                        tokens.set_group(&input.keys, &input.group)?;
                        Ok(OkResponse { ok: true })
                    })
                    .await
            },
        )
        .modeled_route(
            Method::DELETE,
            "/api/tokens/{id}",
            "Delete an API token",
            RouteModels::default().response::<OkResponse>(),
            move |Path(id): Path<String>| async move {
                writes
                    .run(move |tokens| {
                        tokens.delete(&id)?;
                        Ok(OkResponse { ok: true })
                    })
                    .await
            },
        )
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Keys {
    keys: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Group {
    keys: Vec<String>,
    #[serde(default)]
    group: String,
}

#[derive(Serialize, JsonSchema)]
struct Issued {
    token: TokenView,
    secret: String,
}
