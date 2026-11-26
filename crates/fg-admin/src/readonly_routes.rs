use std::sync::Arc;

use axum::{
    Json,
    extract::Path,
    http::{HeaderMap, Method},
};
use fg_auth::{AccountManager, ReadonlyUserInfo, Role};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, ApiJson, ApiRouter, RouteModels,
    login::{Sessions, admin_token, credential_error},
    models::OkResponse,
};

pub(super) fn mount(router: ApiRouter, state: Arc<Sessions>) -> ApiRouter {
    let list = state.accounts.clone();
    let add = state.clone();
    let reset = state.clone();
    router
        .modeled_route(
            Method::GET,
            "/api/account/users",
            "List read-only accounts",
            RouteModels::default().response::<Vec<UserView>>(),
            move || async move { Json(views(&list)) },
        )
        .modeled_route(
            Method::POST,
            "/api/account/users",
            "Create a read-only account",
            RouteModels::default()
                .request::<CreateUser>()
                .response::<Vec<UserView>>(),
            move |headers: HeaderMap, ApiJson(request): ApiJson<CreateUser>| async move {
                let token = admin_token(&headers)?;
                let accounts = add.accounts.clone();
                add.work(move || {
                    accounts.add_readonly_user(&token, &request.username, &request.password)
                })
                .await?
                .map_err(credential_error)?;
                Ok::<_, ApiError>(Json(views(&add.accounts)))
            },
        )
        .modeled_route(
            Method::PUT,
            "/api/account/users/{name}",
            "Reset a read-only account password",
            RouteModels::default()
                .request::<ResetPassword>()
                .response::<OkResponse>(),
            move |headers: HeaderMap,
                  Path(username): Path<String>,
                  ApiJson(request): ApiJson<ResetPassword>| async move {
                let token = admin_token(&headers)?;
                let accounts = reset.accounts.clone();
                reset
                    .work(move || {
                        accounts.reset_readonly_password(&token, &username, &request.password)
                    })
                    .await?
                    .map_err(credential_error)?;
                Ok::<_, ApiError>(Json(OkResponse { ok: true }))
            },
        )
        .modeled_route(
            Method::DELETE,
            "/api/account/users/{name}",
            "Delete a read-only account",
            RouteModels::default().response::<Vec<UserView>>(),
            move |headers: HeaderMap, Path(username): Path<String>| async move {
                let token = admin_token(&headers)?;
                let accounts = state.accounts.clone();
                state
                    .work(move || accounts.delete_readonly_user(&token, &username))
                    .await?
                    .map_err(credential_error)?;
                Ok::<_, ApiError>(Json(views(&state.accounts)))
            },
        )
}

fn views(accounts: &AccountManager) -> Vec<UserView> {
    accounts
        .readonly_users()
        .into_iter()
        .map(|ReadonlyUserInfo { username }| UserView {
            username,
            role: Role::Readonly.as_str(),
        })
        .collect()
}

#[derive(Serialize, JsonSchema)]
struct UserView {
    username: String,
    role: &'static str,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CreateUser {
    username: String,
    password: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ResetPassword {
    password: String,
    #[serde(rename = "username")]
    _username: Option<String>,
}
