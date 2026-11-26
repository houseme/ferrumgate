use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json,
    extract::{ConnectInfo, Extension, Path},
    http::{HeaderMap, Method},
    response::{IntoResponse, Response},
};
use fg_auth::passkey::{PasskeyInfo, Passkeys, PublicKeyCredential, RegisterPublicKeyCredential};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::{
    ApiError, ApiJson, ApiRouter, RouteModels,
    login::{Sessions, admin_token, credential_error, login_error},
    models::OkResponse,
};

type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

struct Routes {
    passkeys: Arc<Passkeys>,
    sessions: Arc<Sessions>,
}

pub(super) fn mount(router: ApiRouter, sessions: Arc<Sessions>, passkeys: Passkeys) -> ApiRouter {
    let passkeys = Arc::new(passkeys);
    let list = passkeys.clone();
    let password_status = passkeys.clone();
    let routes = Arc::new(Routes { passkeys, sessions });
    let begin = routes.clone();
    let register = routes.clone();
    let remove = routes.clone();
    let password_switch = routes.clone();
    let login_begin = routes.clone();
    router
        .modeled_route(
            Method::GET,
            "/api/account/passkeys",
            "List administrator Passkeys",
            RouteModels::default().response::<Vec<PasskeyView>>(),
            move || async move { Json(views(&list)) },
        )
        .modeled_route(
            Method::POST,
            "/api/account/passkeys/begin",
            "Begin Passkey registration",
            RouteModels::default().response::<Value>(),
            move |headers| begin.begin_registration(headers),
        )
        .modeled_route(
            Method::POST,
            "/api/account/passkeys",
            "Register an administrator Passkey",
            RouteModels::default()
                .request::<Registration>()
                .response::<Vec<PasskeyView>>(),
            move |headers, ApiJson(request)| register.register(headers, request),
        )
        .modeled_route(
            Method::DELETE,
            "/api/account/passkeys/{id}",
            "Remove an administrator Passkey",
            RouteModels::default()
                .request::<Password>()
                .response::<Vec<PasskeyView>>(),
            move |headers, Path(id), ApiJson(request)| remove.remove(headers, id, request),
        )
        .modeled_route(
            Method::GET,
            "/api/account/password-login",
            "Get password login status",
            RouteModels::default().response::<PasswordStatus>(),
            move || async move {
                Json(PasswordStatus {
                    disabled: password_status.password_login_disabled(),
                    passkeys: password_status.list().len(),
                })
            },
        )
        .modeled_route(
            Method::PUT,
            "/api/account/password-login",
            "Change password login status",
            RouteModels::default()
                .request::<PasswordSwitch>()
                .response::<OkResponse>(),
            move |headers, ApiJson(request)| password_switch.set_password_login(headers, request),
        )
        .public_route(
            Method::POST,
            "/api/login/passkey/begin",
            "Begin Passkey sign-in",
            move |peer| login_begin.begin_login(peer),
        )
        .public_route(
            Method::POST,
            "/api/login/passkey/finish",
            "Sign in with a Passkey",
            move |peer, ApiJson(request)| routes.finish_login(peer, request),
        )
}

impl Routes {
    async fn begin_registration(self: Arc<Self>, headers: HeaderMap) -> Result<Response, ApiError> {
        let token = admin_token(&headers)?;
        let passkeys = self.passkeys.clone();
        let request = self
            .sessions
            .work(move || passkeys.begin_registration(&token))
            .await?
            .map_err(credential_error)?;
        Ok(Json(request.public_key).into_response())
    }

    async fn register(
        self: Arc<Self>,
        headers: HeaderMap,
        request: Registration,
    ) -> Result<Response, ApiError> {
        let token = admin_token(&headers)?;
        let passkeys = self.passkeys.clone();
        self.sessions
            .work(move || {
                passkeys.finish_registration(
                    &token,
                    &request.challenge,
                    &request.password,
                    &request.name,
                    &request.credential,
                )
            })
            .await?
            .map_err(credential_error)?;
        Ok(Json(views(&self.passkeys)).into_response())
    }

    async fn remove(
        self: Arc<Self>,
        headers: HeaderMap,
        id: String,
        request: Password,
    ) -> Result<Response, ApiError> {
        let token = admin_token(&headers)?;
        let passkeys = self.passkeys.clone();
        self.sessions
            .work(move || passkeys.remove(&token, &request.password, &id))
            .await?
            .map_err(credential_error)?;
        Ok(self.sessions.cookies.invalidated(views(&self.passkeys)))
    }

    async fn set_password_login(
        self: Arc<Self>,
        headers: HeaderMap,
        request: PasswordSwitch,
    ) -> Result<Json<OkResponse>, ApiError> {
        let token = admin_token(&headers)?;
        let passkeys = self.passkeys.clone();
        self.sessions
            .work(move || {
                passkeys.set_password_login_disabled(&token, &request.password, request.disabled)
            })
            .await?
            .map_err(credential_error)?;
        Ok(Json(OkResponse { ok: true }))
    }

    async fn begin_login(self: Arc<Self>, peer: Peer) -> Result<Response, ApiError> {
        let Extension(ConnectInfo(peer)) = peer.ok_or_else(ApiError::internal)?;
        let passkeys = self.passkeys.clone();
        Ok(
            match self
                .sessions
                .work(move || passkeys.begin_login(peer.ip()))
                .await?
            {
                Ok(request) => Json(request.public_key).into_response(),
                Err(error) => login_error(error),
            },
        )
    }

    async fn finish_login(
        self: Arc<Self>,
        peer: Peer,
        request: Assertion,
    ) -> Result<Response, ApiError> {
        let Extension(ConnectInfo(peer)) = peer.ok_or_else(ApiError::internal)?;
        let passkeys = self.passkeys.clone();
        match self
            .sessions
            .work(move || passkeys.finish_login(peer.ip(), &request.challenge, &request.credential))
            .await?
        {
            Ok((session, username)) => self.sessions.cookies.response(session, username),
            Err(error) => Ok(login_error(error)),
        }
    }
}

fn views(passkeys: &Passkeys) -> Vec<PasskeyView> {
    passkeys
        .list()
        .into_iter()
        .map(
            |PasskeyInfo {
                 id,
                 name,
                 created_at,
             }| {
                PasskeyView {
                    id,
                    name,
                    created_at,
                }
            },
        )
        .collect()
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct PasskeyView {
    id: String,
    name: String,
    #[serde(with = "time::serde::rfc3339")]
    #[schemars(with = "String")]
    created_at: OffsetDateTime,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Registration {
    #[serde(default)]
    name: String,
    password: String,
    challenge: String,
    #[schemars(with = "Value")]
    credential: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assertion {
    challenge: String,
    credential: PublicKeyCredential,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Password {
    password: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PasswordSwitch {
    password: String,
    disabled: bool,
}

#[derive(Serialize, JsonSchema)]
struct PasswordStatus {
    disabled: bool,
    passkeys: usize,
}
