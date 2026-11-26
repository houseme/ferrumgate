use std::{
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use axum::{
    Json,
    extract::{ConnectInfo, Extension},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use fg_auth::{
    AccountManager, CredentialChangeRejected, Identity, LoginError, PasswordIssue,
    ReadonlyUserNotFound, Role, Session, check_password_strength, passkey::Passkeys,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::Semaphore;

use crate::{
    ApiError, ApiJson, ApiRouter, RouteModels, assets::normalized_prefix, models::OkResponse,
};

pub(super) const COOKIE_NAME: &str = "gately_token";
const BUSY: ApiError = ApiError::new(StatusCode::TOO_MANY_REQUESTS, "login verification is busy");

pub(super) struct SessionCookies {
    attributes: String,
    expired: HeaderValue,
}

impl SessionCookies {
    pub fn new(prefix: &str, secure: bool) -> Result<Self> {
        let prefix = normalized_prefix(prefix)?;
        let secure = if secure { "; Secure" } else { "" };
        let attributes = format!("; Path={prefix}/; HttpOnly; SameSite=Strict{secure}");
        let expired = HeaderValue::try_from(format!("{COOKIE_NAME}=; Max-Age=0{attributes}"))?;
        Ok(Self {
            attributes,
            expired,
        })
    }

    pub(super) fn response(
        &self,
        session: Session,
        username: String,
    ) -> Result<Response, ApiError> {
        let (cookie, expires) = self.issue(session)?;
        Ok((
            [(header::SET_COOKIE, cookie)],
            Json(LoginSuccess { username, expires }),
        )
            .into_response())
    }

    pub(super) fn issue(&self, session: Session) -> Result<(HeaderValue, String), ApiError> {
        let timestamp = session
            .expires_at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ApiError::internal())?;
        let timestamp = i64::try_from(timestamp.as_secs()).map_err(|_| ApiError::internal())?;
        let expires = OffsetDateTime::from_unix_timestamp(timestamp)
            .map_err(|_| ApiError::internal())?
            .format(&Rfc3339)
            .map_err(|_| ApiError::internal())?;
        let age = session
            .expires_at
            .duration_since(SystemTime::now())
            .unwrap_or_default()
            .as_secs();
        let cookie = HeaderValue::try_from(format!(
            "{COOKIE_NAME}={}; Max-Age={age}{}",
            session.token, self.attributes
        ))
        .map_err(|_| ApiError::internal())?;
        Ok((cookie, expires))
    }

    pub(super) fn clear(&self) -> Response {
        self.invalidated(OkResponse { ok: true })
    }

    pub(super) fn invalidated(&self, body: impl Serialize) -> Response {
        ([(header::SET_COOKIE, self.expired.clone())], Json(body)).into_response()
    }
}

pub(super) fn session_token(headers: &HeaderMap) -> Option<&str> {
    let authorization = headers.get_all(header::AUTHORIZATION);
    let mut authorization = authorization.iter();
    if let Some(value) = authorization.next() {
        if authorization.next().is_some() {
            return None;
        }
        let (scheme, token) = value.to_str().ok()?.split_once(' ')?;
        return scheme
            .eq_ignore_ascii_case("bearer")
            .then_some(token.trim())
            .filter(|token| !token.is_empty());
    }
    cookie(headers, COOKIE_NAME)
}

pub(super) fn cookie<'a>(headers: &'a HeaderMap, cookie_name: &str) -> Option<&'a str> {
    let mut token = None;
    for field in headers.get_all(header::COOKIE) {
        for cookie in field.to_str().ok()?.split(';') {
            if let Some((name, value)) = cookie.trim().split_once('=')
                && name == cookie_name
                && token.replace(value).is_some()
            {
                return None;
            }
        }
    }
    token.filter(|token| !token.is_empty())
}

pub(super) fn password_fix_allowed(method: &Method, path: &str) -> bool {
    matches!(
        (method, path),
        (&Method::GET | &Method::HEAD | &Method::OPTIONS, _)
            | (&Method::PUT, "/api/account" | "/api/account/ui-language")
            | (
                &Method::POST,
                "/api/account/password-check"
                    | "/api/account/sessions/revoke"
                    | "/api/system/onboarding/dismiss"
            )
    )
}

pub(super) fn admin_token(headers: &HeaderMap) -> Result<String, ApiError> {
    session_token(headers)
        .map(str::to_owned)
        .ok_or(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "administrator session required",
        ))
}

pub(super) struct Sessions {
    pub(super) accounts: Arc<AccountManager>,
    pub(super) cookies: SessionCookies,
    workers: Arc<Semaphore>,
}

impl Sessions {
    pub(super) async fn work<T: Send + 'static>(
        &self,
        operation: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, ApiError> {
        let permit = self.workers.clone().try_acquire_owned().map_err(|_| BUSY)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            operation()
        })
        .await
        .map_err(|_| ApiError::internal())
    }

    async fn login(
        self: Arc<Self>,
        peer: Option<Extension<ConnectInfo<SocketAddr>>>,
        request: LoginRequest,
    ) -> Result<Response, ApiError> {
        let Extension(ConnectInfo(peer)) = peer.ok_or_else(ApiError::internal)?;
        let accounts = self.accounts.clone();
        let outcome = self
            .work(move || {
                accounts
                    .login_with_totp_from(
                        peer.ip(),
                        &request.username,
                        &request.password,
                        request.code.as_deref(),
                    )
                    .map(|session| (session, request.username))
            })
            .await?;
        match outcome {
            Ok((session, username)) => self.cookies.response(session, username),
            Err(error) => Ok(login_error(error)),
        }
    }

    async fn logout(self: Arc<Self>, headers: HeaderMap) -> Result<Response, ApiError> {
        if let Some(token) = session_token(&headers)
            && self.accounts.identify(token).is_some()
        {
            let accounts = self.accounts.clone();
            let token = token.to_owned();
            self.work(move || accounts.revoke(&token))
                .await?
                .map_err(|_| ApiError::internal())?;
        }
        Ok(self.cookies.clear())
    }

    async fn revoke(self: Arc<Self>) -> Result<Response, ApiError> {
        let accounts = self.accounts.clone();
        self.work(move || accounts.revoke_all())
            .await?
            .map_err(|_| ApiError::internal())?;
        Ok(self.cookies.clear())
    }

    async fn change(self: Arc<Self>, request: ChangePassword) -> Result<Response, ApiError> {
        let accounts = self.accounts.clone();
        self.work(move || {
            accounts.change_credentials(
                &request.old_password,
                &request.username,
                &request.new_password,
            )
        })
        .await?
        .map_err(credential_error)?;
        Ok(self.cookies.clear())
    }

    async fn prepare_totp(
        self: Arc<Self>,
        headers: HeaderMap,
        identity: Identity,
    ) -> Result<Json<TotpSetup>, ApiError> {
        let accounts = self.accounts.clone();
        let token = session_token(&headers)
            .ok_or(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "administrator session required",
            ))?
            .to_owned();
        let secret = self
            .work(move || accounts.prepare_totp(&token))
            .await?
            .map_err(credential_error)?;
        let mut url = url::Url::parse("otpauth://totp").expect("static otpauth URL");
        url.path_segments_mut()
            .expect("hierarchical otpauth URL")
            .push(&format!("FerrumGate:{}", identity.username));
        url.query_pairs_mut()
            .append_pair("secret", &secret)
            .append_pair("issuer", "FerrumGate")
            .append_pair("digits", "6")
            .append_pair("period", "30");
        Ok(Json(TotpSetup {
            secret,
            url: url.into(),
        }))
    }

    async fn set_totp(
        self: Arc<Self>,
        headers: HeaderMap,
        request: TotpRequest,
        enabled: bool,
    ) -> Result<Response, ApiError> {
        let accounts = self.accounts.clone();
        let token = session_token(&headers)
            .ok_or(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "administrator session required",
            ))?
            .to_owned();
        self.work(move || accounts.set_totp(&token, &request.password, &request.code, enabled))
            .await?
            .map_err(credential_error)?;
        Ok(self.cookies.clear())
    }
}

pub(super) fn mount(
    router: ApiRouter,
    accounts: Arc<AccountManager>,
    cookies: SessionCookies,
    disabled: Vec<&'static str>,
    absent: Vec<&'static str>,
    passkeys: Option<Passkeys>,
) -> ApiRouter {
    let state = Arc::new(Sessions {
        accounts,
        cookies,
        workers: Arc::new(Semaphore::new(4)),
    });
    let login = state.clone();
    let logout = state.clone();
    let revoke = state.clone();
    let change = state.clone();
    let totp_status = state.clone();
    let totp_setup = state.clone();
    let totp_enable = state.clone();
    let totp_disable = state.clone();
    let disabled = Arc::new(disabled);
    let absent = Arc::new(absent);
    let router =
        router
            .public_route(
                Method::POST,
                "/api/login",
                "Sign in with an administrator password",
                move |peer, ApiJson(request)| login.login(peer, request),
            )
            .public_route(
                Method::POST,
                "/api/logout",
                "Sign out of the current session",
                move |headers| logout.logout(headers),
            )
            .modeled_route(
                Method::GET,
                "/api/session",
                "Get the current identity",
                RouteModels::default().response::<SessionView>(),
                move |identity: Option<Extension<Identity>>| async move {
                    let identity = identity.map(|Extension(identity)| identity);
                    let password_issue = identity.as_ref().map_or("", Identity::password_issue);
                    let role = identity
                        .as_ref()
                        .map_or(Role::Admin, |identity| identity.role);
                    Json(SessionView {
                        username: identity.map_or_else(String::new, |identity| identity.username),
                        role: role.as_str(),
                        default_password: password_issue == "default",
                        password_issue,
                        disabled_modules: disabled,
                        absent_modules: absent,
                    })
                },
            )
            .modeled_route(
                Method::POST,
                "/api/account/sessions/revoke",
                "Sign out of every session",
                RouteModels::default().response::<OkResponse>(),
                move || revoke.revoke(),
            )
            .modeled_route(
                Method::PUT,
                "/api/account",
                "Change administrator credentials",
                RouteModels::default()
                    .request::<ChangePassword>()
                    .response::<OkResponse>(),
                move |ApiJson(request)| change.change(request),
            )
            .modeled_route(
                Method::POST,
                "/api/account/password-check",
                "Check a proposed password",
                RouteModels::default()
                    .request::<PasswordCheck>()
                    .response::<PasswordFeedback>(),
                |Extension(identity): Extension<Identity>,
                 ApiJson(request): ApiJson<PasswordCheck>| async move {
                    let username = request
                        .username
                        .as_deref()
                        .filter(|username| !username.trim().is_empty())
                        .unwrap_or(&identity.username);
                    let code = check_password_strength(username, &request.password)
                        .err()
                        .map(PasswordIssue::code);
                    Json(PasswordFeedback {
                        ok: code.is_none(),
                        code,
                    })
                },
            )
            .modeled_route(
                Method::GET,
                "/api/account/totp",
                "Get two-step verification status",
                RouteModels::default().response::<TotpStatus>(),
                move || async move {
                    Json(TotpStatus {
                        enabled: totp_status.accounts.totp_enabled(),
                    })
                },
            )
            .modeled_route(
                Method::POST,
                "/api/account/totp/setup",
                "Prepare two-step verification",
                RouteModels::default().response::<TotpSetup>(),
                move |headers, Extension(identity)| totp_setup.prepare_totp(headers, identity),
            )
            .modeled_route(
                Method::POST,
                "/api/account/totp/enable",
                "Enable two-step verification",
                RouteModels::default()
                    .request::<TotpRequest>()
                    .response::<OkResponse>(),
                move |headers, ApiJson(request)| totp_enable.set_totp(headers, request, true),
            )
            .modeled_route(
                Method::POST,
                "/api/account/totp/disable",
                "Disable two-step verification",
                RouteModels::default()
                    .request::<TotpRequest>()
                    .response::<OkResponse>(),
                move |headers, ApiJson(request)| totp_disable.set_totp(headers, request, false),
            );
    let router = crate::readonly_routes::mount(router, state.clone());
    match passkeys {
        Some(passkeys) => crate::passkey_routes::mount(router, state, passkeys),
        None => router,
    }
}

pub(super) fn credential_error(error: anyhow::Error) -> ApiError {
    if let Some(issue) = error.downcast_ref::<PasswordIssue>() {
        ApiError::new(StatusCode::BAD_REQUEST, issue.code())
    } else if let Some(rejection) = error.downcast_ref::<CredentialChangeRejected>() {
        ApiError::new(StatusCode::BAD_REQUEST, rejection.0)
    } else if error.is::<ReadonlyUserNotFound>() {
        ApiError::new(StatusCode::NOT_FOUND, "read-only account was not found")
    } else if matches!(error.downcast_ref::<LoginError>(), Some(LoginError::Busy)) {
        BUSY
    } else {
        ApiError::internal()
    }
}

pub(super) fn login_error(error: LoginError) -> Response {
    match error {
        LoginError::TotpRequired => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error":"two-step verification code required", "totpRequired":true})),
        ).into_response(),
        LoginError::InvalidCredentials => ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid administrator credentials",
        )
        .into_response(),
        LoginError::Locked(delay) => {
            let mut response = ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "login source is temporarily locked",
            )
            .into_response();
            let seconds = delay.as_secs() + u64::from(delay.subsec_nanos() != 0);
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(seconds));
            response
        }
        LoginError::Flood => ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "unfamiliar login source is temporarily limited",
        )
        .into_response(),
        LoginError::Busy => BUSY.into_response(),
        LoginError::Internal(_) => ApiError::internal().into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    username: String,
    password: String,
    code: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct TotpRequest {
    password: String,
    code: String,
}

#[derive(Serialize, JsonSchema)]
struct TotpStatus {
    enabled: bool,
}

#[derive(Serialize, JsonSchema)]
struct TotpSetup {
    secret: String,
    url: String,
}

#[derive(Serialize)]
struct LoginSuccess {
    username: String,
    expires: String,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct SessionView {
    username: String,
    role: &'static str,
    disabled_modules: Arc<Vec<&'static str>>,
    absent_modules: Arc<Vec<&'static str>>,
    default_password: bool,
    password_issue: &'static str,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChangePassword {
    username: String,
    old_password: String,
    new_password: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PasswordCheck {
    username: Option<String>,
    password: String,
}

#[derive(Serialize, JsonSchema)]
struct PasswordFeedback {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'static str>,
}
