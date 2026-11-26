use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::Result;
use axum::{
    Json,
    extract::{ConnectInfo, Extension, Query},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use fg_auth::third_login::ThirdLogin;
use serde::Deserialize;

use crate::{
    ApiError, ApiRouter,
    assets::normalized_prefix,
    login::{SessionCookies, cookie, login_error},
};

const NONCE: &str = "gately_login_nonce";

impl ApiRouter {
    pub fn with_third_login(self, service: Arc<ThirdLogin>) -> Result<Self> {
        let prefix = normalized_prefix(service.base().path())?;
        let secure = service.base().scheme() == "https";
        let cookies = SessionCookies::new(prefix, secure)?;
        let attributes = format!(
            "; Path={prefix}/api/login/oauth; HttpOnly; SameSite=Lax{}",
            if secure { "; Secure" } else { "" }
        );
        let routes = Arc::new(Routes {
            service,
            cookies,
            attributes,
        });
        let view = routes.clone();
        let start = routes.clone();
        Ok(self
            .public_route(
                Method::GET,
                "/api/login/providers",
                "List available identity providers",
                move || async move {
                    Json(serde_json::json!({
                        "providers":view.service.providers(),
                        "passwordLogin":view.service.password_login_enabled(),
                    }))
                },
            )
            .public_route(
                Method::GET,
                "/api/login/oauth/start",
                "Start third-party login",
                move |headers, peer, Query(query): Query<Start>| async move {
                    start.begin(headers, peer, query)
                },
            )
            .public_route(
                Method::GET,
                "/api/login/oauth/callback",
                "Complete third-party login",
                move |headers, peer, Query(query): Query<Callback>| {
                    routes.finish(headers, peer, query)
                },
            ))
    }
}

struct Routes {
    service: Arc<ThirdLogin>,
    cookies: SessionCookies,
    attributes: String,
}

type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

impl Routes {
    fn begin(&self, headers: HeaderMap, peer: Peer, query: Start) -> Result<Response, ApiError> {
        let address = self.address(&headers, peer)?;
        let (target, browser) = match self.service.begin(&query.p, address) {
            Ok(result) => result,
            Err(error) => return Ok(login_error(error)),
        };
        let cookie = self.nonce_cookie(&browser, 600)?;
        Ok((
            [(header::SET_COOKIE, cookie)],
            Redirect::to(target.as_str()),
        )
            .into_response())
    }

    async fn finish(
        self: Arc<Self>,
        headers: HeaderMap,
        peer: Peer,
        query: Callback,
    ) -> Result<Response, ApiError> {
        let address = self.address(&headers, peer)?;
        let browser = cookie(&headers, NONCE).ok_or(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "third-party login is invalid",
        ))?;
        let session = match self
            .service
            .finish(
                address,
                &query.state,
                browser,
                query.code.as_deref().unwrap_or(""),
            )
            .await
        {
            Ok(session) => session,
            Err(error) => return Ok(login_error(error)),
        };
        let (session, _) = self.cookies.issue(session)?;
        let mut response = Redirect::to(self.service.base().path()).into_response();
        response.headers_mut().append(header::SET_COOKIE, session);
        response
            .headers_mut()
            .append(header::SET_COOKIE, self.nonce_cookie("", 0)?);
        Ok(response)
    }

    fn address(&self, headers: &HeaderMap, peer: Peer) -> Result<IpAddr, ApiError> {
        let mut hosts = headers.get_all(header::HOST).iter();
        let host = hosts.next().and_then(|host| host.to_str().ok());
        if hosts.next().is_some()
            || host.is_none_or(|host| !host.eq_ignore_ascii_case(self.service.base().authority()))
        {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "use the configured management origin",
            ));
        }
        let Extension(ConnectInfo(peer)) = peer.ok_or_else(ApiError::internal)?;
        Ok(peer.ip())
    }

    fn nonce_cookie(&self, value: &str, age: u16) -> Result<HeaderValue, ApiError> {
        HeaderValue::try_from(format!("{NONCE}={value}; Max-Age={age}{}", self.attributes))
            .map_err(|_| ApiError::internal())
    }
}

#[derive(Deserialize)]
struct Start {
    p: String,
}

#[derive(Deserialize)]
struct Callback {
    state: String,
    code: Option<String>,
}
