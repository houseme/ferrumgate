use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use arc_swap::ArcSwapOption;
use axum::{
    Json,
    extract::{ConnectInfo, Extension, Query},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use fg_auth::{
    AccountManager,
    third_login::{ThirdLogin, ThirdLoginConfig},
};
use fg_core::settings::ThirdLoginSettings;
use serde::Deserialize;
use tokio::sync::watch;
use url::Url;

use crate::{
    ApiError, ApiRouter,
    assets::normalized_prefix,
    login::{SessionCookies, cookie, login_error},
};

const NONCE: &str = "gately_login_nonce";
const DISABLED: ApiError =
    ApiError::new(StatusCode::UNAUTHORIZED, "third-party login is unavailable");

pub struct ManagedThirdLogin {
    settings: watch::Receiver<Arc<ThirdLoginSettings>>,
    accounts: Arc<AccountManager>,
    prefix: String,
    active: ArcSwapOption<Routes>,
}

impl ManagedThirdLogin {
    pub fn new(
        settings: watch::Receiver<Arc<ThirdLoginSettings>>,
        accounts: Arc<AccountManager>,
        prefix: &str,
    ) -> Result<Self> {
        Ok(Self {
            settings,
            accounts,
            prefix: normalized_prefix(prefix)?.into(),
            active: ArcSwapOption::empty(),
        })
    }

    fn current(&self) -> Option<Arc<Routes>> {
        self.active.load_full().filter(|routes| {
            routes
                .settings
                .as_ref()
                .is_some_and(|prepared| Arc::ptr_eq(prepared, &self.settings.borrow()))
        })
    }

    pub async fn run(&self) {
        let mut updates = self.settings.clone();
        loop {
            let config = updates.borrow_and_update().clone();
            if !config.enable {
                self.active.store(None);
            } else {
                let prepare = async {
                    let mut base = Url::parse(&config.callback_base)?;
                    base.set_path(&format!("{}/", self.prefix));
                    let service = ThirdLogin::new(
                        self.accounts.clone(),
                        base,
                        ThirdLoginConfig::from_settings(&config)?,
                    )
                    .await?;
                    Routes::new(Arc::new(service), Some(config))
                };
                tokio::select! {
                    biased;
                    changed = updates.changed() => {
                        if changed.is_err() { return; }
                        continue;
                    }
                    result = tokio::time::timeout(Duration::from_secs(30), prepare) => match result {
                        Ok(Ok(routes)) => self.active.store(Some(Arc::new(routes))),
                        _ => {
                            self.active.store(None);
                            tracing::warn!(target: "fg_core::auth", "third-party login configuration could not be activated");
                            tokio::select! {
                                changed = updates.changed() => if changed.is_err() { return; },
                                _ = tokio::time::sleep(Duration::from_secs(30)) => {},
                            }
                            continue;
                        }
                    }
                }
            }
            if updates.changed().await.is_err() {
                return;
            }
        }
    }
}

impl ApiRouter {
    pub fn with_third_login(self, service: Arc<ThirdLogin>) -> Result<Self> {
        let routes = Arc::new(Routes::new(service.clone(), None)?);
        Ok(self.mount_third_login(
            move || Some(routes.clone()),
            move || service.password_login_enabled(),
        ))
    }

    pub fn with_managed_third_login(self, service: Arc<ManagedThirdLogin>) -> Self {
        let accounts = service.accounts.clone();
        self.mount_third_login(
            move || service.current(),
            move || accounts.password_login_enabled(),
        )
    }

    fn mount_third_login(
        self,
        current: impl Fn() -> Option<Arc<Routes>> + Clone + Send + Sync + 'static,
        password_login_enabled: impl Fn() -> bool + Clone + Send + Sync + 'static,
    ) -> Self {
        let view = current.clone();
        let start = current.clone();
        self.public_route(
            Method::GET,
            "/api/login/providers",
            "List available identity providers",
            move || async move {
                Json(serde_json::json!({
                    "providers":view().map_or_else(Vec::new, |routes| routes.service.providers()),
                    "passwordLogin":password_login_enabled(),
                }))
            },
        )
        .public_route(
            Method::GET,
            "/api/login/oauth/start",
            "Start third-party login",
            move |headers, peer, Query(query): Query<Start>| async move {
                start().ok_or(DISABLED)?.begin(headers, peer, query)
            },
        )
        .public_route(
            Method::GET,
            "/api/login/oauth/callback",
            "Complete third-party login",
            move |headers, peer, Query(query): Query<Callback>| async move {
                let routes = current().ok_or(DISABLED)?;
                let is_current = || current().is_some_and(|active| Arc::ptr_eq(&active, &routes));
                let result = routes.finish(headers, peer, query, &is_current).await;
                if !is_current() {
                    return Err(DISABLED);
                }
                result
            },
        )
    }
}

struct Routes {
    service: Arc<ThirdLogin>,
    settings: Option<Arc<ThirdLoginSettings>>,
    cookies: SessionCookies,
    attributes: String,
}

type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

impl Routes {
    fn new(service: Arc<ThirdLogin>, settings: Option<Arc<ThirdLoginSettings>>) -> Result<Self> {
        let prefix = normalized_prefix(service.base().path())?;
        let secure = service.base().scheme() == "https";
        let cookies = SessionCookies::new(prefix, secure)?;
        let attributes = format!(
            "; Path={prefix}/api/login/oauth; HttpOnly; SameSite=Lax{}",
            if secure { "; Secure" } else { "" }
        );
        Ok(Self {
            service,
            settings,
            cookies,
            attributes,
        })
    }

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
        &self,
        headers: HeaderMap,
        peer: Peer,
        query: Callback,
        is_current: impl FnOnce() -> bool,
    ) -> Result<Response, ApiError> {
        let address = self.address(&headers, peer)?;
        let browser = cookie(&headers, NONCE).ok_or(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "third-party login is invalid",
        ))?;
        let session = match self
            .service
            .finish_while(
                address,
                &query.state,
                browser,
                query.code.as_deref().unwrap_or(""),
                is_current,
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
