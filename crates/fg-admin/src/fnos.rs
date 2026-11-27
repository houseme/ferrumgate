//! fnOS 单点登录（可选切片）：飞牛网关把管理请求转发到本服务的 Unix Socket，
//! 并把已认证的飞牛身份写入可信请求头。本模块把这些身份换成管理员会话——
//! 仅对经网关 Socket 进入的请求生效；TCP 管理端口不受影响。

use std::sync::Arc;

use axum::{
    Json,
    extract::Extension,
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use fg_auth::AccountManager;
use serde::Serialize;

use crate::{
    ApiError, ApiRouter,
    gateway::ViaGateway,
    login::{SessionCookies, session_token},
};

/// 所有前置条件不满足时的统一拒绝：措辞刻意不区分「未开启自动登录」与
/// 「不是管理员」，不向调用方泄露账号状态。
const FORBIDDEN: ApiError = ApiError::new(
    StatusCode::FORBIDDEN,
    "未开启飞牛登录态自动登录，或当前飞牛账号不是管理员",
);

/// 飞牛网关注入的身份请求头（名称沿用上游）。这些头**仅当请求从网关 Socket
/// 进入时才可信**——还原中间件只挂在 Socket 入口上，TCP 监听端口上的同名
/// 请求头一律视为伪造（由下面的 `ViaGateway` 扩展检查排除）。
const TRIM_ISADMIN: &str = "X-Trim-Isadmin";
const TRIM_USERNAME: &str = "X-Trim-Username";

struct FnosLogin {
    accounts: Arc<AccountManager>,
    cookies: SessionCookies,
    gateway_sso: Arc<dyn Fn() -> bool + Send + Sync>,
}

/// 成功响应体，与密码登录（`LoginSuccess`）形状一致。已有会话被保留时
/// `expires` 为空字符串——没有签发新会话，因此不报告新的过期时间。
#[derive(Serialize)]
struct FnosLoginSuccess {
    username: String,
    expires: String,
}

impl FnosLogin {
    async fn login(
        self: Arc<Self>,
        gateway: Option<Extension<ViaGateway>>,
        headers: HeaderMap,
    ) -> Result<Response, ApiError> {
        // 只有经网关 Unix Socket 进入的请求带有该扩展（还原中间件在 Socket
        // 入口注入）；TCP 监听端口永远不会插入，直连一律拒绝。
        let Some(Extension(_)) = gateway else {
            return Err(FORBIDDEN);
        };
        if !(self.gateway_sso)() {
            return Err(FORBIDDEN);
        }
        // X-Trim-* 请求头只在请求穿过网关 Socket 时可信（还原中间件挂载在
        // Socket 入口）；其他路径上它们可被随意伪造，已由上面的扩展检查排除。
        let is_admin = headers
            .get(TRIM_ISADMIN)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"));
        let username = headers
            .get(TRIM_USERNAME)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|username| !username.is_empty());
        let (true, Some(username)) = (is_admin, username) else {
            return Err(FORBIDDEN);
        };
        // 已有任何有效会话（含只读登录）时原样保留：只报告当前身份，
        // 不签发新 Cookie，也不改写已有登录。
        if let Some(identity) =
            session_token(&headers).and_then(|token| self.accounts.identify(token))
        {
            return Ok(Json(FnosLoginSuccess {
                username: identity.username,
                expires: String::new(),
            })
            .into_response());
        }
        // 未知身份与签发内部失败统一按上面的文案拒绝，不泄露账号是否存在。
        let session = self
            .accounts
            .login_via_trusted_gateway(username)
            .map_err(|_| FORBIDDEN)?;
        // 审计备注：结构化日志带上操作者与来源，审计/事件集成可据此订阅
        // 网关登录（AuditLog/EventBus 的接入留给后续接线）。
        tracing::info!(
            target: "fg_core::auth",
            operator = %format!("fnOS:{username}"),
            source = "统一网关",
            "fnOS 网关身份登录"
        );
        self.cookies.response(session, username.to_owned())
    }
}

/// 把 `POST /api/login/fnos` 挂载为公开的引导路由（已列入 bootstrap 白名单）。
/// `cookies` 复用账号路由已构建好的实例（相同前缀与 Secure 标志）；
/// `gateway_sso` 返回是否开启飞牛登录态自动登录（通常读自设置快照）。
pub fn mount_fnos_login(
    router: ApiRouter,
    accounts: Arc<AccountManager>,
    cookies: SessionCookies,
    gateway_sso: Arc<dyn Fn() -> bool + Send + Sync>,
) -> ApiRouter {
    let state = Arc::new(FnosLogin {
        accounts,
        cookies,
        gateway_sso,
    });
    router.public_route(
        Method::POST,
        "/api/login/fnos",
        "Sign in with the fnOS gateway identity",
        move |gateway, headers| state.login(gateway, headers),
    )
}
