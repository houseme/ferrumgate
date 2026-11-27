//! Unified-gateway access (optional slice): fnOS's gateway forwards
//! `https://<nas>/app/gately/…` to a Unix socket. Only active when
//! `--gateway-socket` is passed; the TCP management listener is unaffected.
//! This module holds the pure helpers and the small-IO layer (socket listen,
//! confirmed-origin persistence); the axum integration lands in WP-14 step 9.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use serde::{Deserialize, Serialize};

/// 自定义请求头：管理界面经网关发出的请求都带着它（页面脚本注入，名称沿用上游）。
/// 别的来源的页面要带上它必须先通过 CORS 预检，而管理接口不放行任何预检。
pub const PAGE_HEADER: &str = "X-Gately-Page";

/// 已确认页面来源的数量上限，超出时丢弃最早的。
pub const MAX_CONFIRMED_ORIGINS: usize = 16;

/// 按来源记录「拒绝跨源请求」日志的来源数上限，避免被大量伪造来源刷满日志。
pub const MAX_REJECTED_ORIGIN_LOGS: usize = 32;

/// 已确认来源保存的配置名（`gateway_origins.json`，`{"origins":[…]}`）。
const ORIGINS_CONFIG: &str = "gateway_origins";

/// 经网关登录时限流键的前缀，后接飞牛用户名。
const LOGIN_LIMIT_FNOS_PREFIX: &str = "fnOS:";

/// 校验并规范路径前缀：必须以 / 开头，去掉末尾的 /；空字符串表示不加前缀；
/// 不含 `? # " ' < >` 与空格。
pub fn normalize_prefix(raw: &str) -> anyhow::Result<String> {
    let prefix = raw.trim().trim_end_matches('/');
    if prefix.is_empty() {
        return Ok(String::new());
    }
    let rejected = prefix
        .chars()
        .any(|c| matches!(c, '?' | '#' | '"' | '\'' | '<' | '>' | ' '));
    if !prefix.starts_with('/') || rejected {
        return Err(anyhow::anyhow!("统一网关路径前缀无效: {prefix:?}"));
    }
    Ok(prefix.to_string())
}

/// 监听 Unix Socket（HTTP over UDS）。上次异常退出遗留的 Socket 文件先删除；
/// 同名文件不是 Socket 时报错、不覆盖；权限 0660——只允许属主与同组访问
/// （fnOS 的网关进程以 root 运行）。`UnixListener::bind` 会创建 Socket 文件，
/// 因此 bind 之后再收紧一次权限才是生效的那次。
pub async fn listen_unix(path: &Path) -> std::io::Result<tokio::net::UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "同名文件不是 Socket",
                ));
            }
            std::fs::remove_file(path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    // bind 之前尽力收紧一次（文件此刻通常不存在，失败可忽略）
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660));
    let listener = tokio::net::UnixListener::bind(path)?;
    // bind 按进程 umask 创建文件，这里才是真正生效的权限设置
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

/// 按转发头还原客户端地址：`X-Real-IP` 优先，否则取 `X-Forwarded-For` 最右一项；
/// 从右向左跳过回环与未指定地址（网关自身会以 127.0.0.1 出现），解析失败同样跳过。
/// 端口记 0（转发头里只有地址没有端口）。地址只用于日志、审计与登录限流，
/// 不用于访问控制——直连网关时可以由客户端随意填写。
pub fn gateway_client_addr(real_ip: Option<&str>, forwarded_for: &[&str]) -> Option<SocketAddr> {
    let mut candidates: Vec<&str> = Vec::with_capacity(2 + forwarded_for.len());
    if let Some(real) = real_ip {
        candidates.push(real.trim());
    }
    // 多个 X-Forwarded-For 头从后往前，每个头内自右向左
    for header in forwarded_for.iter().rev() {
        for part in header.rsplit(',') {
            candidates.push(part.trim());
        }
    }
    for candidate in candidates {
        if candidate.is_empty() {
            continue;
        }
        let ip: IpAddr = match candidate.trim_matches(|c| c == '[' || c == ']').parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        // 还原 IPv4 映射的 IPv6（::ffff:a.b.c.d），与上游 ip.Unmap() 一致
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::from).unwrap_or(ip),
            v4 => v4,
        };
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        return Some(SocketAddr::new(ip, 0));
    }
    None
}

/// 把 `Origin` 请求头规范成小写的 `scheme://host[:port]`；只认 http / https 来源，
/// 其余（解析失败、无 host、其他 scheme）返回 `None`。默认端口 80/443 去掉，
/// 使得 `http://nas.local` 与 `http://nas.local:80` 视为同一来源。
pub fn origin_key(origin: &str) -> Option<String> {
    split_origin(origin).map(|(key, _)| key)
}

/// 拆出 `(key, host)`：key 用于确认与持久化（小写、去默认端口），
/// host 是 `host[:port]`，确认后用它替换网关转发来的不带端口的 `Host`。
fn split_origin(origin: &str) -> Option<(String, String)> {
    let url = url::Url::parse(origin.trim()).ok()?;
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let host = url.host_str().filter(|h| !h.is_empty())?;
    let port = match url.port() {
        Some(p) if (scheme == "http" && p == 80) || (scheme == "https" && p == 443) => None,
        other => other,
    };
    let key = match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    };
    let host = match port {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    Some((key, host))
}

/// 经网关访问时已确认的页面来源（`scheme://host[:port]`，小写），保存在配置目录，
/// 重启后仍然有效（已打开的终端页面重连时不必先做一次别的操作）。
#[derive(Debug, Default, Clone)]
pub struct ConfirmedOrigins {
    pub list: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GatewayOriginsFile {
    #[serde(default)]
    origins: Vec<String>,
}

impl ConfirmedOrigins {
    /// 从配置目录读取；文件缺失或损坏时得到空列表。超出上限的旧条目丢弃
    /// （保留最后 [`MAX_CONFIRMED_ORIGINS`] 个），无效条目跳过。
    pub fn load(store: &fg_config::ConfigStore) -> Self {
        let mut list: Vec<String> = Vec::new();
        if let Ok(fg_config::Loaded::Found(file)) = store.load::<GatewayOriginsFile>(ORIGINS_CONFIG)
        {
            for origin in file.origins {
                if let Some(key) = origin_key(&origin)
                    && !list.contains(&key)
                {
                    {
                        list.push(key);
                    }
                }
            }
            if list.len() > MAX_CONFIRMED_ORIGINS {
                list.drain(0..list.len() - MAX_CONFIRMED_ORIGINS);
            }
        }
        Self { list }
    }

    /// 把来源记为已确认：先规范成 key，重复的直接返回（保持原有位置），
    /// 否则追加；超出上限丢弃最早的。
    pub fn confirm(&mut self, origin: String) {
        let Some(key) = origin_key(&origin) else {
            return;
        };
        if self.list.iter().any(|o| o == &key) {
            return;
        }
        self.list.push(key);
        if self.list.len() > MAX_CONFIRMED_ORIGINS {
            self.list.drain(0..self.list.len() - MAX_CONFIRMED_ORIGINS);
        }
    }

    /// 保存到配置目录（`gateway_origins.json`）。
    pub fn save(&self, store: &fg_config::ConfigStore) -> anyhow::Result<()> {
        store
            .save(
                ORIGINS_CONFIG,
                &GatewayOriginsFile {
                    origins: self.list.clone(),
                },
            )
            .context("保存已确认的网关页面来源")?;
        Ok(())
    }

    /// 判断来源是否已确认。
    pub fn contains(&self, key: &str) -> bool {
        self.list.iter().any(|o| o == key)
    }
}

/// 页面来源检查结果。`Trusted` 携带确认过的来源的 `host[:port]`，
/// 调用方用它替换网关转发来的不带端口的 `Host`（跨源校验与 Passkey 需要它）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginCheck {
    Trusted(String),
    UntrustedPresent,
    NoOrigin,
}

/// 确认网关转发来的请求的 `Origin` 是不是管理界面自己所在的页面来源。
///
/// 经网关访问时不知道浏览器地址栏里的端口，不能拿 `Origin` 与 `Host` 逐字比较
/// （网关转发时 `Host` 不带端口，而浏览器的 `Origin` 带端口），改为确认来源：
///
/// 1. 浏览器写入的 `Sec-Fetch-Site: same-origin`（页面脚本无法伪造）**且带着管理员会话**；
/// 2. 自定义请求头 [`PAGE_HEADER`]**且带着管理员会话**；
/// 3. 之前确认过的来源（WebSocket 握手无法加请求头）。
///
/// 只认管理员：只读账号的持有者可以不经浏览器自己构造请求头，不能让他替别的
/// 端口「确认」来源；凭飞牛登录态的登录同样不能据此确认（`admin_role` 为 false
/// 时不走第 1、2 种）。浏览器标明 `same-site` / `cross-site` 时直接不信任——
/// 包括同主机的其他端口，此时不再看确认列表与 [`PAGE_HEADER`]。
///
/// 注意（保持本函数纯净）：当 `Sec-Fetch-Site` 缺失且来源未确认时，
/// `/api/logout`、`/api/login`、`/api/login/*` 放行（登录与退出不依赖已有会话，
/// 放行后由登录成功确认来源）——该例外需要请求路径，由调用方应用。
/// 另外返回 `Trusted` 且 `admin_role` 为 true 时（第 1、2 种依据），调用方应把
/// 来源记入 [`ConfirmedOrigins`] 并保存（[`ConfirmedOrigins::confirm`] 会去重）。
pub fn origin_check(
    sec_fetch_site: Option<&str>,
    page_header: Option<&str>,
    origin: Option<&str>,
    confirmed: &ConfirmedOrigins,
    admin_role: bool,
) -> OriginCheck {
    let Some(origin) = origin.map(str::trim).filter(|o| !o.is_empty()) else {
        return OriginCheck::NoOrigin;
    };
    let Some((key, host)) = split_origin(origin) else {
        // 带 Origin 但不是合法的 http/https 来源：按未确认处理
        return OriginCheck::UntrustedPresent;
    };
    match sec_fetch_site.map(str::trim).map(str::to_ascii_lowercase) {
        Some(site) if site == "same-origin" && admin_role => return OriginCheck::Trusted(host),
        Some(site) if site == "same-site" || site == "cross-site" => {
            return OriginCheck::UntrustedPresent;
        }
        _ => {}
    }
    if confirmed.contains(&key) {
        return OriginCheck::Trusted(host);
    }
    let page_present = page_header.map(str::trim).is_some_and(|p| !p.is_empty());
    if page_present && admin_role {
        return OriginCheck::Trusted(host);
    }
    OriginCheck::UntrustedPresent
}

/// 判断请求是否需要确认页面来源：修改状态的请求与 WebSocket 握手。
/// 其余 GET 请求即使来自别的页面，浏览器也不会把响应交给它（没有跨源许可）。
/// 登录/退出接口的放行例外由调用方结合路径应用（见 [`origin_check`]）。
pub fn needs_origin_guard(method: &Method, has_websocket_upgrade: bool) -> bool {
    match *method {
        Method::GET | Method::HEAD | Method::OPTIONS => has_websocket_upgrade,
        _ => true,
    }
}

/// 给 Set-Cookie 中的 Path 属性补上前缀：`Path=/` 变为 `Path=<前缀>`，
/// `Path=/x` 变为 `Path=<前缀>/x`（大小写不识别）；其余属性不变；
/// 没有 Path 属性时原样返回，不追加。
pub fn prefix_cookie_path(set_cookie: &str, prefix: &str) -> String {
    let mut attrs: Vec<String> = set_cookie.split(';').map(str::to_string).collect();
    for attr in attrs.iter_mut().skip(1) {
        // 第一段是 Cookie 自身的名称与值，不是属性
        let (name, value) = match attr.trim().split_once('=') {
            Some(parts) => parts,
            None => continue,
        };
        if !name.eq_ignore_ascii_case("Path") || !value.starts_with('/') {
            continue;
        }
        let value = if value == "/" {
            prefix.to_string()
        } else {
            format!("{prefix}{value}")
        };
        *attr = format!(" Path={value}");
    }
    attrs.join(";")
}

/// 把 index.html 中构建产物生成的相对资源路径（`="./…`）改写为以前缀开头的
/// 绝对路径。前缀为空时得到 `="/…"`，与直接访问时的页面完全一致。
pub fn absolutize_assets(index: &str, prefix: &str) -> String {
    index.replace("=\"./", &format!("=\"{prefix}/"))
}

/// 在 index.html 的 `<head>` 后（大小写不识别，只处理第一处）插入
/// `<meta name="gately-base" content="<前缀>">`，值做 HTML 转义；
/// 前端据此给接口请求、WebSocket、下载链接与新窗口补前缀。
/// 没有 `<head>` 时原样返回。
pub fn inject_base(index: &str, prefix: &str) -> String {
    let escaped = prefix
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let meta = format!("<meta name=\"gately-base\" content=\"{escaped}\">");
    let needle = "<head>";
    let Some(position) = index.to_ascii_lowercase().find(needle) else {
        return index.to_string();
    };
    let after = position + needle.len();
    let mut out = String::with_capacity(index.len() + meta.len());
    out.push_str(&index[..after]);
    out.push_str(&meta);
    out.push_str(&index[after..]);
    out
}

/// 登录限流的来源键，以及客户端地址 `ip` 是否可信。
/// 经网关访问时客户端地址不可信——浏览器直连网关时为空（所有人落进同一个
/// 限流桶），前面有反向代理时取自 `X-Real-IP`（可以由客户端随意填写）；网关
/// 转发的请求都带有飞牛用户名，因此改按飞牛用户限流：`fnOS:<用户名>`，一个
/// 飞牛用户只能耗尽自己的额度。地址不可信时登录失败事件不带地址，入侵防护
/// 不会据此封禁一个可以伪造的地址。
pub fn login_limit_source(
    via_gateway: bool,
    trim_username: Option<&str>,
    ip: IpAddr,
) -> (String, bool) {
    match via_gateway {
        true => (
            format!(
                "{LOGIN_LIMIT_FNOS_PREFIX}{}",
                trim_username.unwrap_or_default()
            ),
            false,
        ),
        false => (ip.to_string(), true),
    }
}

/// 经网关访问的标记请求扩展：由 [`restore`] 写入，登录限流等据此改按
/// 飞牛用户限流（见 [`login_limit_source`]），不再信任对端地址。
#[derive(Clone, Copy, Debug)]
pub struct ViaGateway;

/// index.html 缓冲改写的字节数上限；只对首页路径生效，正常构建产物远小于此。
const MAX_HTML_BUFFER_BYTES: usize = 16 * 1024 * 1024;

/// 是否已记录过第一个经网关的请求（每个进程只记一次）。
static FIRST_GATEWAY_REQUEST_LOGGED: AtomicBool = AtomicBool::new(false);

/// 已记录过「拒绝跨源请求」的来源（每个来源只记一次，避免刷日志）。
static REJECTED_ORIGINS_LOGGED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// 统一网关中间件的共享状态：已确认来源（含持久化）与账号管理器
/// （后者由网关内的飞牛登录路由使用，与来源检查共享一套状态）。
#[derive(Clone)]
pub struct OriginGuardState {
    pub confirmed: Arc<Mutex<ConfirmedOrigins>>,
    pub store: Arc<fg_config::ConfigStore>,
    pub accounts: Arc<fg_auth::AccountManager>,
}

/// 统一网关入口中间件（最外层）。做三件事：
///
/// 1. 标记 [`ViaGateway`]，供登录限流等下游识别网关流量；
/// 2. 依 `X-Real-IP` / `X-Forwarded-For` 还原客户端地址（读头在删除之前），
///    以 [`ConnectInfo`] 扩展**替换**原有值；随后删掉这两个转发头，下游的
///    代理信任解析就不会再处理它们。还原不出地址时不插（网关侧的登录限流
///    对无地址客户端有自己的处理）；第一个请求另记一条 info 日志（不含 Cookie）；
/// 3. 路径前缀：`path == prefix` → 308 重定向到 `prefix + "/"`（保留 query）；
///    `path` 以 `prefix + "/"` 开头 → 剥掉前缀；已不带前缀的路径原样放行
///    （fnOS 的网关侧有时会先剥掉前缀再转发）。
pub async fn restore(
    State(prefix): State<Arc<String>>,
    mut request: Request,
    next: Next,
) -> Response {
    request.extensions_mut().insert(ViaGateway);
    log_first_gateway_request(&request);

    // 先读后删：还原地址只认这两个头，删除后请求里不再有任何转发头
    let real_ip: Option<String> = request
        .headers()
        .get_all("x-real-ip")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .next()
        .map(str::to_owned);
    let forwarded_for: Vec<String> = request
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    let references = forwarded_for.iter().map(String::as_str).collect::<Vec<_>>();
    let resolved = gateway_client_addr(real_ip.as_deref(), &references);
    request.headers_mut().remove("x-real-ip");
    request.headers_mut().remove("x-forwarded-for");
    if let Some(addr) = resolved {
        request.extensions_mut().insert(ConnectInfo(addr));
    }

    let path = request.uri().path().to_owned();
    if !prefix.is_empty() {
        if path == prefix.as_str() {
            // 无尾斜杠的裸前缀 → 补上尾斜杠，query 原样保留
            let target = match request.uri().query() {
                Some(query) => format!("{}/?{query}", prefix),
                None => format!("{prefix}/"),
            };
            return Redirect::permanent(&target).into_response();
        }
        let with_slash = format!("{prefix}/");
        if let Some(rest) = path.strip_prefix(with_slash.as_str()) {
            let path_and_query = match request.uri().query() {
                Some(query) => format!("/{rest}?{query}"),
                None => format!("/{rest}"),
            };
            if let Ok(uri) = path_and_query.parse::<Uri>() {
                *request.uri_mut() = uri;
            }
        }
        // 其余路径：网关已经剥掉前缀（或本来就不带前缀），原样放行
    }
    next.run(request).await
}

/// 第一个经网关的请求记一条 info 日志，方便对照网关侧配置排查转发头。
/// 只记通用头，绝不记 Cookie（内含会话凭据）。
fn log_first_gateway_request(request: &Request) {
    if FIRST_GATEWAY_REQUEST_LOGGED.swap(true, Ordering::Relaxed) {
        return;
    }
    let headers = request.headers();
    let values = |name: &str| -> String {
        headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ")
    };
    tracing::info!(
        method = %request.method(),
        path = request.uri().path(),
        host = values("host"),
        x_forwarded_proto = values("x-forwarded-proto"),
        x_forwarded_for = values("x-forwarded-for"),
        x_real_ip = values("x-real-ip"),
        user_agent = values("user-agent"),
        "统一网关收到第一个请求"
    );
}

/// 页面来源检查中间件（网关侧最内层）。依据 [`origin_check`] 的结论：
///
/// * 信任：来源此前未确认（即信任来自 same-origin / 页面请求头 + 管理员会话）
///   时记入 [`ConfirmedOrigins`] 并保存到配置目录；并用来源的 `host[:port]`
///   替换网关转发来的不带端口的 `Host`；
/// * 未确认：需要来源守卫的请求（修改状态的、WebSocket 握手）→ 403
///   「拒绝跨源请求」，同一来源只记一次日志；不需要守卫的请求（普通 GET）
///   放行；例外：`Sec-Fetch-Site` 缺失且路径是 `/api/logout`、`/api/login`、
///   `/api/login/*` 时放行（登录/退出不依赖已有会话，登录成功后再确认来源）；
/// * 无 Origin：放行。
pub async fn origin_guard(
    State(guard): State<OriginGuardState>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();
    let first_value = |name: &str| -> Option<String> {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    };
    let sec_fetch_site = first_value("sec-fetch-site");
    let page_header = first_value(PAGE_HEADER);
    let origin = first_value("origin");
    let host = first_value("host");
    let is_admin = request
        .extensions()
        .get::<fg_auth::Identity>()
        .is_some_and(|identity| identity.role == fg_auth::Role::Admin);
    let websocket_upgrade = is_websocket_upgrade(headers);

    // 只借快照给纯函数判别，锁不跨 await
    let confirmed = guard
        .confirmed
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let verdict = origin_check(
        sec_fetch_site.as_deref(),
        page_header.as_deref(),
        origin.as_deref(),
        &confirmed,
        is_admin,
    );
    let needs_guard = needs_origin_guard(request.method(), websocket_upgrade);
    let login_exception = sec_fetch_site.is_none() && is_login_path(request.uri().path());

    match verdict {
        OriginCheck::Trusted(replacement_host) => {
            // 信任来自会话/页面请求头且来源尚未确认时：确认并持久化
            // （来源已在列表里时 origin_check 也返回 Trusted，此时不再写盘）。
            if let Some(origin) = origin.as_deref()
                && let Some(key) = origin_key(origin)
            {
                let mut confirmed = guard
                    .confirmed
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if !confirmed.contains(&key) {
                    confirmed.confirm(origin.to_owned());
                    if let Err(error) = confirmed.save(&guard.store) {
                        tracing::warn!(%error, "保存已确认的网关页面来源失败");
                    }
                }
            }
            // 网关转发的 Host 不带端口：换成浏览器地址栏里的 host[:port]，
            // 跨源校验与 Passkey 等下游逻辑需要它。
            let mut request = request;
            if let Ok(value) = HeaderValue::from_str(&replacement_host) {
                request.headers_mut().insert(header::HOST, value);
            }
            next.run(request).await
        }
        OriginCheck::UntrustedPresent => {
            if needs_guard && !login_exception {
                log_rejected_origin(
                    origin.as_deref(),
                    host.as_deref(),
                    sec_fetch_site.as_deref(),
                );
                (StatusCode::FORBIDDEN, "拒绝跨源请求").into_response()
            } else {
                next.run(request).await
            }
        }
        OriginCheck::NoOrigin => next.run(request).await,
    }
}

/// WebSocket 握手判定：`from_fn` 拿不到 upgrade token，用
/// `Connection` 头含 `upgrade` token（大小写不识别、容忍逗号列表）+
/// `Upgrade` 头存在来近似。
fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let connection_upgrade = headers.get_all(header::CONNECTION).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
    });
    connection_upgrade && headers.contains_key(header::UPGRADE)
}

/// 登录/退出接口：未确认来源且 `Sec-Fetch-Site` 缺失时放行（见 [`origin_check`]）。
fn is_login_path(path: &str) -> bool {
    path == "/api/logout" || path == "/api/login" || path.starts_with("/api/login/")
}

/// 按来源记录「拒绝跨源请求」：同一来源只记一次；来源数封顶
/// [`MAX_REJECTED_ORIGIN_LOGS`]，超出后不再记录（防伪造来源刷日志）。
/// 记 Origin / Host / Sec-Fetch-Site，绝不记 Cookie。
fn log_rejected_origin(origin: Option<&str>, host: Option<&str>, sec_fetch_site: Option<&str>) {
    let key = origin.or(host).unwrap_or_default().to_owned();
    let mut logged = REJECTED_ORIGINS_LOGGED
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if logged.len() >= MAX_REJECTED_ORIGIN_LOGS && !logged.contains(&key) {
        return;
    }
    if logged.insert(key) {
        tracing::warn!(
            origin = origin.unwrap_or_default(),
            host = host.unwrap_or_default(),
            sec_fetch_site = sec_fetch_site.unwrap_or_default(),
            "拒绝跨源请求"
        );
    }
}

/// 统一网关出口中间件：给响应补路径前缀。
///
/// * `Location`：以 `/` 开头的绝对路径（协议相对地址 `//` 除外）补前缀；
/// * `Set-Cookie`：逐条过 [`prefix_cookie_path`]，`Path` 属性补前缀；
/// * `text/html` 且路径是首页（`/`、前缀或 `prefix + "/"`）时缓冲 HTML，
///   应用 [`inject_base`] 与 [`absolutize_assets`]——只缓冲首页这一处，
///   其余响应（含流式与二进制）原样透传。
pub async fn rewrite_response(
    State(prefix): State<Arc<String>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    rewrite_location_and_cookies(&mut response, &prefix);
    rewrite_index_html(&mut response, &path, &prefix).await;
    response
}

/// 首页路径：`/`，或前缀本身 / 前缀加尾斜杠（rewrite 在 restore 内外都能用）。
fn is_index_path(path: &str, prefix: &str) -> bool {
    path == "/" || (!prefix.is_empty() && (path == prefix || path == format!("{prefix}/")))
}

/// `Location` 补前缀；`Set-Cookie` 的 Path 属性补前缀。
fn rewrite_location_and_cookies(response: &mut Response, prefix: &str) {
    let locations: Vec<String> = response
        .headers()
        .get_all(header::LOCATION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    if !locations.is_empty() {
        let headers = response.headers_mut();
        headers.remove(header::LOCATION);
        for location in locations {
            let target = if location.starts_with('/') && !location.starts_with("//") {
                format!("{prefix}{location}")
            } else {
                location
            };
            if let Ok(value) = HeaderValue::from_str(&target) {
                headers.append(header::LOCATION, value);
            }
        }
    }
    let cookies: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    if !cookies.is_empty() {
        let headers = response.headers_mut();
        headers.remove(header::SET_COOKIE);
        for cookie in cookies {
            if let Ok(value) = HeaderValue::from_str(&prefix_cookie_path(&cookie, prefix)) {
                headers.append(header::SET_COOKIE, value);
            }
        }
    }
}

/// 首页 HTML 缓冲改写：注入 base meta、资源路径补前缀，更新 Content-Length。
/// 缓冲失败（超上限或流错误）时丢弃已读内容、去掉 Content-Length，记日志。
async fn rewrite_index_html(response: &mut Response, path: &str, prefix: &str) {
    let is_html = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("text/html"));
    if !is_html || !is_index_path(path, prefix) {
        return;
    }
    let body = std::mem::replace(response.body_mut(), Body::empty());
    match to_bytes(body, MAX_HTML_BUFFER_BYTES).await {
        Ok(bytes) => {
            let rewritten = absolutize_assets(
                &inject_base(&String::from_utf8_lossy(&bytes), prefix),
                prefix,
            );
            response.headers_mut().insert(
                header::CONTENT_LENGTH,
                HeaderValue::from(rewritten.len() as u64),
            );
            *response.body_mut() = Body::from(rewritten);
        }
        Err(error) => {
            tracing::warn!(%error, "缓冲网关 index 响应失败");
            response.headers_mut().remove(header::CONTENT_LENGTH);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use super::*;
    use axum::routing::get;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test ip")
    }

    #[test]
    fn gateway_prefix_cookie_path() {
        let prefix = "/app/gately";
        // Path=/ 与 Path=/x 两种情况
        assert_eq!(
            prefix_cookie_path("gately_token=abc; Path=/; HttpOnly", prefix),
            "gately_token=abc; Path=/app/gately; HttpOnly"
        );
        assert_eq!(
            prefix_cookie_path("n=1; Path=/api/login/oauth; Max-Age=600", prefix),
            "n=1; Path=/app/gately/api/login/oauth; Max-Age=600"
        );
        // 其余属性不变：没有 Path 属性不追加；属性名大小写不识别；非 / 开头的值不动
        assert_eq!(prefix_cookie_path("x=1; HttpOnly", prefix), "x=1; HttpOnly");
        assert_eq!(
            prefix_cookie_path("x=1; path=/; Secure", prefix),
            "x=1; Path=/app/gately; Secure"
        );
        assert_eq!(
            prefix_cookie_path(
                "x=1; Domain=example.com; Path=relative; SameSite=Lax",
                prefix
            ),
            "x=1; Domain=example.com; Path=relative; SameSite=Lax"
        );
        // 第一段是 Cookie 名称与值，即使它长得像属性也不处理
        assert_eq!(
            prefix_cookie_path("Path=/; Path=/", prefix),
            "Path=/; Path=/app/gately"
        );
    }

    #[test]
    fn gateway_normalize_prefix() {
        // 合法值：空 = 不加前缀；末尾的 / 去掉；两侧空白容忍
        assert_eq!(normalize_prefix("").unwrap(), "");
        assert_eq!(normalize_prefix("/").unwrap(), "");
        assert_eq!(normalize_prefix("/app/gately/").unwrap(), "/app/gately");
        assert_eq!(normalize_prefix(" /x ").unwrap(), "/x");
        // 非法值：不以 / 开头；含 ? # " ' < > 与空格
        for bad in [
            "app", "/a?b", "/a#b", "/a\"b", "/a'b", "/a<b", "/a>b", "/a b",
        ] {
            assert!(normalize_prefix(bad).is_err(), "应报错: {bad:?}");
        }
    }

    #[test]
    fn gateway_origin_key_and_check() {
        // origin_key：小写 scheme://host[:port]；只认 http/https；默认端口去掉
        assert_eq!(
            origin_key("HTTP://NAS.Local:5666").as_deref(),
            Some("http://nas.local:5666")
        );
        assert_eq!(
            origin_key("https://nas.local").as_deref(),
            Some("https://nas.local")
        );
        assert_eq!(
            origin_key("http://nas.local:80").as_deref(),
            Some("http://nas.local")
        );
        assert_eq!(
            origin_key("https://nas.local:443").as_deref(),
            Some("https://nas.local")
        );
        assert_eq!(origin_key("ftp://nas.local"), None);
        assert_eq!(origin_key("nas.local"), None);
        assert_eq!(origin_key("null"), None);

        let confirmed = ConfirmedOrigins::default();
        // same-origin + 管理员 → 信任，来源的 host[:port] 用于替换 Host
        assert_eq!(
            origin_check(
                Some(" same-origin "),
                None,
                Some("https://NAS.Local:5666"),
                &confirmed,
                true
            ),
            OriginCheck::Trusted("nas.local:5666".to_string())
        );
        // 页面请求头 + 管理员 → 信任
        assert_eq!(
            origin_check(
                None,
                Some("1"),
                Some("https://nas.local:5666"),
                &confirmed,
                true
            ),
            OriginCheck::Trusted("nas.local:5666".to_string())
        );
        // 只读会话不能确认来源：same-origin 与页面请求头都不放行
        assert_eq!(
            origin_check(
                Some("same-origin"),
                None,
                Some("https://nas.local:5666"),
                &confirmed,
                false
            ),
            OriginCheck::UntrustedPresent
        );
        assert_eq!(
            origin_check(
                None,
                Some("1"),
                Some("https://nas.local:5666"),
                &confirmed,
                false
            ),
            OriginCheck::UntrustedPresent
        );
        // 浏览器标明来自别的来源（含同主机其他端口）时，即使管理员会话 + 页面请求头也不放行
        assert_eq!(
            origin_check(
                Some("same-site"),
                Some("1"),
                Some("https://other.local:80"),
                &confirmed,
                true
            ),
            OriginCheck::UntrustedPresent
        );
        assert_eq!(
            origin_check(
                Some("cross-site"),
                Some("1"),
                Some("https://nas.local:5666"),
                &confirmed,
                true
            ),
            OriginCheck::UntrustedPresent
        );
        // 来源未确认、也没有任何佐证 → 未确认（调用方按需拒绝；登录/退出例外由调用方应用）
        assert_eq!(
            origin_check(
                None,
                None,
                Some("https://nas.local:5666"),
                &confirmed,
                false
            ),
            OriginCheck::UntrustedPresent
        );
        // 无 Origin 请求头 → NoOrigin（GET 等请求由调用方按 needs_origin_guard 放行）
        assert_eq!(
            origin_check(None, None, None, &confirmed, true),
            OriginCheck::NoOrigin
        );
        assert_eq!(
            origin_check(None, None, Some("  "), &confirmed, true),
            OriginCheck::NoOrigin
        );
        // 非 http/https 的 Origin 按未确认处理
        assert_eq!(
            origin_check(None, Some("1"), Some("ftp://nas.local"), &confirmed, true),
            OriginCheck::UntrustedPresent
        );

        // 确认过的来源在之后的请求（如无法加请求头的 WebSocket 握手）中被信任；
        // 只读会话同样受益——确认是管理员此前做出的
        let mut learned = ConfirmedOrigins::default();
        learned.confirm("https://NAS.Local:5666".to_string());
        assert_eq!(learned.list, vec!["https://nas.local:5666".to_string()]);
        assert_eq!(
            origin_check(None, None, Some("https://nas.local:5666"), &learned, false),
            OriginCheck::Trusted("nas.local:5666".to_string())
        );
        // 去重：重复确认不追加
        learned.confirm("https://nas.local:5666".to_string());
        assert_eq!(learned.list.len(), 1);
        // 上限：超出 16 个丢弃最早的
        for n in 0..(MAX_CONFIRMED_ORIGINS + 2) {
            learned.confirm(format!("https://host{n}.local"));
        }
        assert_eq!(learned.list.len(), MAX_CONFIRMED_ORIGINS);
        assert_eq!(learned.list[0], "https://host2.local");
        assert_eq!(
            learned.list.last().map(String::as_str),
            Some("https://host17.local")
        );
    }

    #[test]
    fn gateway_confirmed_origins_load_save_and_cap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = fg_config::ConfigStore::open(dir.path()).expect("store");
        // 缺失 → 默认空列表
        let loaded = ConfirmedOrigins::load(&store);
        assert!(loaded.list.is_empty());

        // 确认并保存，重新读取仍在
        let mut origins = ConfirmedOrigins::default();
        origins.confirm("https://nas.local:5666".to_string());
        origins.confirm("bogus".to_string()); // 无效来源不入列表
        origins.save(&store).expect("save");
        let loaded = ConfirmedOrigins::load(&store);
        assert_eq!(loaded.list, vec!["https://nas.local:5666".to_string()]);
        assert!(loaded.contains("https://nas.local:5666"));
        assert!(!loaded.contains("https://other.local"));

        // 文件中超出上限时保留最后 16 个
        let overflow: Vec<String> = (0..MAX_CONFIRMED_ORIGINS + 3)
            .map(|n| format!("https://old{n}.local"))
            .collect();
        let origins = ConfirmedOrigins { list: overflow };
        origins.save(&store).expect("save");
        let loaded = ConfirmedOrigins::load(&store);
        assert_eq!(loaded.list.len(), MAX_CONFIRMED_ORIGINS);
        assert_eq!(loaded.list[0], "https://old3.local");
    }

    #[test]
    fn gateway_client_ip_walks_headers() {
        // X-Real-IP 优先
        assert_eq!(
            gateway_client_addr(Some("203.0.113.7"), &["198.51.100.9"]),
            Some(SocketAddr::new(ip("203.0.113.7"), 0))
        );
        // 无 X-Real-IP 时取最后一个 X-Forwarded-For 的最右一项
        assert_eq!(
            gateway_client_addr(None, &["10.0.0.1, 127.0.0.1", "198.51.100.9, 203.0.113.5"]),
            Some(SocketAddr::new(ip("203.0.113.5"), 0))
        );
        // 最右一项是回环（网关自身）时向左走
        assert_eq!(
            gateway_client_addr(None, &["203.0.113.9, 127.0.0.1"]),
            Some(SocketAddr::new(ip("203.0.113.9"), 0))
        );
        // X-Real-IP 是回环时落到 X-Forwarded-For
        assert_eq!(
            gateway_client_addr(Some("127.0.0.1"), &["203.0.113.4"]),
            Some(SocketAddr::new(ip("203.0.113.4"), 0))
        );
        // 未指定地址跳过；IPv6 方括号剥掉；IPv4 映射的 IPv6 还原为 IPv4
        assert_eq!(
            gateway_client_addr(Some("[::ffff:203.0.113.8]"), &["::"]),
            Some(SocketAddr::new(ip("203.0.113.8"), 0))
        );
        // 解析失败跳过
        assert_eq!(
            gateway_client_addr(None, &["not-an-ip, 203.0.113.3"]),
            Some(SocketAddr::new(ip("203.0.113.3"), 0))
        );
        // 全是回环/未指定/空 → 无地址
        assert_eq!(gateway_client_addr(None, &["127.0.0.1"]), None);
        assert_eq!(gateway_client_addr(Some("0.0.0.0"), &[]), None);
        assert_eq!(gateway_client_addr(None, &[]), None);
        assert_eq!(gateway_client_addr(Some(""), &["", "127.0.0.1"]), None);
    }

    #[test]
    fn gateway_origin_guard_needs() {
        assert!(!needs_origin_guard(&Method::GET, false));
        assert!(needs_origin_guard(&Method::GET, true)); // WebSocket 握手
        assert!(needs_origin_guard(&Method::HEAD, true));
        assert!(!needs_origin_guard(&Method::OPTIONS, false));
        assert!(needs_origin_guard(&Method::POST, false));
        assert!(needs_origin_guard(&Method::PUT, false));
        assert!(needs_origin_guard(&Method::PATCH, false));
        assert!(needs_origin_guard(&Method::DELETE, false));
    }

    #[test]
    fn gateway_absolutize_and_inject_base() {
        let index =
            r#"<!doctype html><html><HEAD><script src="./x.js"></script><a href="./a/b">t</a>"#;
        // 资源路径补前缀；<HEAD> 大小写不识别；前缀值 HTML 转义
        let out = inject_base(index, "/app/gately");
        assert!(out.contains(r#"<HEAD><meta name="gately-base" content="/app/gately">"#));
        assert!(out.starts_with("<!doctype html><html><HEAD>"));
        let absolutized = absolutize_assets(index, "/app/gately");
        assert!(absolutized.contains(r#"src="/app/gately/x.js""#));
        assert!(absolutized.contains(r#"href="/app/gately/a/b""#));
        // 前缀为空时与直接访问时的页面一致
        assert!(absolutize_assets(index, "").contains(r#"src="/x.js""#));
        // 转义：& " < > 依次变为 &amp; &quot; &lt; &gt;
        let escaped = inject_base("<html><head></html>", r#"/a"b<c>&d"#);
        assert_eq!(
            escaped,
            r#"<html><head><meta name="gately-base" content="/a&quot;b&lt;c&gt;&amp;d"></html>"#
        );
        // 没有 <head> 时原样返回
        assert_eq!(inject_base("<body>x</body>", "/p"), "<body>x</body>");
    }

    #[test]
    fn gateway_login_limit_source() {
        // 经网关：按飞牛用户限流，地址不可信
        assert_eq!(
            login_limit_source(true, Some("admin"), ip("203.0.113.1")),
            ("fnOS:admin".to_string(), false)
        );
        // 无用户名（或空）→ 同一个桶
        assert_eq!(
            login_limit_source(true, None, ip("203.0.113.1")),
            ("fnOS:".to_string(), false)
        );
        assert_eq!(
            login_limit_source(true, Some(""), ip("203.0.113.1")),
            ("fnOS:".to_string(), false)
        );
        // 直连 TCP 端口：按地址限流，地址可信
        assert_eq!(
            login_limit_source(false, Some("admin"), ip("192.0.2.9")),
            ("192.0.2.9".to_string(), true)
        );
    }

    // ==== 中间件集成测试 ====
    // `Next` 没有公开构造器，from_fn 中间件只能挂在真实 Router 上调用：
    // 在随机端口起一个 axum::serve，hyper 客户端发请求、断言响应
    // （与 crates/fg-admin/tests/gateway.rs 的 UDS 测试同一套做法）。

    /// 通用 echo 处理器：把经过中间件的请求要素回显出来供断言。
    async fn echo(request: Request) -> Response {
        let facts = serde_json::json!({
            "path": request.uri().path(),
            "query": request.uri().query(),
            "via_gateway": request.extensions().get::<ViaGateway>().is_some(),
            "connect_info": request
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.to_string()),
            "real_ip": header_all(request.headers(), "x-real-ip"),
            "x_forwarded_for": header_all(request.headers(), "x-forwarded-for"),
            "host": header_all(request.headers(), "host"),
        });
        (
            [(header::CONTENT_TYPE, "application/json")],
            facts.to_string(),
        )
            .into_response()
    }

    fn header_all(headers: &HeaderMap, name: &str) -> Vec<String> {
        headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(str::to_owned)
            .collect()
    }

    /// 在随机端口把 router 服务起来，返回地址；测试生命周期内任务一直存活。
    async fn serve(router: axum::Router) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve until test end");
        });
        addr
    }

    /// 发一个请求（无 body），返回 (状态码, 响应头列表, body 文本)。
    async fn send(
        addr: SocketAddr,
        method: &'static str,
        target: &str,
        headers: &[(&str, &str)],
    ) -> (hyper::StatusCode, Vec<(String, String)>, String) {
        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .expect("handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let uri: hyper::Uri = format!("http://{addr}{target}").parse().expect("uri");
        let builder = hyper::Request::builder()
            .method(hyper::Method::from_bytes(method.as_bytes()).expect("method"))
            .uri(uri);
        let builder = headers.iter().fold(builder, |builder, (name, value)| {
            builder.header(*name, *value)
        });
        let request = builder
            .body(Full::new(Bytes::new()))
            .expect("build request");
        let response = sender.send_request(request).await.expect("send request");
        let status = response.status();
        let response_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        (
            status,
            response_headers,
            String::from_utf8_lossy(&body).into_owned(),
        )
    }

    fn header_values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
        headers
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    fn json_body(body: &str) -> serde_json::Value {
        serde_json::from_str(body).expect("echo json")
    }

    /// 测试专用：先插一个假的 ConnectInfo（restore 应把它替换掉）。
    async fn inject_fake_connect_info(mut request: Request, next: Next) -> Response {
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            IpAddr::from([192, 0, 2, 50]),
            9999,
        )));
        next.run(request).await
    }

    /// 测试专用：按 x-test-role 请求头手工插 Identity（admin / readonly / 不插）。
    async fn insert_identity(mut request: Request, next: Next) -> Response {
        let role = request
            .headers()
            .get("x-test-role")
            .and_then(|value| value.to_str().ok());
        match role {
            Some("admin") => {
                request.extensions_mut().insert(fg_auth::Identity {
                    username: "admin".to_owned(),
                    role: fg_auth::Role::Admin,
                    must_change_password: false,
                    initial_password: false,
                });
            }
            Some("readonly") => {
                request.extensions_mut().insert(fg_auth::Identity {
                    username: "auditor".to_owned(),
                    role: fg_auth::Role::Readonly,
                    must_change_password: false,
                    initial_password: false,
                });
            }
            _ => {}
        }
        next.run(request).await
    }

    /// 来源检查中间件的测试态：独立临时目录 + 全新确认列表。
    /// 返回的 TempDir 由调用方持有，测试期间配置文件一直存在。
    fn guard_state() -> (OriginGuardState, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = fg_config::ConfigStore::open(dir.path()).expect("store");
        let (manager, _) = fg_auth::AccountManager::open(store.clone(), Some("test-password-123"))
            .expect("account manager");
        (
            OriginGuardState {
                confirmed: Arc::new(Mutex::new(ConfirmedOrigins::default())),
                store,
                accounts: Arc::new(manager),
            },
            dir,
        )
    }

    /// 来源检查的测试应用：insert_identity 在最外层（先有 Identity 再查来源）。
    fn guard_app(state: OriginGuardState) -> axum::Router {
        axum::Router::new()
            .fallback(echo)
            .layer(axum::middleware::from_fn_with_state(state, origin_guard))
            .layer(axum::middleware::from_fn(insert_identity))
    }

    #[tokio::test]
    async fn gateway_restore_redirects_strips_and_passes_prefix() {
        let prefix = Arc::new("/app/gately".to_string());
        let app = axum::Router::new()
            .fallback(echo)
            .layer(axum::middleware::from_fn_with_state(
                prefix.clone(),
                restore,
            ));
        let addr = serve(app).await;

        // 裸前缀 → 308 重定向到 prefix + "/"，query 保留
        let (status, headers, _) = send(addr, "GET", "/app/gately?theme=dark", &[]).await;
        assert_eq!(status, hyper::StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            header_values(&headers, "location"),
            vec!["/app/gately/?theme=dark"]
        );
        let (status, headers, _) = send(addr, "GET", "/app/gately", &[]).await;
        assert_eq!(status, hyper::StatusCode::PERMANENT_REDIRECT);
        assert_eq!(header_values(&headers, "location"), vec!["/app/gately/"]);

        // 带前缀的路径 → 剥掉前缀，query 保留；转发头删除；ViaGateway + 地址注入
        let (status, _, body) = send(
            addr,
            "GET",
            "/app/gately/api/echo?a=1&b=2",
            &[
                ("x-real-ip", "203.0.113.7"),
                ("x-forwarded-for", "198.51.100.9"),
            ],
        )
        .await;
        assert_eq!(status, hyper::StatusCode::OK);
        let facts = json_body(&body);
        assert_eq!(facts["path"], "/api/echo");
        assert_eq!(facts["query"], "a=1&b=2");
        assert_eq!(facts["via_gateway"], true);
        assert_eq!(facts["connect_info"], "203.0.113.7:0");
        assert_eq!(facts["real_ip"], serde_json::json!([]));
        assert_eq!(facts["x_forwarded_for"], serde_json::json!([]));

        // 已不带前缀的路径（网关侧已剥）→ 原样放行
        let (status, _, body) = send(addr, "GET", "/api/echo", &[]).await;
        assert_eq!(status, hyper::StatusCode::OK);
        assert_eq!(json_body(&body)["path"], "/api/echo");
        // 前缀开头的杂项路径（不是 prefix + "/"）同样原样放行
        let (status, _, body) = send(addr, "GET", "/app/gately-x", &[]).await;
        assert_eq!(status, hyper::StatusCode::OK);
        assert_eq!(json_body(&body)["path"], "/app/gately-x");
    }

    #[tokio::test]
    async fn gateway_restore_replaces_connect_info_and_deletes_forwarded_headers() {
        let prefix = Arc::new("/app/gately".to_string());
        // 外层先插一个假的 ConnectInfo：restore 应替换或按规则保留
        let app = axum::Router::new()
            .fallback(echo)
            .layer(axum::middleware::from_fn_with_state(
                prefix.clone(),
                restore,
            ))
            .layer(axum::middleware::from_fn(inject_fake_connect_info));
        let addr = serve(app).await;

        // X-Real-IP 优先；两个转发头都被删掉；假的 ConnectInfo 被替换
        let (status, _, body) = send(
            addr,
            "GET",
            "/api/echo",
            &[
                ("x-real-ip", "203.0.113.7"),
                ("x-forwarded-for", "198.51.100.9, 203.0.113.5"),
            ],
        )
        .await;
        assert_eq!(status, hyper::StatusCode::OK);
        let facts = json_body(&body);
        assert_eq!(facts["connect_info"], "203.0.113.7:0");
        assert_eq!(facts["real_ip"], serde_json::json!([]));
        assert_eq!(facts["x_forwarded_for"], serde_json::json!([]));

        // 只有 X-Forwarded-For：取最右一项
        let (_, _, body) = send(
            addr,
            "GET",
            "/api/echo",
            &[("x-forwarded-for", "198.51.100.9, 203.0.113.5")],
        )
        .await;
        assert_eq!(json_body(&body)["connect_info"], "203.0.113.5:0");

        // 还原不出地址（回环）→ 不插 ConnectInfo，外层假值保留
        let (_, _, body) = send(addr, "GET", "/api/echo", &[("x-real-ip", "127.0.0.1")]).await;
        assert_eq!(json_body(&body)["connect_info"], "192.0.2.50:9999");
    }

    #[tokio::test]
    async fn gateway_origin_guard_confirms_and_persists_with_admin() {
        let (state, _dir) = guard_state();
        let addr = serve(guard_app(state.clone())).await;

        // same-origin + 管理员 → 信任：Host 被换成 origin 的 host[:port]，
        // 来源确认进共享列表并持久化到配置目录
        let (status, _, body) = send(
            addr,
            "POST",
            "/api/session",
            &[
                ("sec-fetch-site", "same-origin"),
                ("origin", "https://NAS.Local:5666"),
                ("host", "nas.local"),
                ("x-test-role", "admin"),
            ],
        )
        .await;
        assert_eq!(status, hyper::StatusCode::OK);
        let facts = json_body(&body);
        assert_eq!(facts["host"], serde_json::json!(["nas.local:5666"]));
        assert!(
            state
                .confirmed
                .lock()
                .expect("lock")
                .contains("https://nas.local:5666")
        );
        assert_eq!(
            ConfirmedOrigins::load(&state.store).list,
            vec!["https://nas.local:5666".to_owned()]
        );

        // 已确认的来源：无需任何佐证也信任（WebSocket 场景），不重复追加
        let (status, _, body) = send(
            addr,
            "POST",
            "/api/session",
            &[
                ("origin", "https://nas.local:5666"),
                ("host", "nas.local"),
                ("x-test-role", "admin"),
            ],
        )
        .await;
        assert_eq!(status, hyper::StatusCode::OK);
        assert_eq!(
            json_body(&body)["host"],
            serde_json::json!(["nas.local:5666"])
        );
        assert_eq!(
            ConfirmedOrigins::load(&state.store).list.len(),
            1,
            "重复确认不应追加"
        );
    }

    #[tokio::test]
    async fn gateway_origin_guard_readonly_session_does_not_confirm() {
        let (state, _dir) = guard_state();
        let addr = serve(guard_app(state.clone())).await;

        // 只读会话 + 页面请求头：GET 不需要守卫 → 放行，但不确认、不持久化、Host 不动
        let (status, _, body) = send(
            addr,
            "GET",
            "/api/data",
            &[
                (PAGE_HEADER, "1"),
                ("origin", "https://nas.local:5666"),
                ("host", "nas.local"),
                ("x-test-role", "readonly"),
            ],
        )
        .await;
        assert_eq!(status, hyper::StatusCode::OK);
        assert_eq!(json_body(&body)["host"], serde_json::json!(["nas.local"]));
        assert!(state.confirmed.lock().expect("lock").list.is_empty());
        assert!(ConfirmedOrigins::load(&state.store).list.is_empty());

        // 只读会话的修改请求：即使 same-origin 也不放行、不确认
        let (status, _, body) = send(
            addr,
            "POST",
            "/api/session",
            &[
                ("sec-fetch-site", "same-origin"),
                ("origin", "https://nas.local:5666"),
                ("x-test-role", "readonly"),
            ],
        )
        .await;
        assert_eq!(status, hyper::StatusCode::FORBIDDEN);
        assert_eq!(body, "拒绝跨源请求");
        assert!(ConfirmedOrigins::load(&state.store).list.is_empty());
    }

    #[tokio::test]
    async fn gateway_origin_guard_blocks_cross_site_mutations() {
        let (state, _dir) = guard_state();
        let addr = serve(guard_app(state.clone())).await;

        // 浏览器标明 cross-site：管理员会话 + 页面请求头也不放行
        let (status, _, body) = send(
            addr,
            "POST",
            "/api/session",
            &[
                ("sec-fetch-site", "cross-site"),
                ("origin", "https://evil.local"),
                (PAGE_HEADER, "1"),
                ("host", "nas.local"),
                ("x-test-role", "admin"),
            ],
        )
        .await;
        assert_eq!(status, hyper::StatusCode::FORBIDDEN);
        assert_eq!(body, "拒绝跨源请求");
        assert!(
            ConfirmedOrigins::load(&state.store).list.is_empty(),
            "被拒的来源不应入列表"
        );

        // same-site 同样直接拒绝
        let (status, _, _) = send(
            addr,
            "PUT",
            "/api/session",
            &[
                ("sec-fetch-site", "same-site"),
                ("origin", "https://nas.local:5666"),
                ("x-test-role", "admin"),
            ],
        )
        .await;
        assert_eq!(status, hyper::StatusCode::FORBIDDEN);

        // 普通 GET（非 WebSocket 握手）不需要守卫：未确认也放行
        let (status, _, _) = send(
            addr,
            "GET",
            "/api/data",
            &[
                ("sec-fetch-site", "cross-site"),
                ("origin", "https://evil.local"),
                ("x-test-role", "admin"),
            ],
        )
        .await;
        assert_eq!(status, hyper::StatusCode::OK);

        // WebSocket 握手（Connection/Upgrade 近似）需要守卫：未确认 → 403
        let (status, _, _) = send(
            addr,
            "GET",
            "/api/ws",
            &[
                ("origin", "https://evil.local"),
                ("x-test-role", "admin"),
                ("connection", "keep-alive, Upgrade"),
                ("upgrade", "websocket"),
            ],
        )
        .await;
        assert_eq!(status, hyper::StatusCode::FORBIDDEN);

        // 同样的 GET 不带握手头 → 放行
        let (status, _, _) = send(
            addr,
            "GET",
            "/api/ws",
            &[("origin", "https://evil.local"), ("x-test-role", "admin")],
        )
        .await;
        assert_eq!(status, hyper::StatusCode::OK);
    }

    #[tokio::test]
    async fn gateway_origin_guard_login_exception_passes_unconfirmed() {
        let (state, _dir) = guard_state();
        let addr = serve(guard_app(state.clone())).await;

        // 未确认来源 + Sec-Fetch-Site 缺失：登录/退出放行（登录成功后再确认来源）
        for path in ["/api/login", "/api/logout", "/api/login/oauth2/callback"] {
            let (status, _, _) = send(
                addr,
                "POST",
                path,
                &[
                    ("origin", "https://nas.local:5666"),
                    ("x-test-role", "admin"),
                ],
            )
            .await;
            assert_eq!(status, hyper::StatusCode::OK, "{path} 应放行");
        }
        // 不带 Origin 的请求同样放行（NoOrigin）
        let (status, _, _) = send(addr, "POST", "/api/login", &[]).await;
        assert_eq!(status, hyper::StatusCode::OK);

        // 相近但不是登录/退出的路径不放行
        let (status, _, body) = send(
            addr,
            "POST",
            "/api/login-fake",
            &[
                ("origin", "https://nas.local:5666"),
                ("x-test-role", "admin"),
            ],
        )
        .await;
        assert_eq!(status, hyper::StatusCode::FORBIDDEN);
        assert_eq!(body, "拒绝跨源请求");
        // Sec-Fetch-Site 明确标明跨站时例外不生效
        let (status, _, _) = send(
            addr,
            "POST",
            "/api/login",
            &[
                ("origin", "https://evil.local"),
                ("sec-fetch-site", "cross-site"),
            ],
        )
        .await;
        assert_eq!(status, hyper::StatusCode::FORBIDDEN);
        assert!(ConfirmedOrigins::load(&state.store).list.is_empty());
    }

    #[tokio::test]
    async fn gateway_rewrite_response_prefixes_location_cookies_and_index() {
        let prefix = Arc::new("/app/gately".to_string());
        // axum 的 Router::layer 在路由匹配之后才执行，剥前缀的 restore 必须
        // 挂在外层直通路由上才能影响内层路由匹配（bootstrap 也要这样接）。
        // rewrite_response 只改响应，挂在路由之后的内层即可。
        let inner = axum::Router::new()
            .route(
                "/",
                get(|| async {
                    (
                        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                        "<!doctype html><html><head><title>t</title></head><body><a href=\"./x.js\">l</a></body></html>".to_owned(),
                    )
                }),
            )
            .route(
                "/page",
                get(|| async {
                    (
                        [(header::CONTENT_TYPE, "text/html")],
                        "<html><head></head><body><a href=\"./y.js\">m</a></body></html>".to_owned(),
                    )
                }),
            )
            .route(
                "/api/redirect",
                get(|| async { Redirect::temporary("/api/echo") }),
            )
            .route(
                "/api/external",
                get(|| async {
                    (
                        [(header::LOCATION, "//other.local/x")],
                        hyper::StatusCode::FOUND,
                    )
                }),
            )
            .route(
                "/api/cookie",
                get(|| async {
                    // 两条 Set-Cookie：元组数组会互相覆盖（insert），改用 HeaderMap 追加
                    let mut headers = HeaderMap::new();
                    headers.append(
                        header::SET_COOKIE,
                        HeaderValue::from_static("gately_token=abc; Path=/; HttpOnly"),
                    );
                    headers.append(
                        header::SET_COOKIE,
                        HeaderValue::from_static("n=1; Path=/api/login; Max-Age=600"),
                    );
                    (headers, "ok")
                }),
            )
            .fallback(echo)
            .layer(axum::middleware::from_fn_with_state(
                prefix.clone(),
                rewrite_response,
            ));
        let app = axum::Router::new().fallback_service(inner).layer(
            axum::middleware::from_fn_with_state(prefix.clone(), restore),
        );
        let addr = serve(app).await;

        // Location 绝对路径补前缀
        let (status, headers, _) = send(addr, "GET", "/app/gately/api/redirect", &[]).await;
        assert_eq!(status, hyper::StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            header_values(&headers, "location"),
            vec!["/app/gately/api/echo"]
        );
        // 协议相对地址（// 开头）不动
        let (_, headers, _) = send(addr, "GET", "/app/gately/api/external", &[]).await;
        assert_eq!(header_values(&headers, "location"), vec!["//other.local/x"]);
        // Set-Cookie 的 Path 补前缀，多条各自处理
        let (_, headers, _) = send(addr, "GET", "/app/gately/api/cookie", &[]).await;
        assert_eq!(
            header_values(&headers, "set-cookie"),
            vec![
                "gately_token=abc; Path=/app/gately; HttpOnly",
                "n=1; Path=/app/gately/api/login; Max-Age=600",
            ]
        );
        // 首页 HTML（路径 prefix + "/"）：注入 base meta、资源路径绝对化
        let (status, headers, body) = send(addr, "GET", "/app/gately/", &[]).await;
        assert_eq!(status, hyper::StatusCode::OK);
        assert!(
            body.contains(r#"<meta name="gately-base" content="/app/gately">"#),
            "{body}"
        );
        assert!(body.contains(r#"href="/app/gately/x.js""#), "{body}");
        // Content-Length 与改写后的 body 一致
        let length: usize = header_values(&headers, "content-length")
            .first()
            .expect("content-length")
            .parse()
            .expect("parse content-length");
        assert_eq!(length, body.len());
        // 直连 "/"（前缀根）同样改写
        let (_, _, body) = send(addr, "GET", "/", &[]).await;
        assert!(
            body.contains(r#"<meta name="gately-base" content="/app/gately">"#),
            "{body}"
        );
        // 非首页的 HTML 不改写：资源相对路径保留、无 base meta
        let (_, _, body) = send(addr, "GET", "/app/gately/page", &[]).await;
        assert!(!body.contains("gately-base"), "{body}");
        assert!(body.contains(r#"href="./y.js""#), "{body}");
    }
}
