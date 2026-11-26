//! Unified-gateway access (optional slice): fnOS's gateway forwards
//! `https://<nas>/app/gately/…` to a Unix socket. Only active when
//! `--gateway-socket` is passed; the TCP management listener is unaffected.
//! This module holds the pure helpers and the small-IO layer (socket listen,
//! confirmed-origin persistence); the axum integration lands in WP-14 step 9.

use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;

use anyhow::Context;
use axum::http::Method;
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use super::*;

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
}
