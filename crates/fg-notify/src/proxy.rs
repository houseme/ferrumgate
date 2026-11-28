//! Proxy selection (WP-68 §3.3): the notification settings' global proxy
//! and a channel's per-channel choice resolve to one effective proxy per
//! send. `http://`, `https://`, `socks5://` and `socks5h://` are accepted
//! (with optional user/password). "No proxy" lets HTTP channels follow
//! `HTTPS_PROXY`/`NO_PROXY` style environment variables, "direct"
//! connection ignores them; SMTP never reads environment proxies — it
//! dials through an explicit HTTP CONNECT tunnel or a SOCKS5 handshake
//! ([`connect`]) when configured.

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::sync::CancellationToken;

use crate::model::{ChannelProxy, SettingsProxy};

/// The proxy a send actually uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effective {
    /// No explicit proxy; HTTP clients follow the proxy environment
    /// variables, SMTP dials directly.
    NoneEnv,
    /// Force a direct connection; environment proxies are ignored too.
    Direct,
    /// Dial through this proxy URL.
    Url(String),
}

/// Resolves the per-channel choice against the global setting and the
/// global update proxy URL (`None`/empty = unset).
pub fn resolve(
    settings: &SettingsProxy,
    channel: &ChannelProxy,
    update_proxy: Option<&str>,
) -> Effective {
    let update = || match update_proxy {
        Some(url) if !url.trim().is_empty() => Effective::Url(url.trim().to_owned()),
        _ => Effective::NoneEnv,
    };
    match channel {
        ChannelProxy::Direct => Effective::Direct,
        ChannelProxy::Custom(url) => Effective::Url(url.clone()),
        ChannelProxy::UpdateProxy => update(),
        ChannelProxy::Follow => match settings {
            SettingsProxy::None => Effective::NoneEnv,
            SettingsProxy::UpdateProxy => update(),
            SettingsProxy::Custom(url) => Effective::Url(url.clone()),
        },
    }
}

/// A parsed proxy URL (`scheme://[user[:pass]@]host[:port]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyUrl {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

impl ProxyUrl {
    /// Whether the proxy hides the target host from local resolution
    /// (`socks5h`).
    pub fn remote_dns(&self) -> bool {
        self.scheme == "socks5h"
    }

    /// The Basic authorization header value for the proxy credentials.
    pub fn basic_auth(&self) -> Option<String> {
        if self.username.is_empty() {
            return None;
        }
        use base64::Engine as _;
        Some(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", self.username, self.password))
        ))
    }
}

/// Parses a proxy URL; the schemes are restricted to http, https, socks5
/// and socks5h (validate::PROXY_SCHEMES).
pub fn parse_proxy(url: &str) -> Result<ProxyUrl, String> {
    let parsed = url::Url::parse(url).map_err(|error| format!("代理地址无效：{error}"))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if !crate::validate::PROXY_SCHEMES.contains(&scheme.as_str()) {
        return Err(format!(
            "代理协议只支持 {}",
            crate::validate::PROXY_SCHEMES.join("、")
        ));
    }
    let port = parsed.port().unwrap_or(match scheme.as_str() {
        "https" => 443,
        "socks5" | "socks5h" => 1080,
        _ => 80,
    });
    Ok(ProxyUrl {
        scheme,
        host: parsed.host_str().unwrap_or_default().to_owned(),
        port,
        username: parsed.username().to_owned(),
        password: parsed.password().unwrap_or_default().to_owned(),
    })
}

/// Hides the password of a proxy URL for display and records: the
/// password is replaced with `xxxxx`.
pub fn redact(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    // The authority ends at the first slash/query/fragment.
    let (authority, tail) = match rest.find(['/', '?', '#']) {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, ""),
    };
    let Some((userinfo, host)) = authority.rsplit_once('@') else {
        return url.to_owned();
    };
    let hidden = match userinfo.split_once(':') {
        Some((user, _)) => format!("{user}:xxxxx"),
        None => userinfo.to_owned(),
    };
    format!("{scheme}://{hidden}@{host}{tail}")
}

/// Configures a reqwest client builder for the effective proxy: direct
/// connections explicitly drop environment proxies, "no proxy" keeps the
/// environment behavior.
pub fn apply_to_client(
    builder: reqwest::ClientBuilder,
    effective: &Effective,
) -> reqwest::ClientBuilder {
    match effective {
        Effective::NoneEnv => builder,
        Effective::Direct => builder.no_proxy(),
        Effective::Url(url) => match reqwest::Proxy::all(url) {
            Ok(proxy) => builder.proxy(proxy),
            Err(_) => builder,
        },
    }
}

/// Builds an HTTP client for one channel send.
pub fn client(
    effective: &Effective,
    timeout: Duration,
    insecure_skip_verify: bool,
) -> Result<reqwest::Client, String> {
    apply_to_client(
        reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout.min(Duration::from_secs(10)))
            .danger_accept_invalid_certs(insecure_skip_verify),
        effective,
    )
    .build()
    .map_err(|error| format!("HTTP 客户端构建失败：{error}"))
}

/// Dial errors carry a redacted proxy URL (no passwords).
fn redacted(effective: &Effective) -> String {
    match effective {
        Effective::Url(url) => redact(url),
        _ => String::new(),
    }
}

/// Opens a plain TCP connection to `host:port`, honoring the effective
/// proxy: HTTP(S) proxies get a CONNECT tunnel, SOCKS5 proxies a full
/// handshake (`socks5h` sends the hostname, `socks5` resolves locally).
/// Returns the stream plus any bytes the proxy handshake already buffered
/// past its response (a chatty proxy may piggyback the peer's first
/// bytes). E-mail and other raw-TCP channels use this.
pub async fn connect(
    host: &str,
    port: u16,
    effective: &Effective,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<(TcpStream, Vec<u8>), String> {
    let attempt = connect_inner(host, port, effective);
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err("投递在模块关闭时被终止".to_owned()),
        result = tokio::time::timeout(timeout, attempt) => match result {
            Ok(inner) => inner,
            Err(_) => Err(format!("经代理连接超时（{} 秒）", timeout.as_secs().max(1))),
        },
    }
}

async fn connect_inner(
    host: &str,
    port: u16,
    effective: &Effective,
) -> Result<(TcpStream, Vec<u8>), String> {
    match effective {
        Effective::NoneEnv | Effective::Direct => TcpStream::connect((host, port))
            .await
            .map(|stream| (stream, Vec::new()))
            .map_err(|error| format!("连接 {host}:{port} 失败：{error}")),
        Effective::Url(url) => {
            let proxy =
                parse_proxy(url).map_err(|error| format!("经代理 {url} 连接失败：{error}"))?;
            match proxy.scheme.as_str() {
                "http" | "https" => connect_via_http(&proxy, host, port).await,
                _ => connect_via_socks5(&proxy, host, port).await,
            }
        }
    }
}

async fn dial(proxy: &ProxyUrl, label: &str) -> Result<TcpStream, String> {
    TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .map_err(|error| format!("经代理 {label} 连接失败：{error}"))
}

/// HTTP CONNECT tunnel (WP-68 §3.3: e-mail through http(s) proxies).
async fn connect_via_http(
    proxy: &ProxyUrl,
    host: &str,
    port: u16,
) -> Result<(TcpStream, Vec<u8>), String> {
    let mut stream = dial(proxy, &proxy.host).await?;
    let mut request = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some(auth) = proxy.basic_auth() {
        request.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| format!("经代理 {} 连接失败：{error}", proxy.host))?;
    let (response, leftover) = read_headers(&mut stream)
        .await
        .map_err(|error| format!("经代理 {} 建立隧道失败：{error}", proxy.host))?;
    let status = response
        .lines()
        .next()
        .unwrap_or_default()
        .split(' ')
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    if !status.starts_with('2') {
        return Err(format!(
            "经代理 {} 建立隧道失败：代理返回 HTTP {status}",
            proxy.host
        ));
    }
    Ok((stream, leftover))
}

/// Reads an HTTP response head (until the blank line, capped); bytes past
/// the head are returned so the caller keeps what the peer already sent.
async fn read_headers(stream: &mut TcpStream) -> Result<(String, Vec<u8>), String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(at) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..at]).to_string();
            return Ok((head, buffer[at + 4..].to_vec()));
        }
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("代理连接被关闭".to_owned());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > 64 * 1024 {
            return Err("代理响应头过大".to_owned());
        }
    }
}

/// SOCKS5 handshake (RFC 1928); optional username/password subnegotiation
/// (RFC 1929). `socks5h` proxies resolve the target hostname, `socks5`
/// resolves locally first. The reply is read with exact-length reads, so
/// no peer bytes are buffered here.
async fn connect_via_socks5(
    proxy: &ProxyUrl,
    host: &str,
    port: u16,
) -> Result<(TcpStream, Vec<u8>), String> {
    let mut stream = dial(proxy, &proxy.host).await?;
    let wants_auth = !proxy.username.is_empty();
    stream
        .write_all(&[0x05, 0x01, if wants_auth { 0x02 } else { 0x00 }])
        .await
        .map_err(|error| format!("经代理 {} 握手失败：{error}", proxy.host))?;
    let mut reply = [0u8; 2];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|error| format!("经代理 {} 握手失败：{error}", proxy.host))?;
    let chosen = reply[1];
    if wants_auth {
        if chosen != 0x02 {
            return Err(format!(
                "经代理 {} 握手失败：代理不接受用户名/密码认证",
                proxy.host
            ));
        }
        let mut auth = Vec::with_capacity(3 + proxy.username.len() + proxy.password.len());
        auth.push(0x01);
        auth.push(proxy.username.len() as u8);
        auth.extend_from_slice(proxy.username.as_bytes());
        auth.push(proxy.password.len() as u8);
        auth.extend_from_slice(proxy.password.as_bytes());
        stream
            .write_all(&auth)
            .await
            .map_err(|error| format!("经代理 {} 认证失败：{error}", proxy.host))?;
        let mut status = [0u8; 2];
        stream
            .read_exact(&mut status)
            .await
            .map_err(|error| format!("经代理 {} 认证失败：{error}", proxy.host))?;
        if status[1] != 0x00 {
            return Err(format!(
                "经代理 {} 认证失败：用户名或密码被拒绝",
                proxy.host
            ));
        }
    } else if chosen != 0x00 {
        return Err(format!(
            "经代理 {} 握手失败：代理不接受免认证连接",
            proxy.host
        ));
    }
    let mut request = vec![0x05, 0x01, 0x00];
    if proxy.remote_dns() {
        request.push(0x03);
        request.push(host.len() as u8);
        request.extend_from_slice(host.as_bytes());
    } else {
        use std::net::ToSocketAddrs;
        let resolved = (host, port)
            .to_socket_addrs()
            .map_err(|error| format!("解析 {host} 失败：{error}"))?
            .next()
            .ok_or_else(|| format!("解析 {host} 失败：没有可用地址"))?;
        match resolved.ip() {
            std::net::IpAddr::V4(ip) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|error| format!("经代理 {} 连接失败：{error}", proxy.host))?;
    // Reply: VER REP RSV ATYP ADDR PORT; read generously, parse from the head.
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|error| format!("经代理 {} 连接失败：{error}", proxy.host))?;
    if head[1] != 0x00 {
        return Err(format!(
            "经代理 {} 连接失败：SOCKS5 返回码 {}",
            proxy.host, head[1]
        ));
    }
    let skip = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0u8; 1];
            stream
                .read_exact(&mut length)
                .await
                .map_err(|error| format!("经代理 {} 连接失败：{error}", proxy.host))?;
            u32::from(length[0]) as usize
        }
        other => {
            return Err(format!(
                "经代理 {} 连接失败：未知地址类型 {other}",
                proxy.host
            ));
        }
    };
    let mut tail = vec![0u8; skip + 2];
    stream
        .read_exact(&mut tail)
        .await
        .map_err(|error| format!("经代理 {} 连接失败：{error}", proxy.host))?;
    Ok((stream, Vec::new()))
}

/// The error prefix used by raw-TCP channels when the proxy dial fails;
/// passwords stay redacted.
pub fn dial_error(effective: &Effective, detail: &str) -> String {
    let via = match effective {
        Effective::Url(_) => format!("经代理 {} ", redacted(effective)),
        _ => String::new(),
    };
    format!("{via}连接失败：{detail}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ChannelProxy, SettingsProxy};

    #[test]
    fn proxy_channel_overrides_global() {
        let update = Some("http://update-proxy:3128");
        // Follow keeps the global decision.
        assert_eq!(
            resolve(&SettingsProxy::None, &ChannelProxy::Follow, update),
            Effective::NoneEnv
        );
        assert_eq!(
            resolve(
                &SettingsProxy::Custom("http://global:8080".into()),
                &ChannelProxy::Follow,
                update
            ),
            Effective::Url("http://global:8080".into())
        );
        // A channel override wins over the global custom proxy.
        assert_eq!(
            resolve(
                &SettingsProxy::Custom("http://global:8080".into()),
                &ChannelProxy::Direct,
                update
            ),
            Effective::Direct
        );
        assert_eq!(
            resolve(
                &SettingsProxy::Custom("http://global:8080".into()),
                &ChannelProxy::Custom("socks5://other:1080".into()),
                update
            ),
            Effective::Url("socks5://other:1080".into())
        );
        // The update proxy is used on request; unset it falls back to env.
        assert_eq!(
            resolve(&SettingsProxy::None, &ChannelProxy::UpdateProxy, update),
            Effective::Url("http://update-proxy:3128".into())
        );
        assert_eq!(
            resolve(&SettingsProxy::None, &ChannelProxy::UpdateProxy, None),
            Effective::NoneEnv
        );
        assert_eq!(
            resolve(&SettingsProxy::None, &ChannelProxy::UpdateProxy, Some("  ")),
            Effective::NoneEnv
        );
    }

    #[test]
    fn proxy_direct_ignores_env() {
        // The effective values decide the client behavior: Direct applies
        // `.no_proxy()`, NoneEnv keeps the environment.
        let builder = reqwest::Client::builder();
        let applied = apply_to_client(builder, &Effective::Direct);
        let _ = applied.build().expect("direct client builds");
        let builder = reqwest::Client::builder();
        let applied = apply_to_client(builder, &Effective::NoneEnv);
        let _ = applied.build().expect("env client builds");
        // A URL proxy is attached.
        let builder = reqwest::Client::builder();
        let applied = apply_to_client(builder, &Effective::Url("socks5h://127.0.0.1:1080".into()));
        let _ = applied.build().expect("proxied client builds");
        // parse_proxy covers the four schemes and credentials.
        let proxy = parse_proxy("socks5h://user:secret@proxy.internal:1080").expect("parse");
        assert_eq!(proxy.scheme, "socks5h");
        assert_eq!(proxy.host, "proxy.internal");
        assert_eq!(proxy.port, 1080);
        assert_eq!(proxy.username, "user");
        assert_eq!(proxy.password, "secret");
        assert!(proxy.remote_dns());
        assert!(parse_proxy("ftp://proxy:21").is_err());
        assert_eq!(parse_proxy("http://proxy").expect("parse").port, 80);
    }

    #[test]
    fn proxy_password_hidden_in_records() {
        assert_eq!(
            redact("http://user:password@gate.local:8080"),
            "http://user:xxxxx@gate.local:8080"
        );
        assert_eq!(
            redact("socks5://gate.local:1080"),
            "socks5://gate.local:1080"
        );
        assert_eq!(
            redact("http://:pass@gate.local"),
            "http://:xxxxx@gate.local"
        );
        assert_eq!(redact("http://user@gate.local"), "http://user@gate.local");
        assert_eq!(redact("not a url"), "not a url");
        // Dial errors never carry the password.
        let effective = Effective::Url("http://user:password@gate.local:8080".into());
        let error = dial_error(&effective, "refused");
        assert!(!error.contains("password"), "{error}");
        assert!(error.contains("xxxxx"), "{error}");
    }
}
