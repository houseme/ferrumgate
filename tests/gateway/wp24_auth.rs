//! WP-24 batch 3: the authentication pipeline driven end-to-end through
//! [`Proxy::forward`] — HTTP basic auth, the web login flow (reserved
//! paths, same-origin, `next` restriction, signed session cookie), the
//! shared-user TOTP step and the site binding of session cookies.
//!
//! Same harness shape as `wp23_options.rs`: an echo backend, sites
//! compiled through the webservice bridge, and a direct
//! `Proxy::forward` frontend. The authenticator carries a fast (cost 4)
//! bcrypt shared-user hash — production saves use the default cost,
//! which does not affect these behaviors.

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::{BodyExt, Full};
use hyper::{
    HeaderMap, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::SET_COOKIE,
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use ring::hmac;
use serde_json::{Value, json};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

use super::Proxy;
use crate::{
    config::Settings,
    web::{
        auth::{Authenticator, shared::AuthUser},
        compile_routes,
        model::{Listener, Site},
    },
};

const DEADLINE: Duration = Duration::from_secs(5);
/// The reserved auth path (kept in sync with `auth::AUTH_PATH`).
const AUTH_PATH: &str = "/__gately_auth";

/// An HTTP/1.1 backend that answers every request with a JSON echo of
/// the request target and headers, so the tests can tell proxied
/// requests (backend hit) from auth answers (no hit).
struct EchoBackend {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    _task: JoinHandle<()>,
}

async fn echo_backend() -> Result<EchoBackend> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let hits = Arc::new(AtomicUsize::new(0));
    let serving = hits.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let serving = serving.clone();
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |request: Request<Incoming>| {
                            let serving = serving.clone();
                            async move {
                                serving.fetch_add(1, Ordering::SeqCst);
                                Ok::<_, Infallible>(echo(request))
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    Ok(EchoBackend {
        addr,
        hits,
        _task: task,
    })
}

fn echo(request: Request<Incoming>) -> Response<Full<Bytes>> {
    let mut seen = serde_json::Map::new();
    for (name, value) in request.headers() {
        seen.entry(name.as_str().to_owned())
            .or_insert_with(|| json!(value.to_str().unwrap_or_default()));
    }
    let body = json!({
        "target": request
            .uri()
            .path_and_query()
            .map(|target| target.as_str())
            .unwrap_or_default(),
        "seen": Value::Object(seen),
    });
    Response::builder()
        .header("x-trace-resp", "leak")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("static echo response")
}

/// Serves [`Proxy::forward`] over plain loopback HTTP/1.1, the same
/// service shape the webservice listener uses (no TLS, no tunnels).
async fn spawn_frontend(proxy: Proxy) -> Result<SocketAddr> {
    let proxy = Arc::new(proxy);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            let proxy = proxy.clone();
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |request: Request<Incoming>| {
                            let proxy = proxy.clone();
                            async move {
                                Ok::<_, Infallible>(proxy.forward(request, peer, None, None).await)
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    Ok(addr)
}

/// Compiles the sites through the webservice bridge and fronts them
/// with one proxy carrying an authenticator built from `secret` and the
/// shared users (what the webservice settings path would wire).
async fn spawn_auth_gateway(
    sites: Vec<Site>,
    secret: &[u8],
    shared: Vec<AuthUser>,
) -> Result<SocketAddr> {
    let listener = Listener {
        key: "wp24".to_owned(),
        enable: true,
        sites,
        ..Listener::default()
    };
    let routes = compile_routes(&listener)
        .await
        .map_err(|errors| anyhow::anyhow!("site compile failed: {errors:?}"))?;
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let authenticator = Authenticator::new(secret, shared);
    spawn_frontend(
        Proxy::new(routes, &Settings::default(), tls).with_authenticator(Arc::new(authenticator)),
    )
    .await
}

/// A proxy site on `domain` towards `backend`, with the auth fields
/// assigned by `shape` on top of `Site::default()`.
fn auth_site(
    domain: &str,
    key: &str,
    backend: SocketAddr,
    shape: impl FnOnce(&mut Site),
) -> Site {
    let mut site = Site {
        key: key.to_owned(),
        enable: true,
        domains: vec![domain.to_owned()],
        site_type: "proxy".to_owned(),
        targets: vec![format!("http://{backend}")],
        ..Site::default()
    };
    shape(&mut site);
    site
}

/// A shared user with a fast (cost 4) bcrypt hash.
fn shared_user(name: &str, password: &str, totp: &str) -> AuthUser {
    AuthUser {
        id: String::new(),
        name: name.to_owned(),
        password: bcrypt::hash(password, 4).expect("bcrypt hash"),
        totp_secret: totp.to_owned(),
        remark: String::new(),
        email: String::new(),
        display_name: String::new(),
        groups: Vec::new(),
    }
}

/// One fresh HTTP/1.1 request to the gateway; returns the status, the
/// response headers and the raw body text. Every request presents as a
/// browser (`Accept: text/html`) — the auth tests care about the
/// browser shape.
async fn send(
    addr: SocketAddr,
    method: &str,
    path: &str,
    host: &str,
    headers: &[(&str, String)],
    form: Option<&str>,
) -> Result<(StatusCode, HeaderMap, String)> {
    let stream = timeout(DEADLINE, TcpStream::connect(addr)).await??;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host)
        .header("accept", "text/html,application/xhtml+xml");
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let request = builder.body(Full::new(Bytes::from(
        form.unwrap_or_default().to_owned(),
    )))?;
    let response = timeout(DEADLINE, sender.send_request(request)).await??;
    let status = response.status();
    let fields = response.headers().clone();
    let body = timeout(DEADLINE, response.into_body().collect())
        .await??
        .to_bytes();
    Ok((status, fields, String::from_utf8_lossy(&body).into_owned()))
}

/// The `name=value` part of the first Set-Cookie whose value starts
/// with `prefix` (the attributes stay off).
fn set_cookie(fields: &HeaderMap, prefix: &str) -> Option<String> {
    set_cookie_raw(fields, prefix).map(|value| {
        value
            .split(';')
            .next()
            .unwrap_or_default()
            .to_owned()
    })
}

/// The full `name=value; attributes` text of the first Set-Cookie whose
/// value starts with `prefix`.
fn set_cookie_raw(fields: &HeaderMap, prefix: &str) -> Option<String> {
    fields
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(prefix))
        .map(str::to_owned)
}

/// The cookie header built from a `name=value` pair.
fn cookie_header(pair: &str) -> (&'static str, String) {
    ("cookie", pair.to_owned())
}

/// `Authorization: Basic base64(user:pass)`.
fn basic_header(credentials: &str) -> (&'static str, String) {
    (
        "authorization",
        format!("Basic {}", STANDARD.encode(credentials)),
    )
}

/// One six-digit TOTP code for the Base32 secret at `unix` (RFC 6238
/// SHA-1, generated locally — `Totp` only exposes verification).
fn totp_code(secret: &str, unix: u64) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits: u32 = 0;
    let mut length = 0u32;
    let mut key = Vec::new();
    for character in secret.to_ascii_uppercase().bytes() {
        let Some(value) = ALPHABET.iter().position(|&letter| letter == character) else {
            continue;
        };
        bits = (bits << 5) | value as u32;
        length += 5;
        if length >= 8 {
            length -= 8;
            key.push((bits >> length) as u8);
        }
    }
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &key);
    let digest = hmac::sign(&key, &(unix / 30).to_be_bytes());
    let digest = digest.as_ref();
    let offset = usize::from(digest[19] & 0x0f);
    let truncated = u32::from_be_bytes(digest[offset..offset + 4].try_into().expect("HOTP block"))
        & 0x7fff_ffff;
    format!("{:06}", truncated % 1_000_000)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A one-request login POST with same-origin Origin header.
async fn login(
    addr: SocketAddr,
    host: &str,
    origin: &str,
    form: &str,
    cookies: &[&str],
) -> Result<(StatusCode, HeaderMap, String)> {
    let mut headers = vec![(
        "content-type",
        "application/x-www-form-urlencoded".to_owned(),
    )];
    if !origin.is_empty() {
        headers.push(("origin", origin.to_owned()));
    }
    for pair in cookies {
        headers.push(cookie_header(pair));
    }
    send(addr, "POST", AUTH_PATH, host, &headers, Some(form)).await
}

#[tokio::test]
async fn basic_auth_allows_and_denies() -> Result<()> {
    let backend = echo_backend().await?;
    let site = auth_site("b.test", "basic", backend.addr, |site| {
        site.basic_auth = true;
        site.users = vec!["alice:s3cret".to_owned()];
    });
    let gateway = spawn_auth_gateway(vec![site], b"basic-secret", vec![]).await?;

    // 正确凭据：透传到后端，响应头（echo 的 x-trace-resp）经转发。
    let (status, fields, body) = send(
        gateway,
        "GET",
        "/data?x=1",
        "b.test",
        &[basic_header("alice:s3cret")],
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "correct credentials pass through");
    let echo: Value = serde_json::from_str(&body)?;
    assert_eq!(echo["target"], "/data?x=1", "the request is proxied");
    assert_eq!(
        fields.get("x-trace-resp").and_then(|value| value.to_str().ok()),
        Some("leak"),
        "backend response headers are forwarded"
    );

    // 错误凭据：401 + WWW-Authenticate 挑战，且不触达后端。
    let hits = backend.hits.load(Ordering::SeqCst);
    let (status, fields, _) = send(
        gateway,
        "GET",
        "/",
        "b.test",
        &[basic_header("alice:wrong")],
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        fields.get("www-authenticate").and_then(|value| value.to_str().ok()),
        Some("Basic"),
        "the 401 carries the Basic challenge"
    );
    // 无凭据同样 401 挑战。
    let (status, fields, _) = send(gateway, "GET", "/", "b.test", &[], None).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(fields.contains_key("www-authenticate"));
    assert_eq!(
        backend.hits.load(Ordering::SeqCst),
        hits,
        "refused requests never reach the backend"
    );
    Ok(())
}

#[tokio::test]
async fn web_auth_login_flow() -> Result<()> {
    let backend = echo_backend().await?;
    let site = auth_site("a.test", "alpha", backend.addr, |site| {
        site.web_auth = true;
        site.users = vec!["alice:pw".to_owned()];
    });
    let gateway = spawn_auth_gateway(vec![site], b"web-secret", vec![]).await?;

    // 未登录的浏览器请求：302 到认证保留路径，原路径进 next。
    let (status, fields, _) = send(gateway, "GET", "/html", "a.test", &[], None).await?;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        fields.get("location").and_then(|value| value.to_str().ok()),
        Some(format!("{AUTH_PATH}?next=/html").as_str()),
        "the original target rides in next"
    );

    // 登录页：200 + 表单（next 作为隐藏字段带回）。
    let (status, _, body) = send(gateway, "GET", &format!("{AUTH_PATH}?next=/html"), "a.test", &[], None).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("<form") && body.contains("用户名") && body.contains("密码"),
        "the login page renders the form: {body}"
    );
    assert!(
        body.contains(r#"name="next" value="/html""#),
        "the hidden next field is preserved: {body}"
    );

    // 同源登录：302 到 next，Set-Cookie 带 gately_site_ 前缀。
    let (status, fields, _) = login(
        gateway,
        "a.test",
        "http://a.test",
        "next=%2Fhtml&username=alice&password=pw",
        &[],
    )
    .await?;
    assert_eq!(status, StatusCode::FOUND, "a valid login redirects");
    assert_eq!(
        fields.get("location").and_then(|value| value.to_str().ok()),
        Some("/html"),
        "the redirect follows the safe next target"
    );
    let session = set_cookie(&fields, "gately_site_")
        .expect("the login sets the site session cookie");

    // 带 Cookie 重访：透传（不再要求登录）。
    let (status, _, body) = send(
        gateway,
        "GET",
        "/html",
        "a.test",
        &[cookie_header(&session)],
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "the session cookie admits");
    let echo: Value = serde_json::from_str(&body)?;
    assert_eq!(echo["target"], "/html", "the request is proxied");

    // 跨域 Origin：拒绝（错误页，无会话 Cookie）。
    let hits = backend.hits.load(Ordering::SeqCst);
    let (status, fields, body) = login(
        gateway,
        "a.test",
        "http://evil.test",
        "next=%2F&username=alice&password=pw",
        &[],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "the cross-origin POST is refused");
    assert!(
        body.contains("跨站提交被拒绝"),
        "the refusal is rendered: {body}"
    );
    assert!(
        set_cookie(&fields, "gately_site_").is_none(),
        "a refused login never sets a session cookie"
    );
    assert_eq!(backend.hits.load(Ordering::SeqCst), hits);

    // 缺失 Origin/Referer 的表单提交同样拒绝。
    let (status, fields, _) = login(
        gateway,
        "a.test",
        "",
        "next=%2F&username=alice&password=pw",
        &[],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(set_cookie(&fields, "gately_site_").is_none());
    Ok(())
}

#[tokio::test]
async fn safe_next_only() -> Result<()> {
    let backend = echo_backend().await?;
    let site = auth_site("n.test", "next", backend.addr, |site| {
        site.web_auth = true;
        site.users = vec!["alice:pw".to_owned()];
    });
    let gateway = spawn_auth_gateway(vec![site], b"next-secret", vec![]).await?;

    // //evil、/\evil、https://evil 都不是站内相对路径：回落 /。
    for (label, form) in [
        ("protocol-relative", "next=//evil.test"),
        ("backslash", "next=/%5Cevil.test"),
        ("absolute-url", "next=https%3A%2F%2Fevil.test"),
    ] {
        let (status, fields, _) = login(
            gateway,
            "n.test",
            "http://n.test",
            &format!("{form}&username=alice&password=pw"),
            &[],
        )
        .await?;
        assert_eq!(status, StatusCode::FOUND, "{label} still logs in");
        assert_eq!(
            fields.get("location").and_then(|value| value.to_str().ok()),
            Some("/"),
            "{label} falls back to the site root"
        );
    }
    Ok(())
}

#[tokio::test]
async fn session_cookie_bound_to_site() -> Result<()> {
    let backend = echo_backend().await?;
    let alpha = auth_site("a.test", "alpha", backend.addr, |site| {
        site.web_auth = true;
        site.users = vec!["alice:pw".to_owned()];
    });
    let beta = auth_site("b.test", "beta", backend.addr, |site| {
        site.web_auth = true;
        site.users = vec!["alice:pw".to_owned()];
    });
    let gateway = spawn_auth_gateway(vec![alpha, beta], b"bind-secret", vec![]).await?;

    // 在 A 站登录。
    let (_, fields, _) = login(
        gateway,
        "a.test",
        "http://a.test",
        "next=%2F&username=alice&password=pw",
        &[],
    )
    .await?;
    let session = set_cookie(&fields, "gately_site_").expect("alpha session cookie");

    // 同站有效。
    let (status, _, _) = send(
        gateway,
        "GET",
        "/",
        "a.test",
        &[cookie_header(&session)],
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "the cookie admits its own site");

    // B 站（不同 key → 不同 Cookie 名 + 不同会话 host）：重新登录。
    let (status, fields, _) = send(
        gateway,
        "GET",
        "/",
        "b.test",
        &[cookie_header(&session)],
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::FOUND, "the cookie does not admit b.test");
    assert_eq!(
        fields.get("location").and_then(|value| value.to_str().ok()),
        Some(format!("{AUTH_PATH}?next=/").as_str()),
        "b.test bounces to its own login page"
    );
    Ok(())
}

#[tokio::test]
async fn shared_user_totp_step() -> Result<()> {
    let backend = echo_backend().await?;
    const TOTP_SEED: &str = "JBSWY3DPEHPK3PXP";
    let site = auth_site("s.test", "totp", backend.addr, |site| {
        site.web_auth = true;
        site.shared_users = true;
    });
    let gateway = spawn_auth_gateway(
        vec![site],
        b"totp-secret",
        vec![shared_user("carol", "pw", TOTP_SEED)],
    )
    .await?;

    // 密码步：TOTP 共享用户进入验证码步（need_code 页面 + 一次性令牌）。
    let (status, fields, body) = login(
        gateway,
        "s.test",
        "http://s.test",
        "next=%2F&username=carol&password=pw",
        &[],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "the password step needs the code");
    assert!(
        body.contains(r#"name="code""#),
        "the page shows the code input: {body}"
    );
    let token = set_cookie(&fields, "gately_totp=").expect("the one-time token cookie");
    assert!(
        set_cookie(&fields, "gately_site_").is_none(),
        "no session cookie before the code step"
    );

    // 验证码步：令牌 + 正确的验证码 → 会话 Cookie，令牌被消费并清除。
    let code = totp_code(TOTP_SEED, unix_now());
    let form = format!("next=%2F&username=carol&password=pw&code={code}");
    let (status, fields, _) = login(
        gateway,
        "s.test",
        "http://s.test",
        &form,
        &[&token],
    )
    .await?;
    assert_eq!(status, StatusCode::FOUND, "a valid code completes the login");
    let session = set_cookie(&fields, "gately_site_").expect("the session cookie");
    assert!(
        set_cookie_raw(&fields, "gately_totp=")
            .is_some_and(|value| value.ends_with("Max-Age=0")),
        "the token cookie is cleared after the step"
    );

    // 会话有效。
    let (status, _, _) = send(
        gateway,
        "GET",
        "/",
        "s.test",
        &[cookie_header(&session)],
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "the session admits");

    // 令牌重放：同一令牌第二次使用被拒绝（无新会话 Cookie）。
    let replay = format!("next=%2F&username=carol&password=pw&code={code}");
    let (status, fields, body) = login(
        gateway,
        "s.test",
        "http://s.test",
        &replay,
        &[&token],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "the replayed token is rejected");
    assert!(
        body.contains("验证码错误"),
        "the rejection is rendered: {body}"
    );
    assert!(
        set_cookie(&fields, "gately_site_").is_none(),
        "a rejected step never sets a session cookie"
    );
    Ok(())
}

#[tokio::test]
async fn auth_paths_bypass_path_rules_but_not_access_control() -> Result<()> {
    let backend = echo_backend().await?;
    let site = auth_site("p.test", "reserved", backend.addr, |site| {
        site.web_auth = true;
        site.users = vec!["alice:pw".to_owned()];
    });
    let gateway = spawn_auth_gateway(vec![site], b"reserved-secret", vec![]).await?;

    let hits = backend.hits.load(Ordering::SeqCst);
    // 登录页在任何站点路径规则下可达：200（登录页）而非代理转发。
    let (status, _, body) = send(gateway, "GET", AUTH_PATH, "p.test", &[], None).await?;
    assert_eq!(status, StatusCode::OK, "the login page is always reachable");
    assert!(
        body.contains("<form"),
        "the reply is the login page, not the backend echo: {body}"
    );
    assert_eq!(
        backend.hits.load(Ordering::SeqCst),
        hits,
        "reserved-path GETs never proxy"
    );

    // 未知的 auth 子路径：404（同样不代理）。
    let (status, _, body) =
        send(gateway, "GET", &format!("{AUTH_PATH}/bogus"), "p.test", &[], None).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        !body.contains("target"),
        "the 404 is the gateway's own, not a proxy reply: {body}"
    );

    // 退出：清 Cookie + 302 回根。
    let (status, fields, _) =
        send(gateway, "POST", &format!("{AUTH_PATH}/logout"), "p.test", &[], None).await?;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        fields.get("location").and_then(|value| value.to_str().ok()),
        Some("/")
    );
    let cleared = set_cookie_raw(&fields, "gately_site_").expect("the cleared cookie");
    assert!(
        cleared.ends_with("Max-Age=0"),
        "logout expires the session cookie: {cleared}"
    );

    // 未登录的普通路径仍然要登录（访问控制不受保留路径影响）。
    let (status, fields, _) = send(gateway, "GET", "/", "p.test", &[], None).await?;
    assert_eq!(status, StatusCode::FOUND, "ordinary paths still require login");
    assert_eq!(
        fields.get("location").and_then(|value| value.to_str().ok()),
        Some(format!("{AUTH_PATH}?next=/").as_str())
    );
    assert_eq!(
        backend.hits.load(Ordering::SeqCst),
        hits,
        "none of the reserved-path traffic reached the backend"
    );
    Ok(())
}
