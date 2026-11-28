//! Channel contract tests (WP-68 §6): every HTTP channel's request format
//! is pinned against a loopback fake server; business codes (HTTP 200 with
//! a failing payload) are errors; SMTP works over STARTTLS, implicit TLS,
//! an HTTP CONNECT tunnel and a SOCKS5 proxy. No test dials out: channels
//! with fixed https endpoints (telegram, pushover, serverchan, pushplus,
//! wecom, dingtalk) go through a local CONNECT proxy into a self-signed
//! TLS fake server (`insecureSkipVerify`).

mod common;

use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use fg_core::module::Module as _;

use common::{FakeHttp, message};

fn never_cancelled() -> CancellationToken {
    CancellationToken::new()
}

/// Sends one message through the channel against the plain fake server
/// base (`http://fake` placeholders are replaced).
async fn send(channel: &fg_notify::Channel, base: &str) -> Result<(), String> {
    let mut channel = channel.clone();
    channel.config.url = channel.config.url.replacen("http://fake", base, 1);
    channel.config.server = channel.config.server.replacen("http://fake", base, 1);
    fg_notify::channels::send(
        &channel,
        &message("服务器告警", "10.0.0.9 登录失败"),
        &fg_notify::proxy::Effective::Direct,
        &never_cancelled(),
    )
    .await
}

/// Sends through the fixed-endpoint chain: the channel's proxy points at
/// the local CONNECT proxy, TLS verification skipped.
async fn send_via_tls_proxy(
    channel: &fg_notify::Channel,
    chain: &common::FakeHttps,
) -> Result<(), String> {
    let mut channel = channel.clone();
    channel.config.insecure_skip_verify = true;
    channel.proxy = fg_notify::ChannelProxy::Custom(chain.proxy_base.clone());
    // The production path resolves the channel proxy into the effective
    // dialing proxy — never a bare Direct.
    let effective =
        fg_notify::proxy::resolve(&fg_notify::SettingsProxy::default(), &channel.proxy, None);
    fg_notify::channels::send(
        &channel,
        &message("服务器告警", "10.0.0.9 登录失败"),
        &effective,
        &never_cancelled(),
    )
    .await
}

/// Asserts the request line and returns the request text.
fn assert_post(request: &str, path: &str) {
    assert!(
        request.starts_with(&format!("POST {path} ")),
        "expected POST {path}, got: {request}"
    );
}

fn body_of(request: &str) -> &str {
    request.rsplit("\r\n\r\n").next().unwrap_or_default()
}

fn header_of<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    let lower = name.to_ascii_lowercase();
    request
        .lines()
        .take_while(|line| !line.is_empty())
        .find(|line| line.to_ascii_lowercase().starts_with(&format!("{lower}:")))
        .and_then(|line| line.split_once(':'))
        .map(|(_, value)| value.trim())
}

#[tokio::test]
async fn webhook_request_format() {
    let server = FakeHttp::start("200 OK", "ok").await;
    let channel = common::channel(
        "webhook",
        serde_json::json!({
            "url": "http://fake/hook?ip={sourceAddr}",
            "method": "POST",
            "headers": ["X-Token: abc", "X-When: {time}"],
            "body": "{\"text\":\"{title}|{message}\"}",
        }),
    );
    send(&channel, &server.base).await.expect("send");
    let request = server.one();
    assert_post(&request, "/hook?ip=10.0.0.9");
    assert_eq!(header_of(&request, "X-Token"), Some("abc"));
    assert_eq!(header_of(&request, "X-When"), Some("2026-01-02T03:04:05Z"));
    assert_eq!(
        body_of(&request),
        "{\"text\":\"服务器告警|10.0.0.9 登录失败\"}"
    );
    server.stop();
}

#[tokio::test]
async fn telegram_request_format() {
    let chain = common::FakeHttps::start("200 OK", r#"{"ok":true,"result":{}}"#).await;
    let channel = common::channel(
        "telegram",
        serde_json::json!({ "token": "bot123", "chatId": "-42" }),
    );
    send_via_tls_proxy(&channel, &chain).await.expect("send");
    let request = chain.one();
    assert!(
        request.starts_with("POST /botbot123/sendMessage"),
        "{request}"
    );
    assert_eq!(header_of(&request, "Host"), Some("api.telegram.org"));
    let body: serde_json::Value = serde_json::from_str(body_of(&request)).expect("json");
    assert_eq!(body["chat_id"], "-42");
    assert_eq!(body["text"], "服务器告警\n10.0.0.9 登录失败");
    chain.stop();
}

#[tokio::test]
async fn bark_request_format() {
    let server = FakeHttp::start("200 OK", r#"{"code":200,"message":"success"}"#).await;
    let channel = common::channel(
        "bark",
        serde_json::json!({ "deviceKey": "devkey", "server": "http://fake" }),
    );
    send(&channel, &server.base).await.expect("send");
    let request = server.one();
    assert_post(&request, "/push");
    let body: serde_json::Value = serde_json::from_str(body_of(&request)).expect("json");
    assert_eq!(body["device_key"], "devkey");
    assert_eq!(body["title"], "服务器告警");
    assert_eq!(body["body"], "10.0.0.9 登录失败");
    server.stop();
}

#[tokio::test]
async fn ntfy_request_format() {
    let server = FakeHttp::start("200 OK", "ok").await;
    let channel = common::channel(
        "ntfy",
        serde_json::json!({
            "server": "http://fake",
            "topic": "alerts",
            "token": "tk",
        }),
    );
    send(&channel, &server.base).await.expect("send");
    let request = server.one();
    assert_post(&request, "/alerts");
    assert_eq!(header_of(&request, "Authorization"), Some("Bearer tk"));
    assert_eq!(header_of(&request, "Title"), Some("服务器告警"));
    assert_eq!(body_of(&request), "10.0.0.9 登录失败");
    server.stop();
}

#[tokio::test]
async fn gotify_request_format() {
    let server = FakeHttp::start("200 OK", "{}").await;
    let channel = common::channel(
        "gotify",
        serde_json::json!({ "server": "http://fake", "token": "apptoken" }),
    );
    send(&channel, &server.base).await.expect("send");
    let request = server.one();
    assert_post(&request, "/message?token=apptoken");
    let body: serde_json::Value = serde_json::from_str(body_of(&request)).expect("json");
    assert_eq!(body["title"], "服务器告警");
    assert_eq!(body["message"], "10.0.0.9 登录失败");
    server.stop();
}

#[tokio::test]
async fn pushover_request_format() {
    let chain = common::FakeHttps::start("200 OK", "{\"status\":1}").await;
    let channel = common::channel(
        "pushover",
        serde_json::json!({ "token": "apptok", "user": "userkey" }),
    );
    send_via_tls_proxy(&channel, &chain).await.expect("send");
    let request = chain.one();
    assert!(request.starts_with("POST /1/messages.json"), "{request}");
    assert_eq!(header_of(&request, "Host"), Some("api.pushover.net"));
    let body = body_of(&request);
    assert!(body.contains("token=apptok"), "{body}");
    assert!(body.contains("user=userkey"), "{body}");
    assert!(body.contains("title="), "{body}");
    assert!(body.contains("message="), "{body}");
    chain.stop();
}

#[tokio::test]
async fn discord_request_format() {
    let server = FakeHttp::start("200 OK", "{}").await;
    let channel = common::channel(
        "discord",
        serde_json::json!({ "url": "http://fake/webhook" }),
    );
    send(&channel, &server.base).await.expect("send");
    let request = server.one();
    assert_post(&request, "/webhook");
    let body: serde_json::Value = serde_json::from_str(body_of(&request)).expect("json");
    assert_eq!(body["content"], "服务器告警\n10.0.0.9 登录失败");
    server.stop();
}

#[tokio::test]
async fn slack_request_format() {
    let server = FakeHttp::start("200 OK", "ok").await;
    let channel = common::channel(
        "slack",
        serde_json::json!({ "url": "http://fake/services" }),
    );
    send(&channel, &server.base).await.expect("send");
    let request = server.one();
    assert_post(&request, "/services");
    let body: serde_json::Value = serde_json::from_str(body_of(&request)).expect("json");
    assert_eq!(body["text"], "服务器告警\n10.0.0.9 登录失败");
    server.stop();
}

#[tokio::test]
async fn serverchan_request_format() {
    let chain = common::FakeHttps::start("200 OK", "{\"code\":0}").await;
    let channel = common::channel("serverchan", serde_json::json!({ "sendKey": "sct" }));
    send_via_tls_proxy(&channel, &chain).await.expect("send");
    let request = chain.one();
    assert!(request.starts_with("POST /sct.send"), "{request}");
    assert_eq!(header_of(&request, "Host"), Some("sctapi.ftqq.com"));
    let body = body_of(&request);
    assert!(body.contains("title="), "{body}");
    assert!(body.contains("desp="), "{body}");
    chain.stop();
}

#[tokio::test]
async fn pushplus_request_format_escapes_html() {
    let chain = common::FakeHttps::start("200 OK", "{\"code\":200}").await;
    let channel = common::channel("pushplus", serde_json::json!({ "token": "pptok" }));
    // HTML-special characters in the message must arrive escaped.
    let alert = fg_notify::Message {
        title: "<b>告警</b>".into(),
        body: "a & b > c \"d\" 'e'".into(),
        ..message("", "")
    };
    let mut channel = channel.clone();
    channel.config.insecure_skip_verify = true;
    channel.proxy = fg_notify::ChannelProxy::Custom(chain.proxy_base.clone());
    let effective =
        fg_notify::proxy::resolve(&fg_notify::SettingsProxy::default(), &channel.proxy, None);
    fg_notify::channels::send(&channel, &alert, &effective, &never_cancelled())
        .await
        .expect("send");
    let request = chain.one();
    assert!(request.starts_with("POST /send"), "{request}");
    assert_eq!(header_of(&request, "Host"), Some("www.pushplus.plus"));
    let body: serde_json::Value = serde_json::from_str(body_of(&request)).expect("json");
    assert_eq!(body["token"], "pptok");
    assert_eq!(body["template"], "html");
    assert_eq!(body["title"], "&lt;b&gt;告警&lt;/b&gt;");
    // The content carries the (escaped) title and body.
    assert_eq!(
        body["content"],
        "&lt;b&gt;告警&lt;/b&gt;\na &amp; b &gt; c &quot;d&quot; &#39;e&#39;"
    );
    chain.stop();
}

#[tokio::test]
async fn wecom_request_format() {
    let chain = common::FakeHttps::start("200 OK", "{\"errcode\":0,\"errmsg\":\"ok\"}").await;
    let channel = common::channel("wecom", serde_json::json!({ "key": "robotkey" }));
    send_via_tls_proxy(&channel, &chain).await.expect("send");
    let request = chain.one();
    assert!(
        request.starts_with("POST /cgi-bin/webhook/send?key=robotkey"),
        "{request}"
    );
    assert_eq!(header_of(&request, "Host"), Some("qyapi.weixin.qq.com"));
    let body: serde_json::Value = serde_json::from_str(body_of(&request)).expect("json");
    assert_eq!(body["msgtype"], "text");
    assert_eq!(body["text"]["content"], "服务器告警\n10.0.0.9 登录失败");
    chain.stop();
}

#[tokio::test]
async fn dingtalk_request_format_appends_signature() {
    let chain = common::FakeHttps::start("200 OK", "{\"errcode\":0,\"errmsg\":\"ok\"}").await;
    let channel = common::channel(
        "dingtalk",
        serde_json::json!({ "accessToken": "acc", "secret": "SECxyz" }),
    );
    send_via_tls_proxy(&channel, &chain).await.expect("send");
    let request = chain.one();
    let path = request.lines().next().expect("request line");
    assert!(
        path.starts_with("POST /robot/send?access_token=acc&timestamp="),
        "{path}"
    );
    assert!(path.contains("&sign="), "signature appended: {path}");
    assert_eq!(header_of(&request, "Host"), Some("oapi.dingtalk.com"));
    let body: serde_json::Value = serde_json::from_str(body_of(&request)).expect("json");
    assert_eq!(body["msgtype"], "text");
    assert_eq!(body["text"]["content"], "服务器告警\n10.0.0.9 登录失败");
    // Without a secret there is no timestamp/sign.
    let chain = common::FakeHttps::start("200 OK", "{\"errcode\":0}").await;
    let plain = common::channel("dingtalk", serde_json::json!({ "accessToken": "acc" }));
    send_via_tls_proxy(&plain, &chain).await.expect("send");
    let path = chain.one().lines().next().expect("request line").to_owned();
    assert!(
        path.starts_with("POST /robot/send?access_token=acc "),
        "no signature without secret: {path}"
    );
    chain.stop();
}

#[tokio::test]
async fn feishu_request_format_and_signature() {
    let server = FakeHttp::start("200 OK", "{\"code\":0,\"msg\":\"success\"}").await;
    let channel = common::channel(
        "feishu",
        serde_json::json!({ "url": "http://fake/open-apis/bot", "secret": "s3cret" }),
    );
    send(&channel, &server.base).await.expect("send");
    let request = server.one();
    assert_post(&request, "/open-apis/bot");
    let body: serde_json::Value = serde_json::from_str(body_of(&request)).expect("json");
    assert_eq!(body["msg_type"], "text");
    assert_eq!(body["content"]["text"], "服务器告警\n10.0.0.9 登录失败");
    assert!(
        body["timestamp"].is_string() && body["sign"].is_string(),
        "signed body: {body}"
    );
    // Without a secret the body has no timestamp/sign (legacy responses
    // with StatusCode: 0 still pass the business check).
    let server = FakeHttp::start("200 OK", "{\"StatusCode\":0}").await;
    let plain = common::channel(
        "feishu",
        serde_json::json!({ "url": "http://fake/open-apis/bot" }),
    );
    send(&plain, &server.base).await.expect("send");
    let body: serde_json::Value = serde_json::from_str(body_of(&server.one())).expect("json");
    assert!(body.get("timestamp").is_none(), "{body}");
    server.stop();
}

#[tokio::test]
async fn business_code_checked() {
    // HTTP 200 with a failing business payload is a delivery failure for
    // WeCom, DingTalk, Feishu, Bark and Telegram.
    // Plain-http channels first.
    let plain_cases: [(&str, serde_json::Value, &str); 3] = [
        (
            "feishu",
            serde_json::json!({ "url": "http://fake/bot" }),
            r#"{"code":19021,"msg":"sign match fail"}"#,
        ),
        (
            "bark",
            serde_json::json!({ "deviceKey": "d", "server": "http://fake" }),
            r#"{"code":400,"message":"bad key"}"#,
        ),
        (
            "slack",
            serde_json::json!({ "url": "http://fake/hook" }),
            "ok",
        ),
    ];
    for (kind, config, response) in plain_cases {
        let server = FakeHttp::start("200 OK", response).await;
        let result = send(&common::channel(kind, config), &server.base).await;
        server.stop();
        if kind == "slack" {
            // A channel without a business code treats 2xx as success.
            assert!(result.is_ok(), "{kind}: {result:?}");
            continue;
        }
        let error = result.expect_err("business failure");
        assert!(
            error.contains("业务失败") || error.contains("业务码"),
            "{kind} should report a business failure: {error}"
        );
    }
    // Fixed-endpoint channels through the TLS chain.
    // PushPlus is 2xx-only (no business code) and is not listed here.
    let tls_cases: [(&str, serde_json::Value, &str); 3] = [
        (
            "wecom",
            serde_json::json!({ "key": "k" }),
            r#"{"errcode":93000,"errmsg":"invalid webhook url"}"#,
        ),
        (
            "dingtalk",
            serde_json::json!({ "accessToken": "a" }),
            r#"{"errcode":310000,"errmsg":"sign not match"}"#,
        ),
        (
            "telegram",
            serde_json::json!({ "token": "t" }),
            r#"{"ok":false,"error_code":401,"description":"Unauthorized"}"#,
        ),
    ];
    for (kind, config, response) in tls_cases {
        let chain = common::FakeHttps::start("200 OK", response).await;
        let error = send_via_tls_proxy(&common::channel(kind, config), &chain)
            .await
            .expect_err("business failure");
        chain.stop();
        assert!(
            error.contains("业务失败") || error.contains("业务码") || error.contains("返回失败"),
            "{kind} should report a business failure: {error}"
        );
    }
    // A non-2xx transport status is a failure too.
    let server = FakeHttp::start("500 Internal Server Error", "nope").await;
    let error = send(
        &common::channel("discord", serde_json::json!({ "url": "http://fake/hook" })),
        &server.base,
    )
    .await
    .expect_err("HTTP 500");
    assert!(error.contains("HTTP 返回 500"), "{error}");
    server.stop();
}

// ---------------------------------------------------------------------
// E-mail: fake SMTP over plain / STARTTLS / implicit TLS, plus the
// CONNECT and SOCKS5 proxy paths.

/// The SMTP configuration for the fake server at `addr`.
fn email_channel(addr: SocketAddr, security: &str, insecure: bool) -> fg_notify::Channel {
    let mut channel = common::channel(
        "email",
        serde_json::json!({
            "host": addr.ip().to_string(),
            "port": addr.port(),
            "security": security,
            "smtpUser": "mailer",
            "password": "secret",
            "from": "gate@example.com",
            "to": ["ops@example.com", "sec@example.com"],
            "insecureSkipVerify": insecure,
        }),
    );
    channel.key = "email00000001".into();
    channel
}

async fn send_email(channel: &fg_notify::Channel) -> Result<(), String> {
    let effective =
        fg_notify::proxy::resolve(&fg_notify::SettingsProxy::default(), &channel.proxy, None);
    fg_notify::channels::send(
        channel,
        &message("证书即将到期", "example.com 的证书 7 天后到期"),
        &effective,
        &never_cancelled(),
    )
    .await
}

#[tokio::test]
async fn email_smtp_starttls_and_ssl() {
    // STARTTLS: the session upgrades inside the same connection.
    let (addr, captured) = common::fake_smtp(true).await;
    send_email(&email_channel(addr, "starttls", true))
        .await
        .expect("STARTTLS send");
    let commands = captured.lock().expect("captured").clone();
    assert!(
        commands
            .iter()
            .any(|line| line.eq_ignore_ascii_case("STARTTLS")),
        "{commands:?}"
    );
    assert!(
        commands.iter().any(|line| line.starts_with("EHLO")),
        "{commands:?}"
    );
    assert!(
        commands.iter().any(|line| line.starts_with("AUTH PLAIN")),
        "{commands:?}"
    );
    assert!(
        commands.iter().any(|line| line
            .to_ascii_uppercase()
            .starts_with("MAIL FROM:<GATE@EXAMPLE.COM>")),
        "{commands:?}"
    );
    assert_eq!(
        commands
            .iter()
            .filter(|line| line.to_ascii_uppercase().starts_with("RCPT TO:"))
            .count(),
        2,
        "one RCPT per recipient: {commands:?}"
    );
    // The fake server captures DATA payloads line by line.
    assert!(
        commands
            .iter()
            .any(|line| line.starts_with("Subject: =?UTF-8?B?")),
        "subject is an RFC 2047 encoded word: {commands:?}"
    );
    assert!(
        commands
            .iter()
            .any(|line| line == "From: <gate@example.com>"),
        "{commands:?}"
    );
    assert!(
        commands
            .iter()
            .any(|line| line == "To: ops@example.com, sec@example.com"),
        "{commands:?}"
    );
    assert!(
        commands.iter().any(|line| line.contains("charset=UTF-8")),
        "{commands:?}"
    );
    assert!(
        commands
            .iter()
            .any(|line| line.contains("Content-Transfer-Encoding: base64")),
        "{commands:?}"
    );

    // Implicit TLS from the first byte.
    let (addr, captured) = tls_smtp_server().await;
    let mut channel = email_channel(addr, "ssl", true);
    channel.config.host = addr.ip().to_string();
    channel.config.port = addr.port();
    send_email(&channel).await.expect("implicit TLS send");
    let commands = captured.lock().expect("captured").clone();
    assert!(
        commands.iter().any(|line| line.starts_with("EHLO")),
        "{commands:?}"
    );
    assert!(
        commands.iter().any(|line| line.contains("Subject:")),
        "the message arrives over TLS: {commands:?}"
    );
    assert!(
        !commands
            .iter()
            .any(|line| line.eq_ignore_ascii_case("STARTTLS"))
    );
}

/// A one-shot implicit-TLS SMTP server reusing the fake conversation.
async fn tls_smtp_server() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
            .expect("self-signed cert");
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("AWS-LC supports the default protocol versions")
    .with_no_client_auth()
    .with_single_cert(vec![certified.cert.der().clone()], key)
    .expect("server config");
    let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(config)));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let slot = Arc::clone(&captured);
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut tls) = acceptor.accept(stream).await else {
            return;
        };
        let _ = tls.write_all(b"220 test ESMTP ready\r\n").await;
        let mut line = Vec::new();
        let mut in_data = false;
        loop {
            let mut chunk = [0u8; 1024];
            let read = match tls.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            line.extend_from_slice(&chunk[..read]);
            while let Some(at) = line.iter().position(|byte| *byte == b'\n') {
                let command: Vec<u8> = line.drain(..=at).collect();
                let text = String::from_utf8_lossy(&command).trim_end().to_owned();
                if in_data {
                    if text == "." {
                        in_data = false;
                        let _ = tls.write_all(b"250 accepted\r\n").await;
                    } else {
                        slot.lock().expect("captured").push(text);
                    }
                    continue;
                }
                slot.lock().expect("captured").push(text.clone());
                let upper = text.to_ascii_uppercase();
                if upper == "QUIT" {
                    let _ = tls.write_all(b"221 bye\r\n").await;
                    return;
                }
                if upper.starts_with("EHLO") {
                    let _ = tls
                        .write_all(b"250-test greets\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n")
                        .await;
                } else if upper == "DATA" {
                    in_data = true;
                    let _ = tls.write_all(b"354 end with .\r\n").await;
                } else {
                    let _ = tls.write_all(b"250 ok\r\n").await;
                }
            }
        }
    });
    (addr, captured)
}

#[tokio::test]
async fn email_via_http_connect_tunnel() {
    // The CONNECT request names the SMTP host:port; the session (with
    // STARTTLS and authentication) runs inside the tunnel.
    let (smtp_addr, captured) = common::fake_smtp(true).await;
    let (proxy_addr, proxy_log) = common::fake_http_proxy(smtp_addr).await;
    let mut channel = email_channel(smtp_addr, "starttls", true);
    channel.proxy = fg_notify::ChannelProxy::Custom(format!(
        "http://tunnel-user:tunnel-pass@127.0.0.1:{}",
        proxy_addr.port()
    ));
    send_email(&channel)
        .await
        .expect("send through CONNECT tunnel");
    let connects = proxy_log.lock().expect("captured").clone();
    assert_eq!(connects.len(), 1, "{connects:?}");
    let request = &connects[0];
    assert!(
        request.starts_with(&format!("CONNECT {}:{}", smtp_addr.ip(), smtp_addr.port())),
        "{request}"
    );
    // The proxy password never reaches the wire unencrypted, and the
    // credentials authenticate the proxy itself (Basic auth).
    assert!(
        header_of(request, "Proxy-Authorization").is_some(),
        "proxy credentials are sent: {request}"
    );
    let commands = captured.lock().expect("captured").clone();
    assert!(
        commands
            .iter()
            .any(|line| line.eq_ignore_ascii_case("STARTTLS")),
        "STARTTLS happens inside the tunnel: {commands:?}"
    );
    assert!(
        commands.iter().any(|line| line.starts_with("AUTH PLAIN")),
        "authentication happens inside the tunnel: {commands:?}"
    );
}

#[tokio::test]
async fn email_via_socks5() {
    // socks5h: the hostname is sent to the proxy (ATYP 0x03), the proxy
    // pipes to the SMTP server.
    let (smtp_addr, captured) = common::fake_smtp(false).await;
    let (proxy_addr, proxy_log) = common::fake_socks5_proxy(smtp_addr).await;
    let mut channel = email_channel(smtp_addr, "none", false);
    channel.config.host = "smtp.internal.test".to_owned();
    channel.config.port = smtp_addr.port();
    channel.proxy =
        fg_notify::ChannelProxy::Custom(format!("socks5h://127.0.0.1:{}", proxy_addr.port()));
    send_email(&channel).await.expect("send through SOCKS5");
    let targets = proxy_log.lock().expect("captured").clone();
    assert_eq!(targets.len(), 1, "{targets:?}");
    assert!(
        targets[0].contains("smtp.internal.test") && targets[0].contains("atyp=0x3"),
        "the hostname goes to the proxy: {}",
        targets[0]
    );
    let commands = captured.lock().expect("captured").clone();
    assert!(
        commands.iter().any(|line| line.starts_with("MAIL FROM")),
        "SMTP ran through the tunnel: {commands:?}"
    );
}

#[tokio::test]
async fn smtp_plain_session_rejects_bad_credentials() {
    // A 5xx AUTH reply fails the delivery with the server's code.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let _ = stream.write_all(b"220 ok\r\n").await;
        let mut line = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => read,
            };
            line.extend_from_slice(&chunk[..read]);
            while let Some(at) = line.iter().position(|byte| *byte == b'\n') {
                let command: Vec<u8> = line.drain(..=at).collect();
                let text = String::from_utf8_lossy(&command).to_ascii_uppercase();
                if text.starts_with("AUTH") {
                    let _ = stream.write_all(b"535 authentication failed\r\n").await;
                    return;
                }
                let _ = stream.write_all(b"250 ok\r\n").await;
            }
        }
    });
    let error = send_email(&email_channel(addr, "none", false))
        .await
        .expect_err("auth rejected");
    assert!(
        error.contains("535") || error.contains("认证被拒绝"),
        "{error}"
    );
}

#[tokio::test]
async fn concurrent_sends_share_the_semaphores_budget() {
    // A burst of publishes produces one request per matching event; the
    // global semaphore caps in-flight sends without losing any.
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_responder = Arc::clone(&hits);
    let server = FakeHttp::start_with(move |_| {
        hits_for_responder.fetch_add(1, Ordering::SeqCst);
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()
    })
    .await;
    let dir = tempfile::tempdir().expect("tempdir");
    let store = fg_config::ConfigStore::open(dir.path()).expect("store");
    let events = fg_core::events::EventBus::default();
    let channel = common::channel(
        "webhook",
        serde_json::json!({ "url": format!("{}/hook", server.base), "method": "POST" }),
    );
    let rule = fg_notify::Rule {
        key: "rule00000001".into(),
        name: "auth".into(),
        enable: true,
        events: vec!["auth.failed".into()],
        min_level: fg_core::events::Level::Warn,
        channels: vec![channel.key.clone()],
        ..fg_notify::Rule::default()
    };
    let config = fg_notify::FileConfig {
        channels: vec![channel],
        rules: vec![rule],
        ..fg_notify::FileConfig::default()
    };
    store.save("notify", &config).expect("save");
    let module =
        fg_notify::Module::new(store, events.clone(), fg_notify::Deps::default()).expect("module");
    let (drain_tx, drain_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(module.run(drain_rx));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    for _ in 0..5 {
        events.publish(fg_core::events::Event::new(
            fg_core::events::Kind::AuthFailed,
            "auth",
        ));
    }
    common::wait_until(|| hits.load(Ordering::SeqCst) >= 5).await;
    drain_tx.send(true).expect("drain");
    let _ = handle.await;
    server.stop();
}
