//! Management API integration tests: local shell gate, maxSessions 429,
//! preset reuse & referenced deletion block, security settings session-only
//! gate + TOTP 2FA flow, readonly masking, and Module graceful drain (WP-61 §6).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use fg_config::ConfigStore;
use fg_core::module::Module;
use fg_webterminal::model::{
    Auth, AuthKind, ConnKind, Connection, Preset, Settings, Shortcut, limits,
};
use fg_webterminal::security::totp_code_at;
use fg_webterminal::{WebTerminalHandle, WebTerminalModule};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

async fn call_api(
    addr: SocketAddr,
    method: &str,
    path: &str,
    role: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let payload = body.map(|v| serde_json::to_vec(&v).unwrap());
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if let Some(r) = role {
        req.push_str(&format!("x-fg-caller-role: {r}\r\n"));
    }
    if let Some(ref bytes) = payload {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", bytes.len()));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    if let Some(ref bytes) = payload {
        stream.write_all(bytes).await.unwrap();
    }
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    let sep = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("HTTP response header");
    let head = std::str::from_utf8(&resp[..sep]).unwrap();
    let code: u16 = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let json = serde_json::from_slice(&resp[sep + 4..]).unwrap_or(Value::Null);
    (StatusCode::from_u16(code).unwrap(), json)
}

async fn setup() -> (tempfile::TempDir, Arc<WebTerminalHandle>, SocketAddr) {
    let dir = tempfile::tempdir().unwrap();
    let store = ConfigStore::open(dir.path()).unwrap();
    let handle = WebTerminalHandle::open(store).unwrap();
    let app = handle.router();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (dir, handle, addr)
}

#[tokio::test]
async fn local_shell_disabled_by_default() {
    let (_dir, handle, addr) = setup().await;

    // Local shell is disabled by default -> /shells returns empty.
    let (st, shells) = call_api(addr, "GET", "/api/webterminal/shells", None, None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(shells.as_array().unwrap().is_empty());

    // Create a local connection.
    let conn = Connection {
        key: "local1111111".into(),
        name: "local-sh".into(),
        kind: ConnKind::Local,
        shell_path: "/bin/sh".into(),
        ..Connection::default()
    };
    let (st, _) = call_api(
        addr,
        "POST",
        "/api/webterminal/connections",
        None,
        Some(serde_json::to_value(&conn).unwrap()),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    // Testing a local connection returns 400.
    let (st, _) = call_api(
        addr,
        "POST",
        "/api/webterminal/connections/local1111111/test",
        None,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // Creating a local session while disabled fails (502 connect error).
    let (st, _) = call_api(
        addr,
        "POST",
        "/api/webterminal/sessions",
        None,
        Some(json!({ "connKey": "local1111111" })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_GATEWAY);

    // Enable allowLocalShell via PUT /settings (login session).
    let settings = Settings {
        allow_local_shell: true,
        max_sessions: 2,
        ..Settings::default()
    };
    let (st, _) = call_api(
        addr,
        "PUT",
        "/api/webterminal/settings",
        None,
        Some(serde_json::to_value(&settings).unwrap()),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Now /shells returns available shells.
    let (st, shells) = call_api(addr, "GET", "/api/webterminal/shells", None, None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(!shells.as_array().unwrap().is_empty());

    // Now creating local sessions works AND hitting maxSessions (2) returns 429!
    let (st1, s1) = call_api(
        addr,
        "POST",
        "/api/webterminal/sessions",
        None,
        Some(json!({ "connKey": "local1111111", "cols": 80, "rows": 24 })),
    )
    .await;
    assert_eq!(st1, StatusCode::CREATED);
    let id1 = s1["id"].as_str().unwrap().to_owned();

    // Send a command to the real local shell and observe output!
    let mut attach = handle.sessions.attach(&id1).unwrap();
    assert!(handle.sessions.input(&id1, b"echo hello-local\n".to_vec()));
    let mut collected = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline && !collected.contains("hello-local") {
        if let Ok(Ok(fg_webterminal::session::LiveItem::Data { data, .. })) =
            tokio::time::timeout(Duration::from_millis(200), attach.live.recv()).await
        {
            collected.push_str(&String::from_utf8_lossy(&data));
        }
    }
    assert!(collected.contains("hello-local"), "got {collected:?}");

    let (st2, s2) = call_api(
        addr,
        "POST",
        "/api/webterminal/sessions",
        None,
        Some(json!({ "connKey": "local1111111" })),
    )
    .await;
    assert_eq!(st2, StatusCode::CREATED);
    let id2 = s2["id"].as_str().unwrap().to_owned();

    // 3rd session exceeds maxSessions=2 -> HTTP 429!
    let (st3, _) = call_api(
        addr,
        "POST",
        "/api/webterminal/sessions",
        None,
        Some(json!({ "connKey": "local1111111" })),
    )
    .await;
    assert_eq!(st3, StatusCode::TOO_MANY_REQUESTS);

    // Cleanup sessions.
    let _ = call_api(
        addr,
        "DELETE",
        &format!("/api/webterminal/sessions/{id1}"),
        None,
        None,
    )
    .await;
    let _ = call_api(
        addr,
        "DELETE",
        &format!("/api/webterminal/sessions/{id2}"),
        None,
        None,
    )
    .await;
}

#[tokio::test]
async fn preset_reuse_and_referenced_cannot_delete() {
    let (_dir, _handle, addr) = setup().await;

    // Create credential preset.
    let preset = Preset {
        key: "cred00000001".into(),
        name: "root-pw".into(),
        kind: AuthKind::Password,
        username: "root".into(),
        password: "initial-password".into(),
        ..Preset::default()
    };
    let (st, created) = call_api(
        addr,
        "POST",
        "/api/webterminal/credentials",
        None,
        Some(serde_json::to_value(&preset).unwrap()),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(created["password"], limits::SECRET_MASK);

    // Create connection referencing that preset.
    let conn = Connection {
        key: "ssh000000001".into(),
        name: "prod".into(),
        kind: ConnKind::Ssh,
        host: "10.0.0.1".into(),
        auth: Auth {
            kind: AuthKind::Preset,
            preset: "cred00000001".into(),
            ..Auth::default()
        },
        ..Connection::default()
    };
    let (st, _) = call_api(
        addr,
        "POST",
        "/api/webterminal/connections",
        None,
        Some(serde_json::to_value(&conn).unwrap()),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    // Deleting referenced preset MUST fail with 409 Conflict!
    let (st, _) = call_api(
        addr,
        "DELETE",
        "/api/webterminal/credentials/cred00000001",
        None,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);

    // Batch-deleting referenced preset also fails with 409!
    let (st, _) = call_api(
        addr,
        "POST",
        "/api/webterminal/credentials-delete",
        None,
        Some(json!({ "keys": ["cred00000001"] })),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);

    // Delete connection -> now preset can be deleted cleanly.
    let (st, _) = call_api(
        addr,
        "DELETE",
        "/api/webterminal/connections/ssh000000001",
        None,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, _) = call_api(
        addr,
        "DELETE",
        "/api/webterminal/credentials/cred00000001",
        None,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn security_settings_require_session() {
    let (_dir, handle, addr) = setup().await;

    // API token & readonly MUST get 403 on security settings and PUT /settings!
    for role in ["api-write", "readonly"] {
        let (st, _) = call_api(
            addr,
            "PUT",
            "/api/webterminal/settings",
            Some(role),
            Some(serde_json::to_value(Settings::default()).unwrap()),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::FORBIDDEN,
            "PUT /settings blocked for {role}"
        );

        let (st, _) = call_api(
            addr,
            "POST",
            "/api/webterminal/security/agreement",
            Some(role),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);

        let (st, _) = call_api(
            addr,
            "POST",
            "/api/webterminal/security/2fa/setup",
            Some(role),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    // Login session accepts agreement and completes 2FA setup -> enable -> verify -> disable.
    let (st, ag) = call_api(
        addr,
        "POST",
        "/api/webterminal/security/agreement",
        Some("session"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(ag["agreementAccepted"], true);

    let (st, setup_resp) = call_api(
        addr,
        "POST",
        "/api/webterminal/security/2fa/setup",
        Some("session"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let secret = setup_resp["secret"].as_str().unwrap().to_owned();
    assert!(
        setup_resp["otpauthUri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/")
    );

    let now = handle.two_fa.now();
    let code = totp_code_at(&secret, now).unwrap();
    let (st, en) = call_api(
        addr,
        "POST",
        "/api/webterminal/security/2fa/enable",
        Some("session"),
        Some(json!({ "code": code })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(en["twoFaEnabled"], true);

    // Clear verification state to simulate a fresh session needing 2FA verification.
    handle.two_fa.clear_all();
    let conn = Connection {
        key: "sec000000001".into(),
        name: "box".into(),
        kind: ConnKind::Ssh,
        host: "10.0.0.2".into(),
        auth: Auth {
            kind: AuthKind::Password,
            password: "top-secret".into(),
            ..Auth::default()
        },
        ..Connection::default()
    };
    let (st, _) = call_api(
        addr,
        "POST",
        "/api/webterminal/connections",
        Some("session"),
        Some(serde_json::to_value(&conn).unwrap()),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    // Secrets endpoint MUST be blocked (403) before verify2fa!
    let (st, _) = call_api(
        addr,
        "GET",
        "/api/webterminal/connections/sec000000001/secrets",
        Some("session"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Verify 2FA -> now secrets endpoint returns plaintext!
    let code2 = totp_code_at(&secret, handle.two_fa.now()).unwrap();
    let (st, _) = call_api(
        addr,
        "POST",
        "/api/webterminal/security/verify2fa",
        Some("session"),
        Some(json!({ "code": code2 })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, secrets) = call_api(
        addr,
        "GET",
        "/api/webterminal/connections/sec000000001/secrets",
        Some("session"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(secrets["password"], "top-secret");

    // Disable 2FA with valid code.
    let (st, dis) = call_api(
        addr,
        "POST",
        "/api/webterminal/security/2fa/disable",
        Some("session"),
        Some(json!({ "code": code2 })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(dis["twoFaEnabled"], false);
}

#[tokio::test]
async fn readonly_sees_masked_credentials() {
    let (_dir, _handle, addr) = setup().await;

    let conn = Connection {
        key: "ro0000000001".into(),
        name: "router".into(),
        kind: ConnKind::Ssh,
        host: "192.168.1.1".into(),
        username: "admin".into(),
        auth: Auth {
            kind: AuthKind::Password,
            password: "super-secret".into(),
            key_file: "/etc/secret.key".into(),
            ..Auth::default()
        },
        shortcuts: vec![Shortcut {
            name: "reboot".into(),
            command: "reboot -f".into(),
        }],
        quick_access: vec!["/etc".into()],
        ..Connection::default()
    };
    let (st, _) = call_api(
        addr,
        "POST",
        "/api/webterminal/connections",
        Some("session"),
        Some(serde_json::to_value(&conn).unwrap()),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    let (st, _) = call_api(
        addr,
        "PUT",
        "/api/webterminal/globalshortcuts",
        Some("session"),
        Some(json!([{ "name": "who", "command": "whoami" }])),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Read-only caller sees masked password, masked keyFile, NO shortcuts/commands!
    let (st, list) = call_api(
        addr,
        "GET",
        "/api/webterminal/connections",
        Some("readonly"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let item = &list[0];
    assert_eq!(item["auth"]["password"], limits::SECRET_MASK);
    assert_eq!(item["auth"]["keyFile"], limits::SECRET_MASK);
    assert!(item["shortcuts"].as_array().unwrap().is_empty());
    assert!(item["quickAccess"].as_array().unwrap().is_empty());

    let (st, gshortcuts) = call_api(
        addr,
        "GET",
        "/api/webterminal/globalshortcuts",
        Some("readonly"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(gshortcuts.as_array().unwrap().is_empty());

    // Read-only gets 403 on secrets and mutations!
    let (st, _) = call_api(
        addr,
        "GET",
        "/api/webterminal/connections/ro0000000001/secrets",
        Some("readonly"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn module_run_and_graceful_drain() {
    let dir = tempfile::tempdir().unwrap();
    let store = ConfigStore::open(dir.path()).unwrap();
    let handle = WebTerminalHandle::open(store).unwrap();
    let module = WebTerminalModule::new(Arc::clone(&handle));
    assert_eq!(WebTerminalModule::ID, "webterminal");

    let (drain_tx, drain_rx) = watch::channel(false);
    let task = tokio::spawn(module.run(drain_rx));
    tokio::time::sleep(Duration::from_millis(20)).await;
    drain_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
