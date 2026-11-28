//! Login gate integration tests (WP-44 §6): the loopback-only HTTP
//! endpoint speaks frp's server-plugin protocol — deny list first, then
//! the token, then the allow / deny mode; allowed Login / NewProxy
//! operations reach the runtime hook.

mod common;

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use fg_frp::login_check::{GateHook, LoginGate, static_sets};
use fg_frp::model::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The observed hook calls of a test gate.
type Observed = Arc<Mutex<Vec<(String, GateHook)>>>;

async fn start_gate(
    servers: HashMap<String, Server>,
    sets: fg_frp::login_check::SetLookup,
) -> (Arc<LoginGate>, Observed) {
    let observed: Observed = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&observed);
    let gate = Arc::new(
        LoginGate::start(
            Arc::new(tokio::sync::RwLock::new(servers)),
            sets,
            Arc::new(move |key, _addr, hook| {
                sink.lock()
                    .expect("observed lock")
                    .push((key.to_owned(), hook));
            }),
        )
        .await
        .expect("gate start"),
    );
    (gate, observed)
}

fn server_config(token: &str, mode: &str, allow: &[&str], deny: &[&str]) -> Server {
    Server {
        key: "s1".into(),
        name: "main".into(),
        token: token.to_owned(),
        ip_mode: mode.to_owned(),
        ip_list: allow.iter().map(|s| s.to_string()).collect(),
        ip_deny_list: deny.iter().map(|s| s.to_string()).collect(),
        ..Server::default()
    }
}

/// POSTs one plugin request over raw TCP and returns the parsed JSON.
async fn post_plugin(
    addr: SocketAddr,
    path: &str,
    op: &str,
    content: serde_json::Value,
) -> serde_json::Value {
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let body = serde_json::json!({ "version": "0.1.0", "op": op, "content": content });
    let request = format!(
        "POST {path}?version=0.1.0&op={op} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.to_string().len(),
        body
    );
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read");
    let text = String::from_utf8_lossy(&raw);
    let split = text.find("\r\n\r\n").expect("response header end");
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "plugin answers 200: {split}"
    );
    serde_json::from_str(&text[split + 4..]).expect("json body")
}

fn login_content(client_address: &str, token: &str) -> serde_json::Value {
    serde_json::json!({
        "version": "0.52.0",
        "hostname": "home",
        "os": "linux",
        "arch": "arm64",
        "user": "u",
        "privilege_key": token,
        "timestamp": 1,
        "client_address": client_address,
    })
}

#[tokio::test]
async fn login_check_allows_and_denies_by_source() {
    let mut sets = HashMap::new();
    sets.insert("office".to_owned(), vec!["198.51.100.0/24".to_owned()]);
    let mut white = server_config("tok", "white", &["10.0.0.1"], &[]);
    white.ip_sets = vec!["office".into()];
    let (gate, observed) =
        start_gate(HashMap::from([("s1".to_owned(), white)]), static_sets(sets)).await;
    assert!(
        gate.base_url().starts_with("http://127.0.0.1:"),
        "the gate only listens on the loopback: {}",
        gate.base_url()
    );
    let addr: SocketAddr = gate
        .base_url()
        .trim_start_matches("http://")
        .parse()
        .expect("gate addr");

    // White-listed source with the right token: allowed, Login observed.
    let response = post_plugin(
        addr,
        "/frp/login/s1",
        "Login",
        login_content("10.0.0.1", "tok"),
    )
    .await;
    assert_eq!(response["reject"], false);
    assert_eq!(response["unchange"], true);
    assert_eq!(
        observed.lock().expect("obs").as_slice(),
        [("s1".to_owned(), GateHook::Login)]
    );

    // Not on the white list: rejected with the allow-list reason.
    let response = post_plugin(
        addr,
        "/frp/login/s1",
        "Login",
        login_content("10.0.0.2", "tok"),
    )
    .await;
    assert_eq!(response["reject"], true);
    assert!(
        response["reject_reason"]
            .as_str()
            .expect("reason")
            .contains("not in the allow list")
    );

    // Set members pass the white list too.
    let response = post_plugin(
        addr,
        "/frp/login/s1",
        "Login",
        login_content("198.51.100.7", "tok"),
    )
    .await;
    assert_eq!(response["reject"], false);

    // Black mode: a listed source is rejected, others pass.
    let (gate, _observed) = start_gate(
        HashMap::from([(
            "s1".to_owned(),
            server_config("tok", "black", &["10.0.0.9"], &[]),
        )]),
        static_sets(HashMap::new()),
    )
    .await;
    let addr: SocketAddr = gate
        .base_url()
        .trim_start_matches("http://")
        .parse()
        .unwrap();
    let response = post_plugin(
        addr,
        "/frp/login/s1",
        "Login",
        login_content("10.0.0.9", "tok"),
    )
    .await;
    assert_eq!(response["reject"], true);
    assert!(
        response["reject_reason"]
            .as_str()
            .unwrap()
            .contains("deny list")
    );
    let response = post_plugin(
        addr,
        "/frp/login/s1",
        "Login",
        login_content("10.0.0.8", "tok"),
    )
    .await;
    assert_eq!(response["reject"], false);

    gate.stop();
}

#[tokio::test]
async fn login_check_rejects_deny_first_and_wrong_token() {
    let (gate, observed) = start_gate(
        HashMap::from([(
            "s1".to_owned(),
            server_config("tok", "", &[], &["203.0.113.5"]),
        )]),
        fg_frp::login_check::no_sets(),
    )
    .await;
    let addr: SocketAddr = gate
        .base_url()
        .trim_start_matches("http://")
        .parse()
        .unwrap();

    // Deny list wins even with a wrong token (deny-first order).
    let response = post_plugin(
        addr,
        "/frp/login/s1",
        "Login",
        login_content("203.0.113.5", "wrong"),
    )
    .await;
    assert_eq!(response["reject"], true);
    assert!(
        response["reject_reason"]
            .as_str()
            .expect("reason")
            .contains("is in the deny list")
    );
    assert!(
        observed.lock().expect("obs").is_empty(),
        "denied logins never register"
    );

    // A wrong token on a non-denied source: the gate rejects it (frps
    // would reject it too; the reason is the gate's).
    let response = post_plugin(
        addr,
        "/frp/login/s1",
        "Login",
        login_content("10.0.0.1", "wrong"),
    )
    .await;
    assert_eq!(response["reject"], true);
    assert!(
        response["reject_reason"]
            .as_str()
            .unwrap()
            .contains("token")
    );

    // NewProxy with a remote port: allowed with a valid token and the
    // hook sees the port.
    let response = post_plugin(
        addr,
        "/frp/login/s1",
        "NewProxy",
        serde_json::json!({
            "user": { "user": "u" },
            "proxy_name": "ssh",
            "proxy_type": "tcp",
            "remote_port": 6022,
            "privilege_key": "tok",
            "client_address": "10.0.0.1",
        }),
    )
    .await;
    assert_eq!(response["reject"], false);
    assert_eq!(
        observed.lock().expect("obs").as_slice(),
        [("s1".to_owned(), GateHook::NewProxy(6022))]
    );

    // An unknown instance key is rejected (the path carries the key).
    let response = post_plugin(
        addr,
        "/frp/login/ghost",
        "Login",
        login_content("10.0.0.1", "tok"),
    )
    .await;
    assert_eq!(response["reject"], true);

    gate.stop();
}

#[tokio::test]
async fn login_check_listens_on_loopback_only() {
    let (gate, _observed) = start_gate(
        HashMap::from([("s1".to_owned(), server_config("tok", "", &[], &[]))]),
        fg_frp::login_check::no_sets(),
    )
    .await;
    let addr: SocketAddr = gate
        .base_url()
        .trim_start_matches("http://")
        .parse()
        .unwrap();
    assert!(addr.ip().is_loopback(), "登录检查端点只监听回环：{addr}");
    // A request answered on the loopback proves the endpoint is live.
    let response = post_plugin(
        addr,
        "/frp/login/s1",
        "Login",
        login_content("10.0.0.1", "tok"),
    )
    .await;
    assert_eq!(response["reject"], false);
    gate.stop();
}
