//! Management-route integration tests (WP-44 §4): the collection contract
//! (keys, masking, merge semantics, batch shapes, validation problems),
//! the import endpoint (preview / apply), settings, and the install
//! endpoints' status view. Authentication is assumed to be applied by the
//! surrounding management router.

mod common;

use std::sync::Arc;

use axum::{
    body::Body,
    http::{StatusCode, header::CONTENT_TYPE},
};
use fg_config::ConfigStore;
use fg_frp::{FileConfig, RoutesState, mount};
use fg_proc::Proc;
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use tokio::sync::RwLock;

struct App {
    addr: std::net::SocketAddr,
    persisted: Arc<std::sync::Mutex<Vec<FileConfig>>>,
    _dir: tempfile::TempDir,
}

async fn app() -> App {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(ConfigStore::open(dir.path()).expect("store"));
    let proc = Proc::open(&store, None).expect("proc");
    let config = Arc::new(RwLock::new(FileConfig::default()));
    let persisted = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&persisted);
    let persist_store = Arc::clone(&store);
    let persist: fg_frp::PersistFn = Arc::new(move |config| {
        sink.lock().expect("persisted lock").push(config.clone());
        // Also persist through the store so the file round-trips.
        let store = Arc::clone(&persist_store);
        store.save("frp", config).map(|_| ())
    });
    let state = Arc::new(RoutesState {
        config: Arc::clone(&config),
        persist,
        runtime: fg_frp::Runtime::open(
            Arc::clone(&config),
            fg_frp::runtime::Deps {
                proc: Arc::clone(&proc),
                fw_open: None,
                open_ports: None,
                ip_sets: None,
            },
            &store,
        )
        .expect("runtime"),
        proc,
        fetch: None,
    });
    let app = mount(axum::Router::new(), state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    App {
        addr,
        persisted,
        _dir: dir,
    }
}

impl App {
    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let stream = tokio::net::TcpStream::connect(self.addr)
            .await
            .expect("connect");
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .expect("handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let builder = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header(CONTENT_TYPE, "application/json");
        let request = match body {
            Some(body) => builder.body(Body::from(body.to_string())).expect("body"),
            None => builder.body(Body::empty()).expect("body"),
        };
        let response = sender.send_request(request).await.expect("send");
        let status = response.status();
        let bytes = BodyExt::collect(response.into_body())
            .await
            .expect("collect")
            .to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    fn saved(&self) -> FileConfig {
        self.persisted
            .lock()
            .expect("persisted lock")
            .last()
            .cloned()
            .expect("persisted at least once")
    }
}

fn base_client() -> serde_json::Value {
    serde_json::json!({
        "key": "",
        "name": "home",
        "enable": true,
        "serverAddr": "frps.example.com",
        "serverPort": 7000,
        "token": "secret-token",
        "user": "",
        "protocol": "tcp",
        "access": { "httpScheme": "", "httpPort": 0, "httpsPort": 0, "subdomainHost": "" }
    })
}

fn is_generated_key(key: &str) -> bool {
    key.len() == 12
        && key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[tokio::test]
async fn client_collection_follows_contract() {
    let app = app().await;
    // Create: a generated key, masked token in the response.
    let (status, created) = app
        .send("POST", "/api/frp/clients", Some(base_client()))
        .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let key = created["key"].as_str().expect("key").to_owned();
    assert!(is_generated_key(&key), "{created}");
    assert_eq!(created["token"], "********", "secrets masked in views");
    // A read-only status object is embedded.
    assert!(created["status"].is_object(), "{created}");

    // List: masked again, persisted file keeps the real token.
    let (_, list) = app.send("GET", "/api/frp/clients", None).await;
    assert_eq!(list[0]["token"], "********");
    assert_eq!(app.saved().clients[0].token, "secret-token");

    // Secrets endpoint returns the plaintext.
    let (status, secrets) = app
        .send("GET", &format!("/api/frp/clients/{key}/secrets"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(secrets["token"], "secret-token");

    // Update with the mask keeps the stored secret; with a new value it
    // replaces it.
    let mut update = base_client();
    update["token"] = "********".into();
    update["name"] = "renamed".into();
    let (status, updated) = app
        .send("PUT", &format!("/api/frp/clients/{key}"), Some(update))
        .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["name"], "renamed");
    assert_eq!(app.saved().clients[0].token, "secret-token");
    let mut update = base_client();
    update["token"] = "next-token".into();
    let (_, _) = app
        .send("PUT", &format!("/api/frp/clients/{key}"), Some(update))
        .await;
    assert_eq!(app.saved().clients[0].token, "next-token");

    // Unknown key → 404; invalid JSON → 400.
    let (status, body) = app.send("DELETE", "/api/frp/clients/ghost", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "item not found");
    let (status, _) = app
        .send(
            "POST",
            "/api/frp/clients",
            Some(serde_json::json!({"nope": 1})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Validation problems: a client without a server address is 400 with
    // the problem list.
    let mut broken = base_client();
    broken["serverAddr"] = "".into();
    let (status, body) = app.send("POST", "/api/frp/clients", Some(broken)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid frp configuration");
    assert!(!body["problems"].as_array().expect("problems").is_empty());
}

#[tokio::test]
async fn proxy_collection_and_batch_ops() {
    let app = app().await;
    // Two clients for the proxies to belong to.
    let (_, c1) = app
        .send("POST", "/api/frp/clients", Some(base_client()))
        .await;
    let (_, c2) = app
        .send("POST", "/api/frp/clients", Some(base_client()))
        .await;
    let c1 = c1["key"].as_str().unwrap().to_owned();
    let c2 = c2["key"].as_str().unwrap().to_owned();

    let mk = |key: &str, client: &str| {
        serde_json::json!({
            "key": "",
            "name": format!("proxy-{key}"),
            "enable": true,
            "type": "tcp",
            "localIp": "127.0.0.1",
            "localPort": 22,
            "remotePort": 6022,
            "client": client
        })
    };
    let (_, p1) = app
        .send("POST", "/api/frp/proxies", Some(mk("a", &c1)))
        .await;
    let (_, p2) = app
        .send("POST", "/api/frp/proxies", Some(mk("b", &c2)))
        .await;
    let p1 = p1["key"].as_str().unwrap().to_owned();
    let p2 = p2["key"].as_str().unwrap().to_owned();

    // The proxy view carries the computed access addresses (tcp here).
    let (_, list) = app.send("GET", "/api/frp/proxies", None).await;
    assert_eq!(list[0]["urls"][0]["display"], "frps.example.com:6022");
    assert_eq!(list[0]["urls"][0]["full"], "tcp://frps.example.com:6022");

    // A proxy bound to a ghost client is a validation problem.
    let (status, body) = app
        .send("POST", "/api/frp/proxies", Some(mk("c", "ghost")))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["problems"]
            .as_array()
            .expect("problems")
            .iter()
            .any(|problem| problem["field"].as_str().unwrap().ends_with(".client"))
    );

    // Proxy-type field mapping: http without domains or subdomain.
    let mut http = mk("d", &c1);
    http["type"] = "http".into();
    http["remotePort"] = 0.into();
    let (status, body) = app.send("POST", "/api/frp/proxies", Some(http)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["problems"]
            .as_array()
            .expect("problems")
            .iter()
            .any(|problem| problem["field"]
                .as_str()
                .unwrap()
                .ends_with("customDomains"))
    );

    // Enable + batch enable.
    let (status, body) = app
        .send(
            "PUT",
            &format!("/api/frp/proxies/{p1}/enable"),
            Some(serde_json::json!({ "enable": false })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    let (status, body) = app
        .send(
            "PUT",
            "/api/frp/proxies-enable",
            Some(serde_json::json!({ "keys": [p1, p2], "enable": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changed"], 1, "p1 flipped, p2 was already on");

    // Group + order.
    let (status, _) = app
        .send(
            "PUT",
            "/api/frp/proxies-group",
            Some(serde_json::json!({ "keys": [p1, p2], "group": "隧道" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, list) = app.send("GET", "/api/frp/proxies", None).await;
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .all(|p| p["group"] == "隧道")
    );
    let (status, _) = app
        .send(
            "PUT",
            "/api/frp/proxies-order",
            Some(serde_json::json!({ "keys": [p2, p1] })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, list) = app.send("GET", "/api/frp/proxies", None).await;
    assert_eq!(list[0]["key"], p2);

    // Batch delete rejects unknown keys without partial removal.
    let (status, _) = app
        .send(
            "POST",
            "/api/frp/proxies-delete",
            Some(serde_json::json!({ "keys": [p1, "ghost"] })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = app
        .send(
            "POST",
            "/api/frp/proxies-delete",
            Some(serde_json::json!({ "keys": [p1] })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["removed"], 1);
}

#[tokio::test]
async fn server_collection_secrets_and_restart() {
    let app = app().await;
    let server = serde_json::json!({
        "key": "",
        "name": "main",
        "enable": true,
        "bindPort": 7000,
        "token": "srv-token",
        "dashboardPort": 7500,
        "dashboardPwd": "dash-pwd"
    });
    let (status, created) = app.send("POST", "/api/frp/servers", Some(server)).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let key = created["key"].as_str().unwrap().to_owned();
    assert_eq!(created["token"], "********");
    assert_eq!(created["dashboardPwd"], "********");

    let (_, secrets) = app
        .send("GET", &format!("/api/frp/servers/{key}/secrets"), None)
        .await;
    assert_eq!(secrets["token"], "srv-token");
    assert_eq!(secrets["dashboardPwd"], "dash-pwd");

    // Update with masks keeps both stored secrets.
    let mut update = created.clone();
    update["token"] = "********".into();
    update["dashboardPwd"] = "********".into();
    let (status, _) = app
        .send("PUT", &format!("/api/frp/servers/{key}"), Some(update))
        .await;
    assert_eq!(status, StatusCode::OK);
    let saved = app.saved();
    assert_eq!(saved.servers[0].token, "srv-token");
    assert_eq!(saved.servers[0].dashboard_pwd, "dash-pwd");

    // KCP / QUIC port equality is a validation problem.
    let mut conflict = created.clone();
    conflict["kcpBindPort"] = 7001.into();
    conflict["quicBindPort"] = 7001.into();
    let (status, body) = app.send("POST", "/api/frp/servers", Some(conflict)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["problems"]
            .as_array()
            .expect("problems")
            .iter()
            .any(|problem| problem["reason"].as_str().unwrap().contains("不能相同"))
    );

    // Restart on a disabled instance is a stop-only ok (nothing to start;
    // this test app has no binaries, so an enabled restart would fail).
    let (status, _) = app
        .send(
            "PUT",
            &format!("/api/frp/servers/{key}/enable"),
            Some(serde_json::json!({ "enable": false })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = app
        .send("POST", &format!("/api/frp/servers/{key}/restart"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ok"], true);
    // Restart on an unknown key → 404.
    let (status, _body) = app
        .send("POST", "/api/frp/servers/ghost/restart", None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn import_endpoint_previews_then_applies() {
    let app = app().await;
    let content = r#"
[common]
server_addr = frps.example.com
server_port = 7000
token = legacy-token
protocol = kcp
websocket_pool_count = 5

[ssh]
type = tcp
local_port = 22
remote_port = 6022
use_encryption = true
"#;
    // Preview: masked entries plus the ignored fields.
    let (status, preview) = app
        .send(
            "POST",
            "/api/frp/import",
            Some(serde_json::json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["clients"][0]["serverAddr"], "frps.example.com");
    assert_eq!(preview["clients"][0]["protocol"], "kcp");
    assert_eq!(preview["clients"][0]["token"], "********");
    assert_eq!(
        preview["clients"][0]["enable"], false,
        "导入的新实例默认停用"
    );
    assert_eq!(preview["proxies"][0]["name"], "ssh");
    let ignored = preview["ignored"].as_array().expect("ignored");
    assert!(
        ignored.iter().any(|line| line
            .as_str()
            .unwrap()
            .starts_with("common.websocket_pool_count")),
        "{ignored:?}"
    );
    assert!(
        ignored
            .iter()
            .any(|line| line.as_str().unwrap().starts_with("ssh.use_encryption"))
    );

    // Apply as new: entries land disabled with fresh keys.
    let (status, body) = app
        .send(
            "POST",
            "/api/frp/import",
            Some(serde_json::json!({ "content": content, "apply": { "target": "new" } })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ok"], true);
    let saved = app.saved();
    assert_eq!(saved.clients.len(), 1);
    assert!(!saved.clients[0].enable);
    assert_eq!(saved.clients[0].token, "legacy-token");
    assert_eq!(saved.proxies.len(), 1);
    assert_eq!(saved.proxies[0].client, saved.clients[0].key);
}

#[tokio::test]
async fn settings_and_install_status_endpoints() {
    let app = app().await;
    // Settings GET default → PUT → round-trip.
    let (_, settings) = app.send("GET", "/api/frp/settings", None).await;
    assert_eq!(settings["frpcPath"], "");
    assert_eq!(settings["install"]["autoCheck"], true);
    let (status, saved) = app
        .send(
            "PUT",
            "/api/frp/settings",
            Some(serde_json::json!({
                "frpcPath": "/usr/local/bin/frpc",
                "frpsPath": "",
                "install": { "autoCheck": false, "proxy": "http://127.0.0.1:7890" }
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["frpcPath"], "/usr/local/bin/frpc");
    assert_eq!(saved["install"]["autoCheck"], false);
    let stored = app.saved();
    assert_eq!(stored.settings.frpc_path, "/usr/local/bin/frpc");
    assert!(!stored.install.auto_check);

    // Install status: both programs, nothing installed.
    let (status, view) = app.send("GET", "/api/frp/install", None).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["frpc"]["program"], "frpc");
    assert_eq!(view["frps"]["program"], "frps");
    assert!(view["frpc"]["installed"].is_null());
    assert!(view["frpc"]["backups"].is_array());
    assert_eq!(view["frpc"]["stage"]["stage"], "idle");

    // Install start with an unknown program → 400.
    let (status, _) = app
        .send(
            "POST",
            "/api/frp/install",
            Some(serde_json::json!({ "program": "sudp" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Backup delete for an unknown version → 404.
    let (status, _) = app
        .send(
            "DELETE",
            "/api/frp/install/backups/0.0.1?program=frpc",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Reset clears the collections.
    let (status, body) = app.send("POST", "/api/frp/reset", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    let saved = app.saved();
    assert!(saved.clients.is_empty() && saved.servers.is_empty() && saved.proxies.is_empty());
}
