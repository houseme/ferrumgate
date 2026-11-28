//! Management-route contract tests (WP-42 §4): the rule collection
//! mirrors the fg-admin `Collection<T>` shapes, settings round-trip with
//! normalization, and the helper endpoints answer. Authentication is out
//! of scope here (applied by the management router).

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use axum::body::Body;
use http_body_util::BodyExt;
use hyper::header::CONTENT_TYPE;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::sync::RwLock as AsyncRwLock;

use fg_stun::model::FileConfig;
use fg_stun::routes::{PersistFn, RoutesState, mount};
use fg_stun::runtime::Runtime;
use fg_stun::validate::normalize;

/// A mounted router over an in-memory store, counting persist calls.
struct Harness {
    addr: std::net::SocketAddr,
    persists: Arc<AtomicUsize>,
    last_saved: Arc<Mutex<Option<FileConfig>>>,
}

async fn harness() -> Harness {
    let persists = Arc::new(AtomicUsize::new(0));
    let last_saved: Arc<Mutex<Option<FileConfig>>> = Arc::new(Mutex::new(None));
    let config = Arc::new(AsyncRwLock::new(normalize(FileConfig::default())));
    let runtime = Arc::new(Runtime::new(config.clone(), None, None));
    let (count_persist, slot) = (persists.clone(), last_saved.clone());
    let persist: PersistFn = Arc::new(move |config: &FileConfig| {
        serde_json::to_vec(config)?;
        *slot.lock().expect("slot") = Some(config.clone());
        count_persist.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let on_change = runtime.on_change_handle();
    let state = Arc::new(RoutesState {
        config,
        on_change,
        persist,
        runtime,
    });
    let app = mount(axum::Router::new(), state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    Harness {
        addr,
        persists,
        last_saved,
    }
}

impl Harness {
    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (axum::http::StatusCode, Value) {
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
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn create(&self, rule: Value) -> Value {
        let (status, body) = self.send("POST", "/api/stun/rules", Some(rule)).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        body
    }

    async fn keys(&self) -> Vec<String> {
        let (_, rules) = self.send("GET", "/api/stun/rules", None).await;
        rules
            .as_array()
            .expect("rules array")
            .iter()
            .map(|rule| rule["key"].as_str().expect("key").to_owned())
            .collect()
    }
}

fn base_rule(key: &str) -> Value {
    json!({
        "key": key,
        "name": if key.is_empty() { "generated" } else { key },
        "group": "",
        "enable": false,
        "protocol": "udp",
        "bind": { "mode": "auto", "ip": "", "interface": "", "regex": "" },
        "localPort": 0,
        "useGlobalServers": false,
        "stunServers": ["127.0.0.1:3478"],
        "keepAliveServers": [],
        "disableForward": true,
        "targetAddresses": [],
        "targetPort": 0,
        "upnp": false,
        "upnpGateway": "",
        "upnpLocalHost": "",
        "upnpControlUrl": "",
        "upnpInternalPort": 0,
        "natpmp": false,
        "natpmpGateway": "",
        "autoFirewall": false,
        "heartbeatInterval": 3000,
        "stunTimeout": 3000,
        "retryInterval": 3000,
        "autoRetry": true,
        "disableCheck": false,
        "useGlobalWebhook": true,
        "webhook": { "url": "", "method": "", "headers": [], "body": "", "proxy": false, "timeout": 0 },
        "webhookOnlyOnChange": false,
        "scriptEnable": false,
        "script": "",
        "maxConnections": 0,
        "udpSessionTimeout": 300,
        "access": { "enable": false, "whitelist": [], "blacklist": [] },
        "remark": ""
    })
}

fn is_generated_key(key: &str) -> bool {
    key.len() == 12
        && key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[tokio::test]
async fn create_keeps_valid_key_and_lists_with_status() {
    let app = harness().await;
    let created = app.create(base_rule("")).await;
    assert!(
        is_generated_key(created["key"].as_str().expect("key")),
        "{created}"
    );
    // The view carries the read-only status block (stopped: not running).
    assert_eq!(created["status"]["state"], "disabled");
    assert_eq!(created["protocol"], "udp");
    // A valid unique client key is kept; a duplicate one is regenerated.
    let kept = app.create(base_rule("web")).await;
    assert_eq!(kept["key"], "web");
    let clash = app.create(base_rule("web")).await;
    assert!(is_generated_key(clash["key"].as_str().expect("key")));
    let (_, rules) = app.send("GET", "/api/stun/rules", None).await;
    assert_eq!(rules.as_array().expect("array").len(), 3);
    // The persist hook received the normalized candidate.
    let saved = app
        .last_saved
        .lock()
        .expect("slot")
        .clone()
        .expect("persisted");
    assert_eq!(saved.rules.len(), 3);
}

#[tokio::test]
async fn update_copy_and_delete_follow_the_collection_contract() {
    let app = harness().await;
    app.create(base_rule("first")).await;
    app.create(base_rule("second")).await;
    // Update: the path key wins over the body key.
    let mut replacement = base_rule("ignored");
    replacement["name"] = "renamed".into();
    let (status, body) = app
        .send("PUT", "/api/stun/rules/first", Some(replacement))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["key"], "first");
    assert_eq!(body["name"], "renamed");
    let (status, body) = app
        .send("PUT", "/api/stun/rules/nope", Some(base_rule("nope")))
        .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "item not found");
    // Copy: fresh key, inserted after the source.
    let (status, copied) = app
        .send(
            "POST",
            "/api/stun/rules/first/copy",
            Some(base_rule("first")),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{copied}");
    assert!(is_generated_key(copied["key"].as_str().expect("key")));
    assert_eq!(
        app.keys().await,
        [
            "first".to_owned(),
            copied["key"].as_str().unwrap().to_owned(),
            "second".to_owned()
        ]
    );
    // Single delete.
    let (status, body) = app.send("DELETE", "/api/stun/rules/second", None).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["removed"], 1);
    assert_eq!(app.keys().await.len(), 2);
}

#[tokio::test]
async fn enable_order_group_and_batch_delete_follow_contract() {
    let app = harness().await;
    app.create(base_rule("a")).await;
    app.create(base_rule("b")).await;
    // Single enable + no-op accounting.
    let (status, body) = app
        .send(
            "PUT",
            "/api/stun/rules/a/enable",
            Some(json!({ "enable": true })),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["ok"], true);
    let persists_before = app.persists.load(Ordering::SeqCst);
    let (_, body) = app
        .send(
            "PUT",
            "/api/stun/rules/a/enable",
            Some(json!({ "enable": true })),
        )
        .await;
    assert_eq!(body["ok"], true);
    assert_eq!(app.persists.load(Ordering::SeqCst), persists_before);
    // Batch enable.
    let (status, body) = app
        .send(
            "PUT",
            "/api/stun/rules-enable",
            Some(json!({ "keys": ["a", "b"], "enable": true })),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["changed"], 1, "a was already on, b flipped");
    let (status, body) = app
        .send(
            "PUT",
            "/api/stun/rules-enable",
            Some(json!({ "keys": ["ghost"], "enable": true })),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "item not found");
    // Order requires every item exactly once.
    let (status, body) = app
        .send(
            "PUT",
            "/api/stun/rules-order",
            Some(json!({ "keys": ["b"] })),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "order must include every item once");
    let (status, _) = app
        .send(
            "PUT",
            "/api/stun/rules-order",
            Some(json!({ "keys": ["b", "a"] })),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(app.keys().await, ["b", "a"]);
    // Group.
    let (status, body) = app
        .send(
            "PUT",
            "/api/stun/rules-group",
            Some(json!({ "keys": ["a", "b"], "group": "内网" })),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["ok"], true);
    let (_, rules) = app.send("GET", "/api/stun/rules", None).await;
    assert!(
        rules
            .as_array()
            .unwrap()
            .iter()
            .all(|rule| rule["group"] == "内网")
    );
    // Batch delete: no partial removals, ceilings enforced.
    let (status, _) = app
        .send(
            "POST",
            "/api/stun/rules-delete",
            Some(json!({ "keys": ["a", "ghost"] })),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    let (status, body) = app
        .send(
            "POST",
            "/api/stun/rules-delete",
            Some(json!({ "keys": ["a"] })),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["removed"], 1);
    let many: Vec<String> = (0..501).map(|index| format!("k{index}")).collect();
    let (status, body) = app
        .send(
            "POST",
            "/api/stun/rules-delete",
            Some(json!({ "keys": many })),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "expected between 1 and 500 valid keys");
}

#[tokio::test]
async fn settings_roundtrip_normalizes_and_validates() {
    let app = harness().await;
    let (_, settings) = app.send("GET", "/api/stun/settings", None).await;
    // The module defaults are visible in the settings.
    assert_eq!(settings["enable"], false);
    assert_eq!(
        settings["stunServers"],
        json!([
            "stun.nextcloud.com:3478",
            "stun.hot-chilli.net:3478",
            "stun.voip.blackberry.com:3478",
            "stun.radiojar.com:3478",
            "stun.freeswitch.org:3478"
        ])
    );
    assert_eq!(
        settings["keepAliveServers"],
        json!(["www.baidu.com:80", "www.qq.com:80"])
    );
    assert_eq!(settings["addrCheckInterval"], 60);
    // Saving applies defaults and canonicalizes server entries.
    let mut candidate = settings.clone();
    candidate["enable"] = true.into();
    candidate["stunServers"] = json!(["stun.example.com"]);
    candidate["addrCheckInterval"] = 5.into();
    let (status, saved) = app
        .send("PUT", "/api/stun/settings", Some(candidate.clone()))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{saved}");
    assert_eq!(saved["enable"], true);
    assert_eq!(saved["stunServers"], json!(["stun.example.com:3478"]));
    assert_eq!(saved["addrCheckInterval"], 60);
    // Unknown fields and broken webhooks are rejected.
    let (status, body) = app
        .send(
            "PUT",
            "/api/stun/settings",
            Some(json!({ "enable": true, "nope": 1 })),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid JSON body");
    let mut candidate = saved.clone();
    candidate["webhook"]["url"] = "ftp://example.com".into();
    let (status, body) = app.send("PUT", "/api/stun/settings", Some(candidate)).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid stun configuration");
    let problems = body["problems"].as_array().expect("problems");
    assert!(
        problems
            .iter()
            .any(|problem| problem["field"].as_str().unwrap().contains("webhook"))
    );
}

#[tokio::test]
async fn restart_endpoint_and_netinterfaces_answer() {
    let app = harness().await;
    let created = app.create(base_rule("")).await;
    let key = created["key"].as_str().expect("key").to_owned();
    // The module switch is off, so the restart reports "not started" but
    // still succeeds; an absent rule is 404.
    let (status, body) = app
        .send("POST", &format!("/api/stun/rules/{key}/restart"), None)
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["ok"], true);
    assert_eq!(body["started"], false);
    let (status, body) = app
        .send("POST", "/api/stun/rules/ghost/restart", None)
        .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "item not found");
    // The interface list is a JSON array with name/ip/loopback fields and
    // contains the loopback interface.
    let (status, interfaces) = app.send("GET", "/api/stun/netinterfaces", None).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{interfaces}");
    let list = interfaces.as_array().expect("interfaces array");
    assert!(!list.is_empty());
    assert!(
        list.iter()
            .all(|iface| iface["name"].is_string() && iface["ip"].is_string())
    );
}

#[tokio::test]
async fn invalid_json_unknown_fields_and_problems_are_reported() {
    let app = harness().await;
    // Unknown fields in the rule body are rejected by serde.
    let (status, body) = app
        .send("POST", "/api/stun/rules", Some(json!({ "nope": true })))
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid JSON body");
    // A rule that fails validation collects every problem.
    let mut rule = base_rule("bad");
    rule["name"] = "".into();
    rule["useGlobalServers"] = false.into();
    rule["stunServers"] = json!([]);
    rule["disableForward"] = false.into();
    rule["targetAddresses"] = json!(["not a target"]);
    rule["targetPort"] = json!(0);
    let (status, body) = app.send("POST", "/api/stun/rules", Some(rule)).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid stun configuration");
    let fields: Vec<String> = body["problems"]
        .as_array()
        .expect("problems")
        .iter()
        .map(|problem| problem["field"].as_str().expect("field").to_owned())
        .collect();
    assert!(fields.iter().any(|f| f.ends_with(".name")), "{fields:?}");
    assert!(
        fields.iter().any(|f| f.ends_with(".stunServers")),
        "{fields:?}"
    );
    assert!(
        fields.iter().any(|f| f.ends_with(".targetPort")),
        "{fields:?}"
    );
    // Invalid path keys are rejected before lookup.
    let (status, body) = app
        .send("DELETE", "/api/stun/rules/batch-delete", None)
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid item key");
}
