//! Integration tests for the WP-52 jail surfaces: the jails collection
//! API (create / copy / update / enable / order / group / batch delete),
//! the presets and rule-test endpoints, and the engine reload wiring
//! that turns a saved rule into live counting.

#![forbid(unsafe_code)]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{Router, http::StatusCode};
use fg_config::ConfigStore;
use fg_core::events::EventBus;
use fg_guard::{
    bans::GuardService,
    jail::JailEngine,
    model::FileConfig,
    routes::{PersistFn, RoutesState, mount},
    validate,
};
use http_body_util::BodyExt;
use hyper::header::CONTENT_TYPE;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::sync::RwLock;

/// A mounted router over a temp config store, counting persist calls.
struct Harness {
    addr: std::net::SocketAddr,
    _store: Arc<ConfigStore>,
    service: Arc<GuardService>,
    engine: Arc<JailEngine>,
    persists: Arc<AtomicUsize>,
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = ConfigStore::open(dir.path()).expect("config store");
    let events = EventBus::new(64);
    let settings = validate::normalize(FileConfig::default()).settings;
    let service = GuardService::open(&store, &settings, events.clone()).expect("service");
    let engine = Arc::new(JailEngine::new(
        Arc::clone(&service),
        fg_net::banlist::system_clock(),
    ));
    let config = Arc::new(RwLock::new(FileConfig {
        settings: settings.clone(),
        jails: Vec::new(),
    }));
    let persists = Arc::new(AtomicUsize::new(0));
    let (count_persist, store_for_persist) = (persists.clone(), Arc::clone(&store));
    let persist: PersistFn = Arc::new(move |config: &FileConfig| {
        store_for_persist.save(fg_guard::model::FILE_NAME, config)?;
        count_persist.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let state = Arc::new(RoutesState {
        config,
        service: Arc::clone(&service),
        engine: Arc::clone(&engine),
        persist,
    });
    let app: Router = mount(Router::new(), state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    Harness {
        addr,
        _store: store,
        service,
        engine,
        persists,
        _dir: dir,
    }
}

impl Harness {
    async fn send(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
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
            Some(body) => builder
                .body(axum::body::Body::from(body.to_string()))
                .expect("body"),
            None => builder.body(axum::body::Body::empty()).expect("body"),
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

    /// Parses the error body's collected problems (field, reason).
    fn problems(body: &Value) -> Vec<(String, String)> {
        body["problems"]
            .as_array()
            .map(|problems| {
                problems
                    .iter()
                    .map(|problem| {
                        (
                            problem["field"].as_str().unwrap_or_default().to_owned(),
                            problem["reason"].as_str().unwrap_or_default().to_owned(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn sshd_jail(key: &str) -> Value {
    json!({
        "key": key,
        "name": "SSH",
        "group": "auth",
        "enable": true,
        "source": "file",
        "target": "/var/log/auth.log",
        "filter": "Failed password .* from <HOST>",
        "ignore": "healthcheck .*",
        "maxRetry": 3,
        "findTime": 120,
        "banTime": 7200,
        "remark": "integration"
    })
}

#[tokio::test]
async fn jails_api_create_copy_update_enable_and_delete() {
    let app = harness().await;
    // Create: the client key is kept when valid and unique.
    let (status, created) = app
        .send("POST", "/api/guard/jails", Some(sshd_jail("aabbccddeeff")))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created["key"], "aabbccddeeff");
    assert_eq!(created["maxRetry"], 3);
    assert_eq!(created["findTime"], 120);
    assert_eq!(app.persists.load(Ordering::SeqCst), 1);

    // Create without a key (or with a duplicate): a fresh one is generated.
    let (status, generated) = app
        .send("POST", "/api/guard/jails", Some(sshd_jail("aabbccddeeff")))
        .await;
    assert_eq!(status, StatusCode::OK);
    let generated = generated["key"].as_str().expect("generated key").to_owned();
    assert_ne!(generated, "aabbccddeeff");
    assert_eq!(generated.len(), 12);

    // Copy: fresh key, inserted after the source; the body is the
    // template whose fields the copy takes (key always regenerated).
    let (status, copy) = app
        .send(
            "POST",
            "/api/guard/jails/aabbccddeeff/copy",
            Some(sshd_jail("irrelevant")),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let copy_key = copy["key"].as_str().expect("copy key").to_owned();
    assert_ne!(copy_key, "aabbccddeeff");
    assert_eq!(copy["name"], "SSH");

    // Replace: same key, new settings.
    let (status, replaced) = app
        .send(
            "PUT",
            "/api/guard/jails/aabbccddeeff",
            Some(json!({
                "name": "SSH hard", "source": "file", "target": "/var/log/secure",
                "filter": "from <HOST>", "maxRetry": 2, "enable": false
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replaced["key"], "aabbccddeeff");
    assert_eq!(replaced["name"], "SSH hard");
    assert_eq!(replaced["target"], "/var/log/secure");
    assert_eq!(replaced["enable"], false);

    // Enable toggles the switch.
    let (status, ok) = app
        .send(
            "PUT",
            "/api/guard/jails/aabbccddeeff/enable",
            Some(json!({"enable": true})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ok["ok"], true);

    // Delete removes exactly the one jail.
    let (status, removed) = app
        .send("DELETE", "/api/guard/jails/aabbccddeeff", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(removed["removed"], 1);
    let (_, list) = app.send("GET", "/api/guard/jails", None).await;
    assert_eq!(list.as_array().map(Vec::len), Some(2));
    // Unknown keys are 404.
    let (status, _) = app
        .send("DELETE", "/api/guard/jails/ghost0000000", None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn jails_api_batch_order_enable_group_and_delete() {
    let app = harness().await;
    let mut keys = Vec::new();
    for step in 0..3 {
        let (status, created) = app
            .send(
                "POST",
                "/api/guard/jails",
                Some(sshd_jail(&format!("key{step:08}"))),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{created}");
        keys.push(created["key"].as_str().expect("key").to_owned());
    }
    // Order: reverse the whole list.
    let reversed: Vec<&String> = keys.iter().rev().collect();
    let (status, ok) = app
        .send(
            "PUT",
            "/api/guard/jails-order",
            Some(json!({ "keys": reversed })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ok["ok"], true);
    let (_, list) = app.send("GET", "/api/guard/jails", None).await;
    let ordered: Vec<&str> = list
        .as_array()
        .expect("array")
        .iter()
        .map(|jail| jail["key"].as_str().expect("key"))
        .collect();
    assert_eq!(ordered, ["key00000002", "key00000001", "key00000000"]);
    // An incomplete order is refused.
    let (status, _) = app
        .send(
            "PUT",
            "/api/guard/jails-order",
            Some(json!({ "keys": [keys[0]] })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Batch enable.
    let (status, changed) = app
        .send(
            "PUT",
            "/api/guard/jails-enable",
            Some(json!({ "keys": keys, "enable": false })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(changed["changed"], 3);
    let (_, list) = app.send("GET", "/api/guard/jails", None).await;
    assert!(
        list.as_array()
            .expect("array")
            .iter()
            .all(|jail| jail["enable"] == false)
    );

    // Batch group.
    let (status, ok) = app
        .send(
            "PUT",
            "/api/guard/jails-group",
            Some(json!({ "keys": keys, "group": "ssh" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ok["ok"], true);
    let (_, list) = app.send("GET", "/api/guard/jails", None).await;
    assert!(
        list.as_array()
            .expect("array")
            .iter()
            .all(|jail| jail["group"] == "ssh")
    );

    // Batch delete removes every requested key.
    let (status, removed) = app
        .send(
            "POST",
            "/api/guard/jails-delete",
            Some(json!({ "keys": keys })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(removed["removed"], 3);
    let (_, list) = app.send("GET", "/api/guard/jails", None).await;
    assert_eq!(list.as_array().map(Vec::len), Some(0));
}

#[tokio::test]
async fn jails_api_rejects_invalid_jails_with_problems() {
    let app = harness().await;
    // No <HOST> in the filter: refused with the collected problem.
    let (status, body) = app
        .send(
            "POST",
            "/api/guard/jails",
            Some(json!({
                "key": "aabbccddeeff", "name": "bad", "enable": true,
                "source": "file", "target": "/var/log/auth.log",
                "filter": "Failed password for .*"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let problems = Harness::problems(&body);
    assert!(
        problems
            .iter()
            .any(|(field, reason)| field == "jails[0].filter[0]" && reason.contains("<HOST>")),
        "{problems:?}"
    );

    // `anyStatus` with neither path rules nor `unknownHost`: refused.
    let (status, body) = app
        .send(
            "POST",
            "/api/guard/jails",
            Some(json!({
                "key": "aabbccddeeff", "name": "web", "enable": true,
                "source": "web", "anyStatus": true
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        Harness::problems(&body)
            .iter()
            .any(|(field, _)| field == "jails[0].anyStatus")
    );

    // A tls jail without kinds and an event jail with a dead filter are
    // refused too.
    let (status, body) = app
        .send(
            "POST",
            "/api/guard/jails",
            Some(json!({
                "key": "aabbccddeeff", "name": "tls", "enable": true,
                "source": "tls", "filter": ""
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        Harness::problems(&body)
            .iter()
            .any(|(field, _)| field == "jails[0].filter")
    );
}

#[tokio::test]
async fn jails_api_docker_source_refused_without_module() {
    let app = harness().await;
    let docker = json!({
        "key": "aabbccddeeff", "name": "vault", "enable": true,
        "source": "docker", "target": "vaultwarden",
        "filter": "IP: <HOST>"
    });
    // No docker follow handle injected: the save is refused.
    let (status, body) = app
        .send("POST", "/api/guard/jails", Some(docker.clone()))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("docker module"),
        "{body}"
    );

    // With a handle the jail saves. The stub is a no-op feeder; the point
    // is the accept path.
    struct Stub;
    impl fg_guard::jail::docker_source::DockerFollow for Stub {
        fn follow(
            &self,
            _container: &str,
            _on_line: Arc<dyn Fn(String) + Send + Sync>,
        ) -> fg_guard::jail::docker_source::FollowFut {
            Box::pin(async { Ok(()) })
        }
    }
    app.engine.set_docker(Some(Arc::new(Stub)));
    let (status, _) = app.send("POST", "/api/guard/jails", Some(docker)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn jails_preset_endpoint_lists_and_clones_templates() {
    let app = harness().await;
    let (status, presets) = app.send("GET", "/api/guard/presets", None).await;
    assert_eq!(status, StatusCode::OK);
    let presets = presets.as_array().expect("array");
    assert!(presets.len() >= 17, "the documented preset table");
    let ids: Vec<&str> = presets
        .iter()
        .map(|preset| preset["id"].as_str().expect("id"))
        .collect();
    for expected in [
        "sshd",
        "sshd-journal",
        "dropbear",
        "nginx-http-auth",
        "nginx-botsearch",
        "vaultwarden",
        "homeassistant",
        "proxmox",
        "gately-admin",
        "gately-waf",
        "gately-knock",
        "gately-files",
        "web-decoy",
        "web-unknown-host",
        "web-404",
        "tls-probe",
        "tls-abort",
    ] {
        assert!(ids.contains(&expected), "missing preset {expected}");
    }
    let decoy = presets
        .iter()
        .find(|preset| preset["id"] == "web-decoy")
        .expect("decoy");
    assert_eq!(decoy["anyStatus"], true);
    assert_eq!(decoy["maxRetry"], 1);
    assert_eq!(decoy["banTime"], 86_400);

    // Cloning a preset into a jail keeps its thresholds; the preset id
    // is interface metadata and stripped before the collection sees it.
    let mut template = decoy.clone();
    template.as_object_mut().expect("object").remove("id");
    let (status, created) = app.send("POST", "/api/guard/jails", Some(template)).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["maxRetry"], 1);
    assert_eq!(created["anyStatus"], true);
    assert_eq!(created["preset"], "web-decoy");
}

#[tokio::test]
async fn jails_persist_reloads_engine_for_line_matching() {
    let app = harness().await;
    let (status, _) = app
        .send(
            "POST",
            "/api/guard/jails",
            Some(json!({
                "key": "aabbccddeeff", "name": "ssh", "enable": true,
                "source": "file", "target": "/var/log/auth.log",
                "filter": "Failed password .* from <HOST>", "maxRetry": 2
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    // The reload after the persist made the rule live: two matching
    // lines ban the address with the jail source tag.
    let line = "Failed password for root from 203.0.113.77";
    app.engine.on_line("aabbccddeeff", line);
    assert!(!app.service.is_banned("203.0.113.77".parse().unwrap()));
    app.engine.on_line("aabbccddeeff", line);
    assert!(app.service.is_banned("203.0.113.77".parse().unwrap()));
    let (_, bans) = app
        .send("GET", "/api/guard/bans?source=jail%3Aaabbccddeeff", None)
        .await;
    assert_eq!(bans["total"], 1);

    // Disabling the jail through the API removes it from the snapshot:
    // further lines no longer count.
    let (status, _) = app
        .send(
            "PUT",
            "/api/guard/jails/aabbccddeeff/enable",
            Some(json!({"enable": false})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    app.engine.on_line("aabbccddeeff", line);
    let (_, bans) = app
        .send("GET", "/api/guard/bans?source=jail%3Aaabbccddeeff", None)
        .await;
    assert_eq!(bans["total"], 1, "the disabled jail stopped counting");
}

#[tokio::test]
async fn test_filter_endpoint_reports_lines_and_hosts() {
    let app = harness().await;
    let (status, body) = app
        .send(
            "POST",
            "/api/guard/jails/test",
            Some(json!({
                "source": "file",
                "filter": "Failed password .* from <HOST>\nInvalid user .* from <HOST>",
                "ignore": "healthcheck .*",
                "lines": [
                    "Failed password for root from 203.0.113.4 port 22 ssh2",
                    "Invalid user admin from 2001:db8::9 port 41424",
                    "healthcheck Failed password for x from 198.51.100.1",
                    "session opened for user root by (uid=0)"
                ]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let results = body["results"].as_array().expect("results");
    assert_eq!(results.len(), 4);
    assert_eq!(results[0]["hit"], true);
    assert_eq!(results[0]["ip"], "203.0.113.4");
    assert_eq!(results[0]["ignored"], false);
    assert_eq!(results[1]["hit"], true);
    assert_eq!(results[1]["ip"], "2001:db8::9");
    assert_eq!(results[2]["ignored"], true);
    assert_eq!(results[2]["hit"], false, "ignored lines never count");
    assert_eq!(results[3]["hit"], false);
    assert_eq!(results[3]["ip"], Value::Null);

    // A filter that does not compile is refused with a clear message.
    let (status, body) = app
        .send(
            "POST",
            "/api/guard/jails/test",
            Some(json!({
                "source": "command",
                "filter": "from (unclosed <HOST>",
                "lines": []
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("compile")
    );
}

#[tokio::test]
async fn test_path_and_tls_endpoints() {
    let app = harness().await;
    // Web: the raw and normalized path both feed the rules; a deny on
    // the default site counts as 444.
    let (status, body) = app
        .send(
            "POST",
            "/api/guard/jails/test",
            Some(json!({
                "source": "web",
                "filter": "*/.env",
                "ignore": "*/keep/.env",
                "anyStatus": true,
                "samples": [
                    {"path": "/.env", "status": 200},
                    {"path": "//.env", "status": 200},
                    {"path": "/a/../.env", "status": 404},
                    {"path": "/keep/.env", "status": 200},
                    {"path": "/.env", "status": 403, "accessDenied": true, "defaultSite": true},
                    {"path": "/.env", "status": 200, "trustedUser": true}
                ]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let results = body["results"].as_array().expect("results");
    assert_eq!(results[0]["counted"], true);
    assert_eq!(results[1]["counted"], true, "normalized path");
    assert_eq!(results[2]["counted"], true, "dot segments resolve");
    assert_eq!(results[3]["counted"], false, "excluded path");
    assert_eq!(
        results[4]["counted"], true,
        "default-site deny counts as 444"
    );
    assert_eq!(results[4]["status"], 444);
    assert_eq!(results[5]["counted"], false, "trusted users never count");

    // TLS: pasted reasons are classified and tested against the
    // selection.
    let (status, body) = app
        .send(
            "POST",
            "/api/guard/jails/test",
            Some(json!({
                "source": "tls",
                "filter": "not_tls\nno_shared_params",
                "samples": [
                    {"reason": "received plaintext HTTP request"},
                    {"reason": "no shared cipher suites"},
                    {"reason": "unexpected eof during handshake"},
                    {"kind": "not_tls"},
                    {"reason": "totally mysterious"}
                ]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let results = body["results"].as_array().expect("results");
    assert_eq!(results[0]["kind"], "not_tls");
    assert_eq!(results[0]["counted"], true);
    assert_eq!(results[1]["kind"], "no_shared_params");
    assert_eq!(results[1]["counted"], true);
    assert_eq!(results[2]["kind"], "eof");
    assert_eq!(results[2]["counted"], false, "eof is not selected");
    assert_eq!(results[3]["kind"], "not_tls");
    assert_eq!(results[4]["kind"], "other");
}

#[tokio::test]
async fn jails_settings_save_updates_engine_ignore_set() {
    let app = harness().await;
    let (status, _) = app
        .send(
            "POST",
            "/api/guard/jails",
            Some(json!({
                "key": "aabbccddeeff", "name": "ssh", "enable": true,
                "source": "file", "target": "/var/log/auth.log",
                "filter": "Failed password .* from <HOST>", "maxRetry": 1
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    // Whitelist the /24 through the settings endpoint.
    let (status, _) = app
        .send(
            "PUT",
            "/api/guard/settings",
            Some(json!({
                "enable": true, "firewall": false, "banSeconds": 3600,
                "increment": true, "maxBanSeconds": 604800,
                "ignorePrivate": false, "ignoreList": ["203.0.113.0/24"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    app.engine
        .on_line("aabbccddeeff", "Failed password for root from 203.0.113.8");
    assert!(
        !app.service.is_banned("203.0.113.8".parse().unwrap()),
        "the freshly whitelisted network never counts"
    );
    // A non-whitelisted address still counts and bans.
    app.engine
        .on_line("aabbccddeeff", "Failed password for root from 198.51.100.4");
    assert!(app.service.is_banned("198.51.100.4".parse().unwrap()));
}
