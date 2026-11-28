//! NetBird integration tests (WP-45 §6): the management routes against a
//! real config store, with the `netbird` program replaced by a tiny Rust
//! stand-in compiled with `rustc` at test time (conventions §4).
//!
//! Fake behavior (state dir derived from the `--daemon-addr` unix://
//! path, like the real CLI):
//!
//! - `service run`: counts each start (`starts` file in the working
//!   directory, which the runtime pins to the state dir), touches the
//!   control socket file and stays alive until stopped.
//! - `up`: with `NB_SETUP_KEY` or an existing auth marker it writes the
//!   marker and connects; without one it prints a login link.
//! - `logout`: removes the auth marker and records a `logout-<dir>`
//!   counter beside the state dir, so a deletion test can prove logout
//!   ran before the directory went away.
//! - `status --json`: connected payload when authenticated, needs-login
//!   payload otherwise.
//! - `version`: prints `<state dir>/fake-version` when present, so the
//!   pre-0.75 SOCKS5 warning can be exercised.

#![forbid(unsafe_code)]

use std::{path::PathBuf, sync::Arc, time::Duration};

use axum::Router;
use fg_config::ConfigStore;
use fg_proc::LogHandle;
use http_body_util::BodyExt;
use hyper::header::CONTENT_TYPE;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};

const FAKE_PROGRAM: &str = r##"
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // State dir: parent of the `--daemon-addr` unix:// path.
    let mut addr: Option<String> = None;
    let mut index = 1;
    while index < args.len() {
        if args[index] == "--daemon-addr" && index + 1 < args.len() {
            addr = Some(args[index + 1].clone());
            index += 2;
            continue;
        }
        index += 1;
    }
    let addr = addr.unwrap_or_default();
    let socket = addr.strip_prefix("unix://").unwrap_or(&addr).to_owned();
    let state_dir = PathBuf::from(&socket)
        .parent()
        .map(PathBuf::from)
        .unwrap_or_default();
    let command = args
        .iter()
        .position(|arg| {
            matches!(
                arg.as_str(),
                "up" | "down" | "logout" | "status" | "version" | "run"
            )
        })
        .map(|position| args[position].as_str())
        .unwrap_or("");
    match command {
        "run" => {
            let cwd = std::env::current_dir().expect("cwd");
            let starts = cwd.join("starts");
            let count: u32 = std::fs::read_to_string(&starts)
                .ok()
                .and_then(|text| text.trim().parse().ok())
                .unwrap_or(0);
            std::fs::write(&starts, format!("{}", count + 1)).expect("write starts");
            std::fs::write(&socket, "daemon").expect("touch socket");
            loop {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
        "up" => {
            let authed = std::env::var("NB_SETUP_KEY").is_ok()
                || state_dir.join(".authed").exists();
            if authed {
                std::fs::write(state_dir.join(".authed"), "1").expect("write authed");
                println!("Connected");
            } else {
                println!("Please open the following link to authenticate:");
                println!("  https://login.netbird.io/auth?code=ONETIMELINK");
            }
        }
        "logout" => {
            let _ = std::fs::remove_file(state_dir.join(".authed"));
            if let Some(base) = state_dir.parent() {
                let key = state_dir
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let marker = base.join(format!("logout-{key}"));
                let count: u32 = std::fs::read_to_string(&marker)
                    .ok()
                    .and_then(|text| text.trim().parse().ok())
                    .unwrap_or(0);
                std::fs::write(&marker, format!("{}", count + 1)).expect("write logout");
            }
            println!("Logged out");
        }
        "status" => {
            let authed = state_dir.join(".authed").exists();
            if authed {
                println!(r#"{{"managementState":{{"url":"https://api.netbird.io:443","connected":true}},"localPeerState":{{"IP":"100.90.0.5"}},"peers":[{{"ip":"100.90.0.2","fqdn":"alpha.corp","connected":true,"direct":true,"lastWireguardHandshake":"2025-06-01T12:00:00Z","transferReceived":1024,"transferSent":2048}},{{"ip":"100.90.0.3","fqdn":"beta.corp","status":"Connected","direct":false,"relay":"relay-1"}}]}}"#);
            } else {
                println!(r#"{{"managementState":{{"url":"https://api.netbird.io:443","connected":false}},"localPeerState":{{}},"peers":[]}}"#);
            }
        }
        "version" => {
            let custom = std::fs::read_to_string(state_dir.join("fake-version"))
                .ok()
                .map(|text| text.trim().to_owned())
                .unwrap_or_default();
            println!("{}", if custom.is_empty() { "0.28.0".to_owned() } else { custom });
        }
        "down" => {
            println!("disconnected");
        }
        _ => {
            eprintln!("unknown command");
            std::process::exit(2);
        }
    }
}
"##;

struct Harness {
    addr: std::net::SocketAddr,
    store: Arc<ConfigStore>,
    runtime: Arc<fg_netbird::Runtime>,
    _dir: tempfile::TempDir,
    drain: tokio::sync::watch::Sender<bool>,
}

fn compile_fake(bin: &std::path::Path) {
    let source = bin.join("fake_netbird.rs");
    std::fs::write(&source, FAKE_PROGRAM).expect("write fake source");
    let out = bin.join("fake_tailscale");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let status = std::process::Command::new(rustc)
        .arg("--edition")
        .arg("2021")
        .arg(&source)
        .arg("-o")
        .arg(&out)
        .status()
        .expect("run rustc");
    assert!(status.success(), "compiling the fake binary failed");
    std::fs::copy(&out, bin.join("netbird")).expect("copy daemon");
}

fn instance_json(name: &str, extra: Value) -> Value {
    let mut value = json!({
        "key": "",
        "name": name,
        "group": "",
        "enable": true,
        "remark": "",
        "managed": true,
        "userspace": true,
        "managementUrl": "",
        "setupKey": "nb-secret-key",
        "acceptRoutes": true,
        "routingPeer": false,
        "acceptDns": true,
        "blockInbound": false,
        "socks5": "",
        "controlAddr": "",
        "stateDir": "",
        "extraArgs": [],
        "extraEnv": []
    });
    for (key, override_value) in extra.as_object().expect("object") {
        value[key] = override_value.clone();
    }
    value
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ConfigStore::open(&dir.path().join("config")).expect("store");
    let proc = fg_proc::Proc::open(&store, None).expect("proc");
    compile_fake(proc.bin_dir());
    store
        .save(fg_netbird::CONFIG_NAME, &fg_netbird::FileConfig::default())
        .expect("save initial config");
    let logs = LogHandle::tracing();
    let module = fg_netbird::Module::new(
        Arc::clone(&store),
        fg_netbird::Deps {
            proc,
            fetch: None,
            logs: Some(logs),
        },
    )
    .expect("module");
    let runtime = module.runtime();
    let router = module.mount(Router::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    let (drain, drain_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(<fg_netbird::Module as fg_core::module::Module>::run(
        module, drain_rx,
    ));
    Harness {
        addr,
        store,
        runtime,
        _dir: dir,
        drain,
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.drain.send(true);
    }
}

async fn wait_until(mut check: impl FnMut() -> bool) {
    for _ in 0..200 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not reached within the timeout");
}

impl Harness {
    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (hyper::StatusCode, Value) {
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

    async fn create(&self, instance: Value) -> Value {
        let (status, body) = self
            .send("POST", "/api/netbird/instances", Some(instance))
            .await;
        assert_eq!(status, hyper::StatusCode::OK, "{body}");
        body
    }

    fn state_dir(&self, key: &str) -> PathBuf {
        self.store.dir().join("netbird").join(key)
    }

    fn starts(&self, key: &str) -> u32 {
        std::fs::read_to_string(self.state_dir(key).join("starts"))
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .unwrap_or(0)
    }

    fn logout_count(&self, key: &str) -> u32 {
        std::fs::read_to_string(
            self.store
                .dir()
                .join("netbird")
                .join(format!("logout-{key}")),
        )
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
    }
}

async fn create_running(harness: &Harness, name: &str) -> String {
    let created = harness.create(instance_json(name, json!({}))).await;
    let key = created["key"].as_str().expect("key").to_owned();
    let runtime = Arc::clone(&harness.runtime);
    let wanted = key.clone();
    wait_until(|| {
        runtime
            .try_snapshot()
            .map(|snaps| snaps.iter().any(|snap| snap.key == wanted && snap.running))
            .unwrap_or(false)
    })
    .await;
    key
}

#[tokio::test]
async fn netbird_restart_only_own_instance() {
    let harness = harness().await;
    let first = create_running(&harness, "first").await;
    let second = create_running(&harness, "second").await;
    wait_until(|| harness.starts(&first) == 1 && harness.starts(&second) == 1).await;
    let (status, body) = harness
        .send(
            "POST",
            &format!("/api/netbird/instances/{first}/restart"),
            None,
        )
        .await;
    assert_eq!(status, hyper::StatusCode::OK, "{body}");
    wait_until(|| harness.starts(&first) == 2 && harness.starts(&second) == 1).await;
    // The login ran again for the restarted instance only.
    assert!(harness.state_dir(&first).join(".authed").exists());
    assert!(harness.state_dir(&second).join(".authed").exists());
}

#[tokio::test]
async fn netbird_group_or_remark_change_no_restart() {
    let harness = harness().await;
    let key = create_running(&harness, "main").await;
    wait_until(|| harness.starts(&key) == 1).await;
    let mut replacement = instance_json("main", json!({}));
    replacement["key"] = key.as_str().into();
    replacement["group"] = "office".into();
    replacement["remark"] = "edited".into();
    let (status, body) = harness
        .send(
            "PUT",
            &format!("/api/netbird/instances/{key}"),
            Some(replacement),
        )
        .await;
    assert_eq!(status, hyper::StatusCode::OK, "{body}");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(harness.starts(&key), 1, "分组与备注修改不重启进程");
}

#[tokio::test]
async fn netbird_delete_default_state_dir_logs_out_first() {
    let harness = harness().await;
    let key = create_running(&harness, "main").await;
    wait_until(|| harness.starts(&key) == 1).await;
    assert!(harness.state_dir(&key).join(".authed").exists());
    let (status, body) = harness
        .send("DELETE", &format!("/api/netbird/instances/{key}"), None)
        .await;
    assert_eq!(status, hyper::StatusCode::OK, "{body}");
    // Logout ran (counter beside the state dir), then the dir was removed.
    wait_until(|| harness.logout_count(&key) == 1).await;
    wait_until(|| !harness.state_dir(&key).exists()).await;
    let runtime = Arc::clone(&harness.runtime);
    wait_until(|| {
        runtime
            .try_snapshot()
            .map(|snaps| snaps.is_empty())
            .unwrap_or(false)
    })
    .await;
}

#[tokio::test]
async fn netbird_custom_state_dir_kept_on_delete() {
    let harness = harness().await;
    let custom = harness._dir.path().join("custom-state");
    let created = harness
        .create(instance_json(
            "main",
            json!({"stateDir": custom.display().to_string()}),
        ))
        .await;
    let key = created["key"].as_str().expect("key").to_owned();
    let runtime = Arc::clone(&harness.runtime);
    let wanted = key.clone();
    wait_until(|| {
        runtime
            .try_snapshot()
            .map(|snaps| snaps.iter().any(|snap| snap.key == wanted && snap.running))
            .unwrap_or(false)
    })
    .await;
    let (status, _) = harness
        .send("DELETE", &format!("/api/netbird/instances/{key}"), None)
        .await;
    assert_eq!(status, hyper::StatusCode::OK);
    // The custom state directory is preserved (no logout, no deletion).
    assert!(custom.exists(), "自定义状态目录必须保留");
    assert_eq!(harness.logout_count(&key), 0);
    std::fs::remove_dir_all(&custom).ok();
}

#[tokio::test]
async fn netbird_reset_stops_and_clears_generated_files() {
    let harness = harness().await;
    let first = create_running(&harness, "first").await;
    let second = create_running(&harness, "second").await;
    wait_until(|| harness.starts(&first) >= 1 && harness.starts(&second) >= 1).await;
    let (status, body) = harness.send("POST", "/api/netbird/reset", None).await;
    assert_eq!(status, hyper::StatusCode::OK, "{body}");
    let runtime = Arc::clone(&harness.runtime);
    wait_until(|| {
        runtime
            .try_snapshot()
            .map(|snaps| snaps.is_empty())
            .unwrap_or(false)
    })
    .await;
    wait_until(|| !harness.state_dir(&first).exists()).await;
    wait_until(|| !harness.state_dir(&second).exists()).await;
    // Reset deregistered both nodes from the control plane.
    assert_eq!(harness.logout_count(&first), 1);
    assert_eq!(harness.logout_count(&second), 1);
    let raw = harness
        .store
        .load_raw(fg_netbird::CONFIG_NAME)
        .expect("load")
        .expect("config present");
    let config: Value = serde_json::from_slice(&raw).expect("json");
    assert_eq!(config["instances"].as_array().expect("array").len(), 0);
    // Installed programs are preserved.
    let bin = harness.store.dir().join("bin");
    assert!(bin.join("netbird").exists());
}

#[tokio::test]
async fn netbird_status_parsed_from_cli_json() {
    let harness = harness().await;
    let key = create_running(&harness, "main").await;
    let (status, body) = harness
        .send("GET", &format!("/api/netbird/instances/{key}/status"), None)
        .await;
    assert_eq!(status, hyper::StatusCode::OK, "{body}");
    assert_eq!(body["running"], true);
    assert_eq!(body["connected"], true);
    assert_eq!(body["managementUrl"], "https://api.netbird.io:443");
    assert_eq!(body["localIp"], "100.90.0.5");
    let peers = body["peers"].as_array().expect("peers");
    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0]["fqdn"], "alpha.corp");
    assert_eq!(peers[0]["direct"], true);
    assert_eq!(peers[0]["lastHandshake"], "2025-06-01T12:00:00Z");
    assert_eq!(peers[0]["rxBytes"], 1024);
    assert_eq!(peers[1]["direct"], false, "经中继的路径");
    assert_eq!(peers[1]["relay"], "relay-1");
    // With the setup key present there is no login link.
    assert_eq!(body["loginUrl"], Value::Null);
}

#[tokio::test]
async fn netbird_login_link_surfaced_when_keyless() {
    let harness = harness().await;
    let created = harness
        .create(instance_json("keyless", json!({"setupKey": ""})))
        .await;
    let key = created["key"].as_str().expect("key").to_owned();
    let runtime = Arc::clone(&harness.runtime);
    let wanted = key.clone();
    wait_until(|| {
        runtime
            .try_snapshot()
            .map(|snaps| snaps.iter().any(|snap| snap.key == wanted && snap.running))
            .unwrap_or(false)
    })
    .await;
    let (_, body) = harness
        .send("GET", &format!("/api/netbird/instances/{key}/status"), None)
        .await;
    assert_eq!(body["running"], true, "守护进程仍在运行");
    assert_eq!(body["managementConnected"], false, "尚未认证");
    assert_eq!(
        body["loginUrl"].as_str(),
        Some("https://login.netbird.io/auth?code=ONETIMELINK"),
        "登录链接只出现在状态接口，不进日志原文"
    );
}

#[tokio::test]
async fn netbird_old_version_socks5_warning() {
    let harness = harness().await;
    let created = harness
        .create(instance_json("old", json!({"socks5": "127.0.0.1:1080"})))
        .await;
    let key = created["key"].as_str().expect("key").to_owned();
    // The fake reads the version from this file during the probe.
    std::fs::write(harness.state_dir(&key).join("fake-version"), "0.74.2")
        .expect("write fake version");
    let runtime = Arc::clone(&harness.runtime);
    let wanted = key.clone();
    wait_until(|| {
        runtime
            .try_snapshot()
            .map(|snaps| snaps.iter().any(|snap| snap.key == wanted && snap.running))
            .unwrap_or(false)
    })
    .await;
    let (_, body) = harness
        .send("GET", &format!("/api/netbird/instances/{key}/status"), None)
        .await;
    assert_eq!(
        body["oldVersionSocks5Warning"], true,
        "0.75 之前的版本在用户态网络下 SOCKS5 监听全部地址，必须告警"
    );
    // A current version does not warn. The save changes a behavior field
    // so the daemon restarts and the version probe runs again.
    std::fs::write(harness.state_dir(&key).join("fake-version"), "0.75.1")
        .expect("write fake version");
    let mut update = instance_json("old", json!({"socks5": "127.0.0.1:1080"}));
    update["key"] = key.as_str().into();
    update["acceptRoutes"] = false.into();
    let (status, _) = harness
        .send(
            "PUT",
            &format!("/api/netbird/instances/{key}"),
            Some(update),
        )
        .await;
    assert_eq!(status, hyper::StatusCode::OK);
    wait_until(|| harness.starts(&key) == 2).await;
    let (_, body) = harness
        .send("GET", &format!("/api/netbird/instances/{key}/status"), None)
        .await;
    assert_eq!(body["oldVersionSocks5Warning"], false);
}

#[tokio::test]
async fn netbird_logout_endpoint_deregisters() {
    let harness = harness().await;
    let key = create_running(&harness, "main").await;
    let (status, body) = harness
        .send(
            "POST",
            &format!("/api/netbird/instances/{key}/logout"),
            None,
        )
        .await;
    assert_eq!(status, hyper::StatusCode::OK, "{body}");
    wait_until(|| harness.logout_count(&key) == 1).await;
    assert!(!harness.state_dir(&key).join(".authed").exists());
    // Unknown key: 404.
    let (status, _) = harness
        .send("POST", "/api/netbird/instances/ghost/logout", None)
        .await;
    assert_eq!(status, hyper::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn netbird_routes_contract_and_secret_masking() {
    let harness = harness().await;
    let created = harness.create(instance_json("main", json!({}))).await;
    let key = created["key"].as_str().expect("key").to_owned();
    assert_eq!(key.len(), 12);
    assert_eq!(created["setupKey"], "********");
    assert_eq!(created["managed"], true);
    assert_eq!(created["userspace"], true);
    let (_, list) = harness.send("GET", "/api/netbird/instances", None).await;
    assert_eq!(list[0]["setupKey"], "********");
    let (_, secrets) = harness
        .send(
            "GET",
            &format!("/api/netbird/instances/{key}/secrets"),
            None,
        )
        .await;
    assert_eq!(secrets["setupKey"], "nb-secret-key");
    // Updating with the mask keeps the stored key.
    let mut update = instance_json("main", json!({}));
    update["key"] = key.as_str().into();
    let (status, body) = harness
        .send(
            "PUT",
            &format!("/api/netbird/instances/{key}"),
            Some(update),
        )
        .await;
    assert_eq!(status, hyper::StatusCode::OK, "{body}");
    assert_eq!(body["setupKey"], "********");
    let (_, secrets) = harness
        .send(
            "GET",
            &format!("/api/netbird/instances/{key}/secrets"),
            None,
        )
        .await;
    assert_eq!(secrets["setupKey"], "nb-secret-key");
    // Module status: read-only snapshots, no secrets, program summary.
    let (_, status_body) = harness.send("GET", "/api/netbird/status", None).await;
    assert_eq!(status_body["instances"][0]["key"], key.as_str());
    let rendered = serde_json::to_string(&status_body).expect("render");
    assert!(!rendered.contains("nb-secret-key"), "{rendered}");
    // Unknown fields rejected, bad keys rejected.
    let (status, _) = harness
        .send("POST", "/api/netbird/instances", Some(json!({"nope": 1})))
        .await;
    assert_eq!(status, hyper::StatusCode::BAD_REQUEST);
    let (status, body) = harness
        .send("DELETE", "/api/netbird/instances/batch-delete", None)
        .await;
    assert_eq!(status, hyper::StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid item key");
    // Empty name is a validation problem.
    let (status, body) = harness
        .send(
            "POST",
            "/api/netbird/instances",
            Some(instance_json("", json!({"name": ""}))),
        )
        .await;
    assert_eq!(status, hyper::StatusCode::BAD_REQUEST);
    assert!(
        body["problems"]
            .as_array()
            .expect("problems")
            .iter()
            .any(|problem| problem["field"].as_str().expect("f").ends_with(".name"))
    );
}

#[tokio::test]
async fn netbird_kernel_mode_conflict_reported_on_enable() {
    let harness = harness().await;
    // One enabled kernel-mode instance saves fine.
    let _first = harness
        .create(instance_json("kernel", json!({"userspace": false})))
        .await;
    // A second enabled kernel instance is rejected with the conflict.
    let (status, body) = harness
        .send(
            "POST",
            "/api/netbird/instances",
            Some(instance_json("kernel2", json!({"userspace": false}))),
        )
        .await;
    assert_eq!(status, hyper::StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["problems"]
            .as_array()
            .expect("problems")
            .iter()
            .any(|problem| problem["reason"]
                .as_str()
                .expect("r")
                .contains("netbird.conflict.kernelMode")),
        "{body}"
    );
    // Enabling a disabled second kernel instance through the batch
    // endpoint is rejected as well.
    let mut quiet = instance_json("kernel2", json!({"userspace": false}));
    quiet["enable"] = false.into();
    let created = harness.create(quiet).await;
    let second = created["key"].as_str().expect("key").to_owned();
    let (status, body) = harness
        .send(
            "PUT",
            "/api/netbird/instances-enable",
            Some(json!({"keys": [second], "enable": true})),
        )
        .await;
    assert_eq!(status, hyper::StatusCode::BAD_REQUEST);
    assert!(
        body["problems"]
            .as_array()
            .expect("problems")
            .iter()
            .any(|problem| problem["reason"]
                .as_str()
                .expect("r")
                .contains("kernelMode"))
    );
}

#[tokio::test]
async fn netbird_blocked_instance_reports_reason_and_stays_stopped() {
    let harness = harness().await;
    let created = harness.create(instance_json("main", json!({}))).await;
    let key = created["key"].as_str().expect("key").to_owned();
    // Remove the binaries: the next apply reports the missing program.
    let bin = harness.store.dir().join("bin");
    std::fs::remove_file(bin.join("netbird")).expect("remove");
    let mut update = instance_json("main", json!({}));
    update["key"] = key.as_str().into();
    update["acceptRoutes"] = false.into();
    let (status, _) = harness
        .send(
            "PUT",
            &format!("/api/netbird/instances/{key}"),
            Some(update),
        )
        .await;
    assert_eq!(status, hyper::StatusCode::OK);
    let runtime = Arc::clone(&harness.runtime);
    let wanted = key.clone();
    wait_until(|| {
        runtime
            .try_snapshot()
            .map(|snaps| {
                snaps
                    .iter()
                    .any(|snap| snap.key == wanted && !snap.running && snap.blocked.is_some())
            })
            .unwrap_or(false)
    })
    .await;
    let snapshot = runtime.try_snapshot().expect("snapshot");
    assert!(
        snapshot[0]
            .blocked
            .as_ref()
            .expect("blocked")
            .contains("netbird")
    );
}
