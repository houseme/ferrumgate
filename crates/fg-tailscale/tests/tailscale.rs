//! Tailscale integration tests (WP-45 §6): the management routes against a
//! real config store, with `tailscaled` / `tailscale` replaced by a tiny
//! multi-call Rust stand-in compiled with `rustc` at test time
//! (conventions §4).
//!
//! Fake behavior (switching on the file name, state dir derived from the
//! `--socket` argument like the real CLI derives the daemon):
//!
//! - `tailscaled`: counts each start (`starts` file in the working
//!   directory, which the runtime pins to the state dir) and stays alive
//!   until stopped.
//! - `tailscale up`: with `TS_AUTHKEY` or an existing auth marker it
//!   writes the marker and succeeds; without one it prints a login link.
//! - `tailscale logout`: removes the auth marker and records a
//!   `logout-<dir>` counter *beside* the state dir, so a deletion test can
//!   prove logout ran before the directory went away.
//! - `tailscale status --json`: canned payload whose `Peer` keys carry a
//!   node key that must never leak.

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
    let name = std::path::Path::new(&args[0])
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    if name.contains("tailscaled") {
        daemon();
    } else {
        cli(&args);
    }
}

fn daemon() {
    let cwd = std::env::current_dir().expect("cwd");
    let starts = cwd.join("starts");
    let count: u32 = std::fs::read_to_string(&starts)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0);
    std::fs::write(&starts, format!("{}", count + 1)).expect("write starts");
    loop {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn cli(args: &[String]) {
    // The state dir is the parent of the `--socket` path.
    let mut socket: Option<String> = None;
    let mut index = 1;
    while index < args.len() {
        if args[index] == "--socket" && index + 1 < args.len() {
            socket = Some(args[index + 1].clone());
            index += 2;
            continue;
        }
        index += 1;
    }
    let socket = std::path::PathBuf::from(socket.unwrap_or_default());
    let state_dir = socket.parent().map(PathBuf::from).unwrap_or_default();
    let command = args
        .iter()
        .position(|arg| arg == "up" || arg == "logout" || arg == "status")
        .map(|position| args[position].as_str())
        .unwrap_or("");
    if command == "up" {
        let authed = std::env::var("TS_AUTHKEY").is_ok()
            || state_dir.join(".authed").exists();
        if authed {
            std::fs::write(state_dir.join(".authed"), "1").expect("write authed");
            println!("Success.");
        } else {
            println!("To authenticate, visit https://controlplane.example/login?token=ONETIME");
        }
    } else if command == "logout" {
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
        println!("Logged out.");
    } else if command == "status" {
        println!(r#"{{"Version":"1.80.0","BackendState":"Running","AuthURL":"","Self":{{"HostName":"host-a","TailscaleIPs":["100.64.0.1"]}},"CurrentTailnet":{{"Name":"example.ts.net"}},"Peer":{{"nodekey:SECRETNODEKEY0123456789":{{"HostName":"host-b","DNSName":"host-b.example.ts.net.","TailscaleIPs":["100.64.0.2"],"Online":true,"Relay":"","CurAddr":"203.0.113.5:4242","RxBytes":1024,"TxBytes":2048,"LastHandshake":"2025-06-01T12:00:00Z"}}}}}}"#);
    }
}
"##;

struct Harness {
    addr: std::net::SocketAddr,
    store: Arc<ConfigStore>,
    runtime: Arc<fg_tailscale::Runtime>,
    _dir: tempfile::TempDir,
    drain: tokio::sync::watch::Sender<bool>,
}

fn compile_fake(bin: &std::path::Path) {
    let source = bin.join("fake_tailscale.rs");
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
    std::fs::copy(&out, bin.join("tailscaled")).expect("copy daemon");
    std::fs::copy(&out, bin.join("tailscale")).expect("copy cli");
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
        "authKey": "tskey-auth-secret",
        "loginServer": "",
        "advertiseRoutes": [],
        "exitNode": "none",
        "exitNodeTarget": "",
        "socks5": "",
        "socket": "",
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
        .save(
            fg_tailscale::CONFIG_NAME,
            &fg_tailscale::FileConfig::default(),
        )
        .expect("save initial config");
    let logs = LogHandle::tracing();
    let module = fg_tailscale::Module::new(
        Arc::clone(&store),
        fg_tailscale::Deps {
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
    tokio::spawn(<fg_tailscale::Module as fg_core::module::Module>::run(
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
            .send("POST", "/api/tailscale/instances", Some(instance))
            .await;
        assert_eq!(status, hyper::StatusCode::OK, "{body}");
        body
    }

    fn state_dir(&self, key: &str) -> PathBuf {
        self.store.dir().join("tailscale").join(key)
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
                .join("tailscale")
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
async fn tailscale_restart_only_own_instance() {
    let harness = harness().await;
    let first = create_running(&harness, "first").await;
    let second = create_running(&harness, "second").await;
    wait_until(|| harness.starts(&first) == 1 && harness.starts(&second) == 1).await;
    let (status, body) = harness
        .send(
            "POST",
            &format!("/api/tailscale/instances/{first}/restart"),
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
async fn tailscale_group_or_remark_change_no_restart() {
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
            &format!("/api/tailscale/instances/{key}"),
            Some(replacement),
        )
        .await;
    assert_eq!(status, hyper::StatusCode::OK, "{body}");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(harness.starts(&key), 1, "分组与备注修改不重启进程");
}

#[tokio::test]
async fn tailscale_delete_default_state_dir_logs_out_first() {
    let harness = harness().await;
    let key = create_running(&harness, "main").await;
    wait_until(|| harness.starts(&key) == 1).await;
    assert!(harness.state_dir(&key).join(".authed").exists());
    let (status, body) = harness
        .send("DELETE", &format!("/api/tailscale/instances/{key}"), None)
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
async fn tailscale_custom_state_dir_kept_on_delete() {
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
        .send("DELETE", &format!("/api/tailscale/instances/{key}"), None)
        .await;
    assert_eq!(status, hyper::StatusCode::OK);
    // The custom state directory is preserved (no logout, no deletion).
    assert!(custom.exists(), "自定义状态目录必须保留");
    assert_eq!(harness.logout_count(&key), 0);
    std::fs::remove_dir_all(&custom).ok();
}

#[tokio::test]
async fn tailscale_reset_stops_and_clears_generated_files() {
    let harness = harness().await;
    let first = create_running(&harness, "first").await;
    let second = create_running(&harness, "second").await;
    wait_until(|| harness.starts(&first) >= 1 && harness.starts(&second) >= 1).await;
    let (status, body) = harness.send("POST", "/api/tailscale/reset", None).await;
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
        .load_raw(fg_tailscale::CONFIG_NAME)
        .expect("load")
        .expect("config present");
    let config: Value = serde_json::from_slice(&raw).expect("json");
    assert_eq!(config["instances"].as_array().expect("array").len(), 0);
    // Installed programs are preserved.
    let bin = harness.store.dir().join("bin");
    assert!(bin.join("tailscaled").exists());
    assert!(bin.join("tailscale").exists());
}

#[tokio::test]
async fn tailscale_status_parsed_from_cli_json_and_no_node_key_leak() {
    let harness = harness().await;
    let key = create_running(&harness, "main").await;
    let (status, body) = harness
        .send(
            "GET",
            &format!("/api/tailscale/instances/{key}/status"),
            None,
        )
        .await;
    assert_eq!(status, hyper::StatusCode::OK, "{body}");
    assert_eq!(body["running"], true);
    assert_eq!(body["connected"], true);
    assert_eq!(body["backendState"], "Running");
    assert_eq!(body["version"], "1.80.0");
    assert_eq!(body["selfHostname"], "host-a");
    let peers = body["peers"].as_array().expect("peers");
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0]["hostname"], "host-b");
    assert_eq!(peers[0]["directAddr"], "203.0.113.5:4242");
    assert_eq!(peers[0]["rxBytes"], 1024);
    let rendered = serde_json::to_string(&body).expect("render");
    assert!(
        !rendered.contains("SECRETNODEKEY"),
        "节点密钥不得出现在状态输出: {rendered}"
    );
    assert!(!rendered.contains("nodekey"));
}

#[tokio::test]
async fn tailscale_logout_endpoint_deregisters() {
    let harness = harness().await;
    let key = create_running(&harness, "main").await;
    let (status, body) = harness
        .send(
            "POST",
            &format!("/api/tailscale/instances/{key}/logout"),
            None,
        )
        .await;
    assert_eq!(status, hyper::StatusCode::OK, "{body}");
    wait_until(|| harness.logout_count(&key) == 1).await;
    assert!(!harness.state_dir(&key).join(".authed").exists());
    // Unknown key: 404.
    let (status, _) = harness
        .send("POST", "/api/tailscale/instances/ghost/logout", None)
        .await;
    assert_eq!(status, hyper::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tailscale_routes_contract_and_secret_masking() {
    let harness = harness().await;
    let created = harness.create(instance_json("main", json!({}))).await;
    let key = created["key"].as_str().expect("key").to_owned();
    assert_eq!(key.len(), 12);
    assert_eq!(created["authKey"], "********");
    assert_eq!(created["managed"], true);
    assert_eq!(created["userspace"], true);
    let (_, list) = harness.send("GET", "/api/tailscale/instances", None).await;
    assert_eq!(list[0]["authKey"], "********");
    let (_, secrets) = harness
        .send(
            "GET",
            &format!("/api/tailscale/instances/{key}/secrets"),
            None,
        )
        .await;
    assert_eq!(secrets["authKey"], "tskey-auth-secret");
    // Updating with the mask keeps the stored key.
    let mut update = instance_json("main", json!({}));
    update["key"] = key.as_str().into();
    let (status, body) = harness
        .send(
            "PUT",
            &format!("/api/tailscale/instances/{key}"),
            Some(update),
        )
        .await;
    assert_eq!(status, hyper::StatusCode::OK, "{body}");
    assert_eq!(body["authKey"], "********");
    let (_, secrets) = harness
        .send(
            "GET",
            &format!("/api/tailscale/instances/{key}/secrets"),
            None,
        )
        .await;
    assert_eq!(secrets["authKey"], "tskey-auth-secret");
    // Module status: read-only snapshots, no secrets, program summary.
    let (_, status_body) = harness.send("GET", "/api/tailscale/status", None).await;
    assert_eq!(status_body["instances"][0]["key"], key.as_str());
    let rendered = serde_json::to_string(&status_body).expect("render");
    assert!(!rendered.contains("tskey-auth-secret"), "{rendered}");
    // Unknown fields rejected, bad keys rejected.
    let (status, _) = harness
        .send("POST", "/api/tailscale/instances", Some(json!({"nope": 1})))
        .await;
    assert_eq!(status, hyper::StatusCode::BAD_REQUEST);
    let (status, body) = harness
        .send("DELETE", "/api/tailscale/instances/batch-delete", None)
        .await;
    assert_eq!(status, hyper::StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid item key");
    // Empty name is a validation problem.
    let (status, body) = harness
        .send(
            "POST",
            "/api/tailscale/instances",
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
async fn tailscale_kernel_mode_conflict_reported_on_enable() {
    let harness = harness().await;
    // One enabled kernel-mode instance saves fine.
    let _first = harness
        .create(instance_json("kernel", json!({"userspace": false})))
        .await;
    // A second enabled kernel instance is rejected with the conflict.
    let (status, body) = harness
        .send(
            "POST",
            "/api/tailscale/instances",
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
                .contains("tailscale.conflict.kernelMode")),
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
            "/api/tailscale/instances-enable",
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
async fn tailscale_blocked_instance_reports_reason_and_stays_stopped() {
    let harness = harness().await;
    let created = harness.create(instance_json("main", json!({}))).await;
    let key = created["key"].as_str().expect("key").to_owned();
    // Remove the binaries: the next apply reports the missing program.
    let bin = harness.store.dir().join("bin");
    std::fs::remove_file(bin.join("tailscaled")).expect("remove daemon");
    std::fs::remove_file(bin.join("tailscale")).expect("remove cli");
    let mut update = instance_json("main", json!({}));
    update["key"] = key.as_str().into();
    update["advertiseRoutes"] = json!(["10.9.0.0/24"]);
    let (status, _) = harness
        .send(
            "PUT",
            &format!("/api/tailscale/instances/{key}"),
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
            .contains("tailscaled")
    );
}
