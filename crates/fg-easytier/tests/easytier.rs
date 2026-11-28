//! EasyTier integration tests (WP-45 §6): the management routes against a
//! real config store, with the two program binaries replaced by tiny Rust
//! stand-ins compiled with `rustc` at test time (conventions §4: 外部程序
//! 的替身用 Rust 编写的小型可执行文件作为夹具，不使用 shell 脚本).
//!
//! The fake multi-call binary switches on its file name:
//!
//! - `easytier-core`: records each start (a counter file in its working
//!   directory, which the runtime sets to the instance state directory),
//!   publishes the allocated portal, and stays alive until stopped. With
//!   network name `tunfail` it prints a TUN failure to stderr but keeps
//!   running (WP-45 §3.3: 创建失败时实例显示原因，进程不退出).
//! - `easytier-cli`: answers `node` / `peer` with canned JSON whose
//!   `Config` block carries a network secret that must never leak.

#![forbid(unsafe_code)]

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::Router;
use fg_config::ConfigStore;
use fg_logging::Level;
use fg_proc::LogHandle;
use http_body_util::BodyExt;
use hyper::header::CONTENT_TYPE;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};

const FAKE_PROGRAM: &str = r##"
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let name = std::path::Path::new(&args[0])
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    if name.contains("easytier-cli") {
        cli(&args);
    } else {
        daemon(&args);
    }
}

fn cli(args: &[String]) {
    let command = args.last().map(String::as_str).unwrap_or("");
    if command == "node" {
        println!(r#"{{"Version":"2.1.0","Hostname":"node-a","Config":"NetworkName: mesh\nNetworkSecret: ET-SECRET-DO-NOT-LEAK\nVirtualIpv4: 10.126.126.1","Listeners":["tcp://0.0.0.0:11010"],"VirtualIpv4":"10.126.126.1 /24","NatType":"cone"}}"#);
    } else if command == "peer" {
        println!(r#"{{"p1":{{"peer_id":"p1","ipv4":"10.126.126.2 /24","hostname":"node-b","latency_ms":12,"loss_rate":0.04,"rx_bytes":1024,"tx_bytes":2048,"tunnel_proto":"udp","direct":true}}}}"#);
    } else {
        eprintln!("unknown command");
        std::process::exit(2);
    }
}

fn daemon(args: &[String]) {
    let mut network_name = String::new();
    let mut portal = String::new();
    let mut index = 1;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--network-name" && index + 1 < args.len() {
            network_name = args[index + 1].clone();
            index += 2;
            continue;
        }
        if let Some(rest) = arg.strip_prefix("--rpc-portal=") {
            portal = rest.to_owned();
        }
        index += 1;
    }
    let cwd = std::env::current_dir().expect("cwd");
    let starts = cwd.join("starts");
    let count: u32 = std::fs::read_to_string(&starts)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0);
    std::fs::write(&starts, format!("{}", count + 1)).expect("write starts");
    std::fs::write(cwd.join("portal"), &portal).expect("write portal");
    std::fs::write(cwd.join("network-name"), &network_name).expect("write name");
    if network_name == "tunfail" {
        eprintln!("failed to create TUN device: operation not permitted");
    }
    // Stay alive; the supervisor stops us with SIGTERM.
    loop {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}
"##;

/// Shared captured module log lines (level, text).
type Capture = Arc<Mutex<Vec<(Level, String)>>>;

struct Harness {
    addr: std::net::SocketAddr,
    store: Arc<ConfigStore>,
    runtime: Arc<fg_easytier::Runtime>,
    logs: Capture,
    _dir: tempfile::TempDir,
    drain: tokio::sync::watch::Sender<bool>,
}

fn compile_fake(dir: &Path) -> PathBuf {
    let source = dir.join("fake_easytier.rs");
    std::fs::write(&source, FAKE_PROGRAM).expect("write fake source");
    let out = dir.join("fake_easytier");
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
    // Multi-call: the same binary under two names.
    std::fs::copy(&out, dir.join("easytier-core")).expect("copy core");
    std::fs::copy(&out, dir.join("easytier-cli")).expect("copy cli");
    out
}

fn instance_json(name: &str, extra: Value) -> Value {
    let mut value = json!({
        "key": "",
        "name": name,
        "group": "",
        "enable": true,
        "remark": "",
        "networkName": "mesh",
        "networkSecret": "hunter2",
        "peers": ["tcp://public.easytier.cn:11010"],
        "listeners": [],
        "virtualIp": "auto",
        "tun": false,
        "portForwards": [],
        "proxyNetworks": [],
        "exitNode": "none",
        "exitNodes": [],
        "latencyFirst": false,
        "kcpProxy": false,
        "quicProxy": false,
        "devName": "",
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
    // The fake programs live in the store's `bin/`, where the resolver
    // looks first (WP-43 lookup order), with an empty configured path.
    let proc = fg_proc::Proc::open(&store, None).expect("proc");
    let bin = proc.bin_dir().to_path_buf();
    compile_fake(&bin);
    store
        .save(
            fg_easytier::CONFIG_NAME,
            &fg_easytier::FileConfig {
                settings: fg_easytier::ProgramSettings {
                    program_path: String::new(),
                    download_proxy: String::new(),
                },
                instances: vec![],
            },
        )
        .expect("save initial config");
    let logs: Capture = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&logs);
    let handle = LogHandle::new(move |level, line| {
        sink.lock()
            .expect("capture lock")
            .push((level, line.to_owned()));
    });
    let module = fg_easytier::Module::new(
        Arc::clone(&store),
        fg_easytier::Deps {
            proc,
            fetch: None,
            logs: Some(handle),
        },
    )
    .expect("module");
    let runtime = module.runtime();
    let state_router = module.mount(Router::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, state_router).await.expect("serve");
    });
    let (drain, drain_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(<fg_easytier::Module as fg_core::module::Module>::run(
        module, drain_rx,
    ));
    Harness {
        addr,
        store,
        runtime,
        logs,
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
            .send("POST", "/api/easytier/instances", Some(instance))
            .await;
        assert_eq!(status, hyper::StatusCode::OK, "{body}");
        body
    }

    fn starts(&self, key: &str) -> u32 {
        let dir = self.state_dir(key);
        std::fs::read_to_string(dir.join("starts"))
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .unwrap_or(0)
    }

    fn state_dir(&self, key: &str) -> PathBuf {
        self.store.dir().join("easytier").join(key)
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
async fn easytier_restart_only_own_instance() {
    let harness = harness().await;
    let first = create_running(&harness, "first").await;
    let second = create_running(&harness, "second").await;
    wait_until(|| harness.starts(&first) == 1 && harness.starts(&second) == 1).await;
    let (status, body) = harness
        .send(
            "POST",
            &format!("/api/easytier/instances/{first}/restart"),
            None,
        )
        .await;
    assert_eq!(status, hyper::StatusCode::OK, "{body}");
    wait_until(|| harness.starts(&first) == 2 && harness.starts(&second) == 1).await;
    // The daemon really restarted into the same state directory.
    assert_eq!(
        std::fs::read_to_string(harness.state_dir(&first).join("network-name")).expect("name"),
        "mesh"
    );
}

#[tokio::test]
async fn easytier_group_or_remark_change_no_restart() {
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
            &format!("/api/easytier/instances/{key}"),
            Some(replacement),
        )
        .await;
    assert_eq!(status, hyper::StatusCode::OK, "{body}");
    // Give the async apply a chance to (wrongly) restart; it must not.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(harness.starts(&key), 1, "分组与备注修改不重启进程");
    // A real behavior change does restart.
    let mut changed = instance_json("main", json!({}));
    changed["key"] = key.as_str().into();
    changed["latencyFirst"] = true.into();
    let (status, _) = harness
        .send(
            "PUT",
            &format!("/api/easytier/instances/{key}"),
            Some(changed),
        )
        .await;
    assert_eq!(status, hyper::StatusCode::OK);
    wait_until(|| harness.starts(&key) == 2).await;
}

#[tokio::test]
async fn easytier_status_parsed_from_cli_json_and_no_secret_leak() {
    let harness = harness().await;
    let key = create_running(&harness, "main").await;
    // The status query runs the fake CLI; poll until the node info
    // arrives (bounded, resilient to scheduler load).
    let mut body = Value::Null;
    for _ in 0..40 {
        let (status, current) = harness
            .send(
                "GET",
                &format!("/api/easytier/instances/{key}/status"),
                None,
            )
            .await;
        assert_eq!(status, hyper::StatusCode::OK, "{current}");
        if current["node"]["version"] == "2.1.0" {
            body = current;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(body["running"], true);
    assert_eq!(body["node"]["version"], "2.1.0");
    assert_eq!(body["node"]["hostname"], "node-a");
    assert_eq!(body["peers"].as_array().expect("peers").len(), 1);
    assert_eq!(body["peers"][0]["direct"], true);
    let rendered = serde_json::to_string(&body).expect("render");
    assert!(
        !rendered.contains("ET-SECRET-DO-NOT-LEAK"),
        "状态输出不得包含网络密钥: {rendered}"
    );
    assert!(!rendered.contains("NetworkSecret"));
    // The daemon really received the portal argument on the loopback.
    let portal = std::fs::read_to_string(harness.state_dir(&key).join("portal")).expect("portal");
    assert!(portal.starts_with("127.0.0.1:"), "{portal}");
}

#[tokio::test]
async fn easytier_tun_failure_reported_not_exit() {
    let harness = harness().await;
    let created = harness
        .create(instance_json(
            "tunfail",
            json!({"networkName": "tunfail", "tun": true}),
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
    // The failure line was captured (poll: delivery is asynchronous), and
    // the process is still running.
    wait_until(|| {
        harness
            .logs
            .lock()
            .expect("capture")
            .iter()
            .any(|(_, line)| line.contains("failed to create TUN"))
    })
    .await;
    let (_, body) = harness
        .send(
            "GET",
            &format!("/api/easytier/instances/{key}/status"),
            None,
        )
        .await;
    assert_eq!(body["running"], true, "进程不退出");
}

#[tokio::test]
async fn easytier_conflicts_reported_on_enable() {
    let harness = harness().await;
    let first = harness
        .create(instance_json(
            "first",
            json!({"listeners": ["tcp://0.0.0.0:11010"]}),
        ))
        .await;
    let second_body = instance_json("second", json!({"listeners": ["tcp://0.0.0.0:11010"]}));
    let (status, body) = harness
        .send("POST", "/api/easytier/instances", Some(second_body))
        .await;
    assert_eq!(status, hyper::StatusCode::BAD_REQUEST, "{body}");
    let problems = body["problems"].as_array().expect("problems");
    assert!(
        problems.iter().any(|problem| problem["reason"]
            .as_str()
            .expect("reason")
            .contains("easytier.conflict.listenerPort")),
        "{problems:?}"
    );
    // Enabling a disabled instance that conflicts through the batch
    // endpoint is rejected as well (the create itself succeeds because
    // disabled instances do not conflict).
    let mut quiet = instance_json("second", json!({"listeners": ["tcp://0.0.0.0:11010"]}));
    quiet["enable"] = false.into();
    let created = harness.create(quiet).await;
    let second = created["key"].as_str().expect("key").to_owned();
    let (status, body) = harness
        .send(
            "PUT",
            "/api/easytier/instances-enable",
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
                .contains("listenerPort"))
    );
    let _ = first;
}

#[tokio::test]
async fn easytier_reset_stops_and_clears_generated_files() {
    let harness = harness().await;
    let first = create_running(&harness, "first").await;
    let second = create_running(&harness, "second").await;
    wait_until(|| harness.starts(&first) >= 1 && harness.starts(&second) >= 1).await;
    let (status, body) = harness.send("POST", "/api/easytier/reset", None).await;
    assert_eq!(status, hyper::StatusCode::OK, "{body}");
    let runtime = Arc::clone(&harness.runtime);
    wait_until(|| {
        runtime
            .try_snapshot()
            .map(|snaps| snaps.is_empty())
            .unwrap_or(false)
    })
    .await;
    // Processes stopped, the generated state directories are gone.
    wait_until(|| !harness.state_dir(&first).exists()).await;
    wait_until(|| !harness.state_dir(&second).exists()).await;
    // The config file is back to defaults (old config stays in history).
    let raw = harness
        .store
        .load_raw(fg_easytier::CONFIG_NAME)
        .expect("load")
        .expect("config present");
    let config: Value = serde_json::from_slice(&raw).expect("json");
    assert_eq!(config["instances"].as_array().expect("array").len(), 0);
    assert_eq!(config["settings"]["programPath"], "");
    // Installed programs are preserved.
    let bin = harness.store.dir().join("bin");
    assert!(bin.join("easytier-core").exists());
    assert!(bin.join("easytier-cli").exists());
}

#[tokio::test]
async fn easytier_delete_default_state_dir_after_stop() {
    let harness = harness().await;
    let key = create_running(&harness, "main").await;
    wait_until(|| harness.starts(&key) >= 1).await;
    let (status, body) = harness
        .send("DELETE", &format!("/api/easytier/instances/{key}"), None)
        .await;
    assert_eq!(status, hyper::StatusCode::OK, "{body}");
    assert_eq!(body["removed"], 1);
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
async fn easytier_routes_contract_and_secret_masking() {
    let harness = harness().await;
    // Create with a generated key; secrets come back masked.
    let created = harness.create(instance_json("main", json!({}))).await;
    let key = created["key"].as_str().expect("key").to_owned();
    assert_eq!(key.len(), 12);
    assert_eq!(created["networkSecret"], "********");
    // The list is masked too.
    let (_, list) = harness.send("GET", "/api/easytier/instances", None).await;
    assert_eq!(list[0]["networkSecret"], "********");
    // The secrets endpoint returns the plaintext (write-permission path).
    let (_, secrets) = harness
        .send(
            "GET",
            &format!("/api/easytier/instances/{key}/secrets"),
            None,
        )
        .await;
    assert_eq!(secrets["networkSecret"], "hunter2");
    // Updating with the mask keeps the stored secret.
    let mut update = instance_json("main", json!({}));
    update["key"] = key.as_str().into();
    let (status, body) = harness
        .send(
            "PUT",
            &format!("/api/easytier/instances/{key}"),
            Some(update),
        )
        .await;
    assert_eq!(status, hyper::StatusCode::OK, "{body}");
    assert_eq!(body["networkSecret"], "********");
    let (_, secrets) = harness
        .send(
            "GET",
            &format!("/api/easytier/instances/{key}/secrets"),
            None,
        )
        .await;
    assert_eq!(secrets["networkSecret"], "hunter2");
    // Module status carries read-only snapshots without secrets.
    let (_, status_body) = harness.send("GET", "/api/easytier/status", None).await;
    assert_eq!(status_body["instances"][0]["key"], key.as_str());
    let rendered = serde_json::to_string(&status_body).expect("render");
    assert!(!rendered.contains("hunter2"), "{rendered}");
    // Settings round-trip.
    let (_, settings) = harness.send("GET", "/api/easytier/settings", None).await;
    assert_eq!(settings["programPath"], "");
    let (status, _) = harness
        .send(
            "PUT",
            "/api/easytier/settings",
            Some(json!({"programPath": "/opt/easytier-core", "downloadProxy": ""})),
        )
        .await;
    assert_eq!(status, hyper::StatusCode::OK);
    let (_, settings) = harness.send("GET", "/api/easytier/settings", None).await;
    assert_eq!(settings["programPath"], "/opt/easytier-core");
    let (status, _) = harness
        .send(
            "PUT",
            "/api/easytier/settings",
            Some(json!({"programPath": "", "downloadProxy": ""})),
        )
        .await;
    assert_eq!(status, hyper::StatusCode::OK);
    // Unknown fields and bad keys are rejected.
    let (status, _) = harness
        .send("POST", "/api/easytier/instances", Some(json!({"nope": 1})))
        .await;
    assert_eq!(status, hyper::StatusCode::BAD_REQUEST);
    let (status, body) = harness
        .send("DELETE", "/api/easytier/instances/batch-delete", None)
        .await;
    assert_eq!(status, hyper::StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid item key");
    // Empty network name is a validation problem.
    let (status, body) = harness
        .send(
            "POST",
            "/api/easytier/instances",
            Some(instance_json("bad", json!({"networkName": ""}))),
        )
        .await;
    assert_eq!(status, hyper::StatusCode::BAD_REQUEST);
    assert!(
        body["problems"]
            .as_array()
            .expect("problems")
            .iter()
            .any(|problem| problem["field"]
                .as_str()
                .expect("f")
                .ends_with("networkName"))
    );
}

#[tokio::test]
async fn easytier_blocked_instance_reports_reason_and_stays_stopped() {
    let harness = harness().await;
    // Two enabled instances with colliding listeners cannot be saved via
    // the API, so simulate a conflict arriving through direct config edit:
    // enable the second instance after clearing the listener of the first
    // is impossible here — instead verify the blocked path via the runtime
    // directly: a missing program yields a blocked snapshot.
    let created = harness.create(instance_json("main", json!({}))).await;
    let key = created["key"].as_str().expect("key").to_owned();
    // Remove the binaries: the next apply (a remark edit) reports the
    // missing program instead of a crash loop.
    let bin = harness.store.dir().join("bin");
    std::fs::remove_file(bin.join("easytier-core")).expect("remove core");
    let mut update = instance_json("main", json!({}));
    update["key"] = key.as_str().into();
    update["latencyFirst"] = true.into();
    let (status, _) = harness
        .send(
            "PUT",
            &format!("/api/easytier/instances/{key}"),
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
            .contains("easytier-core")
    );
}
