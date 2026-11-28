//! Shared helpers for the fg-frp integration tests: the rustc-compiled
//! fixture executable standing in for frpc / frps, a fake config store
//! harness for the runtime, and a local fake HTTP server for the
//! online-install tests (conventions §4: no shell scripts, no real
//! downloads).

#![allow(dead_code)]

use std::{
    io::Write as _,
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::Duration,
};

use fg_config::ConfigStore;
use fg_frp::runtime::Deps;
use fg_frp::{FileConfig, Runtime};
use fg_net::openports::OpenPorts;
use fg_proc::{HttpGetter, HttpResponse, Proc};
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Fixture executable
// ---------------------------------------------------------------------------

/// Builds the fixture executable with rustc; one build per test process.
pub fn fixture() -> PathBuf {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE.get_or_init(build).clone()
}

fn build() -> PathBuf {
    let source = include_str!("../fixtures/frp_fixture.rs");
    let id = std::process::id();
    let source_path = std::env::temp_dir().join(format!("fg-frp-fixture-{id}.rs"));
    let out_path = std::env::temp_dir().join(format!("fg-frp-fixture-{id}"));
    std::fs::write(&source_path, source).expect("write fixture source");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let status = std::process::Command::new(rustc)
        .args(["--edition", "2021"])
        .arg("-o")
        .arg(&out_path)
        .arg(&source_path)
        .status()
        .expect("run rustc");
    assert!(status.success(), "compiling the fixture failed");
    let _ = std::fs::remove_file(&source_path);
    out_path
}

// ---------------------------------------------------------------------------
// Harness: tempdir store + Proc with the fixtures in bin/ + Runtime
// ---------------------------------------------------------------------------

pub struct Harness {
    pub store: Arc<ConfigStore>,
    pub runtime: Arc<Runtime>,
    pub config: Arc<RwLock<FileConfig>>,
    pub open_ports: Arc<OpenPorts>,
    pub proc: Arc<Proc>,
    _dir: tempfile::TempDir,
}

impl std::ops::Deref for Harness {
    type Target = Arc<Runtime>;
    fn deref(&self) -> &Arc<Runtime> {
        &self.runtime
    }
}

impl std::ops::Drop for Harness {
    fn drop(&mut self) {
        // Stop the instances without a runtime (best effort; the
        // supervisors also die with their process on drop).
        futures_stop(&self.runtime);
    }
}

fn futures_stop(runtime: &Arc<Runtime>) {
    // Drop can run inside a tokio worker thread; the stop itself goes to a
    // dedicated blocking thread with its own runtime.
    let runtime = Arc::clone(runtime);
    let _ = std::thread::Builder::new()
        .name("fg-frp-harness-drop".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("drop runtime");
            rt.block_on(async move {
                let _ = tokio::time::timeout(Duration::from_secs(10), runtime.stop_all()).await;
            });
        });
}

/// Builds a harness whose `bin/` holds the fixture as both `frpc` and
/// `frps`, so the runtime resolves them from the bin directory.
pub fn harness() -> Harness {
    harness_with_deps(|store| {
        let proc = Proc::open(store, None).expect("proc open");
        let bin = store.data_dir("bin").expect("bin dir");
        std::fs::copy(fixture(), bin.join("frpc")).expect("copy frpc fixture");
        std::fs::copy(fixture(), bin.join("frps")).expect("copy frps fixture");
        proc
    })
}

/// Builds a harness with a custom `Proc` builder (e.g. a fetch channel for
/// the install tests); fixtures are copied into `bin/` afterwards.
pub fn harness_with_deps(build_proc: impl FnOnce(&Arc<ConfigStore>) -> Arc<Proc>) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    // ConfigStore::open already returns an Arc handle.
    let store = ConfigStore::open(dir.path()).expect("store open");
    let proc = build_proc(&store);
    let bin = store.data_dir("bin").expect("bin dir");
    let _ = std::fs::create_dir_all(&bin);
    let open_ports = OpenPorts::new();
    let config = Arc::new(RwLock::new(FileConfig::default()));
    let runtime = Runtime::open(
        Arc::clone(&config),
        Deps {
            proc: Arc::clone(&proc),
            fw_open: None,
            open_ports: Some(Arc::clone(&open_ports)),
            ip_sets: None,
        },
        &store,
    )
    .expect("runtime open");
    Harness {
        store,
        runtime,
        config,
        open_ports,
        proc,
        _dir: dir,
    }
}

/// A configured frpc client (enabled) with the fixture-compatible shape.
pub fn client(key: &str, name: &str, server: &str) -> fg_frp::Client {
    fg_frp::Client {
        key: key.to_owned(),
        name: name.to_owned(),
        enable: true,
        server_addr: server.to_owned(),
        server_port: 7000,
        token: format!("token-{key}"),
        ..fg_frp::Client::default()
    }
}

/// A configured frps server (enabled).
pub fn server(key: &str, name: &str) -> fg_frp::Server {
    fg_frp::Server {
        key: key.to_owned(),
        name: name.to_owned(),
        enable: true,
        bind_port: 7000,
        token: format!("token-{key}"),
        ..fg_frp::Server::default()
    }
}

/// A tcp proxy owned by `client_key`.
pub fn proxy(key: &str, name: &str, remote: u16, client_key: &str) -> fg_frp::Proxy {
    fg_frp::Proxy {
        key: key.to_owned(),
        name: name.to_owned(),
        enable: true,
        typ: fg_frp::ProxyType::Tcp,
        local_ip: "127.0.0.1".into(),
        local_port: 22,
        remote_port: remote,
        client: client_key.to_owned(),
        ..fg_frp::Proxy::default()
    }
}

/// Installs `config` into the harness and runs a reconcile pass.
pub async fn reconcile_with(harness: &Harness, config: FileConfig) {
    *harness.config.write().await = config;
    Runtime::reconcile(&harness.runtime).await;
}

/// Polls the async `check` until true or the timeout elapses. Stays on the
/// caller's runtime — never creates auxiliary ones (the supervisor's
/// process driver is per-runtime).
pub async fn wait_until(timeout: Duration, mut check: impl AsyncFnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if check().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---------------------------------------------------------------------------
// Fake HTTP server + minimal GET client (online-install tests)
// ---------------------------------------------------------------------------

/// A local fake HTTP server standing in for the GitHub release pages.
pub struct FakeHttp {
    pub base_url: String,
    getter: HttpGetter,
    routes: Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl FakeHttp {
    /// Starts serving `routes` (path → body) on a random loopback port.
    pub async fn start(routes: std::collections::HashMap<String, Vec<u8>>) -> Self {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind fake http server");
        let port = listener.local_addr().expect("local addr").port();
        let routes = Arc::new(std::sync::Mutex::new(routes));
        let accept_routes = Arc::clone(&routes);
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                serve_one(stream, Arc::clone(&accept_routes));
            }
        });
        let port_for_getter = port;
        let _ = port_for_getter;
        let routes_for_getter = Arc::clone(&routes);
        Self {
            base_url: format!("http://127.0.0.1:{port}"),
            getter: HttpGetter::new(move |url, _proxy| {
                let routes = Arc::clone(&routes_for_getter);
                Box::pin(async move {
                    let path = url.path().to_owned();
                    let body = routes
                        .lock()
                        .expect("routes lock")
                        .get(&path)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("no route for {path}"))?;
                    Ok(HttpResponse {
                        total: Some(body.len() as u64),
                        body: Box::pin(std::io::Cursor::new(body)),
                    })
                })
            }),
            routes,
            accept_task,
        }
    }

    pub fn getter(&self) -> HttpGetter {
        self.getter.clone()
    }

    pub fn set_route(&self, path: &str, body: Vec<u8>) {
        self.routes
            .lock()
            .expect("routes lock")
            .insert(path.to_owned(), body);
    }

    pub async fn stop(self) {
        self.accept_task.abort();
    }
}

fn serve_one(
    mut stream: tokio::net::TcpStream,
    routes: Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
) {
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => {
                    buf.extend_from_slice(&chunk[..read]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                        break;
                    }
                }
            }
        }
        let request = String::from_utf8_lossy(&buf);
        let path = request.split_whitespace().nth(1).unwrap_or("/").to_owned();
        let response = {
            let routes = routes.lock().expect("routes lock");
            match routes.get(&path) {
                Some(body) => {
                    let mut head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .into_bytes();
                    head.extend_from_slice(body);
                    head
                }
                None => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            }
        };
        let _ = stream.write_all(&response).await;
    });
}

// ---------------------------------------------------------------------------
// Fake release payloads (frp asset naming, real fixture bytes)
// ---------------------------------------------------------------------------

fn go_os_arch() -> (String, String) {
    (
        fg_proc::install::platform::go_os(std::env::consts::OS).to_owned(),
        fg_proc::install::platform::go_arch(std::env::consts::ARCH).to_owned(),
    )
}

/// Builds a tar.gz payload with the fixture binary under the frp layout
/// (`frp_<version>/<program>`), like the real release archives.
pub fn build_payload(version: &str) -> Vec<u8> {
    let binary = std::fs::read(fixture()).expect("read fixture binary");
    let mut builder = tar::Builder::new(Vec::new());
    for name in ["frpc", "frps"] {
        let mut header = tar::Header::new_gnu();
        header.set_size(binary.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                format!("frp-{version}/{name}"),
                binary.as_slice(),
            )
            .expect("append payload entry");
    }
    let tar_bytes = builder.into_inner().expect("finish payload tar");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&tar_bytes).expect("gzip payload");
    encoder.finish().expect("gzip finish")
}

/// The frp asset name for the current platform per the static spec's
/// pattern (`frp_{version}_{os}_{arch}.tar.gz`).
pub fn asset_name(version: &str) -> String {
    let (os, arch) = go_os_arch();
    format!("frp_{version}_{os}_{arch}.tar.gz")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A release-list JSON entry with a digest-bearing asset.
pub fn release_json_entry(version: &str, asset_url: &str, digest: &str) -> String {
    format!(
        r#"{{ "tag_name": "v{version}", "prerelease": false, "draft": false, "assets": [
            {{ "name": "{}", "browser_download_url": "{asset_url}", "digest": "sha256:{digest}" }}] }}"#,
        asset_name(version)
    )
}

/// Installs a fake release of both programs into the harness store.
pub async fn fake_upstream() -> (FakeHttp, String) {
    let server = FakeHttp::start(std::collections::HashMap::new()).await;
    let payload = build_payload("1.0.0");
    let digest = sha256_hex(&payload);
    let asset_url = format!("{}/asset/1.0.0", server.base_url);
    server.set_route("/asset/1.0.0", payload);
    let list = format!("[{}]", release_json_entry("1.0.0", &asset_url, &digest));
    server.set_route("/repos/fatedier/frp/releases", list.into_bytes());
    (server, digest)
}
