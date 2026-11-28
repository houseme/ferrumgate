//! Shared helpers for the fg-cloudflared integration tests: the
//! rustc-compiled `cloudflared` fixture, a module harness (config store +
//! mounted routes on a random loopback port) and a fake Cloudflare API
//! server with a matching outbound channel (conventions §4: no shell
//! scripts, no real network).

#![allow(dead_code)]

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use fg_cloudflared::{Deps, FileConfig, Module, RoutesState, cf_api};
use fg_config::ConfigStore;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Fixture executable
// ---------------------------------------------------------------------------

/// Builds the `cloudflared` fixture with rustc and returns its path; one
/// build per test process.
pub fn fixture() -> PathBuf {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE.get_or_init(build).clone()
}

fn build() -> PathBuf {
    let source = include_str!("../fixtures/cloudflared.rs");
    let id = std::process::id();
    let source_path = std::env::temp_dir().join(format!("fg-cloudflared-fixture-{id}.rs"));
    let out_path = std::env::temp_dir().join(format!("fg-cloudflared-fixture-{id}"));
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
// Module harness
// ---------------------------------------------------------------------------

/// A mounted module with its store dir and server address.
pub struct Harness {
    /// Taken by tests that run [`Module::run`] (it consumes the module).
    pub module: Option<Module>,
    pub state: Arc<RoutesState>,
    pub addr: std::net::SocketAddr,
    pub dir: PathBuf,
    pub cf: Option<FakeCf>,
    server: tokio::task::JoinHandle<()>,
}

/// A `{"a":"acc","t":"tid","s":"sec"}` token, base64 standard.
pub const TUNNEL_TOKEN: &str = "eyJhIjoiYWNjIiwidCI6InRpZCIsInMiOiJzZWMifQ==";

/// Base64 of `{"a":"acc","t":"tid"}` (no secret — parses fine).
pub const TUNNEL_TOKEN_NO_SECRET: &str = "eyJhIjoiYWNjIiwidCI6InRpZCJ9";

pub fn token_config_json(token: &str, api_token: &str) -> String {
    format!(
        r#"{{"settings":{{"binPath":""}},"install":{{"proxy":""}},"tunnels":[{{"key":"k","name":"nas","group":"","enable":false,"mode":"token","token":"{token}","apiToken":"{api_token}","remark":""}}]}}"#
    )
}

/// Spawns the module routes on a random loopback port. `config_json` seeds
/// `cloudflared.json` (empty string = fresh store); `deps` carries the
/// injected channels.
pub async fn harness_with_deps(config_json: &str, deps: Deps) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir").keep();
    let store = ConfigStore::open(&dir).expect("open store");
    if !config_json.is_empty() {
        store
            .write_raw("cloudflared", config_json.as_bytes())
            .expect("seed config");
    }
    let module = Module::new(Arc::clone(&store), deps).expect("module");
    let state = module.routes_state();
    let router = module.mount(axum::Router::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    Harness {
        module: Some(module),
        state,
        addr,
        dir,
        cf: None,
        server,
    }
}

/// Harness with the fixture binary preinstalled as the program path.
pub async fn harness(config_json: &str) -> Harness {
    let fixture_path = fixture().to_string_lossy().into_owned();
    let config_json = if config_json.is_empty() {
        format!(
            r#"{{"settings":{{"binPath":"{fixture_path}"}},"install":{{"proxy":""}},"tunnels":[]}}"#
        )
    } else {
        config_json.replace("%FIXTURE%", &fixture_path)
    };
    harness_with_deps(&config_json, Deps::default()).await
}

impl Harness {
    /// The module (until [`Harness::take_module`]).
    pub fn module(&self) -> &Module {
        self.module.as_ref().expect("module still owned")
    }

    /// Takes the module to run it ([`Module::run`] consumes it).
    pub fn take_module(&mut self) -> Module {
        self.module.take().expect("module still owned")
    }

    /// The tunnel runtime handle.
    pub fn runtime(&self) -> Arc<fg_cloudflared::TunnelRuntime> {
        self.module().runtime()
    }

    /// Sends a JSON request to the mounted routes over raw HTTP/1.1.
    pub async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (u16, serde_json::Value) {
        send_json(self.addr, method, path, body).await
    }
}

/// A minimal HTTP/1.1 JSON client for the mounted routes (conventions §4:
/// tiny fixtures over heavyweight clients).
pub async fn send_json(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> (u16, serde_json::Value) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n");
    match &body {
        Some(body) => {
            let bytes = body.to_string().into_bytes();
            head.push_str("Content-Type: application/json\r\n");
            head.push_str(&format!("Content-Length: {}\r\n\r\n", bytes.len()));
            stream.write_all(head.as_bytes()).await.expect("send head");
            stream.write_all(&bytes).await.expect("send body");
        }
        None => {
            head.push_str("\r\n");
            stream.write_all(head.as_bytes()).await.expect("send head");
        }
    }
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read response");
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header end");
    let status_line = String::from_utf8_lossy(&raw[..split]);
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let value = serde_json::from_slice(&raw[split + 4..]).unwrap_or(serde_json::Value::Null);
    (status, value)
}

impl Harness {
    /// Stops the HTTP server task.
    pub async fn shutdown(self) {
        self.server.abort();
        let _ = self.server.await;
    }
}

// ---------------------------------------------------------------------------
// Fake Cloudflare API server
// ---------------------------------------------------------------------------

/// One recorded request (method, path, query, auth header, JSON body).
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub auth: String,
    pub body: serde_json::Value,
}

struct FakeCfState {
    version: u64,
    /// Remote config source; empty means `cloudflare`.
    source: String,
    config: serde_json::Value,
    records: Vec<serde_json::Value>,
    puts: usize,
    requests: Vec<RecordedRequest>,
    api_token: String,
}

/// A local fake Cloudflare API server standing in for
/// `api.cloudflare.com` (one tunnel `tid` in account `acc`, one zone).
pub struct FakeCf {
    pub base_url: String,
    inner: Arc<Mutex<FakeCfState>>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl FakeCf {
    /// Starts the server. `config` seeds the remote tunnel config (null =
    /// fresh tunnel).
    pub async fn start(config: serde_json::Value) -> Self {
        Self::start_with(config, "cloudflare", "cf-api").await
    }

    pub async fn start_with(config: serde_json::Value, source: &str, api_token: &str) -> Self {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind fake cf");
        let port = listener.local_addr().expect("addr").port();
        let inner = Arc::new(Mutex::new(FakeCfState {
            version: 3,
            source: source.to_owned(),
            config,
            records: Vec::new(),
            puts: 0,
            requests: Vec::new(),
            api_token: api_token.to_owned(),
        }));
        let accept_inner = Arc::clone(&inner);
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                serve_one(stream, Arc::clone(&accept_inner));
            }
        });
        Self {
            base_url: format!("http://127.0.0.1:{port}"),
            inner,
            accept_task,
        }
    }

    /// The outbound channel pointing at this server (conventions §3.4).
    pub fn fetch(&self) -> cf_api::FetchFn {
        let port: u16 = self
            .base_url
            .rsplit(':')
            .next()
            .and_then(|port| port.parse().ok())
            .expect("port");
        Arc::new(move |request: cf_api::FetchRequest| {
            Box::pin(async move { send_request(port, &request).await })
        })
    }

    /// Recorded requests so far.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.inner.lock().expect("fake cf lock").requests.clone()
    }

    pub fn puts(&self) -> usize {
        self.inner.lock().expect("fake cf lock").puts
    }

    pub fn config(&self) -> serde_json::Value {
        self.inner.lock().expect("fake cf lock").config.clone()
    }

    pub fn version(&self) -> u64 {
        self.inner.lock().expect("fake cf lock").version
    }

    pub fn records(&self) -> Vec<serde_json::Value> {
        self.inner.lock().expect("fake cf lock").records.clone()
    }

    /// Seeds existing DNS records (full record objects).
    pub fn set_records(&self, records: Vec<serde_json::Value>) {
        self.inner.lock().expect("fake cf lock").records = records;
    }

    /// Bumps the remote version without touching the config, simulating a
    /// concurrent modification elsewhere.
    pub fn bump_version(&self) {
        let mut state = self.inner.lock().expect("fake cf lock");
        state.version += 1;
    }

    pub async fn stop(self) {
        self.accept_task.abort();
    }
}

fn serve_one(stream: tokio::net::TcpStream, inner: Arc<Mutex<FakeCfState>>) {
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let read_result = read_request(stream).await;
        let (mut stream, method, full_path, headers, body) = match read_result {
            Some(parts) => parts,
            None => return,
        };
        let auth = headers.get("authorization").cloned().unwrap_or_default();
        let (path, query) = match full_path.split_once('?') {
            Some((path, query)) => (path.to_owned(), query.to_owned()),
            None => (full_path.clone(), String::new()),
        };
        let json_body: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        let record = RecordedRequest {
            method: method.clone(),
            path: path.clone(),
            query: query.clone(),
            auth: auth.clone(),
            body: json_body.clone(),
        };
        let expected_auth = format!("Bearer {}", inner.lock().expect("fake cf lock").api_token);
        let mut status = String::from("200 OK");
        let payload = if auth != expected_auth {
            status = "403 Forbidden".into();
            serde_json::json!({
                "success": false,
                "errors": [{"code": 10000, "message": "Authentication error"}],
                "result": null,
            })
        } else {
            route(&method, &path, &query, &json_body, &inner, &mut status)
        };
        {
            let mut state = inner.lock().expect("fake cf lock");
            state.requests.push(record);
        }
        let body_bytes = serde_json::to_vec(&payload).expect("serialize");
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body_bytes.len()
        )
        .into_bytes();
        let _ = stream.write_all(&response).await;
        let _ = stream.write_all(&body_bytes).await;
    });
}

fn route(
    method: &str,
    path: &str,
    query: &str,
    body: &serde_json::Value,
    inner: &Arc<Mutex<FakeCfState>>,
    status: &mut String,
) -> serde_json::Value {
    let reply = |result: serde_json::Value| -> serde_json::Value {
        serde_json::json!({"success": true, "errors": [], "result": result})
    };
    let mut state = inner.lock().expect("fake cf lock");
    let config_path = "/accounts/acc/cfd_tunnel/tid/configurations";
    match (method, path) {
        ("GET", p) if p == config_path => {
            let source = if state.source.is_empty() {
                "cloudflare".to_owned()
            } else {
                state.source.clone()
            };
            reply(serde_json::json!({
                "tunnel_id": "tid",
                "version": state.version,
                "source": source,
                "config": state.config,
            }))
        }
        ("PUT", p) if p == config_path => {
            let new_config = body
                .get("config")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            state.config = new_config;
            state.version += 1;
            state.puts += 1;
            reply(serde_json::json!({
                "tunnel_id": "tid",
                "version": state.version,
                "source": "cloudflare",
                "config": state.config,
            }))
        }
        ("GET", "/zones") => {
            // 只认隧道所属账号下的域名。
            let params = parse_query(query);
            if params.get("name").map(String::as_str) == Some("example.com")
                && params.get("account.id").map(String::as_str) == Some("acc")
            {
                reply(serde_json::json!([{"id": "z1", "name": "example.com"}]))
            } else {
                reply(serde_json::json!([]))
            }
        }
        ("GET", "/zones/z1/dns_records") => {
            let params = parse_query(query);
            let name = params.get("name").cloned().unwrap_or_default();
            let out: Vec<serde_json::Value> = state
                .records
                .iter()
                .filter(|record| {
                    record.get("name").and_then(|value| value.as_str()) == Some(name.as_str())
                })
                .cloned()
                .collect();
            reply(serde_json::Value::Array(out))
        }
        ("POST", "/zones/z1/dns_records") => {
            state.records.push(body.clone());
            reply(body.clone())
        }
        _ => {
            *status = "404 Not Found".into();
            serde_json::json!({
                "success": false,
                "errors": [{"code": 7000, "message": "No route for that URI"}],
                "result": null,
            })
        }
    }
}

fn parse_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.replace("%2E", ".").replace('+', " ")))
        .collect()
}

type RawParts = (
    tokio::net::TcpStream,
    String,
    String,
    HashMap<String, String>,
    Vec<u8>,
);

async fn read_request(mut stream: tokio::net::TcpStream) -> Option<RawParts> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    let header_end;
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(read) => {
                buf.extend_from_slice(&chunk[..read]);
                if let Some(position) = find_header_end(&buf) {
                    header_end = position;
                    break;
                }
                if buf.len() > 1 << 20 {
                    return None;
                }
            }
        }
    }
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let full_path = parts.next()?.to_owned();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let content_length: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => body.extend_from_slice(&chunk[..read]),
        }
    }
    body.truncate(content_length);
    Some((stream, method, full_path, headers, body))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

/// A minimal HTTP/1.1 client for the injected Cloudflare channel.
pub async fn send_request(
    port: u16,
    request: &cf_api::FetchRequest,
) -> anyhow::Result<cf_api::FetchResponse> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|error| anyhow::anyhow!("连接失败：{error}"))?;
    let path = {
        let mut path = request.url.path().to_owned();
        if let Some(query) = request.url.query() {
            path.push('?');
            path.push_str(query);
        }
        path
    };
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n",
        request.method, path
    );
    head.push_str(&format!("Authorization: {}\r\n", request.auth));
    if let Some(body) = &request.body {
        head.push_str("Content-Type: application/json\r\n");
        head.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    } else {
        head.push_str("\r\n");
    }
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|error| anyhow::anyhow!("发送请求失败：{error}"))?;
    if let Some(body) = &request.body {
        stream
            .write_all(body)
            .await
            .map_err(|error| anyhow::anyhow!("发送请求体失败：{error}"))?;
    }
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .map_err(|error| anyhow::anyhow!("读取响应失败：{error}"))?;
    let split = find_header_end(&raw).ok_or_else(|| anyhow::anyhow!("响应没有头部结束标记"))?;
    let status_line = String::from_utf8_lossy(&raw[..split]);
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    Ok(cf_api::FetchResponse {
        status,
        body: raw[split + 4..].to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Waiting helpers
// ---------------------------------------------------------------------------

/// Polls `check` until it returns true or `timeout` elapses.
pub async fn wait_until(mut check: impl FnMut() -> bool, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if check() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Builds Deps wired to the fake Cloudflare server.
pub fn deps_with_cf(cf: &FakeCf) -> Deps {
    Deps {
        fetch: None,
        cf_http: Some(cf.fetch()),
        bus: None,
        cf_endpoint: Some(cf.base_url.clone()),
    }
}

/// Creates a quick tunnel config JSON with the fixture path; `record`
/// optionally wires the invocation recorder through `extraEnv`.
pub fn quick_tunnel_config(
    extra_args: &[&str],
    quick_url: Option<&str>,
    enabled: bool,
    record: Option<&Path>,
) -> String {
    let fixture_path = fixture().to_string_lossy().replace('\\', "/");
    let extra = serde_json::to_string(
        &extra_args
            .iter()
            .map(|arg| arg.to_string())
            .collect::<Vec<_>>(),
    )
    .expect("args");
    let url = match quick_url {
        Some(url) => format!("\"{url}\""),
        None => "null".to_owned(),
    };
    let env = match record {
        Some(record) => format!(
            r#","extraEnv":[["FGCLOUDFLARED_RECORD","{}"]]"#,
            record.to_string_lossy().replace('\\', "/")
        ),
        None => String::new(),
    };
    format!(
        r#"{{"settings":{{"binPath":"{fixture_path}"}},"install":{{"proxy":""}},"tunnels":[{{"key":"q","name":"quick","group":"","enable":{enabled},"mode":"quick","token":"","service":{url},"extraArgs":{extra}{env},"remark":""}}]}}"#
    )
}

/// Reads the fixture's recorded invocation (args + TUNNEL_TOKEN).
pub fn read_record(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).expect("record file");
    serde_json::from_slice(&bytes).expect("record json")
}

/// A shared config lock wrapper matching the RoutesState shape.
pub fn config_lock(config: FileConfig) -> Arc<RwLock<FileConfig>> {
    Arc::new(RwLock::new(config))
}
