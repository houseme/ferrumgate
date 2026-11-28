//! Shared helpers for the fg-proc integration tests: the rustc-compiled
//! fixture executable, a local fake HTTP server (conventions §4: no shell
//! scripts, no real downloads) and a minimal HTTP/1.1 GET client wired
//! into the injectable [`HttpGetter`] download channel.

#![allow(dead_code)]

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use fg_proc::{HttpGetter, HttpResponse};
use tokio::sync::watch;

// ---------------------------------------------------------------------------
// Fixture executable
// ---------------------------------------------------------------------------

/// Builds the small Rust fixture executable with rustc and returns its
/// path; one build per test process.
pub fn fixture() -> PathBuf {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE.get_or_init(build).clone()
}

fn build() -> PathBuf {
    let source = include_str!("../fixtures/fixture.rs");
    let id = std::process::id();
    let source_path = std::env::temp_dir().join(format!("fg-proc-fixture-{id}.rs"));
    let out_path = std::env::temp_dir().join(format!("fg-proc-fixture-{id}"));
    std::fs::write(&source_path, source).expect("write fixture source");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let status = std::process::Command::new(rustc)
        .args(["--edition", "2021"])
        .arg("-O")
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
// Fake HTTP server + minimal GET client
// ---------------------------------------------------------------------------

struct FakeHttpInner {
    routes: Mutex<HashMap<String, Vec<u8>>>,
    hits: Mutex<HashMap<String, usize>>,
}

/// A local fake HTTP server standing in for the upstream release pages.
pub struct FakeHttp {
    pub base_url: String,
    getter: HttpGetter,
    inner: Arc<FakeHttpInner>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl FakeHttp {
    /// Starts serving `routes` (path → body) on a random loopback port.
    pub async fn start(routes: HashMap<String, Vec<u8>>) -> Self {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind fake http server");
        let port = listener.local_addr().expect("local addr").port();
        let inner = Arc::new(FakeHttpInner {
            routes: Mutex::new(routes),
            hits: Mutex::new(HashMap::new()),
        });
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
            getter: http_getter(port),
            inner,
            accept_task,
        }
    }

    /// The download channel pointing at this server.
    pub fn getter(&self) -> HttpGetter {
        self.getter.clone()
    }

    /// How often a path was fetched.
    pub fn hits(&self, path: &str) -> usize {
        self.inner
            .hits
            .lock()
            .expect("hits lock")
            .get(path)
            .copied()
            .unwrap_or(0)
    }

    /// Adds or replaces a route (path → body).
    pub fn set_route(&self, path: &str, body: Vec<u8>) {
        self.inner
            .routes
            .lock()
            .expect("routes lock")
            .insert(path.to_owned(), body);
    }

    pub async fn stop(self) {
        self.accept_task.abort();
    }
}

fn serve_one(mut stream: tokio::net::TcpStream, inner: Arc<FakeHttpInner>) {
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = Vec::new();
        // 读完请求头（最多 8 KiB）。
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
            let mut hits = inner.hits.lock().expect("hits lock");
            *hits.entry(path.clone()).or_insert(0) += 1;
            drop(hits);
            let routes = inner.routes.lock().expect("routes lock");
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

/// A minimal HTTP/1.1 GET client over TCP, wired into the injectable
/// download channel (production wires `fg_net::http::OutboundHttp`).
pub fn http_getter(port: u16) -> HttpGetter {
    HttpGetter::new(move |url, _proxy| {
        Box::pin(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .map_err(|error| anyhow::anyhow!("连接失败：{error}"))?;
            // 只按路径取数（发布列表带 ?per_page=… 的查询，路由按路径匹配）。
            let path = url.path().to_owned();
            let request =
                format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
            stream
                .write_all(request.as_bytes())
                .await
                .map_err(|error| anyhow::anyhow!("发送请求失败：{error}"))?;
            let mut raw = Vec::new();
            stream
                .read_to_end(&mut raw)
                .await
                .map_err(|error| anyhow::anyhow!("读取响应失败：{error}"))?;
            let split = raw
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .ok_or_else(|| anyhow::anyhow!("响应没有头部结束标记"))?;
            let headers = String::from_utf8_lossy(&raw[..split]);
            let total = headers.lines().find_map(|line| {
                let value = line.strip_prefix("Content-Length:")?;
                value.trim().parse::<u64>().ok()
            });
            let body = raw[split + 4..].to_vec();
            Ok(HttpResponse {
                total,
                body: Box::pin(std::io::Cursor::new(body)),
            })
        })
    })
}

/// 一个永不产出数据的下载通道，用来让安装卡在 Downloading 阶段。
pub fn stuck_getter() -> HttpGetter {
    HttpGetter::new(|_, _| {
        Box::pin(async move {
            Ok(HttpResponse {
                total: Some(1 << 20),
                body: Box::pin(StuckReader),
            })
        })
    })
}

struct StuckReader;

impl tokio::io::AsyncRead for StuckReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
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

/// Waits until the install stage reaches a terminal state.
pub async fn wait_stage(
    mut rx: watch::Receiver<fg_proc::Stage>,
    timeout: Duration,
) -> fg_proc::Stage {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let current = rx.borrow_and_update().clone();
        if matches!(
            current,
            fg_proc::Stage::Done | fg_proc::Stage::UpToDate | fg_proc::Stage::Failed(_)
        ) {
            return current;
        }
        if tokio::time::Instant::now() >= deadline {
            return current;
        }
        if rx.changed().await.is_err() {
            return current;
        }
    }
}

/// Atomic counter helper for hit comparisons.
pub fn count_of(counter: &AtomicUsize) -> usize {
    counter.load(Ordering::SeqCst)
}
