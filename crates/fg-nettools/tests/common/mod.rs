//! Shared helpers for the fg-nettools integration tests: a mounted module
//! over a temp config store plus a minimal HTTP/1.1 client.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{Router, http::StatusCode};
use fg_config::ConfigStore;
use fg_nettools::{Deps, JobRegistry, JobStatus, JobView, Module};
use http_body_util::BodyExt;
use hyper::header::CONTENT_TYPE;
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tempfile::TempDir;

/// A mounted router over a temp config store.
pub struct Harness {
    pub addr: SocketAddr,
    pub registry: Arc<JobRegistry>,
    pub store: Arc<ConfigStore>,
    _dir: TempDir,
}

pub async fn harness() -> Harness {
    harness_with_deps(Deps::default()).await
}

pub async fn harness_with_deps(deps: Deps) -> Harness {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = ConfigStore::open(dir.path()).expect("config store");
    let module = Module::new(Arc::clone(&store), deps).expect("module");
    let registry = module.registry();
    let app: Router = module.mount(Router::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    Harness {
        addr,
        registry,
        store,
        _dir: dir,
    }
}

impl Harness {
    pub async fn send(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
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

    /// Re-reads the persisted config file through a fresh load.
    pub fn load_config(&self) -> fg_nettools::FileConfig {
        match self.store.load(fg_nettools::CONFIG_NAME).expect("load") {
            fg_config::Loaded::Found(config) => config,
            fg_config::Loaded::Missing => fg_nettools::FileConfig::default(),
        }
    }
}

/// Polls until the job left the running state and returns its view.
pub async fn wait_finished(registry: &Arc<JobRegistry>, id: &str) -> JobView {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(view) = registry.get(id)
            && view.status != JobStatus::Running
        {
            return view;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "job {id} did not finish"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Binds a listener on a free loopback port and keeps it open.
pub async fn spawn_listener() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let _ = listener.accept().await;
        }
    });
    addr
}
