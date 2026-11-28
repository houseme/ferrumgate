//! Management HTTP API integration tests (WP-69 §4/§6).

use std::{
    future::poll_fn,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, UNIX_EPOCH},
};

use axum::http::StatusCode;
use fg_config::ConfigStore;
use fg_core::{
    events::{Event, EventBus, Kind},
    sysstat::{HostStats, ProcStats, Sysstat},
};
use fg_perf::{
    BackendSnapshot, Deps, Module, PerfService, ProcHandle, RawProc, SiteSnapshot, limits,
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};

struct StaticSysstat {
    cpu: Mutex<Option<f64>>,
}

impl Sysstat for StaticSysstat {
    fn host(&self) -> HostStats {
        HostStats {
            cpu_percent: *self.cpu.lock().unwrap(),
            mem_used: 2048,
            mem_total: 4096,
            ..HostStats::default()
        }
    }

    fn proc(&self) -> ProcStats {
        ProcStats {
            cpu_percent: Some(1.5),
            rss_bytes: 32 * 1024 * 1024,
            ..ProcStats::default()
        }
    }
}

/// Pure in-memory bidirectional byte stream so tests run real `axum::serve`
/// HTTP/1.1 without touching OS sockets.
struct PipeStream {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    buf: Vec<u8>,
    pos: usize,
}

fn pipe_pair() -> (PipeStream, PipeStream) {
    let (tx_a, rx_b) = mpsc::unbounded_channel();
    let (tx_b, rx_a) = mpsc::unbounded_channel();
    (
        PipeStream {
            rx: rx_a,
            tx: Some(tx_a),
            buf: Vec::new(),
            pos: 0,
        },
        PipeStream {
            rx: rx_b,
            tx: Some(tx_b),
            buf: Vec::new(),
            pos: 0,
        },
    )
}

impl AsyncRead for PipeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.buf.len() {
            let avail = &self.buf[self.pos..];
            let n = avail.len().min(out.remaining());
            out.put_slice(&avail[..n]);
            self.pos += n;
            if self.pos == self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                let n = chunk.len().min(out.remaining());
                out.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.buf = chunk;
                    self.pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for PipeStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let Some(tx) = &self.tx else {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")));
        };
        tx.send(data.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "peer closed"))?;
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.tx.take();
        Poll::Ready(Ok(()))
    }
}

struct PipeListener {
    rx: mpsc::UnboundedReceiver<PipeStream>,
}

impl axum::serve::Listener for PipeListener {
    type Io = PipeStream;
    type Addr = ();

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(io) => (io, ()),
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(())
    }
}

struct Harness {
    connect: mpsc::UnboundedSender<PipeStream>,
    service: Arc<PerfService>,
    clock: Arc<AtomicU64>,
    events: Arc<Mutex<Vec<Arc<Event>>>>,
    _sub: fg_core::events::Subscription,
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let store = ConfigStore::open(dir.path()).unwrap();
    let bus = EventBus::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let capture = Arc::clone(&events);
    let sub = bus
        .subscribe(move |event| {
            let capture = Arc::clone(&capture);
            async move {
                capture.lock().unwrap().push(event);
            }
        })
        .unwrap();

    let clock = Arc::new(AtomicU64::new(1_700_000_000));
    let clock_clone = Arc::clone(&clock);
    let deps = Deps {
        sysstat: Arc::new(StaticSysstat {
            cpu: Mutex::new(Some(95.0)),
        }),
        config_mount: Some(dir.path().to_path_buf()),
        site_stats: Some(Arc::new(|| {
            vec![SiteSnapshot {
                name: "blog".to_owned(),
                active: 2,
                qps: Some(5.0),
                err5xx: Some(0.0),
                latency_p95: Some(12.0),
                window_requests: 50,
                window_span: Duration::from_secs(60),
                backends: vec![BackendSnapshot {
                    name: "up1".to_owned(),
                    healthy: true,
                    conns: 2,
                }],
            }]
        })),
        managed_procs: Some(Arc::new(|| {
            vec![
                ProcHandle {
                    key: "frp:main".to_owned(),
                    name: "frpc".to_owned(),
                    pid: Some(101),
                },
                ProcHandle {
                    key: "tailscale:node1".to_owned(),
                    name: "tailscaled".to_owned(),
                    pid: Some(202),
                },
            ]
        })),
        proc_reader: Arc::new(|handle| match handle.pid {
            Some(101) => RawProc {
                cpu_percent: Some(1.0),
                rss_bytes: Some(1024),
            },
            Some(202) => RawProc {
                cpu_percent: Some(3.0),
                rss_bytes: Some(2048),
            },
            _ => RawProc::default(),
        }),
        clock: Arc::new(move || {
            UNIX_EPOCH + Duration::from_secs(clock_clone.load(Ordering::SeqCst))
        }),
        sample_interval: Duration::from_secs(5),
    };

    let module = Module::new(store, bus, deps).unwrap();
    let service = module.service();
    let app = module.mount(axum::Router::new());
    let (connect, rx) = mpsc::unbounded_channel();
    let listener = PipeListener { rx };
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Harness {
        connect,
        service,
        clock,
        events,
        _sub: sub,
        _dir: dir,
    }
}

impl Harness {
    async fn send_raw(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, String, String) {
        let (mut client, server) = pipe_pair();
        self.connect.send(server).expect("server running");

        let payload = body.map(|v| v.to_string()).unwrap_or_default();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        let req_bytes = request.as_bytes();
        let mut written = 0;
        while written < req_bytes.len() {
            let n = poll_fn(|cx| Pin::new(&mut client).poll_write(cx, &req_bytes[written..]))
                .await
                .unwrap();
            written += n;
        }

        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let mut buf = ReadBuf::new(&mut chunk);
            poll_fn(|cx| Pin::new(&mut client).poll_read(cx, &mut buf))
                .await
                .unwrap();
            if buf.filled().is_empty() {
                break;
            }
            raw.extend_from_slice(buf.filled());
        }

        let text = String::from_utf8(raw).expect("utf-8 HTTP response");
        let (head, body_raw) = text.split_once("\r\n\r\n").expect("HTTP header/body split");
        let mut lines = head.lines();
        let status_line = lines.next().expect("status line");
        let code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .expect("status code")
            .parse()
            .unwrap();
        let mut content_type = String::new();
        let mut chunked = false;
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                if k.eq_ignore_ascii_case("content-type") {
                    content_type = v.trim().to_owned();
                } else if k.eq_ignore_ascii_case("transfer-encoding")
                    && v.to_ascii_lowercase().contains("chunked")
                {
                    chunked = true;
                }
            }
        }
        let body = if chunked {
            decode_chunked(body_raw)
        } else {
            body_raw.to_owned()
        };
        (StatusCode::from_u16(code).unwrap(), content_type, body)
    }

    async fn send(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let (status, _, text) = self.send_raw(method, path, body).await;
        let json: Value = serde_json::from_str(&text).unwrap_or_else(|e| {
            panic!("invalid JSON ({status}): {e}: {text}");
        });
        (status, json)
    }
}

fn decode_chunked(mut rest: &str) -> String {
    let mut out = String::new();
    while let Some((size_line, after)) = rest.split_once("\r\n") {
        let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
        if size == 0 {
            break;
        }
        out.push_str(&after[..size]);
        rest = &after[size + 2..];
    }
    out
}

#[tokio::test]
async fn overview_sites_processes_and_ranges() {
    let h = harness().await;
    h.service.sample_once().await;
    h.clock.fetch_add(60, Ordering::SeqCst);
    h.service.sample_once().await;

    // Default and explicit ranges
    for (path, expected_range, expected_step) in [
        ("/api/perf/overview", "60s", 5),
        ("/api/perf/overview?range=60s", "60s", 5),
        ("/api/perf/overview?range=1h", "1h", 60),
        ("/api/perf/overview?range=24h", "24h", 300),
    ] {
        let (status, body) = h.send("GET", path, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["range"], expected_range);
        assert_eq!(body["step"], expected_step);
        assert!(
            !body["series"]["hostCpu"]["points"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    // Invalid range returns 400
    let (status, _) = h.send("GET", "/api/perf/overview?range=7d", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Sites view
    let (status, sites) = h.send("GET", "/api/perf/sites", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sites.as_array().unwrap().len(), 1);
    assert_eq!(sites[0]["name"], "blog");
    assert_eq!(sites[0]["healthyBackends"], 1);

    // Processes view (unscoped and scoped)
    let (status, procs) = h.send("GET", "/api/perf/processes", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(procs["processes"].as_array().unwrap().len(), 2);
    assert_eq!(procs["totalCpu"], 4.0);
    assert_eq!(procs["totalRss"], 3072);

    let (status, scoped) = h.send("GET", "/api/perf/processes?scope=frp", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(scoped["processes"].as_array().unwrap().len(), 1);
    assert_eq!(scoped["processes"][0]["key"], "frp:main");
    assert_eq!(scoped["totalCpu"], 1.0);
    assert_eq!(scoped["totalRss"], 1024);
}

#[tokio::test]
async fn rules_crud_batch_and_alert_recovery_flow() {
    let h = harness().await;

    // Create rule 1
    let (status, r1) = h
        .send(
            "POST",
            "/api/perf/rules",
            Some(json!({
                "name": "CPU high",
                "metric": "hostCpu",
                "op": ">",
                "threshold": 90.0,
                "durationMinutes": 1
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let k1 = r1["key"].as_str().unwrap().to_owned();
    assert_eq!(k1.len(), 12);

    // Copy rule 1
    let (status, r2) = h
        .send(
            "POST",
            &format!("/api/perf/rules/{k1}/copy"),
            Some(json!({
                "name": "CPU high copy",
                "metric": "hostCpu",
                "op": ">",
                "threshold": 99.0,
                "durationMinutes": 1
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let k2 = r2["key"].as_str().unwrap().to_owned();
    assert_ne!(k1, k2);

    // Order rules: reverse
    let (status, _) = h
        .send(
            "PUT",
            "/api/perf/rules-order",
            Some(json!({ "keys": [k2, k1] })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, list) = h.send("GET", "/api/perf/rules", None).await;
    assert_eq!(list[0]["key"], k2);
    assert_eq!(list[1]["key"], k1);

    // Group rules
    let (status, _) = h
        .send(
            "PUT",
            "/api/perf/rules-group",
            Some(json!({ "keys": [k1, k2], "group": "host" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Trigger alert on rule 1 (hostCpu = 95 > 90; rule 2 is > 99 so not met).
    h.service.sample_once().await;
    h.clock.fetch_add(60, Ordering::SeqCst);
    h.service.sample_once().await;

    let (status, alerts) = h.send("GET", "/api/perf/alerts", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(alerts.as_array().unwrap().len(), 1);
    assert_eq!(alerts[0]["rule"], k1);
    assert_eq!(alerts[0]["state"], "firing");

    let (status, content_type, metrics_text) = h.send_raw("GET", "/api/perf/metrics", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(content_type.starts_with("text/plain"));
    assert!(metrics_text.contains("ferrumgate_perf_alerts_firing 1"));

    // Non-semantic edit (rename only) preserves firing alert.
    let (status, _) = h
        .send(
            "PUT",
            &format!("/api/perf/rules/{k1}"),
            Some(json!({
                "name": "CPU renamed",
                "group": "host",
                "enable": true,
                "metric": "hostCpu",
                "op": ">",
                "threshold": 90.0,
                "durationMinutes": 1,
                "level": "error"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.service.firing_count(), 1);

    // Semantic edit (threshold 90 -> 80) clears firing and emits perf.recovered(ruleEdited).
    let (status, _) = h
        .send(
            "PUT",
            &format!("/api/perf/rules/{k1}"),
            Some(json!({
                "name": "CPU renamed",
                "group": "host",
                "enable": true,
                "metric": "hostCpu",
                "op": ">",
                "threshold": 80.0,
                "durationMinutes": 1,
                "level": "error"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.service.firing_count(), 0);

    // Fire again, then disable via /enable -> emits perf.recovered(ruleDisabled).
    h.clock.fetch_add(5, Ordering::SeqCst);
    h.service.sample_once().await;
    h.clock.fetch_add(60, Ordering::SeqCst);
    h.service.sample_once().await;
    assert_eq!(h.service.firing_count(), 1);

    let (status, _) = h
        .send(
            "PUT",
            &format!("/api/perf/rules/{k1}/enable"),
            Some(json!({ "enable": false })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.service.firing_count(), 0);

    // Re-enable rule 1, fire again, then single DELETE emits perf.recovered(ruleDeleted).
    let (status, _) = h
        .send(
            "PUT",
            &format!("/api/perf/rules/{k1}/enable"),
            Some(json!({ "enable": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    h.clock.fetch_add(5, Ordering::SeqCst);
    h.service.sample_once().await;
    h.clock.fetch_add(60, Ordering::SeqCst);
    h.service.sample_once().await;
    assert_eq!(h.service.firing_count(), 1);

    let (status, res) = h
        .send("DELETE", &format!("/api/perf/rules/{k1}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(res["removed"], 1);
    assert_eq!(h.service.firing_count(), 0);

    // Batch enable & batch delete remaining rule 2
    let (status, res) = h
        .send(
            "PUT",
            "/api/perf/rules-enable",
            Some(json!({ "keys": [k2], "enable": false })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(res["changed"], 1);

    let (status, res) = h
        .send(
            "POST",
            "/api/perf/rules-delete",
            Some(json!({ "keys": [k2] })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(res["removed"], 1);

    // Unknown key returns 404; invalid key returns 400.
    let (status, _) = h.send("DELETE", "/api/perf/rules/deadbeefcafe", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = h.send("DELETE", "/api/perf/rules/not-hex!", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Wait briefly and verify EventBus captured fired + ruleEdited + ruleDisabled + ruleDeleted.
    for _ in 0..40 {
        if h.events.lock().unwrap().len() >= 6 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let captured = h.events.lock().unwrap();
    assert!(captured.iter().any(|e| e.kind == Kind::PerfAlert));
    for expected_reason in ["ruleEdited", "ruleDisabled", "ruleDeleted"] {
        assert!(
            captured.iter().any(|e| {
                e.kind == Kind::PerfRecovered
                    && e.args
                        .iter()
                        .any(|(k, v)| *k == "reason" && v == expected_reason)
            }),
            "missing recovery reason {expected_reason}"
        );
    }
}

#[tokio::test]
async fn rules_enforce_max_limit_200() {
    let h = harness().await;
    // Seed 200 rules directly into config, then verify 201st via POST returns 400.
    {
        let cfg = h.service.config();
        let mut guard = cfg.write().await;
        for i in 0..limits::MAX_RULES {
            guard.rules.push(fg_perf::AlertRule {
                key: format!("{i:012x}"),
                name: format!("rule-{i}"),
                ..fg_perf::AlertRule::default()
            });
        }
    }
    let (status, body) = h
        .send(
            "POST",
            "/api/perf/rules",
            Some(json!({
                "name": "overflow",
                "metric": "hostCpu",
                "op": ">",
                "threshold": 90.0
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["problems"][0]["field"], "rules");
}
