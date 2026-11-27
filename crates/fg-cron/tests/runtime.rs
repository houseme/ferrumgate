//! Runtime integration tests (WP-62 §6): overlap skipping, run-now manual
//! flag, bounded history through the scheduler, the reload loop and the
//! module wiring. Commands run through the real `sh -c` path with the Rust
//! fixture executable.

#![cfg(unix)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use common::{fixture, sh_quote};
use fg_config::{ConfigStore, Loaded};
use fg_cron::model::{FileConfig, Task, TaskKind, limits};
use fg_cron::runtime::{RunNow, Scheduler};

fn task_with(key: &str, spec: &str, command: String, enable: bool) -> Task {
    Task {
        key: key.to_owned(),
        name: key.to_owned(),
        spec: spec.to_owned(),
        kind: TaskKind::Command,
        command,
        enable,
        ..Task::default()
    }
}

fn new_scheduler(tasks: Vec<Task>) -> Arc<Scheduler> {
    let config = Arc::new(tokio::sync::RwLock::new(FileConfig { tasks }));
    Arc::new(Scheduler::new(config, None))
}

async fn wait_for(timeout: Duration, mut check: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    check()
}

#[tokio::test]
async fn overlap_skipped() {
    let program = sh_quote(&fixture());
    // Fires every 400ms while one run takes ~1s: the triggers in between
    // are skipped and recorded.
    let scheduler = new_scheduler(vec![task_with(
        "slow",
        "@every 400ms",
        format!("{program} sleep 1"),
        true,
    )]);
    let (drain_tx, drain_rx) = watch::channel(false);
    let runner = tokio::spawn(Arc::clone(&scheduler).run(drain_rx));
    // Wait for a full cycle: a run finishing after at least one skipped
    // trigger (run starts at ~400ms and takes ~1s).
    let settled = wait_for(Duration::from_secs(6), || {
        let history = scheduler.history("slow");
        let skips = history.iter().filter(|record| record.skipped).count();
        let runs = history
            .iter()
            .filter(|record| !record.skipped && record.success)
            .count();
        skips >= 1 && runs >= 1
    })
    .await;
    assert!(settled, "expected a skipped trigger and a finished run");
    let history = scheduler.history("slow");
    let skips = history.iter().filter(|record| record.skipped).count();
    let runs = history
        .iter()
        .filter(|record| !record.skipped && record.success)
        .count();
    assert!(skips >= 1, "{history:?}");
    assert!(runs >= 1, "successful runs are recorded too: {history:?}");
    for record in history.iter().filter(|record| record.skipped) {
        assert!(record.output.contains("已跳过"));
        assert_eq!(record.duration, Duration::ZERO);
    }
    drain_tx.send(true).expect("drain");
    runner.await.expect("scheduler loop").expect("run");
}

#[tokio::test]
async fn run_now_manual_flag() {
    let program = sh_quote(&fixture());
    let scheduler = new_scheduler(vec![task_with(
        "manual",
        "@daily",
        format!("{program} emit 3"),
        false,
    )]);
    // Start a long manual run in the background.
    let busy_scheduler = Arc::clone(&scheduler);
    let first = tokio::spawn(async move { busy_scheduler.run_now("manual").await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    // A second attempt while it runs is skipped (manual flag kept).
    match scheduler.run_now("manual").await {
        RunNow::Busy => {}
        other => panic!("expected busy, got {other:?}"),
    }
    let record = match first.await.expect("first run") {
        RunNow::Record(record) => record,
        other => panic!("expected a record, got {other:?}"),
    };
    assert!(record.manual);
    assert!(record.success);
    assert_eq!(record.output.trim_end(), "xxx");
    // The busy attempt was recorded as a manual skip.
    let history = scheduler.history("manual");
    assert_eq!(history.len(), 2);
    assert!(history[0].skipped && history[0].manual);
    assert!(history[1].manual && !history[1].skipped);
    // Unknown key.
    assert!(matches!(scheduler.run_now("ghost").await, RunNow::NotFound));
}

#[tokio::test]
async fn history_stays_bounded_through_scheduler() {
    // The scheduler records more runs than the cap; the per-task history
    // keeps the newest 20 (the cap itself is unit-tested on the model).
    let scheduler = new_scheduler(vec![task_with("many", "@daily", "echo run".into(), false)]);
    for _ in 0..25 {
        scheduler.run_now("many").await;
    }
    let history = scheduler.history("many");
    assert_eq!(history.len(), limits::HISTORY_PER_TASK);
}

#[tokio::test]
async fn reload_restores_task_loops_on_config_change() {
    let config = Arc::new(tokio::sync::RwLock::new(FileConfig::default()));
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&config), None));
    let (drain_tx, drain_rx) = watch::channel(false);
    let runner = tokio::spawn(Arc::clone(&scheduler).run(drain_rx));
    let on_change = scheduler.on_change_handle();
    // Add an enabled task through the shared config and notify: the loop
    // restarts and executes it.
    let program = sh_quote(&fixture());
    let task = task_with("reload", "@every 300ms", format!("{program} emit 1"), true);
    config.write().await.tasks.push(task);
    on_change();
    let saw_run = wait_for(Duration::from_secs(3), || {
        scheduler
            .history("reload")
            .iter()
            .any(|record| !record.skipped && record.success)
    })
    .await;
    assert!(saw_run, "the reloaded loop executed the new task");
    // Removing the task and reloading stops its loop: after any in-flight
    // run from before the removal lands, no new records may appear.
    config.write().await.tasks.clear();
    scheduler.forget("reload");
    on_change();
    tokio::time::sleep(Duration::from_millis(600)).await;
    let before = scheduler.history("reload").len();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        scheduler.history("reload").len(),
        before,
        "a removed task's loop stops firing"
    );
    drain_tx.send(true).expect("drain");
    runner.await.expect("scheduler loop").expect("run");
}

#[tokio::test]
async fn module_loads_existing_config_and_persists_mutations() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = ConfigStore::open(dir.path()).expect("store");
    // Pre-seed cron.json with a disabled command task.
    let seeded = FileConfig {
        tasks: vec![task_with("seed", "@daily", "echo seeded".into(), false)],
    };
    store.save(fg_cron::CONFIG_NAME, &seeded).expect("seed");
    let module =
        fg_cron::Module::new(Arc::clone(&store), fg_cron::Deps::default()).expect("module");
    match store
        .load::<FileConfig>(fg_cron::CONFIG_NAME)
        .expect("load")
    {
        Loaded::Found(config) => assert_eq!(config.tasks.len(), 1),
        other => panic!("expected the seeded config, got {other:?}"),
    }
    // The mounted routes see the loaded task (history empty at startup).
    let app = module.mount(axum::Router::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    let (status, body) = get_json(&addr, "/api/cron/tasks").await;
    assert_eq!(status, 200);
    assert_eq!(body[0]["key"], "seed");
    assert_eq!(body[0]["history"], serde_json::json!([]));
    // A route mutation persists through the injected ConfigStore hook.
    let (status, body) = put_json(
        &addr,
        "/api/cron/tasks/seed/enable",
        serde_json::json!({ "enable": true }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let Loaded::Found(config) = store
        .load::<FileConfig>(fg_cron::CONFIG_NAME)
        .expect("reload")
    else {
        panic!("config vanished");
    };
    assert!(config.tasks[0].enable);
}

async fn get_json(addr: &std::net::SocketAddr, path: &str) -> (u16, serde_json::Value) {
    let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .expect("handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::builder()
        .method("GET")
        .uri(path)
        .header("content-type", "application/json")
        .body(axum::body::Body::empty())
        .expect("request");
    let response = sender.send_request(request).await.expect("send");
    let (status, body) = (response.status().as_u16(), response.into_body());
    let bytes = http_body_util::BodyExt::collect(body)
        .await
        .expect("collect")
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn put_json(
    addr: &std::net::SocketAddr,
    path: &str,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .expect("handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::builder()
        .method("PUT")
        .uri(path)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("request");
    let response = sender.send_request(request).await.expect("send");
    let (status, body) = (response.status().as_u16(), response.into_body());
    let bytes = http_body_util::BodyExt::collect(body)
        .await
        .expect("collect")
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}
