//! Job and route integration (WP-71 §6): run a tool through the management
//! API, poll its output, stop it, and exercise the settings round trip.

#![forbid(unsafe_code)]

use std::time::Duration;

use common::{spawn_listener, wait_finished};
use fg_nettools::JobStatus;
use fg_nettools::model::limits;
use serde_json::json;

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn routes_run_port_probe_poll_and_stop() {
    let harness = common::harness().await;
    let open = spawn_listener().await;

    let (status, view) = harness
        .send(
            "POST",
            "/api/nettools/run",
            Some(json!({
                "tool": "portprobe",
                "target": "127.0.0.1",
                "ports": format!("{}", open.port()),
                "concurrency": 8,
                // 1.5s is plenty on an idle machine but flaky under
                // full-workspace parallel load; the probe still opens
                // within the larger budget on this loopback listener.
                "timeout": 4.0
            })),
        )
        .await;
    assert_eq!(status, 200, "run response: {view}");
    assert_eq!(view["kind"], "portprobe");
    assert_eq!(view["name"], "端口探测 127.0.0.1");
    let id = view["id"].as_str().expect("id").to_owned();

    let view = wait_finished(&harness.registry, &id).await;
    assert_eq!(view.status, JobStatus::Done, "lines: {:?}", view.lines);
    let open_line = view
        .lines
        .iter()
        .find(|line| line.contains(&format!("{}/tcp 开放", open.port())))
        .expect("open port line");
    assert!(open_line.contains("ms"), "duration shown: {open_line}");
    assert!(
        view.lines
            .iter()
            .any(|line| line.contains(&format!("共探测 {} 个端口", 1)))
    );

    // The task list shows the finished job; DELETE removes it.
    let (_, list) = harness.send("GET", "/api/nettools/tasks", None).await;
    let tasks = list["tasks"].as_array().expect("tasks");
    assert!(tasks.iter().any(|task| task["id"] == view.id));
    let (status, body) = harness
        .send("DELETE", &format!("/api/nettools/tasks/{id}"), None)
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["ok"], true);
    let (status, _) = harness
        .send("GET", &format!("/api/nettools/tasks/{id}"), None)
        .await;
    assert_eq!(status, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn routes_run_rejects_invalid_bodies_and_unknown_tasks() {
    let harness = common::harness().await;
    let (status, body) = harness
        .send("POST", "/api/nettools/run", Some(json!({ "tool": "ping" })))
        .await;
    assert_eq!(status, 400);
    assert!(body["error"].as_str().expect("error").contains("target"));

    let (status, _) = harness
        .send(
            "POST",
            "/api/nettools/run",
            Some(json!({ "tool": "ping", "target": "127.0.0.1", "unknown": 1 })),
        )
        .await;
    assert_eq!(status, 400);

    let (status, _) = harness
        .send("GET", "/api/nettools/tasks/no-such-id", None)
        .await;
    assert_eq!(status, 404);
    let (status, _) = harness
        .send("DELETE", "/api/nettools/tasks/no-such-id", None)
        .await;
    assert_eq!(status, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_put_normalizes_persists_and_applies_caps() {
    let harness = common::harness().await;

    let (_, view) = harness.send("GET", "/api/nettools/settings", None).await;
    assert_eq!(view["maxRunning"], 4);
    assert_eq!(view["maxTasks"], 50);
    assert_eq!(view["maxTaskLines"], 500);
    assert_eq!(view["taskTimeoutSeconds"], 300);

    let (status, view) = harness
        .send(
            "PUT",
            "/api/nettools/settings",
            Some(json!({
                "maxRunning": 2,
                "maxTasks": 5,
                "maxTaskLines": 100,
                "taskTimeoutSeconds": 60,
                "denyList": ["10.0.0.0/8"],
                "defaultSpeedUrl": "https://speed.example.test/down"
            })),
        )
        .await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["maxRunning"], 2);
    assert_eq!(view["denyList"][0], "10.0.0.0/8");
    let config = harness.load_config();
    assert_eq!(config.settings.max_running, 2);
    assert_eq!(config.settings.deny_list, vec!["10.0.0.0/8".to_owned()]);

    // The caps apply to the registry right away.
    let caps = harness.registry.caps();
    assert_eq!(caps.max_running, 2);
    assert_eq!(caps.max_tasks, 5);
    assert_eq!(caps.task_timeout, Duration::from_secs(60));

    // Out-of-range values are clamped, invalid deny entries are a 400.
    let (status, view) = harness
        .send(
            "PUT",
            "/api/nettools/settings",
            Some(json!({ "maxRunning": 999, "maxTaskLines": 0, "taskTimeoutSeconds": 1 })),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(view["maxRunning"], limits::MAX_RUNNING_CEILING);
    assert_eq!(view["maxTaskLines"], 1);
    assert_eq!(view["taskTimeoutSeconds"], 10);
    let (status, body) = harness
        .send(
            "PUT",
            "/api/nettools/settings",
            Some(json!({ "denyList": ["not a target!"] })),
        )
        .await;
    assert_eq!(status, 400);
    assert!(!body["problems"].as_array().expect("problems").is_empty());

    // The deny list refuses runs: 10.9.9.9 inside the denied CIDR.
    let (status, _) = harness
        .send(
            "PUT",
            "/api/nettools/settings",
            Some(json!({ "denyList": ["10.0.0.0/8"] })),
        )
        .await;
    assert_eq!(status, 200);
    let (status, view) = harness
        .send(
            "POST",
            "/api/nettools/run",
            Some(json!({ "tool": "portprobe", "target": "10.9.9.9", "ports": "80" })),
        )
        .await;
    assert_eq!(status, 200);
    let id = view["id"].as_str().expect("id").to_owned();
    let view = wait_finished(&harness.registry, &id).await;
    assert_eq!(
        view.status,
        JobStatus::Failed("目标在拒绝列表中（10.0.0.0/8）".to_owned())
    );
}
