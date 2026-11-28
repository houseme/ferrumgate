//! Notification integration tests (WP-42 §6): the rule loop's webhook and
//! script deliveries against a fake webhook receiver and a temp-file
//! script — everything on loopback, no real requests leave the machine.

mod fake_stun_server;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fake_stun_server::{Behavior, FakeStun, Mapping};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{RwLock as AsyncRwLock, watch};

use fg_stun::model::{Bind, BindMode, FileConfig, Proto, Rule, Settings, WebhookConfig};
use fg_stun::runtime::Runtime;
use fg_stun::validate::normalize;

/// Polls `check` for up to ten seconds.
async fn wait_until(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    check()
}

/// A minimal HTTP/1.1 fake webhook receiver recording raw requests.
async fn spawn_fake_webhook() -> (String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let requests_for_task = Arc::clone(&requests);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let requests = Arc::clone(&requests_for_task);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // Read the head, then exactly the declared body length.
                let head_end = loop {
                    let read = stream.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        break buf.len();
                    }
                    buf.extend_from_slice(&chunk[..read]);
                    if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break at + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let content_length = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        (name.trim().eq_ignore_ascii_case("content-length"))
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                while buf.len() < head_end + content_length {
                    let read = stream.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..read]);
                }
                requests
                    .lock()
                    .expect("requests")
                    .push(String::from_utf8_lossy(&buf).to_string());
                let response =
                    "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (format!("http://{addr}"), requests, task)
}

fn channel_rule() -> Rule {
    Rule {
        key: "ch1".into(),
        name: "home lab".into(),
        enable: true,
        protocol: Proto::Udp,
        bind: Bind {
            mode: BindMode::Ip,
            ip: "127.0.0.1".into(),
            ..Bind::default()
        },
        local_port: 0,
        use_global_servers: false,
        stun_servers: vec!["placeholder".into()],
        heartbeat_interval: 500,
        stun_timeout: 800,
        retry_interval: 500,
        auto_retry: true,
        disable_check: true,
        ..Rule::default()
    }
}

/// Starts a runtime with one rule over an enabled normalized config.
async fn started(
    rule: Rule,
) -> (
    Arc<Runtime>,
    watch::Sender<bool>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let config = normalize(FileConfig {
        settings: Settings {
            enable: true,
            addr_check_interval: 60,
            ..Settings::default()
        },
        rules: vec![rule],
    });
    let config = Arc::new(AsyncRwLock::new(config));
    let runtime = Arc::new(Runtime::new(config, None, None));
    let (drain_tx, drain_rx) = watch::channel(false);
    let task = tokio::spawn(Arc::clone(&runtime).run(drain_rx));
    (runtime, drain_tx, task)
}

#[tokio::test]
async fn notify_event_webhook_script_deliver_with_variables() {
    let (webhook_url, requests, webhook_task) = spawn_fake_webhook().await;
    let script_path =
        std::env::temp_dir().join(format!("fg-stun-notify-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&script_path);
    let script = format!(
        "printf '%s|%s|%s|%s|%s' \"$ruleName\" \"$ip\" \"$port\" \"$ipAddr\" \"$time\" > {path}",
        path = script_path.display()
    );
    let server = FakeStun::udp().await;
    let mut rule = channel_rule();
    rule.stun_servers = vec![server.udp_server()];
    rule.webhook = WebhookConfig {
        url: format!("{webhook_url}/hook"),
        method: "POST".into(),
        headers: vec!["X-Rule: {ruleName}".into()],
        body: "ip={ip}&port={port}&addr={ipAddr}&rule={ruleName}".into(),
        ..WebhookConfig::default()
    };
    rule.script_enable = true;
    rule.script = script;
    let (_runtime, drain_tx, task) = started(rule).await;
    // The webhook fires on the first learned endpoint.
    let delivered = wait_until(|| !requests.lock().expect("requests").is_empty()).await;
    assert!(delivered, "webhook was never delivered");
    // The script ran with the environment variables.
    let written =
        wait_until(|| std::fs::read_to_string(&script_path).is_ok_and(|c| !c.is_empty())).await;
    assert!(written, "script output missing");
    let output = std::fs::read_to_string(&script_path).expect("script output");
    let parts: Vec<&str> = output.split('|').collect();
    assert_eq!(parts[0], "home lab", "ruleName env: {output}");
    assert_eq!(parts[1], "127.0.0.1", "ip env: {output}");
    assert!(parts[2].parse::<u16>().is_ok(), "port env: {output}");
    assert_eq!(
        parts[3],
        format!("127.0.0.1:{}", parts[2]),
        "ipAddr env: {output}"
    );
    assert!(parts[4].contains('T'), "RFC 3339 time env: {output}");
    // The webhook request carries the rendered variables.
    let request = requests.lock().expect("requests")[0].clone();
    assert!(request.starts_with("POST /hook HTTP/1.1"), "{request}");
    assert!(
        request.contains("x-rule: home lab"),
        "header rendered: {request}"
    );
    assert!(
        request.contains("ip=127.0.0.1&port="),
        "body rendered: {request}"
    );
    assert!(request.contains("&addr=127.0.0.1:"), "{request}");
    assert!(request.contains("&rule=home lab"), "{request}");
    drain_tx.send(true).expect("drain");
    task.await.expect("run task").expect("run ok");
    let _ = std::fs::remove_file(&script_path);
    webhook_task.abort();
    server.stop();
}

#[tokio::test]
async fn webhook_only_on_change_skips_repeated_successes() {
    let (webhook_url, requests, webhook_task) = spawn_fake_webhook().await;
    // A fixed mapping: every heartbeat succeeds with the same endpoint, so
    // only_on_change=false fires on every round while true stays silent
    // after the first.
    let server = FakeStun::udp_with(Behavior {
        mapping: Mapping::Fixed("127.0.0.1:45123".parse().expect("addr")),
        ..Behavior::default()
    })
    .await;
    let mut rule = channel_rule();
    rule.stun_servers = vec![server.udp_server()];
    rule.webhook = WebhookConfig {
        url: format!("{webhook_url}/hook"),
        method: "POST".into(),
        ..WebhookConfig::default()
    };
    // With the switch off every successful round notifies: several
    // heartbeats accumulate within the wait window.
    let (_runtime, _drain_tx, task) = started(rule.clone()).await;
    let many = wait_until(|| requests.lock().expect("requests").len() >= 3).await;
    let count = requests.lock().expect("requests").len();
    assert!(many, "unfiltered webhook should fire per round: {count}");
    task.abort();
    _drain_tx.send(true).expect("drain");
    requests.lock().expect("requests").clear();

    // With onlyOnChange on, the fixed endpoint notifies exactly once — a
    // fresh receiver keeps the aborted runtime's in-flight deliveries out
    // of the count.
    let (webhook_url, requests, changed_task) = spawn_fake_webhook().await;
    rule.webhook = WebhookConfig {
        url: format!("{webhook_url}/hook?port={{port}}"),
        method: "POST".into(),
        ..WebhookConfig::default()
    };
    rule.webhook_only_on_change = true;
    let (_runtime, drain_tx, task) = started(rule).await;
    let once = wait_until(|| !requests.lock().expect("requests").is_empty()).await;
    assert!(once, "the first endpoint is delivered");
    tokio::time::sleep(Duration::from_millis(1600)).await;
    let count = requests.lock().expect("requests").len();
    assert_eq!(count, 1, "repeated successes must not re-fire");
    // A real endpoint change fires again.
    server
        .set_behavior(Behavior {
            mapping: Mapping::Fixed("127.0.0.1:45999".parse().expect("addr")),
            ..Behavior::default()
        })
        .await;
    let changed = wait_until(|| requests.lock().expect("requests").len() >= 2).await;
    assert!(changed, "the endpoint change was delivered");
    let second = requests.lock().expect("requests")[1].clone();
    assert!(
        second.contains("port=45999"),
        "the new port is in the request: {second}"
    );
    drain_tx.send(true).expect("drain");
    task.await.expect("run task").expect("run ok");
    webhook_task.abort();
    changed_task.abort();
    server.stop();
}

#[tokio::test]
async fn webhook_failure_is_logged_and_loop_survives() {
    // Point the webhook at a closed port: delivery fails, the channel
    // keeps running and the mapping still appears.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let dead = listener.local_addr().expect("addr");
    drop(listener);
    let server = FakeStun::udp().await;
    let mut rule = channel_rule();
    rule.stun_servers = vec![server.udp_server()];
    rule.webhook = WebhookConfig {
        url: format!("http://{dead}/hook"),
        method: "POST".into(),
        timeout: 1,
        ..WebhookConfig::default()
    };
    let (runtime, drain_tx, task) = started(rule).await;
    let ready = wait_until(|| {
        runtime
            .snapshot()
            .entries
            .iter()
            .any(|entry| entry.key == "ch1" && entry.state == "ready")
    })
    .await;
    assert!(
        ready,
        "channel must survive webhook failures: {:?}",
        runtime.snapshot().entries
    );
    drain_tx.send(true).expect("drain");
    task.await.expect("run task").expect("run ok");
    server.stop();
}

#[tokio::test]
async fn global_webhook_used_when_rule_opts_in() {
    let (webhook_url, requests, webhook_task) = spawn_fake_webhook().await;
    let server = FakeStun::udp().await;
    let mut rule = channel_rule();
    rule.stun_servers = vec![server.udp_server()];
    rule.use_global_webhook = true;
    // The rule's own webhook is empty; the module's is what fires.
    let config = normalize(FileConfig {
        settings: Settings {
            enable: true,
            addr_check_interval: 60,
            webhook: WebhookConfig {
                url: format!("{webhook_url}/global"),
                method: "POST".into(),
                ..WebhookConfig::default()
            },
            ..Settings::default()
        },
        rules: vec![rule],
    });
    let config = Arc::new(AsyncRwLock::new(config));
    let runtime = Arc::new(Runtime::new(config, None, None));
    let (drain_tx, drain_rx) = watch::channel(false);
    let task = tokio::spawn(Arc::clone(&runtime).run(drain_rx));
    let delivered = wait_until(|| !requests.lock().expect("requests").is_empty()).await;
    assert!(delivered, "global webhook was never delivered");
    let request = requests.lock().expect("requests")[0].clone();
    assert!(request.starts_with("POST /global HTTP/1.1"), "{request}");
    drain_tx.send(true).expect("drain");
    task.await.expect("run task").expect("run ok");
    webhook_task.abort();
    server.stop();
}
