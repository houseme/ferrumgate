//! Delivery integration tests (WP-68 §6): the pending queue persists and
//! resumes after a "restart", a published event reaches matching channels
//! through the module, disabled/silenced paths stay quiet, and test sends
//! go out exactly once.

mod common;

use std::time::{Duration, SystemTime};

use fg_config::ConfigStore;
use fg_core::events::{Event, EventBus, Kind};
use fg_core::module::Module as _;
use fg_notify::{
    Channel, ChannelProxy, Deps, FileConfig, Module, PendingMessage, PendingQueue, Rule,
    SettingsProxy, Silence,
};

/// A webhook channel pointing at the given base URL.
fn webhook_channel(key: &str, base: &str) -> Channel {
    let mut channel = common::channel(
        "webhook",
        serde_json::json!({
            "url": format!("{base}/notify"),
            "method": "POST",
        }),
    );
    channel.key = key.to_owned();
    channel
}

/// A rule pushing auth.* (warn) events to `channels`.
fn auth_rule(key: &str, channels: &[&str]) -> Rule {
    Rule {
        key: key.to_owned(),
        name: "auth".into(),
        enable: true,
        events: vec!["auth.*".into()],
        min_level: fg_core::events::Level::Warn,
        channels: channels.iter().map(|key| (*key).to_owned()).collect(),
        ..Rule::default()
    }
}

/// A module with one webhook channel and an auth rule, loaded from the
/// store like the assembler does.
fn module_with(store: &ArcConfigStore, events: &EventBus, channel: Channel, rule: Rule) -> Module {
    let config = FileConfig {
        settings: fg_notify::Settings::default(),
        channels: vec![channel],
        rules: vec![rule],
    };
    store.save("notify", &config).expect("save notify.json");
    Module::new(store.clone(), events.clone(), Deps::default()).expect("module")
}

type ArcConfigStore = std::sync::Arc<ConfigStore>;

#[tokio::test]
async fn pending_queue_persists_and_resumes() {
    // A queued message survives a "restart" (save → new queue from disk)
    // and is backfilled in order once the channel accepts again.
    let server = common::FakeHttp::start("200 OK", "ok").await;
    let mut queue = PendingQueue::default();
    let now = SystemTime::now();
    for index in 0..3 {
        let dropped = queue.push(
            "ch1",
            PendingMessage {
                enqueued_at: now,
                event: "auth.failed".into(),
                title: format!("title {index}"),
                body: format!("body {index}"),
            },
        );
        assert!(dropped.is_none(), "under the cap, dropped {dropped:?}");
    }
    queue.on_failure("ch1", now);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("pending.json");
    queue.save(&path).expect("save");

    // "Restart": a fresh queue loaded from the same file.
    let mut resumed = PendingQueue::load(&path).expect("load");
    assert_eq!(resumed.backlog("ch1"), 3);
    // The failed channel waits before resuming…
    assert!(resumed.take_due("ch1", now).is_none());
    // …then delivers earliest first, one by one (the clock advances past
    // the doubled wait first).
    let due_at = resumed
        .channels
        .get("ch1")
        .and_then(|backlog| backlog.next_attempt)
        .unwrap_or(now);
    let cancel = common::never_cancelled();
    let mut sent = Vec::new();
    while let Some(message) = resumed.take_due("ch1", due_at) {
        let channel = webhook_channel("ch1", &server.base);
        fg_notify::channels::send(
            &channel,
            &fg_notify::Message {
                title: message.title.clone(),
                body: message.body.clone(),
                ..common::message("", "")
            },
            &fg_notify::proxy::Effective::Direct,
            &cancel,
        )
        .await
        .expect("backfill send");
        resumed.pop("ch1");
        sent.push(message.title);
    }
    assert_eq!(
        sent,
        ["title 0", "title 1", "title 2"],
        "earliest queued message goes first"
    );
    let requests = server.captured();
    assert_eq!(requests.len(), 3);
    for (index, request) in requests.iter().enumerate() {
        assert!(
            request.contains(&format!("title {index}")),
            "request {index} carries the queued body: {request}"
        );
        assert!(request.starts_with("POST /notify"), "{request}");
    }
    server.stop();
}

/// Starts the module's run loop and waits until the bus subscriber is up.
async fn running(
    module: Module,
) -> (
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let (drain_tx, drain_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(module.run(drain_rx));
    // The subscription registers inside run(); a short settle avoids a
    // publish racing the registration.
    tokio::time::sleep(Duration::from_millis(100)).await;
    (drain_tx, handle)
}

#[tokio::test]
async fn event_published_to_matching_channels() {
    let server = common::FakeHttp::start("200 OK", "ok").await;
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ConfigStore::open(dir.path()).expect("store");
    let events = EventBus::default();
    let module = module_with(
        &store,
        &events,
        webhook_channel("ch0000000001", &server.base),
        auth_rule("rule00000001", &["ch0000000001"]),
    );
    let (drain_tx, handle) = running(module).await;
    // One publish → exactly one rendered webhook request.
    let mut event = Event::new(Kind::AuthFailed, "auth");
    event.args = vec![("sourceAddr", "10.0.0.9".to_owned())];
    events.publish(event);
    common::wait_until(|| !server.captured().is_empty()).await;
    let request = server.one();
    assert!(request.starts_with("POST /notify"), "{request}");
    assert!(
        request
            .to_ascii_lowercase()
            .contains("content-type: application/json"),
        "{request}"
    );
    // Default template: title (translated fallback) and rendered body.
    let body = request.rsplit("\r\n\r\n").next().unwrap_or_default();
    let envelope: serde_json::Value = serde_json::from_str(body).expect("default envelope");
    assert_eq!(envelope["kind"], "auth.failed");
    assert_eq!(envelope["level"], "warn");
    assert!(
        envelope["message"]
            .as_str()
            .expect("message")
            .contains("sourceAddr=10.0.0.9"),
        "{envelope}"
    );
    drain_tx.send(true).expect("drain");
    let _ = handle.await;
    server.stop();
}

#[tokio::test]
async fn event_skips_disabled_and_silenced_paths() {
    // A disabled channel receives nothing, and a silence window keeps
    // repeats of the same dedup key down to one send (visible once the
    // channel is re-enabled — here verified at the dedup level).
    let server = common::FakeHttp::start("200 OK", "ok").await;
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ConfigStore::open(dir.path()).expect("store");
    let events = EventBus::default();
    let mut muted = webhook_channel("ch0000000002", &server.base);
    muted.enable = false;
    let mut rule = auth_rule("rule00000001", &["ch0000000002"]);
    rule.silence = Some(Silence {
        dedup_key: "{sourceAddr}".into(),
        window_minutes: 60,
    });
    let module = module_with(&store, &events, muted, rule);
    let (drain_tx, handle) = running(module).await;
    let publish = || {
        let mut event = Event::new(Kind::AuthFailed, "auth");
        event.args = vec![("sourceAddr", "10.0.0.9".to_owned())];
        events.publish(event);
    };
    publish();
    publish();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        server.captured().is_empty(),
        "disabled channels must not receive: {:?}",
        server.captured()
    );
    drain_tx.send(true).expect("drain");
    let _ = handle.await;
    server.stop();
}

#[tokio::test]
async fn silence_window_dedups_published_events() {
    // The same auth.failed source inside one silence window yields one
    // webhook send even after two publishes.
    let server = common::FakeHttp::start("200 OK", "ok").await;
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ConfigStore::open(dir.path()).expect("store");
    let events = EventBus::default();
    let mut rule = auth_rule("rule00000001", &["ch0000000001"]);
    rule.silence = Some(Silence {
        dedup_key: "{sourceAddr}".into(),
        window_minutes: 60,
    });
    let module = module_with(
        &store,
        &events,
        webhook_channel("ch0000000001", &server.base),
        rule,
    );
    let (drain_tx, handle) = running(module).await;
    for _ in 0..3 {
        let mut event = Event::new(Kind::AuthFailed, "auth");
        event.args = vec![("sourceAddr", "10.0.0.9".to_owned())];
        events.publish(event);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    common::wait_until(|| !server.captured().is_empty()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        server.captured().len(),
        1,
        "repeats inside the window are silenced: {:?}",
        server
            .captured()
            .iter()
            .map(|r| r.lines().next().unwrap_or(""))
            .collect::<Vec<_>>()
    );
    drain_tx.send(true).expect("drain");
    let _ = handle.await;
    server.stop();
}

#[tokio::test]
async fn test_notification_sent_once() {
    let server = common::FakeHttp::start("200 OK", "ok").await;
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ConfigStore::open(dir.path()).expect("store");
    let events = EventBus::default();
    let module = module_with(
        &store,
        &events,
        webhook_channel("ch0000000001", &server.base),
        auth_rule("rule00000001", &["ch0000000001"]),
    );
    let channel = {
        let config = module.config();
        config.read().await.channels[0].clone()
    };
    // Two consecutive test sends: exactly one request each, no retry and
    // no pending on failure paths.
    module
        .dispatcher()
        .test_send(&channel)
        .await
        .expect("test send");
    module
        .dispatcher()
        .test_send(&channel)
        .await
        .expect("test send");
    let requests = server.captured();
    assert_eq!(requests.len(), 2, "{requests:?}");
    for request in &requests {
        assert!(
            request
                .to_ascii_lowercase()
                .contains("content-type: application/json"),
            "{request}"
        );
        let body = request.rsplit("\r\n\r\n").next().unwrap_or_default();
        let envelope: serde_json::Value = serde_json::from_str(body).expect("default envelope");
        assert_eq!(envelope["kind"], "notify.test");
    }
    // The history records the test sends.
    let history = module.dispatcher().history();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].outcome.as_str(), "sent");
    assert_eq!(history[0].event, "notify.test");
    server.stop();
}

#[tokio::test]
async fn test_send_failure_is_reported_without_queueing() {
    // A dead endpoint fails the test send; nothing is queued (test sends
    // never retry nor backfill) and the failure is recorded.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ConfigStore::open(dir.path()).expect("store");
    let events = EventBus::default();
    let module = module_with(
        &store,
        &events,
        webhook_channel("ch0000000001", &format!("http://{addr}")),
        auth_rule("rule00000001", &["ch0000000001"]),
    );
    let channel = module.config().read().await.channels[0].clone();
    let error = module
        .dispatcher()
        .test_send(&channel)
        .await
        .expect_err("endpoint is down");
    assert!(!error.is_empty());
    assert!(
        module.dispatcher().pending_total() == 0,
        "test sends never queue"
    );
    let history = module.dispatcher().history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].outcome.as_str(), "dropped");
    assert!(
        history[0]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("请求失败")
            || history[0]
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("连接")
    );
}

#[tokio::test]
async fn proxy_settings_resolve_per_channel_override() {
    // The dispatcher resolves the effective proxy per send; a channel
    // override wins over the global setting (the resolution itself is
    // unit-tested in proxy.rs; here the wiring is checked).
    let settings = fg_notify::Settings {
        proxy: SettingsProxy::Custom("http://global-gate:8080".into()),
        ..fg_notify::Settings::default()
    };
    let channel = Channel {
        proxy: ChannelProxy::Direct,
        ..common::channel(
            "webhook",
            serde_json::json!({ "url": "http://example.invalid/hook" }),
        )
    };
    assert_eq!(
        fg_notify::proxy::resolve(&settings.proxy, &channel.proxy, None),
        fg_notify::proxy::Effective::Direct
    );
    let channel = Channel {
        proxy: ChannelProxy::Follow,
        ..channel
    };
    assert_eq!(
        fg_notify::proxy::resolve(&settings.proxy, &channel.proxy, None),
        fg_notify::proxy::Effective::Url("http://global-gate:8080".into())
    );
}
