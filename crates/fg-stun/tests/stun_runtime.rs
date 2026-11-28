//! Runtime-level integration tests (WP-42 §6): the mapping-keep loop
//! against the fake STUN server — reachability check, mapping change
//! detection with `stun.changed` publications, TCP keep-alive holds,
//! manual restart and the drain deadline. Everything runs on loopback.

mod fake_stun_server;

use std::sync::Arc;
use std::time::Duration;

use fake_stun_server::{Behavior, FakeStun, Mapping};
use fg_core::events::{Event, EventBus};
use tokio::sync::{RwLock as AsyncRwLock, mpsc, watch};

use fg_stun::model::{Bind, BindMode, FileConfig, Proto, Rule, Settings, limits};
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

fn channel_rule() -> Rule {
    Rule {
        key: "ch1".into(),
        name: "channel".into(),
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
        disable_check: false,
        ..Rule::default()
    }
}

/// Starts a runtime with the given rules over an enabled normalized
/// config; returns the runtime and the drain pair.
async fn started(
    rules: Vec<Rule>,
    events: Option<EventBus>,
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
        rules,
    });
    let config = Arc::new(AsyncRwLock::new(config));
    let runtime = Arc::new(Runtime::new(config, events, None));
    let (drain_tx, drain_rx) = watch::channel(false);
    let task = tokio::spawn(Arc::clone(&runtime).run(drain_rx));
    (runtime, drain_tx, task)
}

fn entry<'a>(
    snapshot: &'a fg_stun::runtime::RuntimeSnapshot,
    key: &str,
) -> &'a fg_stun::runtime::EntryStatus {
    snapshot
        .entries
        .iter()
        .find(|entry| entry.key == key)
        .expect("entry present")
}

#[tokio::test]
async fn check_confirms_reachability_on_loopback() {
    // The STUN server reports a fixed "public" endpoint that is really the
    // second fake server — a responder at the mapped address, like a NAT
    // forwarding inbound traffic back to the channel.
    let responder = FakeStun::udp().await;
    let server = FakeStun::udp_with(Behavior {
        mapping: Mapping::Fixed(responder.udp_addr()),
        ..Behavior::default()
    })
    .await;
    let mut rule = channel_rule();
    rule.stun_servers = vec![server.udp_server()];
    let (runtime, drain_tx, task) = started(vec![rule], None).await;
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
        "channel never became ready: {:?}",
        runtime.snapshot().entries
    );
    let snapshot = runtime.snapshot();
    let status = entry(&snapshot, "ch1");
    assert_eq!(status.public_addr, Some(responder.udp_addr()));
    assert!(status.since.is_some());
    assert_eq!(
        status.nat_consistent,
        Some(true),
        "single server: trivially consistent"
    );
    assert!(status.last_error.is_none());
    // The metric surface exposes the confirmed mapping.
    runtime.record_connection("ch1");
    let metrics = runtime.metrics();
    assert!(
        metrics
            .iter()
            .any(|sample| sample.name == "ferrumgate_stun_up"
                && sample.value == 1.0
                && sample.labels.get("rule").map(String::as_str) == Some("ch1")),
        "{metrics:?}"
    );
    assert!(
        metrics
            .iter()
            .any(|sample| sample.name == "ferrumgate_stun_connections_total"
                && sample.value == 1.0),
        "{metrics:?}"
    );
    drain_tx.send(true).expect("drain");
    task.await.expect("run task").expect("run ok");
    server.stop();
    responder.stop();
}

#[tokio::test]
async fn mapping_port_change_detected_and_notified() {
    let server = FakeStun::udp_with(Behavior {
        mapping: Mapping::Increment { base: 41000 },
        ..Behavior::default()
    })
    .await;
    let bus = EventBus::default();
    let (events_tx, mut events_rx) = mpsc::unbounded_channel::<(String, u16)>();
    let subscription = bus
        .subscribe(move |event: Arc<Event>| {
            let tx = events_tx.clone();
            async move {
                let port = event
                    .args
                    .iter()
                    .find(|(name, _)| *name == "port")
                    .and_then(|(_, value)| value.parse::<u16>().ok());
                let _ = tx.send((event.kind.info().name.to_owned(), port.unwrap_or(0)));
            }
        })
        .expect("subscribe");
    let mut rule = channel_rule();
    rule.disable_check = true;
    rule.stun_servers = vec![server.udp_server()];
    let (runtime, drain_tx, task) = started(vec![rule], Some(bus)).await;
    // At least two changes must arrive, strictly increasing ports.
    let got_enough = wait_until(|| events_rx.len() >= 2).await;
    assert!(
        got_enough,
        "expected change events, got {}",
        events_rx.len()
    );
    let mut ports = Vec::new();
    while let Ok((kind, port)) = events_rx.try_recv() {
        assert_eq!(kind, "stun.changed");
        ports.push(port);
    }
    assert!(ports.len() >= 2, "{ports:?}");
    assert!(
        ports.windows(2).all(|pair| pair[0] < pair[1]),
        "ports must increase: {ports:?}"
    );
    // The snapshot always carries the latest mapping.
    let latest = wait_until(|| {
        runtime
            .snapshot()
            .entries
            .iter()
            .any(|entry| entry.key == "ch1" && entry.state == "ready")
    })
    .await;
    assert!(latest, "{:?}", runtime.snapshot().entries);
    drop(subscription);
    drain_tx.send(true).expect("drain");
    task.await.expect("run task").expect("run ok");
    server.stop();
}

#[tokio::test]
async fn tcp_keepalive_connections_hold_while_binding_fails() {
    let keep_alive = FakeStun::tcp().await;
    let mut rule = channel_rule();
    rule.protocol = Proto::Tcp;
    rule.stun_servers = vec!["127.0.0.1:1".into()]; // never answers
    rule.keep_alive_servers = vec![keep_alive.tcp_addr().to_string()];
    rule.disable_check = true;
    let (runtime, drain_tx, task) = started(vec![rule], None).await;
    let held = wait_until(|| keep_alive.accepted() >= 1).await;
    assert!(held, "keep-alive connection was never established");
    // The STUN side fails (dead server) and the channel reports lost, but
    // keeps retrying while the keep-alive connection stays up.
    let lost = wait_until(|| {
        runtime
            .snapshot()
            .entries
            .iter()
            .any(|entry| entry.key == "ch1" && entry.state == "lost")
    })
    .await;
    assert!(lost, "{:?}", runtime.snapshot().entries);
    assert!(keep_alive.accepted() >= 1);
    let last_error = entry(&runtime.snapshot(), "ch1")
        .last_error
        .clone()
        .expect("binding failure recorded");
    assert!(last_error.contains("STUN"), "{last_error}");
    drain_tx.send(true).expect("drain");
    task.await.expect("run task").expect("run ok");
    keep_alive.stop();
}

#[tokio::test]
async fn runtime_restart_rule_respawns_channel() {
    let server = FakeStun::udp().await;
    let mut rule = channel_rule();
    rule.disable_check = true;
    rule.stun_servers = vec![server.udp_server()];
    let (runtime, _drain_tx, _task) = started(vec![rule], None).await;
    let ready = wait_until(|| {
        runtime
            .snapshot()
            .entries
            .iter()
            .any(|entry| entry.key == "ch1" && entry.state == "ready")
    })
    .await;
    assert!(ready, "{:?}", runtime.snapshot().entries);
    assert!(
        !runtime.restart("ghost").await,
        "absent rules cannot restart"
    );
    assert!(runtime.restart("ch1").await, "an enabled rule restarts");
    // The channel returns to ready with a fresh binding round.
    let ready_again = wait_until(|| {
        runtime
            .snapshot()
            .entries
            .iter()
            .any(|entry| entry.key == "ch1" && entry.state == "ready")
    })
    .await;
    assert!(ready_again, "{:?}", runtime.snapshot().entries);
    assert!(server.answered() >= 2, "restart performed another round");
    server.stop();
}

#[tokio::test]
async fn runtime_drain_cancels_and_clears_the_snapshot() {
    let server = FakeStun::udp().await;
    let mut rule = channel_rule();
    rule.disable_check = true;
    rule.stun_servers = vec![server.udp_server()];
    let (runtime, drain_tx, task) = started(vec![rule], None).await;
    let ready = wait_until(|| {
        runtime
            .snapshot()
            .entries
            .iter()
            .any(|entry| entry.key == "ch1" && entry.state == "ready")
    })
    .await;
    assert!(ready, "{:?}", runtime.snapshot().entries);
    assert_eq!(runtime.inflight(), 0);
    drain_tx.send(true).expect("drain");
    // Draining joins the loops; the snapshot ends up empty because every
    // entry cleaned up after itself (within the shutdown deadline).
    let started_at = std::time::Instant::now();
    task.await.expect("run task").expect("run ok");
    assert!(
        started_at.elapsed() < limits::SHUTDOWN_DEADLINE,
        "a quiet channel drains promptly"
    );
    assert!(
        runtime.snapshot().entries.is_empty(),
        "{:?}",
        runtime.snapshot().entries
    );
    server.stop();
}

#[tokio::test]
async fn runtime_module_switch_and_reload_honored() {
    let server = FakeStun::udp().await;
    let mut rule = channel_rule();
    rule.disable_check = true;
    rule.stun_servers = vec![server.udp_server()];
    let config = normalize(FileConfig {
        settings: Settings {
            enable: false,
            ..Settings::default()
        },
        rules: vec![rule],
    });
    let config = Arc::new(AsyncRwLock::new(config));
    let runtime = Arc::new(Runtime::new(config.clone(), None, None));
    let on_change = runtime.on_change_handle();
    let (drain_tx, drain_rx) = watch::channel(false);
    let task = tokio::spawn(Arc::clone(&runtime).run(drain_rx));
    // The module switch is off: nothing starts.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        runtime.snapshot().entries.is_empty(),
        "{:?}",
        runtime.snapshot().entries
    );
    // Restarting a rule inside a disabled module is refused.
    assert!(!runtime.restart("ch1").await);
    // Turning the module switch on and announcing the change starts the
    // channel.
    config.write().await.settings.enable = true;
    on_change();
    let ready = wait_until(|| {
        runtime
            .snapshot()
            .entries
            .iter()
            .any(|entry| entry.key == "ch1" && entry.state == "ready")
    })
    .await;
    assert!(ready, "{:?}", runtime.snapshot().entries);
    drain_tx.send(true).expect("drain");
    task.await.expect("run task").expect("run ok");
    server.stop();
}
