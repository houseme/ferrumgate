//! Instance runtime integration tests (WP-44 §6): rendered files with
//! 0600 and tokens only inside them, per-instance restart granularity
//! (a proxy edit restarts its own frpc; an access edit restarts nothing),
//! status readback, the trusted-source and learned-port registration with
//! their caps and clearing, the bounded drain, and the online install
//! through the WP-43 installer with a local fake upstream.
//!
//! All waits are async on the test's own runtime — no auxiliary runtimes —
//! so the supervisor's process driver keeps working throughout.

mod common;

use std::{
    net::IpAddr,
    time::{Duration, SystemTime},
};

use fg_frp::model::{ClientAccess, FileConfig, limits};
use fg_net::openports::Proto;
use fg_proc::{InstallTarget, Stage};

use common::{client, harness, harness_with_deps, proxy, reconcile_with, server, wait_until};

fn addr(text: &str) -> Option<IpAddr> {
    Some(text.parse().expect("ip"))
}

/// The `starts` counter of one instance from the status readback.
async fn starts_of(harness: &common::Harness, key: &str) -> u64 {
    harness
        .runtime
        .status()
        .await
        .into_iter()
        .find(|status| status.key == key)
        .map(|status| status.starts)
        .unwrap_or(0)
}

async fn is_running(harness: &common::Harness, key: &str) -> bool {
    harness
        .runtime
        .status()
        .await
        .iter()
        .any(|status| status.key == key && status.running)
}

// ---------------------------------------------------------------------------
// Config files: 0600 and tokens only inside
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rendered_file_is_0600_and_start_reads_it() {
    let harness = harness();
    let mut config = FileConfig::default();
    config
        .clients
        .push(client("c1", "home", "frps.example.com"));
    config.clients[0].token = "secret-token-123".into();
    config.proxies.push(proxy("p1", "ssh", 6022, "c1"));
    reconcile_with(&harness, config).await;

    let conf_path = harness.runtime.conf_file_of("frpc", "c1");
    let rendered = std::fs::read_to_string(&conf_path).expect("read rendered conf");
    assert!(
        rendered.contains("secret-token-123"),
        "token lives in the file"
    );
    assert!(rendered.contains("remotePort = 6022"));

    // Mode 0600 on unix (the token is inside).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&conf_path)
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "mode is {mode:o}");
    }

    // The instance is running and its status readback carries no secret.
    let started = wait_until(Duration::from_secs(15), || async {
        is_running(&harness, "c1").await
    })
    .await;
    assert!(started, "the frpc fixture should be running");
    let status = harness
        .runtime
        .status()
        .await
        .into_iter()
        .find(|status| status.key == "c1")
        .expect("status");
    let view = serde_json::to_value(&status).expect("serialize status");
    let view_text = view.to_string();
    assert!(!view_text.contains("secret-token-123"), "{view_text}");
    assert!(view["running"] == true);

    // Disabling the instance stops it and cleans up. `write().clone()`
    // releases the guard at the end of the let statement; the mutated
    // clone is then passed to the reconcile (a guard temporary inside the
    // argument expression would stay alive across the await and deadlock
    // the write inside reconcile_with).
    let mut config = harness.config.write().await.clone();
    config.clients[0].enable = false;
    reconcile_with(&harness, config).await;
    let stopped = wait_until(Duration::from_secs(15), || async {
        !is_running(&harness, "c1").await
    })
    .await;
    assert!(stopped);
}

// ---------------------------------------------------------------------------
// Restart granularity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn proxy_edit_restarts_only_owning_client() {
    let harness = harness();
    let mut config = FileConfig::default();
    config.clients.push(client("c1", "one", "srv.example.com"));
    config.clients.push(client("c2", "two", "srv.example.com"));
    config.proxies.push(proxy("p1", "ssh", 6022, "c1"));
    config.proxies.push(proxy("p2", "web", 6023, "c2"));
    reconcile_with(&harness, config).await;
    assert_eq!(starts_of(&harness, "c1").await, 1);
    assert_eq!(starts_of(&harness, "c2").await, 1);

    // Editing c1's proxy re-renders only c1's config: c1 restarts, c2
    // keeps its process (start count unchanged).
    let mut config = harness.config.read().await.clone();
    config.proxies[0].remote_port = 6122;
    reconcile_with(&harness, config).await;
    assert_eq!(
        starts_of(&harness, "c1").await,
        2,
        "owning client restarted"
    );
    assert_eq!(starts_of(&harness, "c2").await, 1, "other client untouched");

    // An unrelated config change (a new disabled client) restarts nothing.
    let mut config = harness.config.read().await.clone();
    let mut off = client("c3", "three", "srv.example.com");
    off.enable = false;
    config.clients.push(off);
    reconcile_with(&harness, config).await;
    assert_eq!(starts_of(&harness, "c1").await, 2);
    assert_eq!(starts_of(&harness, "c2").await, 1);
}

#[tokio::test]
async fn access_change_does_not_restart() {
    let harness = harness();
    let mut config = FileConfig::default();
    let mut one = client("c1", "one", "srv.example.com");
    one.access = ClientAccess {
        http_scheme: "https".into(),
        http_port: 8443,
        https_port: 0,
        subdomain_host: "tunnel.example.com".into(),
    };
    config.clients.push(one);
    config.proxies.push(proxy("p1", "ssh", 6022, "c1"));
    reconcile_with(&harness, config).await;
    assert_eq!(starts_of(&harness, "c1").await, 1);

    // The visitor access block only feeds link rendering: editing it does
    // not touch the rendered frpc config and must not restart frpc.
    let mut config = harness.config.read().await.clone();
    config.clients[0].access = ClientAccess {
        http_scheme: "https".into(),
        http_port: 0,
        https_port: 9443,
        subdomain_host: "other.example.com".into(),
    };
    reconcile_with(&harness, config).await;
    assert_eq!(
        starts_of(&harness, "c1").await,
        1,
        "访问地址修改不重启 frpc"
    );
}

// ---------------------------------------------------------------------------
// Trusted sources (10 min window, refresh, cap) and learned ports
// ---------------------------------------------------------------------------

#[tokio::test]
async fn frpc_login_registers_trusted_source_for_10min() {
    let harness = harness();
    let key = "s-trust";
    let login = addr("203.0.113.9");
    harness
        .runtime
        .observe_gate_allow(key, login, fg_frp::GateHook::Login);

    let entries = harness.runtime.trust_entries(key);
    assert_eq!(entries.len(), 1);
    let (addr, expiry) = entries[0];
    assert_eq!(addr.to_string(), "203.0.113.9");
    let ttl = expiry
        .duration_since(SystemTime::now())
        .expect("future expiry");
    assert!(
        ttl > limits::TRUST_TTL - Duration::from_secs(5) && ttl <= limits::TRUST_TTL,
        "expiry is now + 10 minutes: {ttl:?}"
    );
    // The window is published into the shared trusted-source registry.
    assert!(
        fg_net::trust_src::is_trusted(addr),
        "the login address is a trusted source"
    );

    // A live connection refreshes the window on every observed operation.
    std::thread::sleep(Duration::from_millis(30));
    harness
        .runtime
        .observe_gate_allow(key, login, fg_frp::GateHook::NewProxy(6022));
    let refreshed = harness.runtime.trust_entries(key)[0].1;
    assert!(refreshed > expiry, "观察到的操作延长豁免窗口");

    // At most 32 addresses per instance.
    for last_octet in 1..=40u16 {
        let ip: IpAddr = format!("198.51.100.{last_octet}").parse().unwrap();
        harness
            .runtime
            .observe_gate_allow(key, Some(ip), fg_frp::GateHook::Login);
    }
    assert_eq!(
        harness.runtime.trust_entries(key).len(),
        limits::TRUSTED_ADDR_CAP
    );

    // Stop / token change clears the instance's sources.
    harness.runtime.trust_clear(key);
    assert!(harness.runtime.trust_entries(key).is_empty());
    assert!(
        !fg_net::trust_src::all()
            .iter()
            .any(|source| source.owner == format!("frp:{key}")),
        "撤销后登记表不再包含该实例"
    );
}

#[tokio::test]
async fn frpc_remote_ports_registered_as_open() {
    let harness = harness();
    let key = "s-ports";
    let login = addr("203.0.113.10");

    // A NewProxy with a tcp remote port learns the port and publishes it.
    harness
        .runtime
        .observe_gate_allow(key, login, fg_frp::GateHook::NewProxy(6022));
    assert_eq!(harness.runtime.learned_ports(key), [6022]);
    assert!(
        harness.open_ports.is_open(Proto::Tcp, 6022),
        "远程端口登记为开放端口"
    );

    // The allow-ports whitelist gates learning (LearnRespectsAllowPorts).
    let mut config = harness.config.write().await.clone();
    let mut gated = server(key, "gated");
    gated.allow_ports = "7000-8000".into();
    config.servers.push(gated);
    drop(config);
    harness
        .runtime
        .observe_gate_allow(key, login, fg_frp::GateHook::NewProxy(6022));
    harness
        .runtime
        .observe_gate_allow(key, login, fg_frp::GateHook::NewProxy(7500));
    assert_eq!(
        harness.runtime.learned_ports(key),
        [6022, 7500],
        "白名单外的端口不学习，白名单内的端口学习"
    );

    // The cap: at most 4096 ports per instance.
    for port in 9000..9000 + limits::OPEN_PORTS_CAP + 3 {
        harness
            .runtime
            .observe_gate_allow(key, login, fg_frp::GateHook::NewProxy(port as u16));
    }
    assert_eq!(
        harness.runtime.learned_ports(key).len(),
        limits::OPEN_PORTS_CAP
    );

    // Clearing (instance stop) revokes the registry entry.
    harness.runtime.port_clear(key);
    assert!(harness.runtime.learned_ports(key).is_empty());
    assert!(!harness.open_ports.is_open(Proto::Tcp, 7500));
}

// ---------------------------------------------------------------------------
// Drain: bounded stop of every instance
// ---------------------------------------------------------------------------

#[tokio::test]
async fn drain_stops_all_instances_within_deadline() {
    let harness = harness();
    let mut config = FileConfig::default();
    config.clients.push(client("c1", "one", "srv.example.com"));
    config.clients.push(client("c2", "two", "srv.example.com"));
    config.servers.push(server("s1", "main"));
    reconcile_with(&harness, config).await;

    let running_count = || async {
        harness
            .runtime
            .status()
            .await
            .iter()
            .filter(|status| status.running)
            .count()
    };
    let started = wait_until(Duration::from_secs(15), || async {
        running_count().await == 3
    })
    .await;
    assert!(started, "three instances running before the drain");

    let (tx, rx) = tokio::sync::watch::channel(false);
    let runtime = std::sync::Arc::clone(&harness.runtime);
    let module_task = tokio::spawn(async move { runtime.run(rx).await });
    // Give the loop a moment to settle, then drain.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = tx.send(true);
    let drained = tokio::time::timeout(
        Duration::from_secs(limits::DRAIN_STOP.as_secs() + 5),
        module_task,
    )
    .await;
    assert!(drained.is_ok(), "drain completes within the deadline");
    assert_eq!(running_count().await, 0, "drain stopped every instance");
}

// ---------------------------------------------------------------------------
// Online install through the WP-43 installer (fake upstream)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn install_from_fake_upstream_starts_instances() {
    let (upstream, _digest) = common::fake_upstream().await;
    let getter = upstream.getter();
    let harness = harness_with_deps(move |store| {
        fg_proc::Proc::open(store, Some(getter)).expect("proc open")
    });

    // Install frpc + frps through the shared installers (static specs).
    for spec in [fg_proc::install::FRPC.name, fg_proc::install::FRPS.name] {
        let program = match spec {
            "frpc" => &fg_proc::install::FRPC,
            _ => &fg_proc::install::FRPS,
        };
        let installer = harness.proc.installer(program);
        let mut stage = installer
            .start(InstallTarget::Latest, None, None)
            .await
            .expect("install start");
        let done = wait_until_stage(&mut stage, Duration::from_secs(60)).await;
        assert!(
            matches!(done, Stage::Done),
            "install of {spec} finished: {done:?}"
        );
        assert_eq!(installer.installed().expect("installed").version, "1.0.0");
    }

    // The resolved binaries now come from bin/ and instances run on them.
    let (from, path) = harness.proc.resolve(None, "frpc").expect("resolved");
    assert!(matches!(from, fg_proc::ResolvedFrom::BinDir), "{from:?}");
    assert!(path.starts_with(harness.proc.bin_dir()));

    let mut config = FileConfig::default();
    config.clients.push(client("c1", "one", "srv.example.com"));
    reconcile_with(&harness, config).await;
    let running = wait_until(Duration::from_secs(15), || async {
        is_running(&harness, "c1").await
    })
    .await;
    assert!(running, "frpc runs on the freshly installed binary");

    upstream.stop().await;
}

async fn wait_until_stage(
    stage: &mut tokio::sync::watch::Receiver<Stage>,
    timeout: Duration,
) -> Stage {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let current = stage.borrow_and_update().clone();
        if matches!(current, Stage::Done | Stage::UpToDate | Stage::Failed(_)) {
            return current;
        }
        if tokio::time::Instant::now() >= deadline {
            return current;
        }
        if stage.changed().await.is_err() {
            return current;
        }
    }
}
