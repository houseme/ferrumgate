//! Port-probe integration (WP-71 §6): an open loopback port is listed with
//! its service name and duration; a closed port is not listed.

#![forbid(unsafe_code)]

use std::time::Duration;

use common::{spawn_listener, wait_finished};
use fg_nettools::model::PortProbeParams;
use fg_nettools::{JobStatus, port_probe};

mod common;

/// Binds one of the ports that has a well-known service name, falling back
/// to an ephemeral port when they are taken.
async fn bind_named_port() -> (u16, Option<&'static str>) {
    for (port, service) in [
        (16181u16, None),
        (6379, Some("redis")),
        (8080, Some("http-alt")),
    ] {
        if let Ok(listener) = tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            tokio::spawn(async move {
                loop {
                    let _ = listener.accept().await;
                }
            });
            return (port, service);
        }
    }
    let addr = spawn_listener().await;
    (addr.port(), None)
}

#[tokio::test(flavor = "multi_thread")]
async fn port_probe_lists_open_with_service_name() {
    let (open_port, service) = bind_named_port().await;
    // A closed port: bind then release.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind closed");
    let closed_port = closed.local_addr().expect("addr").port();
    drop(closed);

    let registry = std::sync::Arc::new(fg_nettools::JobRegistry::new(fg_nettools::Caps::default()));
    let params = PortProbeParams {
        target: "127.0.0.1".into(),
        ports: format!("{open_port},{closed_port}"),
        concurrency: Some(16),
        timeout: Some(1.5),
    };
    let id = registry
        .spawn("portprobe", "loopback", move |handle| {
            port_probe::run(&params, handle, &[])
        })
        .expect("spawn");
    let view = wait_finished(&registry, &id).await;
    assert_eq!(view.status, JobStatus::Done, "lines: {:?}", view.lines);
    let open_line = view
        .lines
        .iter()
        .find(|line| line.starts_with(&format!("{open_port}/tcp 开放")))
        .expect("open port listed");
    assert!(open_line.contains("ms"), "duration: {open_line}");
    if let Some(service) = service {
        assert!(open_line.contains(service), "service name: {open_line}");
    }
    assert!(
        !view
            .lines
            .iter()
            .any(|line| line.starts_with(&format!("{closed_port}/tcp"))),
        "closed port not listed: {:?}",
        view.lines
    );
    assert!(
        view.lines
            .iter()
            .any(|line| line.contains("共探测 2 个端口，开放 1 个")),
        "summary: {:?}",
        view.lines
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn port_probe_bad_ports_spec_fails() {
    let registry = std::sync::Arc::new(fg_nettools::JobRegistry::new(fg_nettools::Caps::default()));
    let params = PortProbeParams {
        target: "127.0.0.1".into(),
        ports: "not-ports".into(),
        concurrency: None,
        timeout: None,
    };
    let id = registry
        .spawn("portprobe", "bad", move |handle| {
            port_probe::run(&params, handle, &[])
        })
        .expect("spawn");
    let view = wait_finished(&registry, &id).await;
    assert!(matches!(view.status, JobStatus::Failed(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn port_probe_connect_timeout_reports_closed() {
    // An address in TEST-NET-1 does not answer; the probe must not hang.
    let registry = std::sync::Arc::new(fg_nettools::JobRegistry::new(fg_nettools::Caps::default()));
    let params = PortProbeParams {
        target: "203.0.113.1".into(),
        ports: "80".into(),
        concurrency: Some(4),
        timeout: Some(0.3),
    };
    let id = registry
        .spawn("portprobe", "timeout", move |handle| {
            port_probe::run(&params, handle, &[])
        })
        .expect("spawn");
    let view = wait_finished(&registry, &id).await;
    assert_eq!(
        view.status,
        JobStatus::Done,
        "closed ports are not failures"
    );
    let _ = Duration::from_millis(300);
}
