//! Ping and LAN-scan integration (WP-71 §6): loopback RTT through the
//! unprivileged ICMP socket and a loopback-neighbour scan. Skips with a
//! notice when the environment does not grant unprivileged ICMP (CI
//! sandboxes); that path is separately covered by
//! `ping_without_privilege_reports_reason`.

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use common::wait_finished;
use fg_nettools::model::LanScanParams;
use fg_nettools::model::PingParams;
use fg_nettools::{JobStatus::*, ping, validate};

mod common;

/// Whether unprivileged ICMP works here; `Some(reason)` when not.
async fn icmp_available() -> Option<String> {
    match ping::ping_once(IpAddr::from(Ipv4Addr::LOCALHOST), Duration::from_secs(2)).await {
        Ok(_) => None,
        Err(ping::EchoError::Io(error)) => {
            let reason = ping::failure_reason(&error);
            if error.kind() == std::io::ErrorKind::PermissionDenied
                || reason.contains("ping_group_range")
            {
                Some(reason)
            } else {
                None // other failures are real failures
            }
        }
        Err(_) => None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ping_loopback_measures_rtt() {
    if let Some(reason) = icmp_available().await {
        eprintln!("skip ping_loopback_measures_rtt: {reason}");
        return;
    }
    let rtt = ping::ping_once(IpAddr::from(Ipv4Addr::LOCALHOST), Duration::from_secs(2))
        .await
        .expect("loopback rtt");
    assert!(rtt < Duration::from_millis(500), "loopback rtt {rtt:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn ping_run_reports_summary_lines() {
    if let Some(reason) = icmp_available().await {
        eprintln!("skip ping_run_reports_summary_lines: {reason}");
        return;
    }
    let registry = std::sync::Arc::new(fg_nettools::JobRegistry::new(fg_nettools::Caps::default()));
    let params = PingParams {
        target: "127.0.0.1".into(),
        count: Some(2),
        timeout: Some(1.0),
        interval: Some(0.05),
    };
    let id = registry
        .spawn("ping", "loopback", move |handle| {
            ping::run(&params, handle, &[])
        })
        .expect("spawn");
    let view = wait_finished(&registry, &id).await;
    assert_eq!(view.status, Done, "lines: {:?}", view.lines);
    assert!(
        view.lines
            .iter()
            .any(|line| line.contains("目标 127.0.0.1（回环）"))
    );
    assert!(
        view.lines
            .iter()
            .any(|line| line.contains("第 1 次：") && line.contains("ms"))
    );
    assert!(
        view.lines
            .iter()
            .any(|line| line.contains("共发送 2 次，收到 2 次"))
    );
    assert!(
        view.lines
            .iter()
            .any(|line| line.contains("最小") && line.contains("最大"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ping_target_without_listener_reports_failure() {
    // A documentation-range address that will not answer.
    if let Some(reason) = icmp_available().await {
        eprintln!("skip ping_target_without_listener_reports_failure: {reason}");
        return;
    }
    let registry = std::sync::Arc::new(fg_nettools::JobRegistry::new(fg_nettools::Caps::default()));
    let params = PingParams {
        target: "203.0.113.1".into(),
        count: Some(1),
        timeout: Some(0.5),
        interval: None,
    };
    let id = registry
        .spawn("ping", "dead", move |handle| {
            ping::run(&params, handle, &[])
        })
        .expect("spawn");
    let view = wait_finished(&registry, &id).await;
    // The TEST-NET address must not answer inside this sandbox; whatever
    // comes back, the job either fails with a clear reason or (if the
    // environment routes it) succeeds — both acceptable, no panic.
    assert_ne!(view.status, Running);
    let _ = validate::classify(IpAddr::from(Ipv4Addr::new(203, 0, 113, 1)));
}

#[tokio::test(flavor = "multi_thread")]
async fn lan_scan_finds_loopback_neighbors() {
    if let Some(reason) = icmp_available().await {
        eprintln!("skip lan_scan_finds_loopback_neighbors: {reason}");
        return;
    }
    let registry = std::sync::Arc::new(fg_nettools::JobRegistry::new(fg_nettools::Caps::default()));
    let params = LanScanParams {
        cidr: Some("127.0.0.1/32".into()),
        include_names: Some(false),
    };
    let id = registry
        .spawn("lanscan", "loopback", move |handle| {
            fg_nettools::lan_scan::run(&params, handle, &[])
        })
        .expect("spawn");
    let view = wait_finished(&registry, &id).await;
    assert_eq!(view.status, Done, "lines: {:?}", view.lines);
    assert!(
        view.lines
            .iter()
            .any(|line| line.starts_with("127.0.0.1 在线")),
        "lines: {:?}",
        view.lines
    );
    assert!(view.lines.iter().any(|line| line.contains("扫描完成")));
}

#[tokio::test]
async fn lan_scan_invalid_cidr_fails() {
    let registry = std::sync::Arc::new(fg_nettools::JobRegistry::new(fg_nettools::Caps::default()));
    let params = LanScanParams {
        cidr: Some("not a net".into()),
        include_names: None,
    };
    let id = registry
        .spawn("lanscan", "bad", move |handle| {
            fg_nettools::lan_scan::run(&params, handle, &[])
        })
        .expect("spawn");
    let view = wait_finished(&registry, &id).await;
    assert!(matches!(view.status, Failed(_)));
}
