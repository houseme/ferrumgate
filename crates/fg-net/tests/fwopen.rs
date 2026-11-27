//! Integration tests for the public `fg_net::fwopen` API. These run on
//! every platform and never touch a real firewall: `setup` and `Group`
//! only probe (on Linux) or report "unsupported" (elsewhere).

use std::net::IpAddr;
use std::time::Duration;

use fg_net::fwopen::{
    CHAIN_PREFIX, COMMENT_PREFIX, Family, Group, LOOPBACK_NOTE, Port, Proto, RECONCILE_INTERVAL,
    for_listen, is_loopback, setup,
};

#[test]
fn reconcile_interval_default_is_30s() {
    assert_eq!(RECONCILE_INTERVAL, Duration::from_secs(30));
}

#[test]
fn constants_use_ferrumgate_namespaces() {
    assert_eq!(COMMENT_PREFIX, "ferrumgate-open:");
    assert_eq!(CHAIN_PREFIX, "GTLY_OPEN_");
    assert!(!LOOPBACK_NOTE.is_empty());
}

#[test]
fn setup_repeated_calls_are_safe() {
    let dir = std::env::temp_dir().join(format!("fg-net-fwopen-it-{}", std::process::id()));
    setup(&dir);
    // Only the first call takes effect; later ones must be no-ops.
    setup(&dir);
}

#[test]
fn for_listen_public_api_opens_and_skips_loopback() {
    let open = for_listen("tcp", None, &[443, 8000, 8001], &[]);
    assert_eq!(
        open,
        vec![
            Port::single(Proto::Tcp, Family::Both, 443),
            Port::range(Proto::Tcp, Family::Both, 8000, 8001),
        ]
    );
    let loopback = for_listen(
        "tcp",
        Some("127.0.0.1".parse::<IpAddr>().unwrap()),
        &[80],
        &[],
    );
    assert!(loopback.is_empty());
    assert!(is_loopback(Some("::1".parse::<IpAddr>().unwrap())));
}

#[test]
fn group_status_empty_before_registration() {
    let group = Group::new("probe");
    assert_eq!(group.status("missing"), "");
    assert!(!group.failed("missing"));
}
