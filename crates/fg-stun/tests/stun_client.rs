//! Client-level integration tests (WP-42 §6): transactions time out, the
//! servers are tried in order, a full round of failures fails the round,
//! TCP carries the binding too, and the concurrent consistency probe
//! judges diverging mappings. Everything talks to the local fake STUN
//! server only — no real network access.

mod fake_stun_server;

use std::time::Duration;

use fake_stun_server::{Behavior, FakeStun, Mapping};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use fg_stun::stun::client::{
    ClientError, ConsistencyVerdict, binding_tcp_once, binding_udp_once, check_consistency,
    connect_tcp, query_servers_tcp, query_servers_udp,
};

fn token() -> CancellationToken {
    CancellationToken::new()
}

#[tokio::test]
async fn client_timeout_when_server_stays_silent() {
    let server = FakeStun::udp_with(Behavior {
        respond: false,
        ..Behavior::default()
    })
    .await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let started = std::time::Instant::now();
    let result = binding_udp_once(
        &socket,
        server.udp_addr(),
        Duration::from_millis(250),
        &token(),
    )
    .await;
    assert!(
        matches!(result, Err(ClientError::Timeout)),
        "expected a timeout, got {result:?}"
    );
    // The transaction window really bounded the wait (two transmits fit
    // into one window).
    assert!(started.elapsed() < Duration::from_secs(3), "{started:?}");
    server.stop();
}

#[tokio::test]
async fn client_retransmission_recovers_delayed_answers() {
    // The server answers after the first wait phase has already passed:
    // the transaction only succeeds because the request is retransmitted
    // at half the window and the client keeps listening.
    let server = FakeStun::udp_with(Behavior {
        delay: Duration::from_millis(700),
        ..Behavior::default()
    })
    .await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let mapped = binding_udp_once(
        &socket,
        server.udp_addr(),
        Duration::from_millis(900),
        &token(),
    )
    .await
    .expect("delayed answer within the window");
    assert_eq!(mapped.port(), socket.local_addr().expect("local").port());
    server.stop();
}

#[tokio::test]
async fn client_tries_servers_in_order() {
    let live = FakeStun::udp().await;
    let live2 = FakeStun::udp().await;
    // Dead ports never answer; the round reaches the live servers.
    let dead1 = "127.0.0.1:1".parse().expect("addr");
    let dead2 = "127.0.0.1:2".parse().expect("addr");
    let servers = vec![dead1, dead2, live.udp_addr(), live2.udp_addr()];
    let outcome = query_servers_udp(
        "127.0.0.1:0".parse().expect("bind"),
        &servers,
        Duration::from_millis(200),
        &token(),
    )
    .await
    .expect("third server answers");
    assert_eq!(outcome.server, live.udp_addr(), "first live server wins");
    assert_eq!(
        outcome.mapped.ip().to_string(),
        "127.0.0.1",
        "echoed source"
    );
    assert!(outcome.mapped.port() > 0, "echoed the ephemeral local port");
    // A live server first is chosen immediately (no wasted timeouts).
    let servers = vec![live2.udp_addr(), dead1];
    let outcome = query_servers_udp(
        "127.0.0.1:0".parse().expect("bind"),
        &servers,
        Duration::from_millis(200),
        &token(),
    )
    .await
    .expect("first server answers");
    assert_eq!(outcome.server, live2.udp_addr());
    live.stop();
    live2.stop();
}

#[tokio::test]
async fn client_all_servers_failing_fails_the_round() {
    let servers = vec![
        "127.0.0.1:1".parse().expect("addr"),
        "127.0.0.1:2".parse().expect("addr"),
    ];
    let errors = query_servers_udp(
        "127.0.0.1:0".parse().expect("bind"),
        &servers,
        Duration::from_millis(150),
        &token(),
    )
    .await
    .expect_err("the round fails");
    assert_eq!(errors.len(), 2, "one error per server: {errors:?}");
}

#[tokio::test]
async fn client_binding_roundtrip_over_tcp() {
    let server = FakeStun::tcp().await;
    let outcome = query_servers_tcp(&[server.tcp_addr()], Duration::from_millis(1000), &token())
        .await
        .expect("tcp binding");
    assert_eq!(outcome.server, server.tcp_addr());
    server.stop();
}

#[tokio::test]
async fn client_tcp_binding_on_existing_stream() {
    let server = FakeStun::tcp().await;
    let mut stream = connect_tcp(server.tcp_addr(), Duration::from_millis(1000), &token())
        .await
        .expect("connect");
    let mapped = binding_tcp_once(&mut stream, Duration::from_millis(1000), &token())
        .await
        .expect("binding over the established stream");
    assert!(mapped.port() > 0);
    server.stop();
}

#[tokio::test]
async fn client_consistency_compares_mappings_from_one_socket() {
    // Both servers echo: same mapping tuple → consistent.
    let echo1 = FakeStun::udp().await;
    let echo2 = FakeStun::udp().await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let report = check_consistency(
        &socket,
        &[echo1.udp_addr(), echo2.udp_addr()],
        Duration::from_millis(1000),
        &token(),
    )
    .await;
    assert_eq!(report.verdict, ConsistencyVerdict::Consistent);
    assert!(report.pairs.iter().all(|(_, answer)| answer.is_some()));
    echo1.stop();
    echo2.stop();

    // The second server reports a fixed different port → divergent.
    let echo = FakeStun::udp().await;
    let other = FakeStun::udp_with(Behavior {
        mapping: Mapping::Fixed("127.0.0.1:44444".parse().expect("addr")),
        ..Behavior::default()
    })
    .await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let report = check_consistency(
        &socket,
        &[echo.udp_addr(), other.udp_addr()],
        Duration::from_millis(1000),
        &token(),
    )
    .await;
    assert_eq!(report.verdict, ConsistencyVerdict::PortDivergent);
    echo.stop();
    other.stop();
}
