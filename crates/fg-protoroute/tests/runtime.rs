//! Real loopback TCP & HTTP integration tests for the protoroute runtime,
//! hot-reloading, SPA handoff, PROXY protocol, failover, haproxy/sslh
//! replacement scenarios, and management API (WP-35 §6).

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fg_config::ConfigStore;
use fg_core::metrics::write_text;
use fg_net::openports::{OpenPorts, Proto};
use fg_net::source_rule::BanCheck;
use fg_protoroute::model::{
    AccessConfig, FileConfig, Net, Protocol, ProxyProtocol, Route, Rule, Settings,
};
use fg_protoroute::runtime::Manager;
use fg_protoroute::{Deps, KnockProvider, Module};
use http_body_util::Full;
use hyper::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn free_v4_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral v4")
        .local_addr()
        .unwrap()
        .port()
}

/// Spawns a tagged echo backend on `127.0.0.1:0`: prefixes every read chunk
/// with `[<tag>]` and echoes the exact bytes back (preserving binary data,
/// PROXY headers, and sniffed prefixes verbatim).
async fn spawn_tagged_backend(tag: &'static str) -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_bg = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let seen_conn = Arc::clone(&seen_bg);
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let mut first = true;
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    seen_conn.lock().unwrap().push(buf[..n].to_vec());
                    if first {
                        first = false;
                        if sock.write_all(format!("[{tag}]").as_bytes()).await.is_err() {
                            break;
                        }
                    }
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, seen)
}

/// Spawns a server-speaks-first backend (e.g. VNC `RFB 003.008\n`) that sends
/// `banner` immediately upon accept without waiting for client bytes.
async fn spawn_server_first_backend(banner: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind vnc");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = sock.write_all(banner).await;
                let mut buf = [0u8; 1024];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

fn build_client_hello(sni: &[u8], alpn: &[&[u8]]) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x55; 32]);
    body.push(0x00);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);
    let mut extensions = Vec::new();
    if !sni.is_empty() {
        let mut entry = vec![0x00];
        entry.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        entry.extend_from_slice(sni);
        let mut ext_data = Vec::with_capacity(2 + entry.len());
        ext_data.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        ext_data.extend_from_slice(&entry);
        extensions.extend_from_slice(&(0x0000_u16).to_be_bytes());
        extensions.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ext_data);
    }
    if !alpn.is_empty() {
        let mut list = Vec::new();
        for id in alpn {
            list.push(id.len() as u8);
            list.extend_from_slice(id);
        }
        let mut ext_data = Vec::with_capacity(2 + list.len());
        ext_data.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext_data.extend_from_slice(&list);
        extensions.extend_from_slice(&(0x0010_u16).to_be_bytes());
        extensions.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ext_data);
    }
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut hello = vec![0x01];
    hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hello.extend_from_slice(&body);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);
    record
}

fn base_rule(key: &str, listen_port: u16, routes: Vec<Route>) -> Rule {
    Rule {
        key: key.into(),
        name: format!("rule-{key}"),
        enable: true,
        protocols: vec![Net::Tcp4],
        listen_address: "127.0.0.1".into(),
        listen_ports: listen_port.to_string(),
        routes,
        sniff_timeout: 0.3,
        ..Rule::default()
    }
}

fn route(name: &str, protocol: Protocol, domains: &[&str], port: u16) -> Route {
    Route {
        name: name.into(),
        protocol,
        domains: domains.iter().map(|d| (*d).into()).collect(),
        target_addresses: vec!["127.0.0.1".into()],
        target_port: port,
        ..Route::default()
    }
}

async fn send_and_read(port: u16, payload: &[u8]) -> Vec<u8> {
    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect protoroute");
    sock.write_all(payload).await.expect("write payload");
    sock.shutdown().await.expect("shutdown write");
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), sock.read_to_end(&mut resp))
        .await
        .expect("read timeout")
        .expect("read body");
    resp
}

async fn wait_for<F, Fut>(mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    panic!("condition not satisfied before timeout");
}

struct MockBan(Mutex<HashSet<IpAddr>>);

impl BanCheck for MockBan {
    fn banned(&self, address: IpAddr) -> bool {
        self.0.lock().unwrap().contains(&address.to_canonical())
    }
}

#[derive(Default)]
struct MockKnock {
    grants: Mutex<HashSet<(String, IpAddr)>>,
    spa_received: Mutex<Vec<(IpAddr, u16, Vec<u8>)>>,
    unlock_on_spa: Mutex<Option<String>>,
}

impl KnockProvider for MockKnock {
    fn is_open(&self, rule_key: &str, peer: IpAddr) -> bool {
        self.grants
            .lock()
            .unwrap()
            .contains(&(rule_key.to_owned(), peer.to_canonical()))
    }

    fn handle_spa(&self, peer: IpAddr, listen_port: u16, packet: &[u8]) {
        self.spa_received
            .lock()
            .unwrap()
            .push((peer, listen_port, packet.to_vec()));
        if let Some(key) = self.unlock_on_spa.lock().unwrap().clone() {
            self.grants
                .lock()
                .unwrap()
                .insert((key, peer.to_canonical()));
        }
    }
}

// ---------------------------------------------------------------------------
// Core runtime integration tests (WP-35 §6)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_protocol_goes_to_default() {
    let (default_port, _) = spawn_tagged_backend("DEFAULT").await;
    let (ssh_port, _) = spawn_tagged_backend("SSH").await;
    let listen_port = free_v4_port();

    let mut rule = base_rule(
        "r1",
        listen_port,
        vec![route("ssh", Protocol::Ssh, &[], ssh_port)],
    );
    rule.target_addresses = vec!["127.0.0.1".into()];
    rule.target_ports = default_port.to_string();

    let mgr = Manager::new(
        FileConfig {
            settings: Settings::default(),
            rules: vec![rule],
        },
        Deps::default(),
    );
    mgr.start().await.unwrap();

    // Unknown length-prefixed binary protocol (like DNS-over-TCP / Shadowsocks).
    let unknown = vec![0x00, 0x0B, 0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5];
    let resp = send_and_read(listen_port, &unknown).await;
    assert!(resp.starts_with(b"[DEFAULT]"));
    assert_eq!(&resp[b"[DEFAULT]".len()..], unknown.as_slice());

    // Malformed TLS ClientHello also falls back to default target verbatim.
    let broken_tls = vec![0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00];
    let resp2 = send_and_read(listen_port, &broken_tls).await;
    assert!(resp2.starts_with(b"[DEFAULT]"));
    assert_eq!(&resp2[b"[DEFAULT]".len()..], broken_tls.as_slice());

    let status = mgr.rule_status("r1").await;
    assert_eq!(status.counters.default_hits, 2);
    assert_eq!(status.counters.dropped, 0);
    mgr.shutdown().await;
}

#[tokio::test]
async fn no_default_target_drops_connection() {
    let (ssh_port, _) = spawn_tagged_backend("SSH").await;
    let listen_port = free_v4_port();

    let rule = base_rule(
        "r1",
        listen_port,
        vec![route("ssh", Protocol::Ssh, &[], ssh_port)],
    );
    let mgr = Manager::new(
        FileConfig {
            settings: Settings::default(),
            rules: vec![rule],
        },
        Deps::default(),
    );
    mgr.start().await.unwrap();

    let resp = send_and_read(listen_port, b"XX unknown binary payload").await;
    assert!(resp.is_empty(), "dropped connection must return no data");

    wait_for(|| async { mgr.rule_status("r1").await.counters.dropped == 1 }).await;
    assert_eq!(mgr.rule_status("r1").await.counters.route_hits, [0]);
    mgr.shutdown().await;
}

#[tokio::test]
async fn timeout_route_for_server_first_protocols() {
    let vnc_port = spawn_server_first_backend(b"RFB 003.008\n").await;
    let (ssh_port, _) = spawn_tagged_backend("SSH").await;
    let listen_port = free_v4_port();

    let mut rule = base_rule(
        "r1",
        listen_port,
        vec![
            route("ssh", Protocol::Ssh, &[], ssh_port),
            route("vnc-timeout", Protocol::Timeout, &[], vnc_port),
        ],
    );
    rule.sniff_timeout = 0.2;

    let mgr = Manager::new(
        FileConfig {
            settings: Settings::default(),
            rules: vec![rule],
        },
        Deps::default(),
    );
    mgr.start().await.unwrap();

    // Connect and send nothing: after ~200ms the timeout route connects to VNC
    // and relays its server-first banner.
    let mut sock = TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .unwrap();
    let mut banner = [0u8; 12];
    tokio::time::timeout(Duration::from_secs(2), sock.read_exact(&mut banner))
        .await
        .expect("timeout waiting for VNC banner")
        .expect("read banner");
    assert_eq!(&banner, b"RFB 003.008\n");

    let status = mgr.rule_status("r1").await;
    assert_eq!(status.counters.route_hits, [0, 1]);
    drop(sock);
    mgr.shutdown().await;
}

#[tokio::test]
async fn client_disconnects_before_sniff() {
    let (ssh_port, _) = spawn_tagged_backend("SSH").await;
    let listen_port = free_v4_port();

    let rule = base_rule(
        "r1",
        listen_port,
        vec![route("ssh", Protocol::Ssh, &[], ssh_port)],
    );
    let mgr = Manager::new(
        FileConfig {
            settings: Settings::default(),
            rules: vec![rule],
        },
        Deps::default(),
    );
    mgr.start().await.unwrap();

    // Send a partial prefix and close immediately before protocol identification.
    {
        let mut sock = TcpStream::connect(("127.0.0.1", listen_port))
            .await
            .unwrap();
        sock.write_all(b"SS").await.unwrap();
    }
    // Also connect and close with zero bytes.
    {
        let _sock = TcpStream::connect(("127.0.0.1", listen_port))
            .await
            .unwrap();
    }

    tokio::time::sleep(Duration::from_millis(80)).await;
    let status = mgr.rule_status("r1").await;
    assert_eq!(status.counters.route_hits, [0]);
    assert_eq!(status.counters.default_hits, 0);
    assert_eq!(status.counters.dropped, 0);
    assert_eq!(status.counters.denied, 0);
    mgr.shutdown().await;
}

#[tokio::test]
async fn route_sets_proxy_protocol_per_target() {
    let (v1_port, _) = spawn_tagged_backend("V1").await;
    let (v2_port, _) = spawn_tagged_backend("V2").await;
    let (def_port, _) = spawn_tagged_backend("DEF").await;
    let listen_port = free_v4_port();

    let mut r_v1 = route("ssh-v1", Protocol::Ssh, &[], v1_port);
    r_v1.proxy_protocol = ProxyProtocol::V1;
    let mut r_v2 = route("tls-v2", Protocol::Tls, &["proxy.example"], v2_port);
    r_v2.proxy_protocol = ProxyProtocol::V2;

    let mut rule = base_rule("r1", listen_port, vec![r_v1, r_v2]);
    rule.target_addresses = vec!["127.0.0.1".into()];
    rule.target_ports = def_port.to_string();
    rule.proxy_protocol = ProxyProtocol::None;

    let mgr = Manager::new(
        FileConfig {
            settings: Settings::default(),
            rules: vec![rule],
        },
        Deps::default(),
    );
    mgr.start().await.unwrap();

    // Route 0 -> PROXY v1 + SSH banner.
    let resp_v1 = send_and_read(listen_port, b"SSH-2.0-test\r\n").await;
    let text_v1 = String::from_utf8_lossy(&resp_v1);
    assert!(
        text_v1.starts_with("[V1]PROXY TCP4 127.0.0.1 127.0.0.1 "),
        "{text_v1}"
    );
    assert!(text_v1.ends_with("SSH-2.0-test\r\n"), "{text_v1}");

    // Route 1 -> PROXY v2 binary header + TLS ClientHello.
    let hello = build_client_hello(b"proxy.example", &[]);
    let resp_v2 = send_and_read(listen_port, &hello).await;
    assert!(resp_v2.starts_with(b"[V2]\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c"));
    assert_eq!(&resp_v2[b"[V2]".len() + 28..], hello.as_slice());

    // Default target -> no PROXY header.
    let resp_def = send_and_read(listen_port, b"ZZZraw").await;
    assert_eq!(resp_def, b"[DEF]ZZZraw");

    mgr.shutdown().await;
}

#[tokio::test]
async fn target_failover_in_order() {
    let dead_port = free_v4_port();
    let (live_port, _) = spawn_tagged_backend("LIVE").await;
    let listen_port = free_v4_port();

    // First target is unreachable (non-routable / refused loopback), second succeeds.
    // Note: targets share `target_port`, so bind live backend on `live_port` and put a
    // closed IPv6 address (or unlistening host) first, OR fail over across two addresses
    // on `live_port`: `[::1]` has nothing listening on `live_port`, `127.0.0.1` has our backend!
    let _ = dead_port;
    let mut ssh_route = route("ssh", Protocol::Ssh, &[], live_port);
    ssh_route.target_addresses = vec!["::1".into(), "127.0.0.1".into()];

    let rule = base_rule("r1", listen_port, vec![ssh_route]);
    let mgr = Manager::new(
        FileConfig {
            settings: Settings {
                dial_timeout: 1,
                ..Settings::default()
            },
            rules: vec![rule],
        },
        Deps::default(),
    );
    mgr.start().await.unwrap();

    let resp = send_and_read(listen_port, b"SSH-2.0-failover\r\n").await;
    assert_eq!(resp, b"[LIVE]SSH-2.0-failover\r\n");
    mgr.shutdown().await;
}

#[tokio::test]
async fn target_port_zero_means_listen_port() {
    // Bind backend on [::1]:P and protoroute on 127.0.0.1:P so both share the
    // exact same port P on loopback without colliding!
    let Ok(backend) = TcpListener::bind("[::1]:0").await else {
        // IPv6 loopback disabled on host: skip cleanly.
        return;
    };
    let shared_port = backend.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = backend.accept().await {
            let mut buf = [0u8; 1024];
            if let Ok(n) = sock.read(&mut buf).await {
                let _ = sock.write_all(b"[SAMEPORT]").await;
                let _ = sock.write_all(&buf[..n]).await;
            }
        }
    });

    let mut ssh_route = route("ssh", Protocol::Ssh, &[], 0); // target_port == 0!
    ssh_route.target_addresses = vec!["::1".into()];
    let rule = base_rule("r1", shared_port, vec![ssh_route]);
    let mgr = Manager::new(
        FileConfig {
            settings: Settings::default(),
            rules: vec![rule],
        },
        Deps::default(),
    );
    mgr.start().await.unwrap();

    let resp = send_and_read(shared_port, b"SSH-2.0-port0\r\n").await;
    assert_eq!(resp, b"[SAMEPORT]SSH-2.0-port0\r\n");
    mgr.shutdown().await;
}

#[tokio::test]
async fn source_policy_before_sniff() {
    let (ssh_port, seen) = spawn_tagged_backend("SSH").await;
    let listen_port = free_v4_port();

    // 1. Blacklisted loopback IP rejected before reading any byte, 0 route hits.
    let mut rule = base_rule(
        "r1",
        listen_port,
        vec![route("ssh", Protocol::Ssh, &[], ssh_port)],
    );
    rule.access = AccessConfig {
        enable: true,
        whitelist: vec!["127.0.0.0/8".into()],
        blacklist: vec!["127.0.0.1".into()], // deny wins over allow
    };
    let ban = Arc::new(MockBan(Mutex::new(HashSet::new())));
    let mgr = Manager::new(
        FileConfig {
            settings: Settings::default(),
            rules: vec![rule.clone()],
        },
        Deps {
            ban: Some(Arc::clone(&ban) as Arc<dyn BanCheck>),
            ..Deps::default()
        },
    );
    mgr.start().await.unwrap();

    // Connect and do NOT even send bytes yet — the server must close immediately
    // because access control runs BEFORE sniffing!
    let mut sock = TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(1), sock.read(&mut buf))
        .await
        .expect("denied client must be closed immediately before sniff")
        .unwrap();
    assert_eq!(n, 0);

    wait_for(|| async { mgr.rule_status("r1").await.counters.denied == 1 }).await;
    assert_eq!(mgr.rule_status("r1").await.counters.route_hits, [0]);
    assert!(seen.lock().unwrap().is_empty());

    // 2. Remove blacklist, but ban 127.0.0.1 via BanCheck: ban beats whitelist!
    rule.access.blacklist.clear();
    mgr.apply(FileConfig {
        settings: Settings::default(),
        rules: vec![rule],
    })
    .await
    .unwrap();
    ban.0.lock().unwrap().insert("127.0.0.1".parse().unwrap());

    let mut sock = TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .unwrap();
    let n = tokio::time::timeout(Duration::from_secs(1), sock.read(&mut buf))
        .await
        .expect("banned client must be closed before sniff")
        .unwrap();
    assert_eq!(n, 0);
    wait_for(|| async { mgr.rule_status("r1").await.counters.denied == 2 }).await;

    // 3. Unban -> whitelisted 127.0.0.1 now succeeds!
    ban.0.lock().unwrap().clear();
    let resp = send_and_read(listen_port, b"SSH-2.0-allowed\r\n").await;
    assert_eq!(resp, b"[SSH]SSH-2.0-allowed\r\n");
    assert_eq!(mgr.rule_status("r1").await.counters.route_hits, [1]);
    mgr.shutdown().await;
}

#[tokio::test]
async fn spa_route_hands_packet_to_knock_without_reply() {
    let (ssh_port, _) = spawn_tagged_backend("SSH").await;
    let listen_port = free_v4_port();
    let knock = Arc::new(MockKnock::default());
    *knock.unlock_on_spa.lock().unwrap() = Some("knock1".into());

    let mut rule = base_rule(
        "r1",
        listen_port,
        vec![
            Route {
                name: "spa-in".into(),
                protocol: Protocol::Spa,
                ..Route::default()
            },
            route("ssh", Protocol::Ssh, &[], ssh_port),
        ],
    );
    rule.knock = Some("knock1".into());

    let mgr = Manager::new(
        FileConfig {
            settings: Settings::default(),
            rules: vec![rule],
        },
        Deps {
            knock: Some(Arc::clone(&knock) as Arc<dyn KnockProvider>),
            ..Deps::default()
        },
    );
    mgr.start().await.unwrap();

    // Before knocking: SSH is denied even though SPA route lets sniffing run.
    let denied_resp = send_and_read(listen_port, b"SSH-2.0-before-knock\r\n").await;
    assert!(denied_resp.is_empty());
    wait_for(|| async { mgr.rule_status("r1").await.counters.denied == 1 }).await;

    // Send a SPA packet (no trailing newline, client closes at EOF):
    // handed to MockKnock, zero reply bytes, zero route hits!
    let spa_payload: Vec<u8> = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .copied()
        .cycle()
        .take(88)
        .collect();
    let spa_reply = send_and_read(listen_port, &spa_payload).await;
    assert!(spa_reply.is_empty(), "SPA must never reply");

    wait_for(|| async { !knock.spa_received.lock().unwrap().is_empty() }).await;
    {
        let received = knock.spa_received.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].0, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(received[0].1, listen_port);
        assert_eq!(received[0].2, spa_payload);
    }
    assert_eq!(mgr.rule_status("r1").await.counters.route_hits, [0, 0]);

    // Now the knock grant is live -> SSH succeeds!
    let ok_resp = send_and_read(listen_port, b"SSH-2.0-after-knock\r\n").await;
    assert_eq!(ok_resp, b"[SSH]SSH-2.0-after-knock\r\n");
    assert_eq!(mgr.rule_status("r1").await.counters.route_hits, [0, 1]);
    mgr.shutdown().await;
}

#[tokio::test]
async fn hot_update_keeps_listener_and_connections() {
    let (ssh_a, _) = spawn_tagged_backend("SSH_A").await;
    let (ssh_b, _) = spawn_tagged_backend("SSH_B").await;
    let (http_port, _) = spawn_tagged_backend("HTTP").await;
    let (def_port, _) = spawn_tagged_backend("DEF").await;
    let listen_port = free_v4_port();

    let mut rule = base_rule(
        "r1",
        listen_port,
        vec![
            route("ssh-orig", Protocol::Ssh, &[], ssh_a),
            route("web", Protocol::Http, &["a.example"], http_port),
        ],
    );
    rule.target_addresses = vec!["127.0.0.1".into()];
    rule.target_ports = def_port.to_string();

    let mgr = Manager::new(
        FileConfig {
            settings: Settings::default(),
            rules: vec![rule.clone()],
        },
        Deps::default(),
    );
    mgr.start().await.unwrap();

    // Open a persistent SSH connection to SSH_A and keep it open across hot update.
    let mut persistent = TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .unwrap();
    persistent.write_all(b"SSH-2.0-long\r\n").await.unwrap();
    let mut first_reply = vec![0u8; b"[SSH_A]SSH-2.0-long\r\n".len()];
    persistent.read_exact(&mut first_reply).await.unwrap();
    assert_eq!(first_reply, b"[SSH_A]SSH-2.0-long\r\n");

    // Also hit the HTTP route and the default target once each.
    let _ = send_and_read(listen_port, b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n").await;
    let _ = send_and_read(listen_port, b"ZZunknown").await;
    assert_eq!(mgr.rule_status("r1").await.counters.route_hits, [1, 1]);
    assert_eq!(mgr.rule_status("r1").await.counters.default_hits, 1);

    // Hot-update: move & rename & retarget SSH (same MatchKey -> keeps count = 1!),
    // change HTTP domain from a.example -> b.example (new MatchKey -> resets to 0!),
    // keep default target (keeps default_hits = 1!).
    rule.routes = vec![
        route("web-changed", Protocol::Http, &["b.example"], http_port),
        route("ssh-moved", Protocol::Ssh, &[], ssh_b),
    ];
    mgr.apply(FileConfig {
        settings: Settings::default(),
        rules: vec![rule],
    })
    .await
    .unwrap();

    // Existing connection MUST remain alive on SSH_A!
    persistent.write_all(b"still-alive").await.unwrap();
    let mut second_reply = [0u8; 11];
    persistent.read_exact(&mut second_reply).await.unwrap();
    assert_eq!(&second_reply, b"still-alive");

    // New SSH connection routes to SSH_B and increments inherited counter 1 -> 2!
    let new_ssh = send_and_read(listen_port, b"SSH-2.0-new\r\n").await;
    assert_eq!(new_ssh, b"[SSH_B]SSH-2.0-new\r\n");

    // New HTTP for b.example starts from 0 -> 1.
    let new_http = send_and_read(listen_port, b"GET / HTTP/1.1\r\nHost: b.example\r\n\r\n").await;
    assert!(new_http.starts_with(b"[HTTP]"));

    let status = mgr.rule_status("r1").await;
    assert_eq!(status.counters.route_hits, [1, 2]);
    assert_eq!(status.counters.default_hits, 1);

    drop(persistent);
    mgr.shutdown().await;
}

#[tokio::test]
async fn listen_change_restarts_rule() {
    let (ssh_port, _) = spawn_tagged_backend("SSH").await;
    let port_old = free_v4_port();
    let port_new = free_v4_port();

    let mut rule = base_rule(
        "r1",
        port_old,
        vec![route("ssh", Protocol::Ssh, &[], ssh_port)],
    );
    let mgr = Manager::new(
        FileConfig {
            settings: Settings::default(),
            rules: vec![rule.clone()],
        },
        Deps::default(),
    );
    mgr.start().await.unwrap();

    let resp = send_and_read(port_old, b"SSH-2.0-old\r\n").await;
    assert_eq!(resp, b"[SSH]SSH-2.0-old\r\n");
    assert_eq!(mgr.rule_status("r1").await.counters.route_hits, [1]);

    // Change listen_ports -> restarts rule, frees old port, binds new port, resets counters.
    rule.listen_ports = port_new.to_string();
    mgr.apply(FileConfig {
        settings: Settings::default(),
        rules: vec![rule],
    })
    .await
    .unwrap();

    assert!(
        TcpStream::connect(("127.0.0.1", port_old)).await.is_err(),
        "old port must be closed after restart"
    );
    assert_eq!(mgr.rule_status("r1").await.counters.route_hits, [0]);

    let resp_new = send_and_read(port_new, b"SSH-2.0-new\r\n").await;
    assert_eq!(resp_new, b"[SSH]SSH-2.0-new\r\n");
    assert_eq!(mgr.rule_status("r1").await.counters.route_hits, [1]);
    mgr.shutdown().await;
}

#[tokio::test]
async fn partial_port_failure_keeps_others() {
    let (ssh_port, _) = spawn_tagged_backend("SSH").await;
    // Occupy port_busy so binding it fails.
    let blocker = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port_busy = blocker.local_addr().unwrap().port();
    let port_ok = free_v4_port();

    let mut rule = base_rule(
        "r1",
        port_ok,
        vec![route("ssh", Protocol::Ssh, &[], ssh_port)],
    );
    rule.listen_ports = format!("{port_busy},{port_ok}");

    let mgr = Manager::new(
        FileConfig {
            settings: Settings::default(),
            rules: vec![rule],
        },
        Deps::default(),
    );
    mgr.start().await.unwrap();

    let status = mgr.rule_status("r1").await;
    assert!(
        status.listening,
        "rule must stay listening on healthy ports"
    );
    assert_eq!(status.listen_errors.len(), 1);
    assert!(status.listen_errors[0].contains(&port_busy.to_string()));

    // Healthy port still serves traffic cleanly.
    let resp = send_and_read(port_ok, b"SSH-2.0-healthy\r\n").await;
    assert_eq!(resp, b"[SSH]SSH-2.0-healthy\r\n");

    drop(blocker);
    mgr.shutdown().await;
}

#[tokio::test]
async fn haproxy_replacement_scenario() {
    let (app_port, _) = spawn_tagged_backend("APP_TLS").await;
    let (api_port, _) = spawn_tagged_backend("API_TLS").await;
    let (corp_port, _) = spawn_tagged_backend("CORP_WILD").await;
    let (http_port, _) = spawn_tagged_backend("WEB_HTTP").await;
    let (def_port, _) = spawn_tagged_backend("FALLBACK").await;
    let listen_port = free_v4_port();

    let mut r_app = route("app", Protocol::Tls, &["app.example.com"], app_port);
    r_app.proxy_protocol = ProxyProtocol::V2;
    let mut r_api = route("api", Protocol::Tls, &["api.example.com"], api_port);
    r_api.proxy_protocol = ProxyProtocol::V2;
    let r_corp = route("corp", Protocol::Tls, &["*.corp.example.com"], corp_port);
    let r_http = route("http", Protocol::Http, &["app.example.com"], http_port);

    let mut rule = base_rule("haproxy", listen_port, vec![r_app, r_api, r_corp, r_http]);
    rule.target_addresses = vec!["127.0.0.1".into()];
    rule.target_ports = def_port.to_string();

    let mgr = Manager::new(
        FileConfig {
            settings: Settings::default(),
            rules: vec![rule],
        },
        Deps::default(),
    );
    mgr.start().await.unwrap();

    // TLS SNI app.example.com -> APP_TLS with PROXY v2.
    let h_app = build_client_hello(b"app.example.com", &[b"h2"]);
    let resp_app = send_and_read(listen_port, &h_app).await;
    assert!(resp_app.starts_with(b"[APP_TLS]\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c"));
    assert_eq!(&resp_app[b"[APP_TLS]".len() + 28..], h_app.as_slice());

    // TLS SNI api.example.com -> API_TLS with PROXY v2.
    let h_api = build_client_hello(b"api.example.com", &[b"h2"]);
    let resp_api = send_and_read(listen_port, &h_api).await;
    assert!(resp_api.starts_with(b"[API_TLS]\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c"));

    // Wildcard TLS SNI git.dev.corp.example.com -> CORP_WILD.
    let h_corp = build_client_hello(b"git.dev.corp.example.com", &[]);
    let resp_corp = send_and_read(listen_port, &h_corp).await;
    assert!(resp_corp.starts_with(b"[CORP_WILD]"));
    assert_eq!(&resp_corp[b"[CORP_WILD]".len()..], h_corp.as_slice());

    // Plain HTTP Host app.example.com -> WEB_HTTP.
    let req = b"GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n";
    let resp_http = send_and_read(listen_port, req).await;
    assert_eq!(resp_http, [b"[WEB_HTTP]".as_slice(), req].concat());

    // Unknown SNI -> FALLBACK.
    let h_other = build_client_hello(b"unknown.org", &[]);
    let resp_other = send_and_read(listen_port, &h_other).await;
    assert!(resp_other.starts_with(b"[FALLBACK]"));

    let status = mgr.rule_status("haproxy").await;
    assert_eq!(status.counters.route_hits, [1, 1, 1, 1]);
    assert_eq!(status.counters.default_hits, 1);
    mgr.shutdown().await;
}

#[tokio::test]
async fn sslh_replacement_scenario() {
    let (ssh_port, _) = spawn_tagged_backend("SSH").await;
    let (ovpn_port, _) = spawn_tagged_backend("OPENVPN").await;
    let (tls_port, _) = spawn_tagged_backend("TLS").await;
    let vnc_port = spawn_server_first_backend(b"RFB 003.008\n").await;
    let listen_port = free_v4_port();

    let mut rule = base_rule(
        "sslh",
        listen_port,
        vec![
            route("ssh", Protocol::Ssh, &[], ssh_port),
            route("openvpn", Protocol::OpenVpn, &[], ovpn_port),
            route("tls", Protocol::Tls, &[], tls_port),
            route("vnc", Protocol::Timeout, &[], vnc_port),
        ],
    );
    rule.sniff_timeout = 0.2;

    let mgr = Manager::new(
        FileConfig {
            settings: Settings::default(),
            rules: vec![rule],
        },
        Deps::default(),
    );
    mgr.start().await.unwrap();

    // 1. SSH
    assert_eq!(
        send_and_read(listen_port, b"SSH-2.0-OpenSSH_9.7\r\n").await,
        b"[SSH]SSH-2.0-OpenSSH_9.7\r\n"
    );
    // 2. OpenVPN
    let ovpn = vec![0x00, 0x0E, 0x38, 0x11, 0x22, 0x33, 0x44];
    let resp_ovpn = send_and_read(listen_port, &ovpn).await;
    assert_eq!(resp_ovpn, [b"[OPENVPN]".as_slice(), &ovpn].concat());
    // 3. TLS
    let hello = build_client_hello(b"any.example", &[]);
    let resp_tls = send_and_read(listen_port, &hello).await;
    assert_eq!(resp_tls, [b"[TLS]".as_slice(), &hello].concat());
    // 4. Timeout (server-speaks-first)
    let mut sock = TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .unwrap();
    let mut banner = [0u8; 12];
    sock.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"RFB 003.008\n");
    drop(sock);

    let status = mgr.rule_status("sslh").await;
    assert_eq!(status.counters.route_hits, [1, 1, 1, 1]);
    mgr.shutdown().await;
}

#[tokio::test]
async fn http_keepalive_sniffed_once_and_stop_does_not_wait_for_sniff() {
    let (a_port, _) = spawn_tagged_backend("HOST_A").await;
    let (b_port, _) = spawn_tagged_backend("HOST_B").await;
    let listen_port = free_v4_port();

    let mut rule = base_rule(
        "ka",
        listen_port,
        vec![
            route("a", Protocol::Http, &["a.example"], a_port),
            route("b", Protocol::Http, &["b.example"], b_port),
        ],
    );
    rule.sniff_timeout = 30.0; // deliberately long to verify stop doesn't wait!

    let mgr = Manager::new(
        FileConfig {
            settings: Settings::default(),
            rules: vec![rule],
        },
        Deps::default(),
    );
    mgr.start().await.unwrap();

    // Send request 1 for a.example, then request 2 for b.example on the SAME TCP connection.
    // Because sniffing happens only once per connection, request 2 goes to HOST_A too.
    let mut sock = TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .unwrap();
    let req1 = b"GET /1 HTTP/1.1\r\nHost: a.example\r\n\r\n";
    sock.write_all(req1).await.unwrap();
    let mut buf1 = vec![0u8; b"[HOST_A]".len() + req1.len()];
    sock.read_exact(&mut buf1).await.unwrap();
    assert!(buf1.starts_with(b"[HOST_A]"));

    let req2 = b"GET /2 HTTP/1.1\r\nHost: b.example\r\n\r\n";
    sock.write_all(req2).await.unwrap();
    let mut buf2 = vec![0u8; req2.len()];
    sock.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, req2);
    drop(sock);

    assert_eq!(mgr.rule_status("ka").await.counters.route_hits, [1, 0]);

    // Open a silent connection waiting in the 30s sniff window, then shutdown:
    // shutdown MUST complete promptly without waiting 30s!
    let _silent = TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    let start = Instant::now();
    mgr.shutdown().await;
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "shutdown waited for sniff timeout: {:?}",
        start.elapsed()
    );
}

// ---------------------------------------------------------------------------
// Management API, OpenPorts, Summary, Metrics & ConfigStore persistence
// ---------------------------------------------------------------------------

async fn http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (StatusCode, String, String) {
    let mut sock = TcpStream::connect(addr).await.expect("connect api");
    let body_bytes = body.unwrap_or("").as_bytes();
    let _body_check = Full::new(axum::body::Bytes::copy_from_slice(body_bytes));
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
        body_bytes.len()
    );
    if body.is_some() {
        req.push_str("Content-Type: application/json\r\n");
    }
    req.push_str("\r\n");
    sock.write_all(req.as_bytes()).await.unwrap();
    if !body_bytes.is_empty() {
        sock.write_all(body_bytes).await.unwrap();
    }
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8(raw).expect("utf8 http response");
    let (head, body_out) = text.split_once("\r\n\r\n").expect("http split");
    let status_code: u16 = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (
        StatusCode::from_u16(status_code).unwrap(),
        head.to_owned(),
        body_out.to_owned(),
    )
}

#[tokio::test]
async fn management_api_crud_batch_settings_metrics_and_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let store = ConfigStore::open(dir.path()).unwrap();
    let open_ports = OpenPorts::new();
    let knock = Arc::new(MockKnock::default());

    let module = Module::new(
        Arc::clone(&store),
        Deps {
            knock: Some(knock),
            open_ports: Some(Arc::clone(&open_ports)),
            ..Deps::default()
        },
    )
    .unwrap();

    let manager = module.manager();
    let app = module.router();

    let (drain_tx, drain_rx) = watch::channel(false);
    let mod_task = tokio::spawn(async move {
        use fg_core::module::Module as _;
        module.run(drain_rx).await.unwrap();
    });

    // Serve the axum router on a real loopback port.
    let api_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = api_listener.local_addr().unwrap();
    let api_task = tokio::spawn(async move {
        let _ = axum::serve(api_listener, app).await;
    });

    let (ssh_port, _) = spawn_tagged_backend("API_SSH").await;
    let p1 = free_v4_port();
    let p2 = free_v4_port();

    // 1. POST /api/protoroute/rules -> creates rule with generated 12-char hex key.
    let create_body = serde_json::json!({
        "name": "primary",
        "enable": true,
        "protocols": ["tcp4"],
        "listenAddress": "127.0.0.1",
        "listenPorts": p1.to_string(),
        "routes": [
            { "name": "ssh", "protocol": "ssh", "targetAddresses": ["127.0.0.1"], "targetPort": ssh_port },
            { "name": "spa", "protocol": "spa" }
        ]
    });
    let (status, headers, body) = http_request(
        api_addr,
        "POST",
        "/api/protoroute/rules",
        Some(&create_body.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store")
    );
    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    let key1 = created["key"].as_str().unwrap().to_owned();
    assert_eq!(key1.len(), 12);
    assert_eq!(created["listening"], true);

    // OpenPorts and spa_ports reflect the newly started listener!
    assert!(open_ports.is_open(Proto::Tcp, p1));
    assert_eq!(manager.spa_ports().await, vec![p1]);

    // Traffic flows through the rule created via the HTTP API.
    assert_eq!(
        send_and_read(p1, b"SSH-2.0-via-api\r\n").await,
        b"[API_SSH]SSH-2.0-via-api\r\n"
    );

    // 2. POST /api/protoroute/rules/{key}/copy -> creates disabled copy.
    let (status, _, body) = http_request(
        api_addr,
        "POST",
        &format!("/api/protoroute/rules/{key1}/copy"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let copied: serde_json::Value = serde_json::from_str(&body).unwrap();
    let key2 = copied["key"].as_str().unwrap().to_owned();
    assert_ne!(key1, key2);
    assert_eq!(copied["enable"], false);

    // 3. PUT /api/protoroute/rules/{key2} -> change listen port to p2 & rename.
    let mut updated_rule = copied.clone();
    updated_rule["name"] = serde_json::json!("secondary");
    updated_rule["listenPorts"] = serde_json::json!(p2.to_string());
    // Strip read-only view fields before PUT.
    let put_payload = serde_json::json!({
        "name": "secondary",
        "enable": false,
        "protocols": ["tcp4"],
        "listenAddress": "127.0.0.1",
        "listenPorts": p2.to_string(),
        "routes": [
            { "name": "ssh", "protocol": "ssh", "targetAddresses": ["127.0.0.1"], "targetPort": ssh_port }
        ]
    });
    let (status, _, body) = http_request(
        api_addr,
        "PUT",
        &format!("/api/protoroute/rules/{key2}"),
        Some(&put_payload.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // 4. PUT /api/protoroute/rules/{key2}/enable
    let (status, _, body) = http_request(
        api_addr,
        "PUT",
        &format!("/api/protoroute/rules/{key2}/enable"),
        Some(r#"{"enable":true}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(open_ports.is_open(Proto::Tcp, p2));

    // 5. PUT /api/protoroute/rules-order, rules-group, rules-enable
    let (status, _, body) = http_request(
        api_addr,
        "PUT",
        "/api/protoroute/rules-order",
        Some(&serde_json::json!({"keys": [&key2, &key1]}).to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ordered: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(ordered[0]["key"], key2);
    assert_eq!(ordered[1]["key"], key1);

    let (status, _, _) = http_request(
        api_addr,
        "PUT",
        "/api/protoroute/rules-group",
        Some(&serde_json::json!({"keys": [&key1, &key2], "group": "edge"}).to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 6. Summary & Prometheus metrics before settings change that alters connection limits.
    let sum = fg_protoroute::routes::summary(&manager).await;
    assert_eq!(sum.total_rules, 2);
    assert_eq!(sum.enabled_rules, 2);
    assert_eq!(sum.total_hits, 1);

    let samples = fg_protoroute::routes::metrics(&manager).await;
    let prom = write_text(&samples);
    assert!(
        prom.contains("ferrumgate_protoroute_rules_total 2"),
        "{prom}"
    );
    assert!(
        prom.contains("ferrumgate_protoroute_route_hits_total")
            && prom.contains("protocol=\"ssh\"")
            && prom.contains("} 1\n"),
        "{prom}"
    );

    // 7. GET & PUT /api/protoroute/settings: changing dialTimeout only hot-updates
    // and preserves hit counts; changing defaultMaxConnections restarts rules inheriting it.
    let (status, _, body) = http_request(
        api_addr,
        "PUT",
        "/api/protoroute/settings",
        Some(r#"{"enable":true,"defaultMaxConnections":0,"dialTimeout":3}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fg_protoroute::routes::summary(&manager).await.total_hits, 1);

    let (status, _, body) = http_request(
        api_addr,
        "PUT",
        "/api/protoroute/settings",
        Some(r#"{"enable":true,"defaultMaxConnections":128,"dialTimeout":3}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let settings: Settings = serde_json::from_str(&body).unwrap();
    assert_eq!(settings.default_max_connections, 128);
    assert_eq!(settings.dial_timeout, 3);
    assert_eq!(fg_protoroute::routes::summary(&manager).await.total_hits, 0);

    let (status, _, body) = http_request(api_addr, "GET", "/api/protoroute/settings", None).await;
    assert_eq!(status, StatusCode::OK);
    let got_settings: Settings = serde_json::from_str(&body).unwrap();
    assert_eq!(got_settings, settings);

    // 8. Batch disable & batch delete + single delete + 404 check
    let (status, _, _) = http_request(
        api_addr,
        "PUT",
        "/api/protoroute/rules-enable",
        Some(&serde_json::json!({"keys": [&key2], "enable": false}).to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!open_ports.is_open(Proto::Tcp, p2));

    let (status, _, body) = http_request(
        api_addr,
        "POST",
        "/api/protoroute/rules-delete",
        Some(&serde_json::json!({"keys": [&key2]}).to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Config persisted to protoroute.json and reloads cleanly.
    let reloaded = store
        .load::<FileConfig>(fg_protoroute::routes::CONFIG_NAME)
        .unwrap();
    match reloaded {
        fg_config::Loaded::Found(cfg) => {
            assert_eq!(cfg.rules.len(), 1);
            assert_eq!(cfg.rules[0].key, key1);
            assert_eq!(cfg.rules[0].group, "edge");
        }
        fg_config::Loaded::Missing => panic!("protoroute.json should exist"),
    }

    let (status, _, _) = http_request(
        api_addr,
        "DELETE",
        &format!("/api/protoroute/rules/{key1}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, _) = http_request(
        api_addr,
        "DELETE",
        &format!("/api/protoroute/rules/{key1}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Drain module via watch channel -> clears open_ports and exits cleanly.
    let _ = drain_tx.send(true);
    mod_task.await.unwrap();
    api_task.abort();
    assert!(!open_ports.is_open(Proto::Tcp, p1));
}
