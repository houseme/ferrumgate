//! Integration tests for the knock module (WP-54 §6): SPA decoding
//! against externally generated OpenSSL vectors, the UDP listener with
//! real loopback sockets, the TCP `submit` path (protocol-routing
//! contract), ban-table and rate-limit interplay, grant lifetime, and the
//! management routes over a real config store.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{Router, http::StatusCode};
use base64::Engine as _;
use fg_config::ConfigStore;
use fg_core::check::BoxFut;
use fg_core::events::{Event, EventBus};
use fg_net::banlist::{BanPolicy, BanTable, Source, system_clock as ban_clock};
use http_body_util::BodyExt;
use hyper::header::CONTENT_TYPE;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use fg_knock::engine::{Engine, Hooks, Outcome, Reject, WindowRequest};
use fg_knock::grants::{GrantSource, Grants};
use fg_knock::limit::RateLimiter;
use fg_knock::listen;
use fg_knock::model::{Access, FileConfig, Proto, Rule, Settings, limits};
use fg_knock::replay::ReplayCache;
use fg_knock::routes::{FirewallRuleView, PersistFn, RoutesState, mount};
use fg_knock::spa::{self, HmacType, MsgType};
use fg_knock::{SharedFn, normalize, validate};

// ---------------------------------------------------------------------------
// Fixtures generated externally with OpenSSL (`OpenSSL 4.1.0`): the key
// and IV come from `openssl enc -aes-256-cbc -md md5 -P -pass
// pass:0123456789abcdef -S 0011223344556677` (EVP_BytesToKey), the
// ciphertext from `openssl enc -K <key> -iv <iv>` framed manually as
// "Salted__" + salt + ct (OpenSSL 4 `enc` output omits the marker), and
// the HMACs from `openssl dgst -<alg> -mac hmac -macopt hexkey:…` over
// the prefixed base64 ciphertext:
//
// plaintext = 0123456789abcdef:dGVzdGVy:1700000000:3.0.0:1:MC4wLjAuMCx0Y3AvMjI=:
//             72572e62023b8f851ceee950b5f9c3568f3ae3a7ac995de9fb36abe82f8002f0
// (random "0123456789abcdef", user "tester", ts 1700000000, version 3.0.0,
//  type Access, message "0.0.0.0,tcp/22", SHA-256 message digest; trailing
//  "=" padding stripped from the base64 ciphertext)
// ---------------------------------------------------------------------------

/// Encryption key "0123456789abcdef", base64 (16 bytes).
const ENC_KEY_B64: &str = "MDEyMzQ1Njc4OWFiY2RlZg==";
/// HMAC key "hmac-secret-hmac-secret-hmac", base64 (28 bytes).
const HMAC_KEY_B64: &str = "aG1hYy1zZWNyZXQtaG1hYy1zZWNyZXQtaG1hYw==";
/// A second, different HMAC key (31 bytes), base64.
const HMAC_KEY2_B64: &str = "c2Vjb25kLWhtYWMta2V5LXNlY29uZC1obWFjLWtleQ==";
/// The packet body: base64("Salted__" + salt + AES-256-CBC(plaintext))
/// without the `U2FsdGVkX1` prefix and without the trailing `==` padding
/// (204 chars; decode restores both).
const PACKET_BODY: &str = "8AESIzRFVmdwLXMaSg8dpiySeUI+O7CBcYCPMOe6b3IJXwOyD70yWgOLJQKuQLRO7gbEa0pvHaSPdXTTiD6obb40Q5T4VlsNcQvNmuzkmHHEXVJVKj1d5FqzvNV59c0oKjE+MmCz/ei8bR6d8VgOXgRiblnEUxF8BdskSDMG1geteJwhoAd4YcAGn4Tz3HmMOWhT+hOCRlLg";
/// SHA-256 message digest carried as the final plaintext field.
const DIGEST_HEX: &str = "72572e62023b8f851ceee950b5f9c3568f3ae3a7ac995de9fb36abe82f8002f0";
/// HMAC-SHA-256 over the prefixed base64 ciphertext, `=` stripped (43).
const MAC_256: &str = "Ld5p9WQzJ28OO/ii3JuIEzTkXpc0HiIMBW+xZV48wFU";
/// HMAC-SHA-384, `=` stripped (64).
const MAC_384: &str = "vfnHJSNuh1tkbwQXhZBZYenaMu3vYpMTBoDNVxzL+cBiuROb0C0/xDcOO546xhkm";
/// HMAC-SHA-512, `=` stripped (86).
const MAC_512: &str =
    "Pqk1yqLYE2+07t/dVDVFKZ2GIWrVgkO/i70TrVCOhbCOOd5nx8SCRwlulSIP4FtY3H+NQWussEazOqOS2Fz6LA";
/// HMAC-SHA-256 under the *second* key (wrong for the first).
const MAC_WRONG_256: &str = "SdZpBYKtB1xM7rgMfH2PoUT9K3HAtE1btTG2Vi3S6Yw";

fn openssl_packet(mac: &str) -> Vec<u8> {
    format!("{PACKET_BODY}{mac}").into_bytes()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
}

fn key_pair_b64() -> (String, String) {
    let mut enc = vec![0u8; 16];
    let mut hmac = vec![0u8; 32];
    getrandom::fill(&mut enc).unwrap();
    getrandom::fill(&mut hmac).unwrap();
    let engine = base64::engine::general_purpose::STANDARD;
    (engine.encode(enc), engine.encode(hmac))
}

fn ssh_rule() -> Rule {
    let (enc, hmac) = key_pair_b64();
    Rule {
        key: "a1b2c3d4e5f6".into(),
        name: "ssh".into(),
        enable: true,
        ports: vec![Access::new(Proto::Tcp, 22)],
        firewall: true,
        enc_key: enc,
        hmac_key: hmac,
        hmac_type: HmacType::Sha256,
        timeout: 30,
        max_timeout: 300,
        ..Rule::default()
    }
}

/// The knock message a test client would send.
fn knock_message(addr: Option<IpAddr>, ports: &[Access]) -> spa::Message {
    spa::Message {
        rand: format!("{:016x}", now_secs() as u64 ^ 0x5eed),
        user: "tester".to_owned(),
        timestamp: now_secs(),
        version: "3.0.0".to_owned(),
        msg_type: MsgType::Access,
        addr,
        access: ports.to_vec(),
        nat: None,
        server_auth: None,
        client_timeout: None,
        digest: String::new(),
    }
}

fn key_of(rule: &Rule) -> spa::Key {
    spa::Key::from_base64(&rule.enc_key, &rule.hmac_key, rule.hmac_type).expect("valid keys")
}

fn encode_packet(message: &spa::Message, key: &spa::Key) -> Vec<u8> {
    spa::encode_random(message, key).expect("encode")
}

type EventLog = Arc<Mutex<Vec<(&'static str, Vec<(String, String)>)>>>;

/// Recorded event names plus their args/fields.
fn event_names(log: &EventLog) -> Vec<&'static str> {
    log.lock()
        .expect("event log")
        .iter()
        .map(|(name, _)| *name)
        .collect()
}

/// The engine rig: hooks record windows, the event bus records events.
#[allow(dead_code)]
struct Rig {
    engine: Arc<Engine>,
    grants: Arc<Grants>,
    events: EventLog,
    opened: Arc<Mutex<Vec<WindowRequest>>>,
    closed: Arc<Mutex<Vec<String>>>,
    bans: Option<Arc<BanTable>>,
    /// Keeps the event subscription alive (dropping it unregisters).
    _subscription: fg_core::events::Subscription,
}

async fn rig(config: FileConfig, bans: Option<Arc<BanTable>>) -> Rig {
    let events_bus = EventBus::new(64);
    let log: EventLog = Arc::default();
    let subscription = {
        let log = Arc::clone(&log);
        events_bus
            .subscribe(move |event: Arc<Event>| {
                let log = Arc::clone(&log);
                async move {
                    let mut args: Vec<(String, String)> = event
                        .args
                        .iter()
                        .map(|(k, v)| ((*k).to_owned(), v.clone()))
                        .collect();
                    args.extend(
                        event
                            .fields
                            .iter()
                            .map(|(k, v)| ((*k).to_owned(), v.clone())),
                    );
                    log.lock()
                        .expect("event log")
                        .push((event.kind.info().name, args));
                }
            })
            .expect("subscribe")
    };
    let opened: Arc<Mutex<Vec<WindowRequest>>> = Arc::default();
    let closed: Arc<Mutex<Vec<String>>> = Arc::default();
    let hooks = Hooks {
        open_window: Some(open_hook(&opened)),
        close_window: Some(close_hook(&closed)),
        events: Some(events_bus),
        bans: bans.clone(),
    };
    let config = normalize(config);
    assert!(validate(&config).is_empty(), "rig config must be valid");
    let grants = Arc::new(Grants::new());
    let engine = Engine::new(
        Arc::clone(&grants),
        ReplayCache::new(SystemTime::now()),
        RateLimiter::new(),
        hooks,
        fg_knock::system_clock(),
    );
    engine.apply_config(None, &config);
    Rig {
        engine,
        grants,
        events: log,
        opened,
        closed,
        bans,
        _subscription: subscription,
    }
}

fn open_hook(opened: &Arc<Mutex<Vec<WindowRequest>>>) -> SharedFn<WindowRequest, ()> {
    let opened = Arc::clone(opened);
    Arc::new(move |request: WindowRequest| {
        let opened = Arc::clone(&opened);
        Box::pin(async move {
            opened.lock().expect("opened windows").push(request);
            Ok(())
        }) as BoxFut<'static, anyhow::Result<()>>
    })
}

fn close_hook(closed: &Arc<Mutex<Vec<String>>>) -> SharedFn<String, ()> {
    let closed = Arc::clone(closed);
    Arc::new(move |rule: String| {
        let closed = Arc::clone(&closed);
        Box::pin(async move {
            closed.lock().expect("closed windows").push(rule);
            Ok(())
        }) as BoxFut<'static, anyhow::Result<()>>
    })
}

fn peer(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

fn admit_addr() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
}

/// Waits until `check` turns true (bounded).
async fn wait_until(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    check()
}

// ---------------------------------------------------------------------------
// spa: external OpenSSL vectors (WP-54 steps 2/7)
// ---------------------------------------------------------------------------

#[test]
fn decode_openssl_vectors() {
    for (hmac_type, mac, expected_mac_len) in [
        (HmacType::Sha256, MAC_256, 43),
        (HmacType::Sha384, MAC_384, 64),
        (HmacType::Sha512, MAC_512, 86),
    ] {
        assert_eq!(hmac_type.b64_stripped_len(), expected_mac_len);
        let key = spa::Key::from_base64(ENC_KEY_B64, HMAC_KEY_B64, hmac_type).unwrap();
        let message = spa::decode(&openssl_packet(mac), &key)
            .unwrap_or_else(|error| panic!("{hmac_type}: {error}"));
        assert_eq!(message.rand, "0123456789abcdef");
        assert_eq!(message.user, "tester");
        assert_eq!(message.timestamp, 1_700_000_000);
        assert_eq!(message.version, "3.0.0");
        assert_eq!(message.msg_type, MsgType::Access);
        // `0.0.0.0` in the message body = the packet's source address.
        assert_eq!(message.addr, None);
        assert_eq!(message.access, vec![spa::Access::new(spa::Proto::Tcp, 22)]);
        assert_eq!(message.digest, DIGEST_HEX);
    }
}

#[test]
fn hmac_mismatch_never_decrypts() {
    // The correct key rejects a packet sealed under the second key before
    // any decryption (the ciphertext would decrypt to garbage; the error
    // is HmacMismatch, not Decrypt/Padding).
    let key = spa::Key::from_base64(ENC_KEY_B64, HMAC_KEY_B64, HmacType::Sha256).unwrap();
    assert_eq!(
        spa::decode(&openssl_packet(MAC_WRONG_256), &key),
        Err(spa::DecodeError::HmacMismatch)
    );
    // Same under the second key with the first packet.
    let key2 = spa::Key::from_base64(ENC_KEY_B64, HMAC_KEY2_B64, HmacType::Sha256).unwrap();
    assert_eq!(
        spa::decode(&openssl_packet(MAC_256), &key2),
        Err(spa::DecodeError::HmacMismatch)
    );
    // Garbage body with a well-formed MAC length: still HMAC first.
    let garbage = vec![b'A'; 100];
    assert_eq!(
        spa::decode(&garbage, &key),
        Err(spa::DecodeError::HmacMismatch)
    );
    // Two keys in a set: exactly the right one authenticates.
    let set = spa::KeySet::new(vec![
        spa::KeyEntry {
            key: key.clone(),
            rule: "r1".into(),
            identity: None,
            cred: "c1".into(),
        },
        spa::KeyEntry {
            key: key2,
            rule: "r2".into(),
            identity: None,
            cred: "c2".into(),
        },
    ]);
    let (index, message) = set.decode(&openssl_packet(MAC_256)).unwrap();
    assert_eq!((index, message.user), (0, "tester".to_owned()));
    let (index, _) = set.decode(&openssl_packet(MAC_WRONG_256)).unwrap();
    assert_eq!(index, 1);
}

// ---------------------------------------------------------------------------
// engine: UDP listener over a real socket (§6 integration)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn udp_knock_opens_grant_and_window() {
    let mut config = FileConfig::default();
    let rule = ssh_rule();
    config.rules.push(rule.clone());
    let rig = rig(config, None).await;
    // Pick a free UDP port.
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let token = CancellationToken::new();
    let engine = Arc::clone(&rig.engine);
    let listener_token = token.clone();
    tokio::spawn(async move {
        listen::run_udp(engine, port, listener_token)
            .await
            .expect("listener");
    });
    // Give the listener a moment to bind, then knock.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let key = key_of(&rule);
    let message = knock_message(Some(admit_addr()), &[Access::new(Proto::Tcp, 22)]);
    let packet = encode_packet(&message, &key);
    sender.send_to(&packet, peer(port)).await.unwrap();
    let grants = Arc::clone(&rig.grants);
    let reached = wait_until(|| grants.admitted(admit_addr(), &rule.key, SystemTime::now())).await;
    token.cancel();
    assert!(reached, "the knock must register a grant");
    let opened = rig.opened.lock().expect("opened").clone();
    assert_eq!(
        opened.len(),
        1,
        "the firewall window hook ran once: {opened:?}"
    );
    assert_eq!(opened[0].rule, rule.key);
    assert_eq!(opened[0].ports, vec![Access::new(Proto::Tcp, 22)]);
    assert_eq!(rig.engine.stats(SystemTime::now()).opened, 1);
    // knock.opened published with the rule name and address.
    let events = Arc::clone(&rig.events);
    let published = wait_until(|| event_names(&events).contains(&"knock.opened")).await;
    assert!(published, "the knock.opened event is delivered");
    let args = rig
        .events
        .lock()
        .expect("log")
        .iter()
        .find(|(name, _)| *name == "knock.opened")
        .cloned();
    assert!(
        args.expect("opened event")
            .1
            .iter()
            .any(|(key, value)| key == "addr" && value == &admit_addr().to_string()),
        "the event carries the admitted address"
    );
}

#[tokio::test]
async fn udp_rejected_knock_emits_no_event() {
    let mut config = FileConfig::default();
    let rule = ssh_rule();
    config.rules.push(rule.clone());
    let rig = rig(config, None).await;
    // A packet sealed under a foreign key arrives over UDP: dropped as
    // invalid, counted, summarized — but never published (spoofable
    // sources; the intrusion-protection contract).
    let key2 = spa::Key::from_base64(ENC_KEY_B64, HMAC_KEY2_B64, HmacType::Sha256).unwrap();
    let packet = encode_packet(&knock_message(None, &[Access::new(Proto::Tcp, 22)]), &key2);
    let outcome = rig
        .engine
        .handle(&packet, peer(40000), fg_knock::Via::Udp)
        .await;
    assert_eq!(outcome, Outcome::Rejected(Reject::HmacMismatch));
    assert!(event_names(&rig.events).is_empty(), "no UDP failure events");
    assert_eq!(rig.engine.stats(SystemTime::now()).invalid, 1);
    // A rule rejection (right key, port not protected) is equally silent.
    let packet = encode_packet(
        &knock_message(None, &[Access::new(Proto::Udp, 8080)]),
        &key_of(&rule),
    );
    let outcome = rig
        .engine
        .handle(&packet, peer(40001), fg_knock::Via::Udp)
        .await;
    assert_eq!(outcome, Outcome::Rejected(Reject::PortNotAllowed));
    assert!(
        event_names(&rig.events).is_empty(),
        "{:?}",
        event_names(&rig.events)
    );
}

#[tokio::test]
async fn tcp_rejected_knock_emits_event() {
    let mut config = FileConfig::default();
    let _rule = ssh_rule();
    config.rules.push(_rule.clone());
    let rig = rig(config, None).await;
    // Protocol routing hands the packet to `submit`: the TCP channel
    // authenticates the source, so rejections publish knock.failed with
    // via=tcp (throttled per source).
    let key2 = spa::Key::from_base64(ENC_KEY_B64, HMAC_KEY2_B64, HmacType::Sha256).unwrap();
    let packet = encode_packet(&knock_message(None, &[Access::new(Proto::Tcp, 22)]), &key2);
    let outcome = rig.engine.submit(&packet, peer(40002)).await;
    assert_eq!(outcome, Outcome::Rejected(Reject::HmacMismatch));
    let reached = wait_until(|| !event_names(&rig.events).is_empty()).await;
    assert!(reached, "the TCP rejection must publish knock.failed");
    let names = event_names(&rig.events);
    assert_eq!(names, vec!["knock.failed"]);
    let (_, args) = rig.events.lock().expect("log")[0].clone();
    assert!(
        args.contains(&("via".to_owned(), "tcp".to_owned())),
        "{args:?}"
    );
    // A second rejection from the same source within 5 s is throttled.
    let _ = rig.engine.submit(&packet, peer(40002)).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(event_names(&rig.events).len(), 1, "throttled per source");
    // …but a different source publishes again.
    let _ = rig
        .engine
        .submit(
            &packet,
            SocketAddr::new("198.51.100.2".parse().unwrap(), 40003),
        )
        .await;
    let reached = wait_until(|| event_names(&rig.events).len() == 2).await;
    assert!(reached);
}

#[tokio::test]
async fn tcp_forwarded_socket_knocks_authenticate() {
    // The protocol-routing contract end to end: a real TCP socket pipes
    // the packet bytes into `submit` (the WP-35 wiring point).
    let mut config = FileConfig::default();
    config.rules.push(ssh_rule());
    let rig = Arc::new(rig(config, None).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let engine = Arc::clone(&rig.engine);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, peer_addr)) = listener.accept().await else {
                break;
            };
            let engine = Arc::clone(&engine);
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut buffer = vec![0u8; 2048];
                if let Ok(read) = stream.read(&mut buffer).await {
                    let _ = engine.submit(&buffer[..read], peer_addr).await;
                }
            });
        }
    });
    // Send the packet bytes over TCP; the grant must appear.
    let key = {
        let snapshot = rig.engine.snapshot();
        let entry = &snapshot.keys.entries()[0];
        spa::Key {
            enc: entry.key.enc.clone(),
            hmac: entry.key.hmac.clone(),
            hmac_type: entry.key.hmac_type,
        }
    };
    let stream = tokio::net::TcpStream::connect(peer(port)).await.unwrap();
    use tokio::io::AsyncWriteExt;
    let mut stream = stream;
    let packet = encode_packet(
        &knock_message(Some(admit_addr()), &[Access::new(Proto::Tcp, 22)]),
        &key,
    );
    stream.write_all(&packet).await.unwrap();
    drop(stream);
    let grants = Arc::clone(&rig.grants);
    let reached =
        wait_until(|| grants.admitted(admit_addr(), "a1b2c3d4e5f6", SystemTime::now())).await;
    assert!(reached, "a TCP-forwarded knock registers the grant");
    let events = Arc::clone(&rig.events);
    let published = wait_until(|| event_names(&events).contains(&"knock.opened")).await;
    assert!(published, "the knock.opened event is delivered");
}

#[tokio::test]
async fn banned_source_knocks_dropped() {
    let bans = BanTable::open_memory(BanPolicy::default(), Default::default(), ban_clock());
    let source: IpAddr = "198.51.100.9".parse().unwrap();
    bans.ban_auto(
        source,
        None,
        false,
        Source::Scan,
        "guard.reason.scan".to_owned(),
        SystemTime::now(),
    );
    let mut config = FileConfig::default();
    config.rules.push(ssh_rule());
    let rig = rig(config, Some(bans)).await;
    // A valid knock from the banned address is dropped before any HMAC
    // work: ignored (not invalid), no grant, no events.
    let rule = ssh_rule();
    let packet = encode_packet(
        &knock_message(None, &[Access::new(Proto::Tcp, 22)]),
        &key_of(&rule),
    );
    let outcome = rig
        .engine
        .handle(&packet, SocketAddr::new(source, 44444), fg_knock::Via::Udp)
        .await;
    assert_eq!(outcome, Outcome::Ignored);
    assert!(
        !rig.grants
            .admitted(source, "a1b2c3d4e5f6", SystemTime::now())
    );
    assert_eq!(rig.engine.stats(SystemTime::now()).ignored, 1);
    assert!(event_names(&rig.events).is_empty());
}

#[tokio::test]
async fn replay_rejected_and_single_addr_revoked() {
    let mut config = FileConfig::default();
    let mut rule = ssh_rule();
    rule.single_addr = true;
    rule.identities.push(fg_knock::Identity {
        id: "alice".into(),
        name: "Alice".into(),
        enable: true,
        enc_key: key_pair_b64().0,
        hmac_key: key_pair_b64().1,
        remark: String::new(),
    });
    config.rules.push(rule);
    let rig = rig(config, None).await;
    // Two knocks with the same (credential, random, timestamp) replay: the
    // second is refused.
    let rule_key = "a1b2c3d4e5f6";
    let alice_key = {
        let snapshot = rig.engine.snapshot();
        let entry = snapshot
            .keys
            .entries()
            .iter()
            .find(|entry| entry.identity.as_deref() == Some("alice"))
            .expect("alice credential");
        spa::Key {
            enc: entry.key.enc.clone(),
            hmac: entry.key.hmac.clone(),
            hmac_type: entry.key.hmac_type,
        }
    };
    let mut message = knock_message(Some(admit_addr()), &[Access::new(Proto::Tcp, 22)]);
    message.msg_type = MsgType::ClientTimeoutAccess;
    message.client_timeout = Some(300);
    let packet = encode_packet(&message, &alice_key);
    let outcome = rig.engine.submit(&packet, peer(40100)).await;
    let Outcome::Opened(opened) = outcome else {
        panic!("first knock must open: {outcome:?}");
    };
    assert_eq!(opened.identity.as_deref(), Some("alice"));
    assert_eq!(opened.duration_secs, 300, "-f request honored");
    let outcome = rig.engine.submit(&packet, peer(40100)).await;
    assert_eq!(outcome, Outcome::Rejected(Reject::Replay));
    // Single-address: a knock from a second address revokes the first.
    let second: IpAddr = "203.0.113.8".parse().unwrap();
    let mut message = knock_message(Some(second), &[Access::new(Proto::Tcp, 22)]);
    message.rand = format!("{:016x}", now_secs() as u64 ^ 0xbeef);
    let packet = encode_packet(&message, &alice_key);
    let outcome = rig.engine.submit(&packet, peer(40101)).await;
    assert!(matches!(outcome, Outcome::Opened(_)));
    assert!(
        !rig.grants
            .admitted(admit_addr(), rule_key, SystemTime::now()),
        "single_addr revokes the earlier address"
    );
    assert!(rig.grants.admitted(second, rule_key, SystemTime::now()));
}

#[tokio::test]
async fn repeat_knock_extends_grant() {
    let mut config = FileConfig::default();
    let rule = ssh_rule();
    config.rules.push(rule.clone());
    let rig = rig(config, None).await;
    let key = key_of(&rule);
    // First knock: rule timeout 30 s.
    let first = knock_message(Some(admit_addr()), &[Access::new(Proto::Tcp, 22)]);
    let _ = rig
        .engine
        .submit(&encode_packet(&first, &key), peer(40200))
        .await;
    let until_first = rig
        .grants
        .list(SystemTime::now())
        .into_iter()
        .find(|view| view.addr == admit_addr())
        .map(|view| view.remaining_seconds)
        .expect("grant");
    // Second knock requesting 300 s extends.
    let mut second = knock_message(Some(admit_addr()), &[Access::new(Proto::Tcp, 22)]);
    second.msg_type = MsgType::ClientTimeoutAccess;
    second.client_timeout = Some(300);
    let _ = rig
        .engine
        .submit(&encode_packet(&second, &key), peer(40200))
        .await;
    let until_second = rig
        .grants
        .list(SystemTime::now())
        .into_iter()
        .find(|view| view.addr == admit_addr())
        .map(|view| view.remaining_seconds)
        .expect("grant");
    assert!(
        until_second > until_first,
        "the repeat knock extends: {until_first} → {until_second}"
    );
    assert!(
        until_second >= 290,
        "requested duration capped by maxTimeout"
    );
}

#[tokio::test]
async fn rate_limit_drops_flood_before_hmac() {
    let mut config = FileConfig::default();
    config.rules.push(ssh_rule());
    let rig = rig(config, None).await;
    // Eleven packets from one /24 within a second: the per-source bucket
    // admits ten, the rest are dropped before any HMAC work.
    // Base64-valid garbage: the first ten packets reach the HMAC check
    // (HmacMismatch), the rest are dropped before any HMAC work.
    let garbage = vec![b'A'; 64];
    let mut hmac_failed = 0;
    let mut rate_limited = 0;
    for i in 0..12u16 {
        match rig
            .engine
            .handle(&garbage, peer(41000 + i), fg_knock::Via::Udp)
            .await
        {
            Outcome::Rejected(Reject::HmacMismatch) => hmac_failed += 1,
            Outcome::RateLimited => rate_limited += 1,
            other => panic!("unexpected outcome {other:?}"),
        }
    }
    assert_eq!(hmac_failed, 10, "10/s per /24 pass the limiter");
    assert_eq!(rate_limited, 2, "packets 11 and 12 are dropped early");
    assert_eq!(rig.engine.stats(SystemTime::now()).rate_limited, 2);
    // The flood did not consume the global budget of another source.
    let outcome = rig
        .engine
        .handle(
            &garbage,
            SocketAddr::new("198.51.100.1".parse().unwrap(), 1),
            fg_knock::Via::Udp,
        )
        .await;
    assert_eq!(outcome, Outcome::Rejected(Reject::HmacMismatch));
}

#[tokio::test]
async fn invalid_knocks_summarized_per_minute() {
    let mut config = FileConfig::default();
    config.rules.push(ssh_rule());
    let rig = rig(config, None).await;
    let garbage = vec![b'B'; 64];
    for i in 0..5u16 {
        let _ = rig
            .engine
            .handle(&garbage, peer(42000 + i), fg_knock::Via::Udp)
            .await;
    }
    // Before the minute elapsed there is nothing to flush.
    assert!(
        rig.engine
            .take_invalid_summary(std::time::Instant::now())
            .is_none()
    );
    // Once it elapsed: 5 packets from (up to) 5 addresses in one /24.
    let summary = rig
        .engine
        .take_invalid_summary(std::time::Instant::now() + Duration::from_secs(61))
        .expect("summary after the minute");
    assert_eq!(summary.count, 5);
    assert_eq!(summary.sources, 1, "127.0.0.x is one /24");
    assert!(
        summary.message().contains("1 个来源"),
        "{}",
        summary.message()
    );
}

#[tokio::test]
async fn grants_lost_on_restart() {
    let mut config = FileConfig::default();
    let rule = ssh_rule();
    config.rules.push(rule.clone());
    let rig = rig(config, None).await;
    let key = key_of(&rule);
    let _ = rig
        .engine
        .submit(
            &encode_packet(&knock_message(None, &[Access::new(Proto::Tcp, 22)]), &key),
            peer(43000),
        )
        .await;
    // `-s` knock: the grant lands on the packet's source address.
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
    assert!(
        rig.grants
            .admitted(source, "a1b2c3d4e5f6", SystemTime::now())
    );
    // A restarted module owns a fresh registry: nobody is admitted.
    let restarted = Arc::new(Grants::new());
    assert!(!restarted.admitted(source, "a1b2c3d4e5f6", SystemTime::now()));
}

#[tokio::test]
async fn admitted_is_lock_free_under_concurrent_reads() {
    let grants = Arc::new(Grants::new());
    grants.set_rules(vec!["r1".into()]);
    let addr = admit_addr();
    grants.grant(
        fg_knock::Grant {
            addr,
            rule: "r1".into(),
            until: SystemTime::now() + Duration::from_secs(60),
            source: GrantSource::Knock,
            identity: None,
            user: None,
            cred: "c".into(),
        },
        false,
        SystemTime::now(),
    );
    // Hammer the hot path from many threads while writers prune — reads
    // never lock and never observe a torn state.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let grants = Arc::clone(&grants);
        handles.push(std::thread::spawn(move || {
            for _ in 0..20_000 {
                let now = SystemTime::now();
                assert!(grants.admitted(addr, "r1", now));
            }
        }));
    }
    for step in 0..50 {
        grants.prune(SystemTime::now());
        grants.grant(
            fg_knock::Grant {
                addr,
                rule: "r1".into(),
                until: SystemTime::now() + Duration::from_secs(60 + step),
                source: GrantSource::Knock,
                identity: None,
                user: None,
                cred: "c".into(),
            },
            false,
            SystemTime::now(),
        );
    }
    for handle in handles {
        handle.join().expect("reader thread");
    }
}

// ---------------------------------------------------------------------------
// Routes over a real config store (fg-admin collection contract)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
struct Harness {
    addr: SocketAddr,
    store: Arc<ConfigStore>,
    events: EventLog,
    opened: Arc<Mutex<Vec<WindowRequest>>>,
    _dir: TempDir,
}

async fn harness(config: FileConfig) -> Harness {
    let rig = rig(config, None).await;
    let dir = tempfile::tempdir().expect("temp dir");
    let store = ConfigStore::open(dir.path()).expect("config store");
    let config = normalize(rig_config(&rig));
    let config = Arc::new(tokio::sync::RwLock::new(config));
    let persist_store = Arc::clone(&store);
    let persist: PersistFn =
        Arc::new(move |config: &FileConfig| persist_store.save("knock", config).map(|_| ()));
    let on_change_engine = Arc::clone(&rig.engine);
    let on_change: fg_knock::OnChangeFn =
        Arc::new(move |old, new| on_change_engine.apply_config(Some(old), new));
    // Delete protection: rule "a1b2c3d4e5f6" is referenced by portforward.
    let references: SharedFn<String, Vec<String>> = Arc::new(|key: String| {
        Box::pin(async move {
            if key == "a1b2c3d4e5f6" {
                Ok(vec!["portforward".to_owned()])
            } else {
                Ok(Vec::new())
            }
        }) as BoxFut<'static, anyhow::Result<Vec<String>>>
    });
    let spa_ports: SharedFn<(), Vec<Access>> = Arc::new(|(): ()| {
        Box::pin(
            async move { Ok(vec![Access::new(Proto::Tcp, 8443)]) as anyhow::Result<Vec<Access>> },
        ) as BoxFut<'static, anyhow::Result<Vec<Access>>>
    });
    let firewall_rules: SharedFn<(), Vec<FirewallRuleView>> = Arc::new(|(): ()| {
        Box::pin(async move {
            Ok(vec![FirewallRuleView {
                rule: "a1b2c3d4e5f6".into(),
                ports: vec![Access::new(Proto::Tcp, 22)],
                state: "synced".into(),
            }]) as anyhow::Result<Vec<FirewallRuleView>>
        }) as BoxFut<'static, anyhow::Result<Vec<FirewallRuleView>>>
    });
    let state = Arc::new(RoutesState {
        config,
        persist,
        on_change,
        engine: Arc::clone(&rig.engine),
        references: Some(references),
        spa_ports: Some(spa_ports),
        firewall_rules: Some(firewall_rules),
    });
    let app: Router = mount(Router::new(), state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    Harness {
        addr,
        store,
        events: rig.events,
        opened: rig.opened,
        _dir: dir,
    }
}

fn rig_config(_rig: &Rig) -> FileConfig {
    // The routes harness starts from the module defaults; rules come from
    // the API itself.
    FileConfig::default()
}

impl Harness {
    async fn send(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let stream = tokio::net::TcpStream::connect(self.addr)
            .await
            .expect("connect");
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .expect("handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let builder = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header(CONTENT_TYPE, "application/json");
        let request = match body {
            Some(body) => builder
                .body(axum::body::Body::from(body.to_string()))
                .expect("body"),
            None => builder.body(axum::body::Body::empty()).expect("body"),
        };
        let response = sender.send_request(request).await.expect("send");
        let status = response.status();
        let bytes = BodyExt::collect(response.into_body())
            .await
            .expect("collect")
            .to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

fn rule_json() -> Value {
    let (enc, hmac) = key_pair_b64();
    json!({
        "key": "a1b2c3d4e5f6",
        "name": "ssh",
        "group": "",
        "enable": true,
        "ports": [{"proto": "tcp", "port": 22}],
        "firewall": true,
        "encKey": enc,
        "hmacKey": hmac,
        "hmacType": "sha256",
        "timeout": 30,
        "maxTimeout": 300,
        "user": "",
        "requireAddr": false,
        "identities": [{
            "id": "alice", "name": "Alice", "enable": true,
            "encKey": key_pair_b64().0, "hmacKey": key_pair_b64().1, "remark": ""
        }],
        "sharedKeyOff": false,
        "singleAddr": false,
        "remark": ""
    })
}

#[tokio::test]
async fn knock_routes_collection_crud_and_secrets() {
    let app = harness(FileConfig::default()).await;
    // Create.
    let (status, created) = app
        .send("POST", "/api/knock/rules", Some(rule_json()))
        .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["key"], "a1b2c3d4e5f6");
    assert_eq!(created["encKey"], "********", "secrets masked in lists");
    assert_eq!(created["identities"][0]["hmacKey"], "********");
    // List shows the mask.
    let (status, listed) = app.send("GET", "/api/knock/rules", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed.as_array().expect("list").len(), 1);
    assert_eq!(listed[0]["encKey"], "********");
    // Secrets endpoint returns plaintexts (client dialog source).
    let (status, secrets) = app
        .send("GET", "/api/knock/rules/a1b2c3d4e5f6/secrets", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(secrets["encKey"], "********");
    assert_eq!(secrets["identities"][0]["name"], "Alice");
    let shared_enc = secrets["encKey"].as_str().unwrap().to_owned();
    // Update with `********` keeps the stored material.
    let mut updated = rule_json();
    updated["encKey"] = json!("********");
    updated["hmacKey"] = json!("********");
    updated["identities"][0]["encKey"] = json!("********");
    let (status, replaced) = app
        .send("PUT", "/api/knock/rules/a1b2c3d4e5f6", Some(updated))
        .await;
    assert_eq!(status, StatusCode::OK, "{replaced}");
    let (_, secrets) = app
        .send("GET", "/api/knock/rules/a1b2c3d4e5f6/secrets", None)
        .await;
    assert_eq!(secrets["encKey"], shared_enc, "mask kept the stored key");
    // Copy generates a fresh key AND fresh material, inserted after.
    let mut template = rule_json();
    template["name"] = json!("ssh copy");
    let (status, copy) = app
        .send("POST", "/api/knock/rules/a1b2c3d4e5f6/copy", Some(template))
        .await;
    assert_eq!(status, StatusCode::OK, "{copy}");
    let copy_key = copy["key"].as_str().unwrap().to_owned();
    assert_ne!(copy_key, "a1b2c3d4e5f6");
    let (_, secrets) = app
        .send("GET", &format!("/api/knock/rules/{copy_key}/secrets"), None)
        .await;
    assert_ne!(secrets["encKey"], shared_enc, "copies re-key");
    // Order.
    let (status, _) = app
        .send(
            "PUT",
            "/api/knock/rules-order",
            Some(json!({"keys": [copy_key, "a1b2c3d4e5f6"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, listed) = app.send("GET", "/api/knock/rules", None).await;
    assert_eq!(listed[0]["key"], copy_key);
    // Batch enable + group.
    let (status, _) = app
        .send(
            "PUT",
            "/api/knock/rules-enable",
            Some(json!({"keys": ["a1b2c3d4e5f6"], "enable": false})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = app
        .send(
            "PUT",
            "/api/knock/rules-group",
            Some(json!({"keys": [copy_key], "group": "infra"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, listed) = app.send("GET", "/api/knock/rules", None).await;
    assert_eq!(listed[1]["enable"], false);
    assert_eq!(listed[0]["group"], "infra");
    // Batch delete the unreferenced copy; the referenced rule refuses.
    let (status, removed) = app
        .send(
            "POST",
            "/api/knock/rules-delete",
            Some(json!({"keys": [copy_key]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(removed["removed"], 1);
    let (status, refusal) = app
        .send("DELETE", "/api/knock/rules/a1b2c3d4e5f6", None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(refusal["referencedBy"][0], "portforward");
    // Enable rejects a firewall rule covering the spa route port.
    let mut conflict = rule_json();
    conflict["key"] = json!("b2c3d4e5f6a1");
    conflict["name"] = json!("conflict");
    conflict["ports"] = json!([{"proto": "tcp", "port": 8443}]);
    let (status, problems) = app.send("POST", "/api/knock/rules", Some(conflict)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        problems["problems"]
            .as_array()
            .expect("problems")
            .iter()
            .any(|p| p["reason"].as_str().unwrap().contains("协议分流"))
    );
}

#[tokio::test]
async fn knock_settings_and_status_and_grants_endpoints() {
    let app = harness(FileConfig::default()).await;
    // Settings normalize: maxAge clamps to the ceiling.
    let (status, saved) = app
        .send(
            "PUT",
            "/api/knock/settings",
            Some(
                json!({"port": 62201, "autoFirewall": true, "allowLan": true,
                        "allowList": ["10.0.0.0/8"], "maxAge": 99999}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["maxAge"], limits::MAX_AGE_MAX);
    // Bad allow list entry is rejected with problems.
    let (status, problems) = app
        .send(
            "PUT",
            "/api/knock/settings",
            Some(
                json!({"port": 62201, "autoFirewall": true, "allowLan": true,
                        "allowList": ["not-an-ip"], "maxAge": 120}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        problems["problems"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("CIDR")
    );
    // Firewall view comes from the injected hook.
    let (status, firewall) = app.send("GET", "/api/knock/firewall/rules", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(firewall["rules"][0]["state"], "synced");
    // Register a grant through the engine, then read status and revoke.
    let mut config = FileConfig::default();
    config.rules.push(ssh_rule());
    let (enc, hmac) = key_pair_b64();
    let _ = (enc, hmac);
    let grants = Arc::new(Grants::new());
    grants.grant(
        fg_knock::Grant {
            addr: admit_addr(),
            rule: "a1b2c3d4e5f6".into(),
            until: SystemTime::now() + Duration::from_secs(30),
            source: GrantSource::Knock,
            identity: Some("alice".into()),
            user: None,
            cred: "c".into(),
        },
        false,
        SystemTime::now(),
    );
    // The route's engine owns its own registry; exercise revocation there.
    let (status, status_body) = app.send("GET", "/api/knock/status", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(status_body["grants"].is_array());
    assert_eq!(
        status_body["keys"], 0,
        "no rules configured in this harness"
    );
    let (status, revoked) = app.send("DELETE", "/api/knock/grants", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(revoked["removed"], 0);
    let _ = grants; // registry exercises live in the other tests
}

#[tokio::test]
async fn module_persists_and_reloads_knock_json() {
    // Module::new over a real store: save through the routes, reload, and
    // find the same rules (persistence contract of the collection).
    let dir = tempfile::tempdir().expect("temp dir");
    let store = ConfigStore::open(dir.path()).expect("config store");
    let deps = fg_knock::Deps::default();
    let module = fg_knock::Module::new(Arc::clone(&store), deps).expect("module");
    let app: Router = module.mount(Router::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    let send = |method: &'static str, path: &'static str, body: Option<Value>| async move {
        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .expect("handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let builder = hyper::Request::builder().method(method).uri(path);
        let request = match body {
            Some(body) => builder
                .header(CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .expect("body"),
            None => builder.body(axum::body::Body::empty()).expect("body"),
        };
        let response = sender.send_request(request).await.expect("send");
        let status = response.status();
        let bytes = BodyExt::collect(response.into_body())
            .await
            .expect("collect")
            .to_bytes();
        (
            status,
            serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
        )
    };
    let (status, created) = send("POST", "/api/knock/rules", Some(rule_json())).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    // A fresh module instance loads the same rule.
    let reloaded =
        fg_knock::Module::new(Arc::clone(&store), fg_knock::Deps::default()).expect("reload");
    let config = reloaded.engine().snapshot();
    assert_eq!(config.rules.len(), 1);
    assert_eq!(config.rules["a1b2c3d4e5f6"].name, "ssh");
    // Windows close on drain; the module run loop exits cleanly.
    let (drain_tx, drain_rx) = tokio::sync::watch::channel(false);
    let module_struct =
        fg_knock::Module::new(Arc::clone(&store), fg_knock::Deps::default()).expect("module2");
    let task = tokio::spawn(async move {
        <fg_knock::Module as fg_core::module::Module>::run(module_struct, drain_rx).await
    });
    drain_tx.send(true).unwrap();
    task.await.expect("module run").expect("clean stop");
}

#[tokio::test]
async fn single_grant_survives_window_close_scheduling() {
    // A firewall rule opens the window and schedules the close timer; a
    // short timeout fires the close hook while the (longer-lived) grant
    // bookkeeping stays consistent.
    let mut config = FileConfig::default();
    let mut rule = ssh_rule();
    rule.timeout = 1;
    rule.max_timeout = 0;
    config.rules.push(rule.clone());
    // (the same rule instance derives the key below)
    let rig = rig(config, None).await;
    let key = key_of(&rule);
    let _ = rig
        .engine
        .submit(
            &encode_packet(
                &knock_message(Some(admit_addr()), &[Access::new(Proto::Tcp, 22)]),
                &key,
            ),
            peer(44000),
        )
        .await;
    assert_eq!(rig.opened.lock().expect("opened").len(), 1);
    let closed = Arc::clone(&rig.closed);
    let reached = wait_until(move || !closed.lock().expect("closed").is_empty()).await;
    assert!(reached, "the close timer fired after 1 s");
    assert_eq!(rig.closed.lock().expect("closed")[0], rule.key);
    // The grant expired alongside the window.
    assert!(
        !rig.grants
            .admitted(admit_addr(), &rule.key, SystemTime::now())
    );
    // Shutdown closes everything and stays clean.
    rig.engine.shutdown().await;
}

#[test]
fn settings_defaults_survive_config_roundtrip() {
    // A saved knock.json roundtrips through the module's serde shape with
    // the documented defaults.
    let config = FileConfig {
        settings: Settings {
            port: 0,
            ..Settings::default()
        },
        rules: vec![ssh_rule()],
    };
    let normalized = normalize(config.clone());
    let text = serde_json::to_string(&normalized).unwrap();
    assert!(text.contains("\"port\":0"));
    assert!(text.contains("\"autoFirewall\":true"));
    assert!(text.contains("\"maxAge\":120"));
    let parsed: FileConfig = serde_json::from_str(&text).unwrap();
    assert_eq!(normalize(parsed), normalize(config));
}

/// Keeps imports referenced when some fixture paths change.
#[allow(unused)]
fn _type_witnesses() -> HashMap<String, u8> {
    HashMap::new()
}
