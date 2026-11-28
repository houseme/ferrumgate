//! Integration & property-style tests for protocol sniffing (WP-35 §6).

use std::time::Instant;

use fg_protoroute::model::{Protocol, limits};
use fg_protoroute::sniff::detect::detect;
use fg_protoroute::sniff::{Probe, SniffOutcome, SniffState};

fn build_client_hello(sni: &[u8], alpn: &[&[u8]]) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x42; 32]);
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

fn split_tls_records(record: &[u8], chunks: usize) -> Vec<u8> {
    let payload = &record[5..];
    let per = (payload.len() / chunks).max(1);
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let stop = (offset + per).min(payload.len());
        out.extend_from_slice(&[0x16, 0x03, 0x01]);
        out.extend_from_slice(&((stop - offset) as u16).to_be_bytes());
        out.extend_from_slice(&payload[offset..stop]);
        offset = stop;
    }
    out
}

fn varint(mut v: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return out;
        }
        out.push(b | 0x80);
    }
}

fn build_mc_handshake(host: &str, port: u16) -> Vec<u8> {
    let mut body = vec![0x00];
    body.extend_from_slice(&varint(765));
    body.extend_from_slice(&varint(host.len()));
    body.extend_from_slice(host.as_bytes());
    body.extend_from_slice(&port.to_be_bytes());
    body.push(0x02);
    let mut pkt = varint(body.len());
    pkt.extend_from_slice(&body);
    pkt
}

fn all_wire_samples() -> Vec<(Protocol, Vec<u8>)> {
    let mut mqtt = vec![0x10, 0x0A, 0x00, 0x04];
    mqtt.extend_from_slice(b"MQTT");
    mqtt.extend_from_slice(&[0x05, 0x02, 0x00, 0x3C]);

    let mut bt = vec![0x13];
    bt.extend_from_slice(b"BitTorrent protocol");
    bt.extend_from_slice(&[0u8; 8]);

    let mut spa: Vec<u8> = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .copied()
        .cycle()
        .take(96)
        .collect();
    spa.push(b'\n');

    vec![
        (
            Protocol::Tls,
            build_client_hello(b"app.example.com", &[b"h2", b"http/1.1"]),
        ),
        (
            Protocol::Http,
            b"GET /health HTTP/1.1\r\nHost: web.example\r\n\r\n".to_vec(),
        ),
        (Protocol::Ssh, b"SSH-2.0-OpenSSH_9.7\r\n".to_vec()),
        (
            Protocol::Rdp,
            vec![0x03, 0x00, 0x00, 0x13, 0xE0, 0, 0, 0, 0, 0, 0, 0, 0x00],
        ),
        (Protocol::Socks, vec![0x05, 0x01, 0x00]),
        (
            Protocol::OpenVpn,
            vec![0x00, 0x0E, 0x38, 0x01, 0x02, 0x03, 0x04, 0x05],
        ),
        (
            Protocol::Xmpp,
            b"<stream:stream to='chat.example' xmlns='jabber:client'>".to_vec(),
        ),
        (Protocol::Mqtt, mqtt),
        (
            Protocol::Postgres,
            vec![0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x30],
        ),
        (
            Protocol::Rtsp,
            b"DESCRIBE rtsp://cam/1 RTSP/1.0\r\n".to_vec(),
        ),
        (
            Protocol::Sip,
            b"INVITE sip:bob@pbx.example SIP/2.0\r\n".to_vec(),
        ),
        (
            Protocol::Minecraft,
            build_mc_handshake("play.example", 25565),
        ),
        (Protocol::Redis, b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n".to_vec()),
        (Protocol::Amqp, b"AMQP\x00\x00\x09\x01".to_vec()),
        (
            Protocol::Smb,
            vec![0x00, 0x00, 0x00, 0x40, 0xFE, b'S', b'M', b'B', 0, 0],
        ),
        (Protocol::Git, b"001egit-upload-pack /repo.git\0".to_vec()),
        (Protocol::BitTorrent, bt),
        (
            Protocol::Adb,
            b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00".to_vec(),
        ),
        (Protocol::Irc, b"USER guest 0 * :Guest\r\n".to_vec()),
        (Protocol::Spa, spa),
    ]
}

#[test]
fn probe_each_protocol_with_real_first_packet() {
    let samples = all_wire_samples();
    // 20 wire-detectable protocols + Protocol::Timeout (client silent) = 21 total.
    assert_eq!(samples.len(), 20);
    for (expected, packet) in samples {
        let with_spa = expected == Protocol::Spa;
        let mut state = SniffState::new(with_spa);
        let outcome = state.feed(&packet);
        match outcome {
            SniffOutcome::Done(result) => {
                assert_eq!(result.protocol, expected, "mismatch for {expected}");
                assert_eq!(result.raw, packet, "raw bytes must be preserved verbatim");
            }
            other => panic!("expected Done({expected}), got {other:?}"),
        }
    }
    // Verify the 21st protocol identifier (`timeout`) exists and formats properly.
    assert_eq!(Protocol::Timeout.as_str(), "timeout");
}

#[test]
fn probe_partial_prefix_waits_for_more() {
    assert_eq!(detect(b"SS", false), Probe::Partial);
    assert_eq!(detect(b"XX", false), Probe::Unknown);

    // Streaming 1 byte at a time through SniffState must succeed for every protocol.
    for (expected, packet) in all_wire_samples() {
        let with_spa = expected == Protocol::Spa;
        let mut state = SniffState::new(with_spa);
        let mut got = None;
        for byte in &packet {
            match state.feed(std::slice::from_ref(byte)) {
                SniffOutcome::NeedMore => {}
                SniffOutcome::Done(res) => {
                    got = Some(res);
                    break;
                }
                other => panic!("1-byte feed for {expected} failed with {other:?}"),
            }
        }
        let res = got.unwrap_or_else(|| panic!("1-byte feed for {expected} never finished"));
        assert_eq!(res.protocol, expected);
    }
}

#[test]
fn probe_probes_are_mutually_exclusive() {
    for (expected, packet) in all_wire_samples() {
        assert_eq!(
            detect(&packet, true),
            Probe::Detected(expected),
            "{expected} must not be shadowed even with SPA enabled"
        );
    }
}

#[test]
fn tls_hello_split_across_records() {
    let record = build_client_hello(b"Edge.Example.", &[b"h2", b"http/1.1"]);
    let fragmented = split_tls_records(&record, 9);
    let mut state = SniffState::new(false);
    let mut done = None;
    for chunk in fragmented.chunks(5) {
        match state.feed(chunk) {
            SniffOutcome::NeedMore => {}
            SniffOutcome::Done(res) => {
                done = Some(res);
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    let res = done.expect("fragmented ClientHello should complete");
    assert_eq!(res.protocol, Protocol::Tls);
    assert_eq!(res.server_name.as_deref(), Some("edge.example"));
    assert_eq!(res.alpn, ["h2", "http/1.1"]);
    assert_eq!(res.raw, fragmented);
}

#[test]
fn tls_hello_over_64k_rejected() {
    // Declared ClientHello length > 64 KiB.
    let mut oversized = vec![0x16, 0x03, 0x01, 0x00, 0x20, 0x01, 0x01, 0x00, 0x01];
    oversized.extend_from_slice(&[0u8; 28]);
    let mut state = SniffState::new(false);
    assert_eq!(state.feed(&oversized), SniffOutcome::Malformed);
    assert_eq!(state.buffered(), oversized.as_slice());

    // Multi-record handshake payload exceeding 64 KiB total.
    let mut multi = SniffState::new(false);
    let chunk_payload = 16_384usize;
    let mut first = vec![0x16, 0x03, 0x01];
    first.extend_from_slice(&(chunk_payload as u16).to_be_bytes());
    first.push(0x01); // ClientHello
    // Declared length = 65536 (at cap), but feed 5 records = 81920 bytes > 64 KiB.
    first.extend_from_slice(&[0x00, 0xFF, 0xFC]);
    first.resize(5 + chunk_payload, 0xAA);
    assert_eq!(multi.feed(&first), SniffOutcome::NeedMore);

    let mut follow = vec![0x16, 0x03, 0x01];
    follow.extend_from_slice(&(chunk_payload as u16).to_be_bytes());
    follow.resize(5 + chunk_payload, 0xBB);
    let mut malformed = false;
    for _ in 0..4 {
        if multi.feed(&follow) == SniffOutcome::Malformed {
            malformed = true;
            break;
        }
    }
    assert!(
        malformed,
        "accumulating > 64 KiB handshake must be Malformed"
    );
}

#[test]
fn tls_hello_malformed() {
    // Truncated body inside a valid ClientHello length.
    let broken = vec![
        0x16, 0x03, 0x01, 0x00, 0x08, 0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0, 0,
    ];
    let mut state = SniffState::new(false);
    assert_eq!(state.feed(&broken), SniffOutcome::Malformed);
    assert_eq!(state.buffered(), broken.as_slice());
}

#[test]
fn tls_sni_and_alpn_extracted() {
    let hello = build_client_hello(b"Api.Internal.Example", &[b"acme-tls/1", b"h2"]);
    let mut state = SniffState::new(false);
    let SniffOutcome::Done(res) = state.feed(&hello) else {
        panic!("expected Done");
    };
    assert_eq!(res.server_name.as_deref(), Some("api.internal.example"));
    assert_eq!(res.alpn, ["acme-tls/1", "h2"]);
}

#[test]
fn http_host_within_32kib_request_line_8kib() {
    // Split Host header across chunks in the SAME SniffState.
    let mut state = SniffState::new(false);
    assert_eq!(
        state.feed(b"GET /index.html HTTP/1.1\r\nX-Pad: "),
        SniffOutcome::NeedMore
    );
    assert_eq!(state.feed(b"value\r\nHo"), SniffOutcome::NeedMore);
    let SniffOutcome::Done(res) = state.feed(b"st: Split.Example:8080\r\n\r\n") else {
        panic!("expected Done");
    };
    assert_eq!(res.protocol, Protocol::Http);
    assert_eq!(res.host.as_deref(), Some("split.example"));

    // Host header near the 32 KiB header cap is still found.
    let mut big = b"GET / HTTP/1.1\r\n".to_vec();
    while big.len() < limits::HTTP_HEAD_MAX - 128 {
        big.extend_from_slice(b"X-Header: 0123456789abcdef0123456789abcdef\r\n");
    }
    big.extend_from_slice(b"Host: deep.example\r\n\r\n");
    assert!(big.len() <= limits::HTTP_HEAD_MAX);
    let mut state = SniffState::new(false);
    let SniffOutcome::Done(res) = state.feed(&big) else {
        panic!("expected Done");
    };
    assert_eq!(res.host.as_deref(), Some("deep.example"));

    // Headers exceeding 32 KiB without Host complete as HTTP with host = None.
    let mut over = b"GET / HTTP/1.1\r\n".to_vec();
    while over.len() <= limits::HTTP_HEAD_MAX + 64 {
        over.extend_from_slice(b"X-Header: 0123456789abcdef0123456789abcdef\r\n");
    }
    let mut state = SniffState::new(false);
    let SniffOutcome::Done(res) = state.feed(&over) else {
        panic!("expected Done");
    };
    assert_eq!(res.protocol, Protocol::Http);
    assert_eq!(res.host, None);

    // Request line > 8 KiB is rejected.
    let mut long_line = b"GET /".to_vec();
    long_line.resize(limits::REQUEST_LINE_MAX + 32, b'x');
    long_line.extend_from_slice(b" HTTP/1.1\r\nHost: a.example\r\n\r\n");
    let mut state = SniffState::new(false);
    assert_eq!(state.feed(&long_line), SniffOutcome::NotProtocol);
}

#[test]
fn http_h2c_prior_knowledge_detected() {
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let mut state = SniffState::new(false);
    assert_eq!(state.feed(&preface[..12]), SniffOutcome::NeedMore);
    let SniffOutcome::Done(res) = state.feed(&preface[12..]) else {
        panic!("expected Done");
    };
    assert_eq!(res.protocol, Protocol::Http);
    assert_eq!(res.host, None);
    assert_eq!(res.raw, preface);
}

#[test]
fn minecraft_server_address_ignores_suffixes() {
    for (raw, want) in [
        ("mc.example\x00FML3\x00", Some("mc.example")),
        (
            "mc.example\x00198.51.100.7\x0000000000-0000-0000-0000-000000000000",
            Some("mc.example"),
        ),
        ("mc.example\x00realip=203.0.113.5\x00", Some("mc.example")),
        // Long hostname (> 128 bytes total packet length -> 2-byte varint!)
        (
            "long-mc.example\x00padding-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            Some("long-mc.example"),
        ),
    ] {
        let pkt = build_mc_handshake(raw, 25565);
        let mut state = SniffState::new(false);
        let SniffOutcome::Done(res) = state.feed(&pkt) else {
            panic!("expected Minecraft Done for {raw:?}");
        };
        assert_eq!(res.protocol, Protocol::Minecraft);
        assert_eq!(res.server_name.as_deref(), want);
    }
}

#[test]
fn sniff_never_panics_on_random_input() {
    let mut seed: u64 = 0x5EED_CAFE_BABE_1234;
    let mut next = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as u8
    };
    for round in 0..200 {
        let mut state = SniffState::new(round % 2 == 0);
        let mut fed = 0;
        while fed < limits::CLIENT_HELLO_MAX + 4096 {
            let len = (next() as usize % 512) + 1;
            let chunk: Vec<u8> = (0..len).map(|_| next()).collect();
            fed += chunk.len();
            if state.feed(&chunk) != SniffOutcome::NeedMore {
                break;
            }
        }
    }
}

#[test]
fn sniff_is_linear() {
    // Feed 31 KiB of HTTP headers in 16-byte chunks (nearly 2000 feeds).
    // With O(N) scanning this completes in milliseconds; quadratic scanning
    // would blow up visibly.
    let mut payload = b"GET / HTTP/1.1\r\n".to_vec();
    while payload.len() < limits::HTTP_HEAD_MAX - 128 {
        payload.extend_from_slice(b"X-Lin: 0123456789abcdef\r\n");
    }
    payload.extend_from_slice(b"Host: linear.example\r\n\r\n");

    let start = Instant::now();
    let mut state = SniffState::new(false);
    let mut found = None;
    for chunk in payload.chunks(16) {
        if let SniffOutcome::Done(res) = state.feed(chunk) {
            found = Some(res);
            break;
        }
    }
    let elapsed = start.elapsed();
    assert_eq!(found.unwrap().host.as_deref(), Some("linear.example"));
    assert!(
        elapsed.as_millis() < 500,
        "linear HTTP sniff took too long: {elapsed:?}"
    );
}
