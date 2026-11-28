//! The ordered first-byte probes (`probes.go` equivalent): every
//! recognizer is a pure `fn(&[u8]) -> Probe`; [`detect`] walks them in
//! order, skipping the ones that answer "not this protocol" and waiting
//! as soon as one answers "could still become". Recognizers that carry no
//! routing data are decided entirely here; TLS / HTTP / Minecraft / SPA
//! hand over to their refinement state machines.
//!
//! The probes are deliberately narrow-prefix heuristics: protocols whose
//! first packet is just a length field or is encrypted land in
//! [`Probe::Unknown`] and fall through to the default target.

use super::Probe;
use super::http;
use super::minecraft;
use super::spa;
use crate::model::Protocol;

/// Probe order (approximates `probes.go`): more specific byte patterns
/// first; text protocols share a request-line shape and are told apart by
/// their version token; SPA last because its only signature is a
/// charset-restricted single line.
const ORDERED: [fn(&[u8]) -> Probe; 19] = [
    tls_probe,
    openvpn_probe,
    ssh_probe,
    rdp_probe,
    socks_probe,
    http::http_probe,
    rtsp_probe,
    sip_probe,
    xmpp_probe,
    mqtt_probe,
    postgres_probe,
    minecraft_probe,
    redis_probe,
    amqp_probe,
    smb_probe,
    git_probe,
    bittorrent_probe,
    adb_probe,
    irc_probe,
];

/// Runs the ordered probes; `with_spa` enables the SPA line probe, which
/// only makes sense when the rule actually carries a `spa` route.
pub fn detect(buf: &[u8], with_spa: bool) -> Probe {
    if buf.is_empty() {
        return Probe::NeedMore;
    }
    let mut any_partial = false;
    for probe in ORDERED {
        match probe(buf) {
            Probe::Detected(protocol) => return Probe::Detected(protocol),
            Probe::Unknown => continue,
            Probe::NeedMore | Probe::Partial => any_partial = true,
        }
    }
    if any_partial {
        return Probe::Partial;
    }
    if with_spa {
        return spa::spa_probe(buf);
    }
    Probe::Unknown
}

/// `buf` is still a byte-prefix of `pattern` (waiting for the rest).
fn is_partial_of(pattern: &[u8], buf: &[u8]) -> bool {
    pattern.starts_with(buf)
}

// -- TLS -------------------------------------------------------------------
//
// A TLS record: content_type 0x16 (handshake), version 0x03 0xXX, length.
// The ClientHello itself is parsed by `tls.rs`; the probe only fixes the
// record header and the handshake type.

fn tls_probe(buf: &[u8]) -> Probe {
    if buf[0] != 0x16 {
        return Probe::Unknown;
    }
    if buf.len() < 3 {
        return Probe::Partial;
    }
    if buf[1] != 0x03 {
        return Probe::Unknown;
    }
    if buf.len() < 5 {
        return Probe::Partial;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if !(1..=18_432).contains(&record_len) {
        return Probe::Unknown;
    }
    if buf.len() < 6 {
        return Probe::Partial;
    }
    // First handshake message must be a ClientHello (0x01).
    if buf[5] == 0x01 {
        Probe::Detected(Protocol::Tls)
    } else {
        Probe::Unknown
    }
}

// -- OpenVPN ---------------------------------------------------------------
//
// Client hard reset / data-v2 packets carry the opcode in the high bits of
// the first byte; the canonical client patterns are 0x38 (hard reset v2)
// and 0x40 (data v2). tls-crypt-v2 wraps the packet in a 2-byte length
// prefix, so the opcode appears at offset 2.

fn openvpn_probe(buf: &[u8]) -> Probe {
    if matches!(buf[0], 0x38 | 0x40) {
        return Probe::Detected(Protocol::OpenVpn);
    }
    // OpenVPN over TCP / tls-crypt-v2: [length hi][length lo][opcode byte]…
    if buf[0] == 0x00 && buf.len() >= 2 && buf[1] != 0x00 {
        if buf.len() < 3 {
            return Probe::Partial;
        }
        if matches!(buf[2], 0x38 | 0x40 | 0x50) {
            return Probe::Detected(Protocol::OpenVpn);
        }
    }
    Probe::Unknown
}

// -- SSH -------------------------------------------------------------------

fn ssh_probe(buf: &[u8]) -> Probe {
    const BANNER: &[u8] = b"SSH-";
    if buf.starts_with(BANNER) {
        Probe::Detected(Protocol::Ssh)
    } else if is_partial_of(BANNER, buf) {
        Probe::Partial
    } else {
        Probe::Unknown
    }
}

// -- RDP -------------------------------------------------------------------
//
// TPKT header (version 3, reserved 0) then X.224 connection request
// (0xE0).

fn rdp_probe(buf: &[u8]) -> Probe {
    if buf[0] != 0x03 {
        return Probe::Unknown;
    }
    if buf.len() < 2 {
        return Probe::Partial;
    }
    if buf[1] != 0x00 {
        return Probe::Unknown;
    }
    if buf.len() < 5 {
        return Probe::Partial;
    }
    if buf[4] == 0xE0 {
        Probe::Detected(Protocol::Rdp)
    } else {
        Probe::Unknown
    }
}

// -- SOCKS -----------------------------------------------------------------
//
// SOCKS4/4a request starts 0x04 0x01|0x02; SOCKS5 method negotiation
// starts 0x05 nmethods (nmethods >= 1).

fn socks_probe(buf: &[u8]) -> Probe {
    if buf.len() < 2 {
        return if matches!(buf[0], 0x04 | 0x05) {
            Probe::Partial
        } else {
            Probe::Unknown
        };
    }
    match buf[0] {
        0x04 if matches!(buf[1], 0x01 | 0x02) => Probe::Detected(Protocol::Socks),
        0x05 if buf[1] >= 1 => Probe::Detected(Protocol::Socks),
        _ => Probe::Unknown,
    }
}

// -- RTSP / SIP ------------------------------------------------------------
//
// Request-line protocols distinguished by their version token
// (`RTSP/1.0|2.0`, `SIP/2.0`). Shared line scanning lives in `http.rs`.

const RTSP_METHODS: [&[u8]; 12] = [
    b"DESCRIBE",
    b"ANNOUNCE",
    b"GET_PARAMETER",
    b"OPTIONS",
    b"PAUSE",
    b"PLAY",
    b"PLAY_NOTIFY",
    b"RECORD",
    b"REDIRECT",
    b"SETUP",
    b"SET_PARAMETER",
    b"TEARDOWN",
];

const SIP_METHODS: [&[u8]; 14] = [
    b"INVITE",
    b"ACK",
    b"BYE",
    b"CANCEL",
    b"OPTIONS",
    b"REGISTER",
    b"PRACK",
    b"SUBSCRIBE",
    b"NOTIFY",
    b"PUBLISH",
    b"INFO",
    b"REFER",
    b"MESSAGE",
    b"UPDATE",
];

fn rtsp_probe(buf: &[u8]) -> Probe {
    text_version_probe(
        buf,
        &RTSP_METHODS,
        &[b" RTSP/1.0", b" RTSP/2.0"],
        Protocol::Rtsp,
    )
}

fn sip_probe(buf: &[u8]) -> Probe {
    text_version_probe(buf, &SIP_METHODS, &[b" SIP/2.0"], Protocol::Sip)
}

/// Waits for the first line (bounded by the request-line cap), verifying
/// that any partial line starts with a valid method token for the protocol.
fn text_version_probe(
    buf: &[u8],
    methods: &[&[u8]],
    versions: &[&[u8]],
    protocol: Protocol,
) -> Probe {
    match http::first_line(buf) {
        http::LineState::Partial => {
            let prefix_ok = match buf.iter().position(|&byte| byte == b' ') {
                None => methods.iter().any(|method| method.starts_with(buf)),
                Some(space) => {
                    let token = &buf[..space];
                    methods.contains(&token)
                }
            };
            if prefix_ok {
                Probe::Partial
            } else {
                Probe::Unknown
            }
        }
        http::LineState::TooLong => Probe::Unknown,
        http::LineState::Line(line) => {
            for version in versions {
                if line.ends_with(version) {
                    return Probe::Detected(protocol);
                }
            }
            Probe::Unknown
        }
    }
}

// -- XMPP ------------------------------------------------------------------

fn xmpp_probe(buf: &[u8]) -> Probe {
    const XML: &[u8] = b"<?xml";
    const STREAM: &[u8] = b"<stream:stream";
    if buf.starts_with(XML) || buf.starts_with(STREAM) {
        Probe::Detected(Protocol::Xmpp)
    } else if is_partial_of(XML, buf) || is_partial_of(STREAM, buf) {
        Probe::Partial
    } else {
        Probe::Unknown
    }
}

// -- MQTT ------------------------------------------------------------------
//
// CONNECT control packet: type 0x10, remaining length varint, then the
// protocol name `MQTT` (5.0 / 3.1.1) or `MQIsdp` (3.1).

fn mqtt_probe(buf: &[u8]) -> Probe {
    if buf[0] != 0x10 {
        return Probe::Unknown;
    }
    let Some((remaining, varint_len)) = decode_varint(&buf[1..]) else {
        return Probe::Partial;
    };
    // A CONNECT of a sane size never exceeds the buffer cap by much.
    if remaining == 0 || remaining > 268_435_455 {
        return Probe::Unknown;
    }
    let name_at = 1 + varint_len;
    if name_at + 2 > buf.len() {
        return Probe::Partial;
    }
    let name_len = u16::from_be_bytes([buf[name_at], buf[name_at + 1]]) as usize;
    let name = match name_len {
        4 => &b"MQTT"[..],
        6 => &b"MQIsdp"[..],
        _ => return Probe::Unknown,
    };
    if name_at + 2 + name_len > buf.len() {
        return Probe::Partial;
    }
    if &buf[name_at + 2..name_at + 2 + name_len] == name {
        Probe::Detected(Protocol::Mqtt)
    } else {
        Probe::Unknown
    }
}

// -- PostgreSQL ------------------------------------------------------------
//
// Startup / SSLRequest / GSSENCRequest: 4-byte big-endian length (top
// three bytes zero, the payload stays small) then the protocol code. SMB
// shares the leading zero length bytes; the magic differs at offset 4, so
// both probes stay `Partial` until the eighth byte arrives.

fn postgres_probe(buf: &[u8]) -> Probe {
    const CODES: [[u8; 4]; 3] = [
        [0x00, 0x03, 0x00, 0x00], // startup v3.x
        [0x00, 0x02, 0x00, 0x00], // startup v2
        [0x04, 0xD2, 0x16, 0x2F], // SSLRequest
    ];
    const GSS_ENC: [u8; 4] = [0x04, 0xD2, 0x16, 0x30];
    let head = &buf[..buf.len().min(3)];
    if head.iter().any(|&byte| byte != 0) {
        return Probe::Unknown;
    }
    if buf.len() < 3 {
        return Probe::Partial;
    }
    if buf.len() < 8 {
        return Probe::Partial;
    }
    if CODES.iter().any(|code| buf[4..8] == *code) || buf[4..8] == GSS_ENC {
        Probe::Detected(Protocol::Postgres)
    } else {
        Probe::Unknown
    }
}

// -- Minecraft -------------------------------------------------------------
//
// A handshake packet: varint length (7 - 2048), packet id 0, protocol
// version, server address string, port, next state. Clients before 1.6
// ping with `0xFE 0x01 0xFA …`.

fn minecraft_probe(buf: &[u8]) -> Probe {
    if minecraft::probe_legacy(buf) {
        return Probe::Detected(Protocol::Minecraft);
    }
    if minecraft::legacy_prefix(buf) {
        return Probe::Partial;
    }
    match minecraft::packet_length(buf) {
        minecraft::Length::Invalid => Probe::Unknown,
        minecraft::Length::NeedMore => Probe::Partial,
        minecraft::Length::Within(len, varint_len) => {
            if buf.len() <= varint_len {
                return Probe::Partial;
            }
            // Modern Minecraft handshake always starts with packet id 0x00.
            if buf[varint_len] != 0x00 {
                return Probe::Unknown;
            }
            if buf.len() < varint_len + len {
                return Probe::Partial;
            }
            if minecraft::parse_body(&buf[varint_len..varint_len + len]).is_some() {
                Probe::Detected(Protocol::Minecraft)
            } else {
                Probe::Unknown
            }
        }
    }
}

// -- Redis -----------------------------------------------------------------
//
// RESP array commands: `*<n>\r\n$<len>\r\n…`.

fn redis_probe(buf: &[u8]) -> Probe {
    if buf[0] != b'*' {
        return Probe::Unknown;
    }
    if buf.len() == 1 {
        return Probe::Partial;
    }
    let mut digits = 0;
    while 1 + digits < buf.len() && buf[1 + digits].is_ascii_digit() {
        digits += 1;
    }
    if digits == 0 {
        return Probe::Unknown;
    }
    let after = &buf[1 + digits..];
    if after.starts_with(b"\r\n$") {
        Probe::Detected(Protocol::Redis)
    } else if after.is_empty() || after == b"\r" || after == b"\r\n" {
        Probe::Partial
    } else {
        Probe::Unknown
    }
}

// -- AMQP ------------------------------------------------------------------

fn amqp_probe(buf: &[u8]) -> Probe {
    const HEADER: &[u8] = b"AMQP";
    if !buf.starts_with(HEADER) {
        return if is_partial_of(HEADER, buf) {
            Probe::Partial
        } else {
            Probe::Unknown
        };
    }
    if buf.len() < 8 {
        return Probe::Partial;
    }
    // 0-9-1: `AMQP\x00\x00\x09\x01`; 1.0: `AMQP\x00\x01\x00\x00`.
    if buf[4] == 0 && matches!((buf[5], buf[6], buf[7]), (0, 9, 1) | (1, 0, 0)) {
        Probe::Detected(Protocol::Amqp)
    } else {
        Probe::Unknown
    }
}

// -- SMB -------------------------------------------------------------------
//
// NetBIOS session service header (type 0x00) then the SMB magic at
// offset 4: `\xffSMB` (SMB1) or `\xfeSMB` (SMB2/3).

fn smb_probe(buf: &[u8]) -> Probe {
    if buf[0] != 0x00 {
        return Probe::Unknown;
    }
    if buf.len() < 5 {
        return Probe::Partial;
    }
    match buf[4] {
        0xFF | 0xFE => {}
        _ => return Probe::Unknown,
    }
    if buf.len() < 8 {
        return Probe::Partial;
    }
    if &buf[5..8] == b"SMB" {
        Probe::Detected(Protocol::Smb)
    } else {
        Probe::Unknown
    }
}

// -- Git -------------------------------------------------------------------
//
// The first pkt-line of the git:// protocol: 4 hex length digits then a
// `git-upload-pack` / `git-receive-pack` / `git-upload-archive` payload.

fn git_probe(buf: &[u8]) -> Probe {
    const PAYLOADS: [&[u8]; 3] = [
        b"git-upload-pack",
        b"git-receive-pack",
        b"git-upload-archive",
    ];
    let take = buf.len().min(4);
    if buf[..take].iter().any(|byte| !byte.is_ascii_hexdigit()) {
        return Probe::Unknown;
    }
    if take < 4 {
        return Probe::Partial;
    }
    let payload = &buf[4..];
    for candidate in PAYLOADS {
        if payload.starts_with(candidate) {
            return Probe::Detected(Protocol::Git);
        }
        if is_partial_of(candidate, payload) {
            return Probe::Partial;
        }
    }
    Probe::Unknown
}

// -- BitTorrent ------------------------------------------------------------
//
// Unencrypted peer handshake: 0x13 then `BitTorrent protocol`.

fn bittorrent_probe(buf: &[u8]) -> Probe {
    const NAME: &[u8] = b"BitTorrent protocol";
    if buf[0] != 0x13 {
        return Probe::Unknown;
    }
    if buf.len() < 1 + NAME.len() {
        return if is_partial_of(NAME, &buf[1..]) {
            Probe::Partial
        } else {
            Probe::Unknown
        };
    }
    if &buf[1..1 + NAME.len()] == NAME {
        Probe::Detected(Protocol::BitTorrent)
    } else {
        Probe::Unknown
    }
}

// -- ADB -------------------------------------------------------------------
//
// CNXN message: magic, version, maxdata.

fn adb_probe(buf: &[u8]) -> Probe {
    const MAGIC: &[u8] = b"CNXN";
    if !buf.starts_with(MAGIC) {
        return if is_partial_of(MAGIC, buf) {
            Probe::Partial
        } else {
            Probe::Unknown
        };
    }
    if buf.len() < 12 {
        return Probe::Partial;
    }
    Probe::Detected(Protocol::Adb)
}

// -- IRC -------------------------------------------------------------------
//
// Clients open with CAP, PASS, NICK or USER (case-insensitive), each
// followed by whitespace.

fn irc_probe(buf: &[u8]) -> Probe {
    const COMMANDS: [&[u8]; 4] = [b"CAP", b"PASS", b"NICK", b"USER"];
    let lowered: Vec<u8> = buf
        .iter()
        .take(6)
        .map(|byte| byte.to_ascii_lowercase())
        .collect();
    for command in COMMANDS {
        let lowered_command: Vec<u8> = command
            .iter()
            .map(|byte| byte.to_ascii_lowercase())
            .collect();
        if lowered.starts_with(&lowered_command) {
            return match buf.get(command.len()) {
                None => Probe::Partial,
                Some(b' ' | b'\r' | b'\n' | b'\t') => Probe::Detected(Protocol::Irc),
                Some(_) => Probe::Unknown,
            };
        }
        if is_partial_of(&lowered_command, &lowered) {
            return Probe::Partial;
        }
    }
    Probe::Unknown
}

/// MQTT / Minecraft-style varint; returns the value and how many bytes it
/// consumed. `None` when all four available bytes continue the value.
pub(super) fn decode_varint(buf: &[u8]) -> Option<(usize, usize)> {
    let mut value = 0usize;
    for (index, byte) in buf.iter().take(4).enumerate() {
        value |= usize::from(byte & 0x7F) << (7 * index);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sniff::minecraft;

    /// One real-world-shaped first packet per protocol identifier
    /// (upstream `sniff_test.go` style samples).
    fn samples() -> Vec<(Protocol, Vec<u8>)> {
        vec![
            (
                Protocol::Tls,
                tls_client_hello(b"www.example.com", &[b"h2", b"http/1.1"]),
            ),
            (
                Protocol::Http,
                b"GET /index.html HTTP/1.1\r\nHost: a.example\r\n\r\n".to_vec(),
            ),
            (Protocol::Http, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec()),
            (Protocol::Ssh, b"SSH-2.0-OpenSSH_9.6\r\n".to_vec()),
            (
                Protocol::Rdp,
                vec![
                    0x03, 0x00, 0x00, 0x13, 0xE0, 0, 0, 0, 0, 0, 0, 0, 0x19, 0, 8, 0, 0, 0, 0,
                ],
            ),
            (Protocol::Socks, vec![0x05, 0x02, 0x00, 0x01]),
            (
                Protocol::Socks,
                vec![0x04, 0x01, 0x00, 0x50, 10, 0, 0, 1, 0],
            ),
            (
                Protocol::OpenVpn,
                vec![0x38, 0x2A, 0xC5, 0x11, 0, 0, 0, 0, 0, 0],
            ),
            (
                Protocol::Xmpp,
                b"<?xml version='1.0'?><stream:stream to='a.example'>".to_vec(),
            ),
            (Protocol::Mqtt, {
                let mut packet = vec![0x10, 0x0A, 0x00, 0x04];
                packet.extend_from_slice(b"MQTT");
                packet.extend_from_slice(&[0x05, 0x02, 0x00, 0x3C]);
                packet
            }),
            (Protocol::Postgres, vec![0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F]),
            (
                Protocol::Minecraft,
                minecraft_handshake("play.example", 8443),
            ),
            (Protocol::Rtsp, b"OPTIONS * RTSP/1.0\r\n".to_vec()),
            (
                Protocol::Sip,
                b"REGISTER sip:pbx.example SIP/2.0\r\n".to_vec(),
            ),
            (Protocol::Redis, b"*1\r\n$4\r\nPING\r\n".to_vec()),
            (Protocol::Amqp, b"AMQP\x00\x00\x09\x01".to_vec()),
            (Protocol::Amqp, b"AMQP\x00\x01\x00\x00".to_vec()),
            (Protocol::Smb, {
                let mut packet = vec![0x00, 0x00, 0x00, 0x40, 0xFE, b'S', b'M', b'B'];
                packet.extend_from_slice(&[0x28, 0, 0, 0, 0, 0, 0, 0]);
                packet
            }),
            (Protocol::Smb, {
                let mut packet = vec![0x00, 0x00, 0x00, 0x54, 0xFF, b'S', b'M', b'B'];
                packet.extend_from_slice(&[0x72, 0, 0, 0, 0]);
                packet
            }),
            (Protocol::Git, {
                let mut packet = b"001e".to_vec();
                packet.extend_from_slice(b"git-upload-pack /p.git\0host=a\0");
                packet
            }),
            (Protocol::BitTorrent, {
                let mut packet = vec![0x13];
                packet.extend_from_slice(b"BitTorrent protocol");
                packet.extend_from_slice(&[0u8; 8]);
                packet
            }),
            (
                Protocol::Adb,
                b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00\x08\x00\x00\x00".to_vec(),
            ),
            (Protocol::Irc, b"NICK bot\r\n".to_vec()),
            (Protocol::Irc, b"CAP LS 302\r\n".to_vec()),
            (Protocol::Spa, {
                let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                let mut packet: Vec<u8> = (0..96).map(|i| alphabet[i % alphabet.len()]).collect();
                packet.push(b'\n');
                packet
            }),
        ]
    }

    fn tls_client_hello(sni: &[u8], alpn: &[&[u8]]) -> Vec<u8> {
        crate::sniff::tls::tests_support::build_client_hello(sni, alpn)
    }

    fn minecraft_handshake(host: &str, port: u16) -> Vec<u8> {
        minecraft::tests_support::build_handshake(host, port)
    }

    #[test]
    fn probe_each_protocol_with_real_first_packet() {
        for (protocol, packet) in samples() {
            let with_spa = protocol == Protocol::Spa;
            let outcome = detect(&packet, with_spa);
            assert_eq!(
                outcome,
                Probe::Detected(protocol),
                "{protocol} sample must detect as {protocol}"
            );
        }
    }

    #[test]
    fn probe_partial_prefix_waits_for_more() {
        assert_eq!(detect(b"SS", false), Probe::Partial);
        assert_eq!(detect(b"G", false), Probe::Partial);
        assert_eq!(detect(b"AMQ", false), Probe::Partial);
        assert_eq!(detect(&[0x16, 0x03, 0x01, 0x00], false), Probe::Partial);
        assert_eq!(detect(b"XX", false), Probe::Unknown);
        assert_eq!(detect(&[0x09, 0x09], false), Probe::Unknown);
    }

    #[test]
    fn probe_probes_are_mutually_exclusive() {
        let samples = samples();
        for (owner, packet) in &samples {
            let Probe::Detected(detected) = detect(packet, true) else {
                panic!("{owner} sample not detected");
            };
            assert_eq!(detected, *owner, "{owner} sample misdetected as {detected}");
            // No other ordered probe may claim the sample either.
            for probe in ORDERED {
                if let Probe::Detected(protocol) = probe(packet) {
                    assert_eq!(
                        protocol, *owner,
                        "probe for {protocol} claims a {owner} sample"
                    );
                }
            }
        }
    }

    #[test]
    fn probe_ssh_banner_matches_only_complete_prefix() {
        assert_eq!(ssh_probe(b"S"), Probe::Partial);
        assert_eq!(ssh_probe(b"SSH"), Probe::Partial);
        assert_eq!(ssh_probe(b"SSH-"), Probe::Detected(Protocol::Ssh));
        assert_eq!(ssh_probe(b"SSX"), Probe::Unknown);
    }

    #[test]
    fn probe_socks_needs_valid_command_or_method_count() {
        assert_eq!(socks_probe(&[0x04]), Probe::Partial);
        assert_eq!(socks_probe(&[0x04, 0x01]), Probe::Detected(Protocol::Socks));
        assert_eq!(socks_probe(&[0x04, 0x09]), Probe::Unknown);
        assert_eq!(socks_probe(&[0x05, 0x00]), Probe::Unknown);
        assert_eq!(socks_probe(&[0x05, 0x02]), Probe::Detected(Protocol::Socks));
    }

    #[test]
    fn probe_minecraft_rejects_lengths_out_of_range() {
        assert_eq!(minecraft_probe(&[0x03, 0x00]), Probe::Unknown);
        assert_eq!(minecraft_probe(&[0x40, 0x00]), Probe::Partial);
    }

    #[test]
    fn decode_varint_reads_short_forms() {
        assert_eq!(decode_varint(&[0x0B]), Some((11, 1)));
        assert_eq!(decode_varint(&[0x80, 0x02]), Some((256, 2)));
        assert_eq!(decode_varint(&[0x80]), None);
    }
}
