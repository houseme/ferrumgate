//! Minecraft handshake parsing (upstream `minecraft.go`): modern servers
//! receive `[varint length][0x00][protocol version][server address][port]
//! [next state]`; the server address drives routing, and the suffixes
//! Forge, BungeeCord and TCPShield append after `\0` are ignored. Clients
//! before 1.6 ping with the legacy `0xFE 0x01 0xFA` server-list query.

use super::detect::decode_varint;
use crate::model::limits;

/// Minimum / maximum packet body length (upstream: 7 - 2048).
pub(super) const MIN: usize = limits::MINECRAFT_MIN;
pub(super) const MAX: usize = limits::MINECRAFT_MAX;

/// The legacy 1.6 server-list ping marker.
const LEGACY: &[u8] = &[0xFE, 0x01, 0xFA];

/// Whether `buf` carries the complete legacy marker.
pub(super) fn probe_legacy(buf: &[u8]) -> bool {
    buf.starts_with(LEGACY)
}

/// Whether `buf` is still a prefix of the legacy marker.
pub(super) fn legacy_prefix(buf: &[u8]) -> bool {
    LEGACY.starts_with(buf)
}

/// Decoded varint packet length.
pub(super) enum Length {
    /// The varint is complete but cannot be a Minecraft length.
    Invalid,
    /// The varint spans more bytes than have arrived.
    NeedMore,
    /// The body length and the number of bytes consumed by the length varint.
    Within(usize, usize),
}

/// Decodes the leading varint of a modern handshake packet.
pub(super) fn packet_length(buf: &[u8]) -> Length {
    match decode_varint(buf) {
        Some((len, used)) if (MIN..=MAX).contains(&len) => Length::Within(len, used),
        Some(_) => Length::Invalid,
        None => {
            // All bytes continue the varint: only valid while a longer
            // varint could still decode into the accepted range.
            if buf.len() < 3 && buf.iter().all(|byte| byte & 0x80 != 0) {
                Length::NeedMore
            } else {
                Length::Invalid
            }
        }
    }
}

/// Refinement state for a modern handshake (kept for parity with the
/// upstream layout; the packet length is re-derived from the buffer).
#[derive(Debug, Default)]
pub struct McState {
    total: Option<usize>,
}

/// Outcome of the packet refinement.
pub(super) enum Step {
    NeedMore,
    /// The packet is complete; the server address (suffix-stripped) or
    /// `None` for the legacy ping.
    Done(Option<String>),
    /// The packet is complete but not a Minecraft handshake.
    NotProtocol,
}

/// Advances the refinement over the whole buffer read so far.
pub(super) fn feed(state: &mut McState, buf: &[u8]) -> Step {
    if probe_legacy(buf) {
        state.total = None;
        return Step::Done(None);
    }
    let (len, varint_len) = match packet_length(buf) {
        Length::Within(len, used) => (len, used),
        Length::NeedMore => return Step::NeedMore,
        Length::Invalid => return Step::NotProtocol,
    };
    if buf.len() < varint_len + len {
        return Step::NeedMore;
    }
    let Some(parsed) = parse_body(&buf[varint_len..varint_len + len]) else {
        return Step::NotProtocol;
    };
    state.total = Some(len);
    Step::Done(parsed)
}

/// Parses the packet body: id 0, protocol version varint, server address
/// string, port, next state. The address is cleaned of the `\0` suffixes
/// Forge / BungeeCord / TCPShield append and lower-cased.
pub(super) fn parse_body(body: &[u8]) -> Option<Option<String>> {
    let mut pos = 0;
    let (id, used) = decode_varint(&body[pos..])?;
    if id != 0 {
        return None;
    }
    pos += used;
    let (_version, used) = decode_varint(&body[pos..])?;
    pos += used;
    let (host_len, used) = decode_varint(&body[pos..])?;
    pos += used;
    if host_len > 255 || pos + host_len + 2 >= body.len() {
        return None;
    }
    let host = std::str::from_utf8(&body[pos..pos + host_len]).ok()?;
    pos += host_len;
    // 2-byte server port.
    pos += 2;
    let (next_state, used) = decode_varint(&body[pos..])?;
    pos += used;
    if !matches!(next_state, 1..=3) || pos != body.len() {
        return None;
    }
    Some(strip_suffixes(host))
}

/// Forge (`…\0FML3\0`), BungeeCord (`…\0ip\0uuid\0`-ish) and TCPShield
/// (`…\0realip…`) data trails the real hostname after `\0`.
fn strip_suffixes(host: &str) -> Option<String> {
    let host = host.split('\0').next().unwrap_or("");
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.len() > 255 {
        return None;
    }
    Some(host)
}

/// Varint encoding used by the test builders.
#[cfg(test)]
pub(super) fn varint(mut value: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

#[cfg(test)]
pub(super) mod tests_support {
    use super::varint;

    /// Builds a modern handshake packet for `host` and `port`.
    pub fn build_handshake(host: &str, port: u16) -> Vec<u8> {
        let mut body = vec![0x00];
        body.extend_from_slice(&varint(765)); // Minecraft 1.20.4 protocol version
        body.extend_from_slice(&varint(host.len()));
        body.extend_from_slice(host.as_bytes());
        body.extend_from_slice(&port.to_be_bytes());
        body.push(0x01);
        let mut packet = varint(body.len());
        packet.extend_from_slice(&body);
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::build_handshake;
    use super::*;

    fn feed_all(packet: &[u8]) -> Step {
        let mut state = McState::default();
        feed(&mut state, packet)
    }

    #[test]
    fn minecraft_server_address_extracted() {
        let packet = build_handshake("Play.Example.", 25565);
        let Step::Done(host) = feed_all(&packet) else {
            panic!("expected Done");
        };
        assert_eq!(host.as_deref(), Some("play.example"));
    }

    #[test]
    fn minecraft_server_address_ignores_suffixes() {
        for (raw, want) in [
            ("mc.example\x00FML3\x00", Some("mc.example")),
            (
                "mc.example\x00192.0.2.7:51000\x00f4f9-…-uuid\x00",
                Some("mc.example"),
            ),
            ("mc.example\x00realip=203.0.113.9\x00", Some("mc.example")),
            ("Mc.Example.", Some("mc.example")),
            ("", None),
        ] {
            let packet = build_handshake(raw, 25565);
            let Step::Done(host) = feed_all(&packet) else {
                panic!("{raw:?} expected Done");
            };
            assert_eq!(host.as_deref(), want, "suffix case {raw:?}");
        }
    }

    #[test]
    fn minecraft_legacy_ping_detected_without_address() {
        let mut packet = vec![0xFE, 0x01, 0xFA, 0x00, 0x0B];
        packet.extend_from_slice(b"MC|PingHost");
        let Step::Done(host) = feed_all(&packet) else {
            panic!("legacy ping expected Done");
        };
        assert_eq!(host, None);
    }

    #[test]
    fn minecraft_packet_size_bounds_rejected() {
        // Length 3 is below the 7-byte minimum.
        let mut small = vec![0x03, 0x00, 0x7F, 0x01];
        small.extend_from_slice(&[0; 4]);
        assert!(matches!(feed_all(&small), Step::NotProtocol));
        // A declared length beyond the 2048 cap.
        let mut packet = varint(4096);
        packet.extend_from_slice(&[0x00; 32]);
        assert!(matches!(feed_all(&packet), Step::NotProtocol));
    }

    #[test]
    fn minecraft_partial_packet_waits() {
        let packet = build_handshake("split.example", 25565);
        for end in 1..packet.len() {
            let mut state = McState::default();
            assert!(matches!(feed(&mut state, &packet[..end]), Step::NeedMore));
        }
        assert!(matches!(feed_all(&packet), Step::Done(Some(_))));
    }

    #[test]
    fn minecraft_id_zero_required() {
        let mut body = vec![0x01]; // packet id 1: not a handshake
        body.push(0x01);
        body.extend_from_slice(&[0x00, 0x01]);
        let mut packet = varint(body.len());
        packet.extend_from_slice(&body);
        assert!(matches!(feed_all(&packet), Step::NotProtocol));
    }

    #[test]
    fn varint_round_trips() {
        for value in [0usize, 7, 127, 128, 2047, 2048] {
            let encoded = varint(value);
            assert_eq!(
                super::super::detect::decode_varint(&encoded),
                Some((value, encoded.len()))
            );
        }
    }
}
