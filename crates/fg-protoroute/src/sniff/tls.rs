//! TLS ClientHello parsing (upstream `tls.go`): the hello may arrive
//! fragmented across several handshake records (up to
//! [`crate::model::limits::CLIENT_HELLO_MAX`]); SNI and ALPN are extracted
//! for routing. Truncated or inconsistent input is [`Step::Malformed`],
//! which the runner treats like "no matching route" (default target).
//!
//! Nothing here terminates TLS: the sniffed bytes are forwarded verbatim
//! and the private key never leaves the backend.

use crate::model::limits;

/// Per-connection state: the accumulated handshake message bytes plus how
/// much of the record stream has already been consumed.
#[derive(Debug, Default)]
pub struct TlsState {
    handshake: Vec<u8>,
    records_consumed: usize,
}

impl TlsState {
    /// Bytes of the handshake message accumulated so far (the cap check
    /// in `sniff::SniffState` reads this).
    pub(super) fn handshake_len(&self) -> usize {
        self.handshake.len()
    }
}

/// Outcome of advancing the ClientHello refinement.
pub(super) enum Step {
    NeedMore,
    Done {
        server_name: Option<String>,
        alpn: Vec<String>,
    },
    Malformed,
}

/// Advances the ClientHello state machine over the whole buffer read so
/// far. The accumulated handshake bytes grow monotonically, so only the
/// record tail after `records_consumed` is parsed again.
pub(super) fn feed(state: &mut TlsState, buf: &[u8]) -> Step {
    let mut offset = state.records_consumed;
    while offset + 5 <= buf.len() {
        let content_type = buf[offset];
        let version_major = buf[offset + 1];
        let record_len = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]) as usize;
        if content_type != 22 || version_major != 3 || record_len == 0 || record_len > 18_432 {
            return Step::Malformed;
        }
        let record_end = offset + 5 + record_len;
        if record_end > buf.len() {
            // Record incomplete: wait for more bytes.
            break;
        }
        state
            .handshake
            .extend_from_slice(&buf[offset + 5..record_end]);
        offset = record_end;
        state.records_consumed = offset;
    }
    if state.handshake.len() > limits::CLIENT_HELLO_MAX {
        return Step::Malformed;
    }
    if state.handshake.len() < 4 {
        return Step::NeedMore;
    }
    let message_len = u32::from(state.handshake[1]) << 16
        | u32::from(state.handshake[2]) << 8
        | u32::from(state.handshake[3]);
    if message_len > limits::CLIENT_HELLO_MAX as u32 {
        return Step::Malformed;
    }
    if state.handshake.len() < 4 + message_len as usize {
        return Step::NeedMore;
    }
    if state.handshake[0] != 0x01 {
        // Not a ClientHello: the probe accepted it on the record header
        // alone, so other handshake types (a server hello of a response)
        // land here.
        return Step::Malformed;
    }
    let body = &state.handshake[4..4 + message_len as usize];
    match parse_client_hello(body) {
        Some((server_name, alpn)) => Step::Done { server_name, alpn },
        None => Step::Malformed,
    }
}

fn u16_at(bytes: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]))
}

/// Parses the ClientHello body: client version, random, session id,
/// cipher suites, compression methods, then the extensions (SNI type 0,
/// ALPN type 16).
fn parse_client_hello(body: &[u8]) -> Option<(Option<String>, Vec<String>)> {
    let mut pos = 2 + 32;
    let session_len = *body.get(pos)? as usize;
    pos += 1 + session_len;
    let cipher_len = u16_at(body, pos)? as usize;
    pos += 2 + cipher_len;
    let compression_len = *body.get(pos)? as usize;
    pos += 1 + compression_len;
    if pos > body.len() {
        return None;
    }
    let mut server_name = None;
    let mut alpn = Vec::new();
    if pos + 2 <= body.len() {
        let extensions_total = u16_at(body, pos)? as usize;
        pos += 2;
        if pos + extensions_total > body.len() {
            return None;
        }
        let extensions_end = pos + extensions_total;
        while pos + 4 <= extensions_end {
            let ext_type = u16_at(body, pos)?;
            let ext_len = u16_at(body, pos + 2)? as usize;
            let data_start = pos + 4;
            if data_start + ext_len > extensions_end {
                return None;
            }
            let data = body.get(data_start..data_start + ext_len)?;
            match ext_type {
                0x0000 if server_name.is_none() => server_name = parse_sni(data),
                0x0010 => {
                    let _ = parse_alpn(data, &mut alpn);
                }
                _ => {}
            }
            pos = data_start + ext_len;
        }
    }
    Some((server_name, alpn))
}

/// SNI extension: `server_name_list` with one host-name entry.
fn parse_sni(data: &[u8]) -> Option<String> {
    let list_len = u16_at(data, 0)? as usize;
    let end = (2 + list_len).min(data.len());
    let mut pos = 2;
    while pos + 3 <= end {
        let name_type = data[pos];
        let name_len = u16_at(data, pos + 1)? as usize;
        let start = pos + 3;
        let stop = (start + name_len).min(end);
        pos = start + name_len;
        if name_type != 0 {
            continue;
        }
        let raw = data.get(start..stop)?;
        if raw.is_empty() {
            continue;
        }
        let name = std::str::from_utf8(raw).ok()?;
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty()
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.' || byte == b'_'
            })
        {
            return None;
        }
        return Some(name);
    }
    None
}

/// ALPN extension: a list of `opaque` protocol ids; keep the printable
/// ASCII ones in wire order.
fn parse_alpn(data: &[u8], out: &mut Vec<String>) -> Option<()> {
    let list_len = u16_at(data, 0)? as usize;
    let end = (2 + list_len).min(data.len());
    let mut pos = 2;
    while pos < end {
        let id_len = *data.get(pos)? as usize;
        let start = pos + 1;
        let stop = (start + id_len).min(end);
        pos = start + id_len;
        let raw = data.get(start..stop)?;
        if raw.is_empty() {
            continue;
        }
        if let Ok(id) = std::str::from_utf8(raw)
            && id.bytes().all(|byte| byte.is_ascii_graphic())
        {
            out.push(id.to_owned());
        }
    }
    Some(())
}

#[cfg(test)]
pub(super) mod tests_support {
    use crate::model::limits;

    /// Builds a single-record ClientHello carrying SNI and ALPN, in the
    /// shape `parse_client_hello` expects. Test-only helper shared with
    /// the detect samples.
    pub fn build_client_hello(sni: &[u8], alpn: &[&[u8]]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x11; 32]);
        body.push(0x00); // session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        body.extend_from_slice(&[0x01, 0x00]); // compression methods
        let mut extensions = Vec::new();
        if !sni.is_empty() {
            let mut list = vec![0x00];
            list.extend_from_slice(&(sni.len() as u16).to_be_bytes());
            list.extend_from_slice(sni);
            let mut ext_data = Vec::with_capacity(2 + list.len());
            ext_data.extend_from_slice(&(list.len() as u16).to_be_bytes());
            ext_data.extend_from_slice(&list);
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

    /// Splits the record payload into `chunks` records, each carrying part
    /// of the handshake message (the fragmented-ClientHello shape).
    pub fn split_records(record: &[u8], chunks: usize) -> Vec<u8> {
        let payload = &record[5..];
        let per_chunk = (payload.len() / chunks).max(1);
        let mut out = Vec::new();
        let mut offset = 0;
        while offset < payload.len() {
            let stop = (offset + per_chunk).min(payload.len());
            out.extend_from_slice(&[0x16, 0x03, 0x01]);
            out.extend_from_slice(&((stop - offset) as u16).to_be_bytes());
            out.extend_from_slice(&payload[offset..stop]);
            offset = stop;
        }
        out
    }

    /// A ClientHello whose declared handshake length exceeds the cap.
    pub fn oversized_hello() -> Vec<u8> {
        let payload_len: u16 = 4 + 64;
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&payload_len.to_be_bytes());
        record.push(0x01);
        // 3-byte handshake length = 65537 (> 64 KiB cap).
        record.extend_from_slice(&[0x01, 0x00, 0x01]);
        assert!(record.len() < limits::CLIENT_HELLO_MAX);
        record.extend_from_slice(&[0u8; 64]);
        record
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{build_client_hello, oversized_hello, split_records};
    use super::*;

    fn feed_all(record: &[u8]) -> Step {
        let mut state = TlsState::default();
        feed(&mut state, record)
    }

    #[test]
    fn tls_sni_and_alpn_extracted() {
        let record = build_client_hello(b"Shop.Example.", &[b"h2", b"http/1.1"]);
        let Step::Done { server_name, alpn } = feed_all(&record) else {
            panic!("expected Done");
        };
        assert_eq!(server_name.as_deref(), Some("shop.example"));
        assert_eq!(alpn, ["h2", "http/1.1"]);
    }

    #[test]
    fn tls_hello_split_across_records() {
        let record = build_client_hello(b"split.example", &[b"http/1.1"]);
        let fragmented = split_records(&record, 7);
        // Feed every prefix with a fresh state, mirroring how SniffState
        // re-runs the refinement over the whole buffer each read.
        let mut done = None;
        for end in 1..=fragmented.len() {
            let mut full = TlsState::default();
            match feed(&mut full, &fragmented[..end]) {
                Step::Done { server_name, alpn } => {
                    done = Some((server_name, alpn));
                    break;
                }
                Step::NeedMore => {}
                Step::Malformed => panic!("fragmented hello must not be malformed"),
            }
        }
        let (server_name, alpn) = done.expect("fragmented hello completed");
        assert_eq!(server_name.as_deref(), Some("split.example"));
        assert_eq!(alpn, ["http/1.1"]);
    }

    #[test]
    fn tls_hello_malformed_inputs() {
        // A truncated record never completes: NeedMore, not an error.
        let mut truncated = vec![0x16, 0x03, 0x01, 0x00, 0x10];
        truncated.extend_from_slice(&[0x01, 0x00, 0x00, 0x08, 0x03, 0x03]);
        let mut state = TlsState::default();
        assert!(matches!(feed(&mut state, &truncated), Step::NeedMore));
        // A declared handshake message beyond the cap.
        assert!(matches!(feed_all(&oversized_hello()), Step::Malformed));
        // A server hello (handshake type 2) is not a ClientHello.
        let mut response = vec![0x16, 0x03, 0x03, 0x00, 0x07];
        response.extend_from_slice(&[0x02, 0x00, 0x00, 0x03, 0x03, 0x03, 0x11]);
        assert!(matches!(feed_all(&response), Step::Malformed));
        // A record that is not a handshake record at all.
        let alert = vec![0x15, 0x03, 0x01, 0x00, 0x02, 0x0A, 0x00];
        let mut state = TlsState::default();
        assert!(matches!(feed(&mut state, &alert), Step::Malformed));
        // A ClientHello header whose body is truncated stays Pending
        // (NeedMore) — the runner's timeout converts it to the default
        // target; garbage that violates the structure is Malformed.
        let mut broken = vec![0x16, 0x03, 0x01, 0x00, 0x04];
        broken.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        let mut state = TlsState::default();
        assert!(matches!(feed(&mut state, &broken), Step::Malformed));
    }

    #[test]
    fn tls_hello_without_extensions_or_sni() {
        let record = build_client_hello(b"", &[]);
        let Step::Done { server_name, alpn } = feed_all(&record) else {
            panic!("expected Done");
        };
        assert_eq!(server_name, None);
        assert!(alpn.is_empty());
    }

    #[test]
    fn tls_hello_over_64k_rejected() {
        // A declared handshake message beyond the cap is Malformed even
        // before the bytes arrive; the cap check in SniffState mirrors it
        // for accumulated bytes.
        let oversized = oversized_hello();
        assert!(matches!(feed_all(&oversized), Step::Malformed));
    }

    #[test]
    fn tls_handshake_len_tracks_accumulation() {
        let record = build_client_hello(b"a.example", &[]);
        let fragmented = split_records(&record, 4);
        let mut state = TlsState::default();
        let half = fragmented.len() / 2;
        assert!(matches!(
            feed(&mut state, &fragmented[..half]),
            Step::NeedMore
        ));
        assert!(state.handshake_len() > 0);
        assert!(matches!(feed(&mut state, &fragmented), Step::Done { .. }));
    }
}
