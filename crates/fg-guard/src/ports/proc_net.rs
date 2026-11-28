//! `/proc/net/tcp` and `/proc/net/tcp6` parsing (WP-53 实施步骤 2): the
//! kernel text format is pure data, so the parser compiles and is tested
//! on every platform while reading the real files is Linux-only (see
//! [`super::refresh_system`]).
//!
//! Format notes (verified against the kernel's `seq_file` rendering):
//! - one listening socket per line: `sl: local_address rem_address st …`,
//!   TCP state `0A` = LISTEN;
//! - the local address is `HEX:PORT` where the port is plain big-endian
//!   hexadecimal and the address bytes are byte-reversed per 32-bit word
//!   (`0100007F` = `127.0.0.1`, the IPv4 little-endian quirk);
//! - only sockets not bound exclusively to a loopback address count as
//!   open: `127.0.0.0/8` for IPv4, `::1` for IPv6 (wildcard `0.0.0.0` /
//!   `::` count, they cover every interface).

use super::range::{self, Range};

/// The TCP LISTEN state (`st` column).
const TCP_LISTEN: &str = "0A";

/// Parses the content of one proc file into the listening port ranges of
/// non-loopback sockets. `v6` selects the IPv6 address layout (`tcp6`).
pub fn parse_proc_net(content: &str, v6: bool) -> Vec<Range> {
    let mut ports = Vec::new();
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Lines start with `sl:`; keep the shape check strict so header /
        // garbage lines are skipped.
        if fields.len() < 4 || !fields[0].ends_with(':') {
            continue;
        }
        if fields[3] != TCP_LISTEN {
            continue;
        }
        let Some((addr_hex, port_hex)) = fields[1].split_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        if port == 0 {
            continue;
        }
        if !v6 {
            let Some(bytes) = v4_bytes(addr_hex) else {
                continue;
            };
            // 127.0.0.0/8 is loopback-only and invisible from outside.
            if bytes[0] == 127 {
                continue;
            }
        } else {
            let Some(bytes) = v6_bytes(addr_hex) else {
                continue;
            };
            // ::1 is the only IPv6 loopback; such listeners are invisible
            // from outside.
            if is_v6_loopback(&bytes) {
                continue;
            }
        }
        ports.push(port);
    }
    range::merge(ports.into_iter().map(Range::single).collect())
}

/// Reconstructs the four IPv4 address bytes from the 8 hex digits
/// (byte-reversed: `0100007F` → `127,0,0,1`).
fn v4_bytes(addr_hex: &str) -> Option<[u8; 4]> {
    if addr_hex.len() != 8 {
        return None;
    }
    let raw = decode_hex(addr_hex)?;
    Some([raw[3], raw[2], raw[1], raw[0]])
}

/// Reconstructs the sixteen IPv6 address bytes from the 32 hex digits:
/// each 4-byte word is byte-reversed (`00000000000000000000000001000000`
/// is `::1`).
fn v6_bytes(addr_hex: &str) -> Option<[u8; 16]> {
    if addr_hex.len() != 32 {
        return None;
    }
    let raw = decode_hex(addr_hex)?;
    let mut bytes = [0u8; 16];
    for (word, group) in raw.as_chunks::<4>().0.iter().enumerate() {
        for (offset, byte) in group.iter().rev().enumerate() {
            bytes[word * 4 + offset] = *byte;
        }
    }
    Some(bytes)
}

fn is_v6_loopback(bytes: &[u8; 16]) -> bool {
    bytes[..15].iter().all(|byte| *byte == 0) && bytes[15] == 1
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trimmed, realistic `/proc/net/tcp` snapshot: wildcard listeners
    /// on 8080/443, a loopback-only listener (skipped), a loopback
    /// address form `0100007F` (skipped), and a non-LISTEN connection.
    const V4_FIXTURE: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when\n\
         0: 00000000:1F90 00000000:0000 0A 00000000:00000000\n\
         1: 00000000:01BB 00000000:0000 0A 00000000:00000000\n\
         2: 0100007F:0035 00000000:0000 0A 00000000:00000000\n\
         3: 7F000001:1F90 00000000:0000 0A 00000000:00000000\n\
         4: 0A000001:04D2 C0A80102:01BB 01 00000000:00000000\n\
         5: C0A80102:1F91 00000000:0000 0A 00000000:00000000\n";

    #[test]
    fn proc_net_parses_listen_and_skips_loopback() {
        let ports = parse_proc_net(V4_FIXTURE, false);
        assert_eq!(
            ports,
            [Range::single(443), Range { lo: 8080, hi: 8081 }],
            "LISTEN rows only; 127.0.0.1:53 and 127.0.0.1:8080 are loopback-only; \
             the established row (state 01) is not counted"
        );
    }

    #[test]
    fn proc_net_parses_ipv6_and_skips_v6_loopback() {
        // ::1 listener plus two wildcard / site listeners, one non-listen.
        let content = "  sl  local_address remote_address st\n\
             0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A\n\
             1: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 0A\n\
             2: 20010DB8000000000000000000000001:01BB 00000000000000000000000000000000:0000 0A\n\
             3: FE800000000000000000000000000001:0050 00000000000000000000000000000000:0000 06\n";
        let ports = parse_proc_net(content, true);
        assert_eq!(
            ports,
            [Range::single(443), Range::single(8080)],
            "::1 is skipped, wildcard and global addresses count; state 06 is not LISTEN"
        );
    }

    #[test]
    fn proc_net_tolerates_garbage_lines_and_merges() {
        let content =
            "not a table\n\n  0: 00000000:0050 0:0000 0A\nxx\n 1: ZZ:0051 00000000:0000 0A\n";
        assert_eq!(parse_proc_net(content, false), [Range::single(80)]);
    }
}
