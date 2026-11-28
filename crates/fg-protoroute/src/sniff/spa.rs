//! SPA (Single Packet Authorization) recognition for the port-knock
//! handoff (upstream `probeSPA`): a knock packet is a single line of
//! base64-ish text. The probe only runs when the rule actually carries a
//! `spa` route, so ordinary text protocols are never shadowed by it.
//! The runner hands the captured packet to the knock module and closes the
//! connection without replying or forwarding.

use super::Probe;
use crate::model::limits;

/// Whether one byte can appear inside a SPA packet: printable, no space.
fn in_charset(byte: u8) -> bool {
    (0x21..=0x7E).contains(&byte)
}

/// The packet content is the buffer without a trailing CRLF.
fn content(buf: &[u8]) -> &[u8] {
    let mut end = buf.len();
    if buf[..end].last() == Some(&b'\n') {
        end -= 1;
        if end > 0 && buf[end - 1] == b'\r' {
            end -= 1;
        }
    }
    &buf[..end]
}

fn valid_content(buf: &[u8]) -> bool {
    content(buf).iter().all(|&byte| in_charset(byte))
}

/// The SPA probe: a printable single line long enough to be a knock
/// packet. Runs last in the detect order; a trailing newline is not
/// required, because clients are expected to send the packet in one go and
/// close the connection.
pub(super) fn spa_probe(buf: &[u8]) -> Probe {
    if !valid_content(buf) {
        return Probe::Unknown;
    }
    if content(buf).len() >= limits::SPA_MIN {
        Probe::Detected(crate::model::Protocol::Spa)
    } else {
        Probe::Partial
    }
}

/// Outcome of the packet-completion refinement.
pub(super) enum Step {
    NeedMore,
    Done,
    NotProtocol,
}

/// Advances the completion check over the whole buffer read so far.
pub(super) fn feed(buf: &[u8]) -> Step {
    if buf.len() > limits::SPA_MAX || !valid_content(buf) {
        return Step::NotProtocol;
    }
    let len = content(buf).len();
    if len >= limits::SPA_MIN {
        if buf.last() == Some(&b'\n') {
            Step::Done
        } else {
            // Waiting for the line end — or for the client to close the
            // connection (the runner completes the packet at EOF).
            Step::NeedMore
        }
    } else if buf.last() == Some(&b'\n') {
        Step::NotProtocol
    } else {
        Step::NeedMore
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Protocol;

    fn packet(len: usize, newline: bool) -> Vec<u8> {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        let mut out: Vec<u8> = (0..len).map(|i| alphabet[i % alphabet.len()]).collect();
        if newline {
            out.push(b'\n');
        }
        out
    }

    #[test]
    fn spa_probe_accepts_single_base64_line() {
        assert_eq!(spa_probe(&packet(96, true)), Probe::Detected(Protocol::Spa));
        // No trailing newline: still detected, the packet completes at EOF.
        assert_eq!(
            spa_probe(&packet(96, false)),
            Probe::Detected(Protocol::Spa)
        );
    }

    #[test]
    fn spa_probe_waits_for_minimum_length() {
        assert_eq!(spa_probe(&packet(16, false)), Probe::Partial);
        assert_eq!(spa_probe(&packet(16, true)), Probe::Partial);
    }

    #[test]
    fn spa_probe_rejects_spaces_and_binary() {
        assert_eq!(
            spa_probe(b"GET / HTTP/1.1\r\nHost: a.example\r\n"),
            Probe::Unknown
        );
        assert_eq!(spa_probe(&[0x00, 0x01, 0x02]), Probe::Unknown);
        assert_eq!(
            spa_probe(
                &packet(100, false)
                    .into_iter()
                    .chain(*b" ")
                    .collect::<Vec<u8>>(),
            ),
            Probe::Unknown
        );
    }

    #[test]
    fn spa_feed_completes_on_newline_and_rejects_short_lines() {
        assert!(matches!(feed(&packet(96, true)), Step::Done));
        assert!(matches!(feed(&packet(96, false)), Step::NeedMore));
        assert!(matches!(feed(&packet(16, true)), Step::NotProtocol));
        assert!(matches!(feed(&packet(16, false)), Step::NeedMore));
        let mut oversized = packet(limits::SPA_MAX + 1, false);
        oversized.push(b'\n');
        assert!(matches!(feed(&oversized), Step::NotProtocol));
    }
}
