//! Protocol sniffing (WP-35 §3.3 "识别"): pure, incremental recognizers
//! over the first bytes a client sends. [`SniffState::feed`] advances the
//! state machine one read chunk at a time without any I/O — the runner
//! owns the socket, the timeouts and the cap on how much is read.
//!
//! Two phases run per connection:
//!
//! 1. **detect** ([`detect`]): ordered prefix probes decide whether the
//!    bytes belong to one of the 21 protocol identifiers. Prefixes that
//!    could still complete (`SS`, the start of `SSH-`) yield
//!    [`Probe::Partial`] and the caller keeps reading.
//! 2. **pending refinement**: protocols that carry routing information
//!    (TLS SNI/ALPN, HTTP Host, Minecraft server address) or need their
//!    full packet (SPA) hand over to a small state machine that watches
//!    the accumulated buffer.

pub mod detect;
pub mod http;
pub mod minecraft;
pub mod spa;
pub mod textline;
pub mod tls;

use crate::model::{Protocol, limits};

/// Result of one prefix probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    /// Not enough bytes yet to say anything at all.
    NeedMore,
    /// The protocol was identified.
    Detected(Protocol),
    /// The bytes could still become this protocol (`SS` of `SSH-`); keep
    /// reading.
    Partial,
    /// The bytes can never become this protocol.
    Unknown,
}

/// What one connection turned out to be.
#[derive(Clone, Debug, PartialEq)]
pub struct SniffResult {
    pub protocol: Protocol,
    /// TLS SNI or Minecraft server address (lower-case, Forge /
    /// BungeeCord / TCPShield suffixes stripped).
    pub server_name: Option<String>,
    /// ALPN ids announced by a TLS ClientHello, in client order.
    pub alpn: Vec<String>,
    /// HTTP `Host` header value.
    pub host: Option<String>,
    /// Every byte read so far; the runner must forward these before the
    /// passthrough stream.
    pub raw: Vec<u8>,
}

/// Outcome of feeding one chunk.
#[derive(Clone, Debug, PartialEq)]
pub enum SniffOutcome {
    /// Keep reading (within the sniff timeout).
    NeedMore,
    /// The protocol (and its routing data) was identified.
    Done(SniffResult),
    /// The data belongs to no recognizable protocol — a candidate for the
    /// default target.
    NotProtocol,
    /// Something that looked parseable could not be parsed (a broken
    /// ClientHello) — also a default-target candidate.
    Malformed,
}

/// Refinement states entered once `detect` identified a protocol that
/// carries routing information.
#[derive(Debug)]
enum Pending {
    ClientHello(tls::TlsState),
    HttpHost(textline::TextState),
    Minecraft(minecraft::McState),
    Spa,
}

/// Incremental sniffing state for one connection. Feed the bytes read
/// from the client; on [`SniffOutcome::Done`] forward
/// [`SniffResult::raw`] before anything else read afterwards.
#[derive(Debug)]
pub struct SniffState {
    buf: Vec<u8>,
    pending: Option<Pending>,
    read: usize,
    with_spa: bool,
}

impl SniffState {
    /// A fresh state. SPA probes run only when the rule actually has a
    /// `spa` route (upstream `probeSPA` gating).
    pub fn new(with_spa: bool) -> Self {
        Self {
            buf: Vec::with_capacity(limits::READ_CHUNK),
            pending: None,
            read: 0,
            with_spa,
        }
    }

    /// Whether SPA detection is enabled for this connection.
    pub fn with_spa(&self) -> bool {
        self.with_spa
    }

    /// Total bytes fed so far.
    pub fn read(&self) -> usize {
        self.read
    }

    /// The accumulated raw bytes read so far (used when routing unmatched or
    /// malformed streams to the default target without losing any byte).
    pub fn buffered(&self) -> &[u8] {
        &self.buf
    }

    /// Consumes the buffered bytes for zero-loss forwarding to the default
    /// target.
    pub fn take_raw(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    /// Whether the state machine is currently waiting for the rest of a
    /// SPA packet. A client that sends such a packet in one go and closes
    /// makes the packet complete at EOF.
    pub fn spa_pending(&self) -> bool {
        matches!(self.pending, Some(Pending::Spa))
    }

    /// Completes a pending SPA packet at EOF: the client sent it in one
    /// go and closed, which upstream treats as the packet delimiter.
    /// Returns `None` when the state machine is not in the SPA pending.
    pub fn finish_spa(&mut self) -> Option<SniffResult> {
        if matches!(self.pending, Some(Pending::Spa)) {
            Some(Self::result(
                &self.buf,
                Protocol::Spa,
                None,
                Vec::new(),
                None,
            ))
        } else {
            None
        }
    }

    /// Advances the state machine with one read chunk. Pure: no I/O, and
    /// arbitrary inputs never panic.
    pub fn feed(&mut self, chunk: &[u8]) -> SniffOutcome {
        self.buf.extend_from_slice(chunk);
        self.read += chunk.len();
        if self.pending.is_none() {
            return self.detect_phase();
        }
        self.step_pending()
    }

    /// Phase 1: run the ordered probes. Re-runs from the start of the
    /// buffer on every feed, so a transient `Partial` from one probe does
    /// not block a more specific one that becomes decidable later.
    fn detect_phase(&mut self) -> SniffOutcome {
        match detect::detect(&self.buf, self.with_spa) {
            Probe::NeedMore | Probe::Partial => {
                // Regular protocols are decided within the sniff cap; TLS and
                // HTTP receive their own larger caps once detected.
                if self.buf.len() >= limits::SNIFF_BUFFER_MAX {
                    SniffOutcome::NotProtocol
                } else {
                    SniffOutcome::NeedMore
                }
            }
            Probe::Unknown => SniffOutcome::NotProtocol,
            Probe::Detected(protocol) => {
                self.pending = Some(match protocol {
                    Protocol::Tls => Pending::ClientHello(tls::TlsState::default()),
                    Protocol::Http => Pending::HttpHost(textline::TextState::default()),
                    Protocol::Minecraft => Pending::Minecraft(minecraft::McState::default()),
                    // `spa` is only ever detected when the probes are
                    // enabled, so the pending always has a route behind it.
                    Protocol::Spa => Pending::Spa,
                    // Everything else is decided by the first bytes alone.
                    _ => {
                        return SniffOutcome::Done(Self::result(
                            &self.buf,
                            protocol,
                            None,
                            Vec::new(),
                            None,
                        ));
                    }
                });
                self.step_pending()
            }
        }
    }

    /// Phase 2: advance the pending refinement over the whole buffer.
    fn step_pending(&mut self) -> SniffOutcome {
        match self.pending.as_mut().expect("pending state") {
            Pending::ClientHello(state) => match tls::feed(state, &self.buf) {
                tls::Step::NeedMore => {
                    if state.handshake_len() > limits::CLIENT_HELLO_MAX {
                        SniffOutcome::Malformed
                    } else {
                        SniffOutcome::NeedMore
                    }
                }
                tls::Step::Done { server_name, alpn } => SniffOutcome::Done(Self::result(
                    &self.buf,
                    Protocol::Tls,
                    server_name,
                    alpn,
                    None,
                )),
                tls::Step::Malformed => SniffOutcome::Malformed,
            },
            Pending::HttpHost(state) => {
                let capped = &self.buf[..self.buf.len().min(limits::HTTP_HEAD_MAX)];
                match http::feed(state, capped) {
                    http::Step::NeedMore => {
                        if self.buf.len() >= limits::HTTP_HEAD_MAX {
                            // The headers grew past the scan cap without a Host
                            // header: still HTTP, just without routing data.
                            SniffOutcome::Done(Self::result(
                                &self.buf,
                                Protocol::Http,
                                None,
                                Vec::new(),
                                state.host.clone(),
                            ))
                        } else {
                            SniffOutcome::NeedMore
                        }
                    }
                    http::Step::Done => SniffOutcome::Done(Self::result(
                        &self.buf,
                        Protocol::Http,
                        None,
                        Vec::new(),
                        state.host.clone(),
                    )),
                    http::Step::Malformed => SniffOutcome::Malformed,
                }
            }
            Pending::Minecraft(state) => match minecraft::feed(state, &self.buf) {
                minecraft::Step::NeedMore => SniffOutcome::NeedMore,
                minecraft::Step::Done(server_name) => SniffOutcome::Done(Self::result(
                    &self.buf,
                    Protocol::Minecraft,
                    server_name,
                    Vec::new(),
                    None,
                )),
                minecraft::Step::NotProtocol => SniffOutcome::NotProtocol,
            },
            Pending::Spa => match spa::feed(&self.buf) {
                spa::Step::NeedMore => {
                    if self.buf.len() > limits::SPA_MAX {
                        SniffOutcome::NotProtocol
                    } else {
                        SniffOutcome::NeedMore
                    }
                }
                spa::Step::Done => SniffOutcome::Done(Self::result(
                    &self.buf,
                    Protocol::Spa,
                    None,
                    Vec::new(),
                    None,
                )),
                spa::Step::NotProtocol => SniffOutcome::NotProtocol,
            },
        }
    }

    fn result(
        buf: &[u8],
        protocol: Protocol,
        server_name: Option<String>,
        alpn: Vec<String>,
        host: Option<String>,
    ) -> SniffResult {
        SniffResult {
            protocol,
            server_name,
            alpn,
            host,
            raw: buf.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared sample table lives in detect.rs; the state machine tests
    /// only exercise the phase transitions.
    #[test]
    fn feed_detects_without_pending_immediately() {
        let mut state = SniffState::new(false);
        let outcome = state.feed(b"SSH-2.0-OpenSSH_9.6\r\n");
        match outcome {
            SniffOutcome::Done(result) => {
                assert_eq!(result.protocol, Protocol::Ssh);
                assert_eq!(result.raw, b"SSH-2.0-OpenSSH_9.6\r\n");
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn feed_partial_prefix_keeps_waiting_across_chunks() {
        let mut state = SniffState::new(false);
        assert_eq!(state.feed(b"SS"), SniffOutcome::NeedMore);
        assert_eq!(
            state.feed(b"H-2.0-dropbear\r\n"),
            SniffOutcome::Done(SniffResult {
                protocol: Protocol::Ssh,
                server_name: None,
                alpn: Vec::new(),
                host: None,
                raw: b"SSH-2.0-dropbear\r\n".to_vec(),
            })
        );
    }

    #[test]
    fn feed_unknown_data_reports_not_protocol() {
        let mut state = SniffState::new(false);
        assert_eq!(state.feed(b"XX not a protocol"), SniffOutcome::NotProtocol);
    }

    #[test]
    fn spa_probe_only_runs_when_enabled() {
        // A base64-ish line looks like a SPA packet only when the rule has
        // a spa route; otherwise the detect phase reports NotProtocol.
        let packet: Vec<u8> = std::iter::repeat_n(b'a', 80).chain(*b"\n").collect();
        let mut without = SniffState::new(false);
        assert_eq!(without.feed(&packet), SniffOutcome::NotProtocol);
        let mut with = SniffState::new(true);
        assert!(matches!(with.feed(&packet), SniffOutcome::Done(_)));
    }

    #[test]
    fn sniff_never_panics_on_random_input() {
        // Deterministic LCG: arbitrary bytes in arbitrary chunk sizes must
        // always produce an outcome, never a panic.
        let mut seed: u64 = 0x2024_1128;
        let mut next = move || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as u8
        };
        for round in 0..64 {
            let mut state = SniffState::new(round % 2 == 0);
            let mut fed = 0;
            while fed < limits::SNIFF_BUFFER_MAX + limits::CLIENT_HELLO_MAX {
                let len = (next() as usize % 300) + 1;
                let chunk: Vec<u8> = (0..len).map(|_| next()).collect();
                let outcome = state.feed(&chunk);
                fed += chunk.len();
                if outcome != SniffOutcome::NeedMore {
                    break;
                }
            }
        }
    }

    #[test]
    fn sniff_stops_at_caps_and_stays_linear() {
        // A valid method token followed by a line that never ends keeps
        // the HTTP probe in Partial until the request-line cap, then
        // terminates with NotProtocol after O(cap / chunk) feeds.
        let mut state = SniffState::new(false);
        let mut chunk = b"GET ".to_vec();
        chunk.resize(limits::READ_CHUNK, b'a');
        let mut feeds = 0;
        loop {
            feeds += 1;
            if let outcome @ (SniffOutcome::NotProtocol
            | SniffOutcome::Done(_)
            | SniffOutcome::Malformed) = state.feed(&chunk)
            {
                assert_eq!(outcome, SniffOutcome::NotProtocol);
                break;
            }
            assert!(feeds <= (limits::REQUEST_LINE_MAX / limits::READ_CHUNK) + 2);
        }
    }
}
