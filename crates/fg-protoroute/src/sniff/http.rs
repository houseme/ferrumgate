//! Plain HTTP recognition: the request line (methods, WebDAV verbs and
//! cleartext HTTP/2 prior knowledge, "h2c") decides the protocol; the
//! incremental refinement scans up to [`HTTP_HEAD_MAX`] bytes of headers
//! for the `Host` header. RTSP and SIP share the line scanner but are
//! distinguished by their version token in `detect`.

use super::Probe;
use super::textline::{self, TextState};
use crate::model::{Protocol, limits};

/// The cleartext HTTP/2 connection preface.
pub(super) const H2C_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Request methods accepted on the request line: the standard set, the
/// WebDAV extensions and `PRI` (the h2c preface method).
const METHODS: [&str; 26] = [
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "PATCH",
    "PRI",
    "PROPFIND",
    "PROPPATCH",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
    "REPORT",
    "SEARCH",
    "MKACTIVITY",
    "CHECKOUT",
    "MERGE",
    "VERSION-CONTROL",
    "BASELINE-CONTROL",
    "PURGE",
    "QUERY",
];

/// The state of the first request line in the accumulated buffer.
pub(super) enum LineState<'a> {
    /// No complete line yet (or the line may still grow).
    Partial,
    /// The first line grew past the request-line cap.
    TooLong,
    /// The complete first line, without its CRLF.
    Line(&'a [u8]),
}

/// Returns the first line of `buf`, bounded by the request-line cap.
pub(super) fn first_line(buf: &[u8]) -> LineState<'_> {
    match buf.iter().position(|&byte| byte == b'\n') {
        None => {
            if buf.len() > limits::REQUEST_LINE_MAX {
                LineState::TooLong
            } else {
                LineState::Partial
            }
        }
        Some(end) => {
            let line = &buf[..end];
            let line = if line.last() == Some(&b'\r') {
                &line[..line.len() - 1]
            } else {
                line
            };
            if line.len() > limits::REQUEST_LINE_MAX {
                LineState::TooLong
            } else {
                LineState::Line(line)
            }
        }
    }
}

/// Whether the bytes read so far can still grow into a request line: the
/// leading token is a prefix of (or exactly) one of the methods, with the
/// first space already seen or not yet arrived.
fn request_line_prefix_ok(buf: &[u8]) -> bool {
    let Some(space) = buf.iter().position(|&byte| byte == b' ') else {
        return METHODS
            .iter()
            .any(|method| method.as_bytes().starts_with(buf));
    };
    let token = &buf[..space];
    METHODS.iter().any(|method| method.as_bytes() == token)
}

/// The HTTP probe: h2c preface or `METHOD target HTTP/x.y` request line.
pub(super) fn http_probe(buf: &[u8]) -> Probe {
    if buf.len() < H2C_PREFACE.len() {
        if H2C_PREFACE.starts_with(buf) {
            return Probe::Partial;
        }
    } else if buf.starts_with(H2C_PREFACE) {
        return Probe::Detected(Protocol::Http);
    }
    match first_line(buf) {
        LineState::Partial => {
            if request_line_prefix_ok(buf) {
                Probe::Partial
            } else {
                Probe::Unknown
            }
        }
        LineState::TooLong => Probe::Unknown,
        LineState::Line(line) => {
            if parse_request_line(line).is_some() {
                Probe::Detected(Protocol::Http)
            } else {
                Probe::Unknown
            }
        }
    }
}

/// `METHOD SP target SP HTTP/x.y`: returns the target when the shape
/// matches.
fn parse_request_line(line: &[u8]) -> Option<()> {
    let space = line.iter().position(|&byte| byte == b' ')?;
    let method = &line[..space];
    if !METHODS.iter().any(|m| m.as_bytes() == method) {
        return None;
    }
    let rest = &line[space + 1..];
    let version_start = rest.iter().rposition(|&byte| byte == b' ')? + 1;
    if version_start == rest.len() {
        return None;
    }
    let version = &rest[version_start..];
    if version.len() < 6 || !version.starts_with(b"HTTP/") || !version[5].is_ascii_digit() {
        return None;
    }
    Some(())
}

/// Outcome of the incremental Host scan.
pub(super) enum Step {
    NeedMore,
    Done,
    /// A single header line grew unreasonably large.
    Malformed,
}

/// Advances the Host-header scan over the whole buffer read so far in
/// linear time: each byte is inspected at most once for `\n`.
pub(super) fn feed(state: &mut TextState, buf: &[u8]) -> Step {
    // The h2c preface carries no headers; routing data stays empty.
    if buf.starts_with(H2C_PREFACE) {
        return Step::Done;
    }
    loop {
        let Some((line, after)) = textline::next_line_from(buf, state.line_start, state.scanned)
        else {
            state.scanned = buf.len();
            if buf.len().saturating_sub(state.line_start) > limits::HTTP_HEAD_MAX {
                return Step::Malformed;
            }
            return Step::NeedMore;
        };
        let text = &buf[line];
        state.line_start = after;
        state.scanned = after;
        if text.len() > limits::HTTP_HEAD_MAX {
            return Step::Malformed;
        }
        if text.is_empty() {
            // End of the header block.
            return Step::Done;
        }
        if state.host.is_none()
            && let Some(value) = header_value(text, b"host")
        {
            state.host = textline::normalize_host(&value);
            return Step::Done;
        }
    }
}

/// `Name: value` header lookup, case-insensitive on the name.
fn header_value(line: &[u8], name: &[u8]) -> Option<String> {
    let colon = line.iter().position(|&byte| byte == b':')?;
    let candidate = &line[..colon];
    if candidate.len() != name.len() {
        return None;
    }
    if !candidate
        .iter()
        .zip(name)
        .all(|(a, b)| a.to_ascii_lowercase() == *b)
    {
        return None;
    }
    let value = std::str::from_utf8(&line[colon + 1..]).ok()?;
    Some(value.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_host_header_is_found_incrementally() {
        let request = b"GET /a?b=c HTTP/1.1\r\nAccept: */*\r\nUser-Agent: t\r\nHost: Shop.Example.:8443\r\n\r\n";
        // Every prefix keeps scanning; the state accumulates the same way
        // SniffState re-runs the refinement over the whole buffer.
        for end in 1..=request.len() {
            let mut state = TextState::default();
            match feed(&mut state, &request[..end]) {
                Step::NeedMore => continue,
                Step::Done => {
                    assert_eq!(state.host.as_deref(), Some("shop.example"));
                    return;
                }
                Step::Malformed => panic!("valid request must not be malformed"),
            }
        }
        panic!("request never completed");
    }

    #[test]
    fn http_h2c_prior_knowledge_detected() {
        assert_eq!(http_probe(H2C_PREFACE), Probe::Detected(Protocol::Http));
        // Fragmented preface waits, and the refinement ends without a
        // Host header.
        assert_eq!(http_probe(&H2C_PREFACE[..10]), Probe::Partial);
        let mut state = TextState::default();
        assert!(matches!(feed(&mut state, H2C_PREFACE), Step::Done));
        assert_eq!(state.host, None);
    }

    #[test]
    fn http_request_line_over_8kib_is_unknown() {
        let mut line = b"GET /".to_vec();
        line.resize(limits::REQUEST_LINE_MAX + 10, b'a');
        line.push(b'\n');
        assert_eq!(http_probe(&line), Probe::Unknown);
    }

    #[test]
    fn http_methods_and_versions_gate_detection() {
        assert_eq!(http_probe(b"GE"), Probe::Partial);
        assert_eq!(
            http_probe(b"GET / HTTP/1.1\r\n"),
            Probe::Detected(Protocol::Http)
        );
        assert_eq!(
            http_probe(b"PROPFIND /a HTTP/1.1\r\n"),
            Probe::Detected(Protocol::Http)
        );
        assert_eq!(http_probe(b"get / HTTP/1.1\r\n"), Probe::Unknown);
        assert_eq!(http_probe(b"GET / RTSP/1.0\r\n"), Probe::Unknown);
        assert_eq!(http_probe(b"XLOBBY / HTTP/1.1\r\n"), Probe::Unknown);
    }

    #[test]
    fn http_header_without_host_completes_with_none() {
        let request = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
        let mut state = TextState::default();
        assert!(matches!(feed(&mut state, request), Step::Done));
        assert_eq!(state.host, None);
    }

    #[test]
    fn http_host_header_matching_is_case_insensitive() {
        let request = b"GET / HTTP/1.1\r\nhOsT: mixed.example\r\n\r\n";
        let mut state = TextState::default();
        assert!(matches!(feed(&mut state, request), Step::Done));
        assert_eq!(state.host.as_deref(), Some("mixed.example"));
    }
}
