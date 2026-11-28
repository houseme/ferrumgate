//! The engine's view of one request (WP-55 §3.2 `RequestHead` refined for
//! the first engine tier): method, host, path, query string, headers,
//! user agent, client address and the body excerpt handed over by the
//! caller. Everything is borrowed — building a `Request` copies nothing,
//! so evaluation on the hot path stays allocation-free unless a rule
//! actually hits.
//!
//! The body is an excerpt ("主体摘要"): the integration layer buffers at
//! most the configured inspection size and passes what it has; the engine
//! additionally truncates the view to [`crate::limits`] during matching so
//! a misbehaving caller cannot widen the cost. Bypass decisions
//! (admin sessions, trusted users) are integration-layer concerns and are
//! deliberately not modeled here.

use std::net::IpAddr;

/// One request header as borrowed name / value pair.
#[derive(Clone, Copy, Debug)]
pub struct HeaderPair<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

impl<'a> HeaderPair<'a> {
    pub const fn new(name: &'a str, value: &'a str) -> Self {
        Self { name, value }
    }
}

/// The request description the engine evaluates against.
#[derive(Clone, Copy, Debug, Default)]
pub struct Request<'a> {
    /// Upper-cased HTTP method, e.g. `GET`.
    pub method: &'a str,
    /// Host as sent (Host header or :authority), without the port.
    pub host: &'a str,
    /// Percent-decoded-or-not path exactly as the caller routes it
    /// (engine rules see the raw path text).
    pub path: &'a str,
    /// Raw query string without the leading `?` (may be empty).
    pub query: &'a str,
    /// `User-Agent` header value (empty when absent).
    pub user_agent: &'a str,
    /// Client address as determined by the caller (socket, trusted
    /// forwarding header, ...); `None` when unknown.
    pub client_ip: Option<IpAddr>,
    /// Body excerpt, `None` when there is no body or body inspection is
    /// skipped (skip paths, streaming uploads, gRPC over HTTP/2).
    pub body: Option<&'a [u8]>,
    /// All request headers; duplicates allowed, lookups take the first
    /// case-insensitive match.
    pub headers: &'a [HeaderPair<'a>],
}

impl<'a> Request<'a> {
    /// First header whose name equals `name` ASCII-case-insensitively.
    pub fn header(&self, name: &str) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|pair| pair.name.eq_ignore_ascii_case(name))
            .map(|pair| pair.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request<'a>(
        method: &'a str,
        path: &'a str,
        headers: &'a [HeaderPair<'a>],
        body: Option<&'a [u8]>,
    ) -> Request<'a> {
        Request {
            method,
            host: "example.com",
            path,
            query: "",
            user_agent: "test-agent",
            client_ip: None,
            body,
            headers,
        }
    }

    #[test]
    fn header_lookup_ignores_name_case() {
        let headers = [
            HeaderPair::new("Content-Type", "text/html"),
            HeaderPair::new("X-Marked", "second"),
        ];
        let req = request("GET", "/", &headers, None);
        assert_eq!(req.header("content-type"), Some("text/html"));
        assert_eq!(req.header("CONTENT-TYPE"), Some("text/html"));
        assert_eq!(req.header("x-marked"), Some("second"));
    }

    #[test]
    fn header_lookup_takes_the_first_match() {
        let headers = [
            HeaderPair::new("X-A", "first"),
            HeaderPair::new("X-A", "second"),
        ];
        let req = request("GET", "/", &headers, None);
        assert_eq!(req.header("x-a"), Some("first"));
    }

    #[test]
    fn header_lookup_on_missing_header_is_none() {
        let headers = [HeaderPair::new("X-A", "1")];
        let req = request("GET", "/", &headers, None);
        assert_eq!(req.header("x-b"), None);
    }
}
