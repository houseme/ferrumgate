//! TLS handshake failure kinds (WP-52 §3.3): the eight categories a
//! `tls` jail counts, the rustls-style error-to-kind mapping used by the
//! reporters and the test endpoint, and the counting predicate. Every
//! failure counts — throttling never applies here — but a source behind
//! a trusted proxy (CDN origin), a whitelisted or an already banned
//! address never does.

use std::net::IpAddr;

/// The eight documented failure kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TlsFailKind {
    /// The peer closed the connection during the handshake (port probes;
    /// browsers' speculative preconnects too).
    Eof,
    /// The peer reset the connection.
    Reset,
    /// The peer connected but never completed the handshake.
    Timeout,
    /// Plaintext HTTP, SSLv2, garbage or a too-old protocol version.
    NotTls,
    /// No shared ciphers, key exchange, curves or application protocol.
    NoSharedParams,
    /// The requested name belongs to no site (a site with explicit
    /// domains missing its certificate is a configuration problem and
    /// never reported under this kind).
    UnknownName,
    /// The peer aborted with a TLS alert (usually a client setting).
    Alert,
    /// Anything else.
    Other,
}

impl TlsFailKind {
    /// All kinds, in the documented table order.
    pub const ALL: [TlsFailKind; 8] = [
        TlsFailKind::Eof,
        TlsFailKind::Reset,
        TlsFailKind::Timeout,
        TlsFailKind::NotTls,
        TlsFailKind::NoSharedParams,
        TlsFailKind::UnknownName,
        TlsFailKind::Alert,
        TlsFailKind::Other,
    ];

    /// The stable tag used in jail `filter` lines and on the wire.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Eof => "eof",
            Self::Reset => "reset",
            Self::Timeout => "timeout",
            Self::NotTls => "not_tls",
            Self::NoSharedParams => "no_shared_params",
            Self::UnknownName => "unknown_name",
            Self::Alert => "alert",
            Self::Other => "other",
        }
    }

    /// Parses a `filter` line tag.
    pub fn from_tag(tag: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.tag() == tag)
    }
}

/// One handshake failure as reported by the web service.
#[derive(Clone, Copy, Debug)]
pub struct TlsFail<'a> {
    /// The listener the handshake arrived on.
    pub listener: &'a str,
    /// The peer address (PROXY-protocol restored, canonicalized).
    pub ip: IpAddr,
    pub kind: TlsFailKind,
    /// The underlying error text, for ban reasons and tests.
    pub reason: &'a str,
    /// True when the peer is one of the web service's trusted proxies
    /// (CDN origin nodes); their failures never count.
    pub trusted_proxy: bool,
}

/// Maps a rustls-style handshake error to a failure kind. Matched on
/// lowercased substrings; first match wins, unknown text lands in
/// [`TlsFailKind::Other`]. The web service may override the result (it
/// knows about unknown names before rustls sees them).
pub fn classify(reason: &str) -> TlsFailKind {
    let text = reason.to_lowercase();
    let contains = |needles: &[&str]| needles.iter().any(|needle| text.contains(needle));
    if contains(&["reset", "econnreset"]) {
        return TlsFailKind::Reset;
    }
    if contains(&["timed out", "timeout", "timedout"]) {
        return TlsFailKind::Timeout;
    }
    if contains(&[
        "eof",
        "closed without",
        "unexpected end",
        "incomplete message",
    ]) {
        return TlsFailKind::Eof;
    }
    if contains(&[
        "handshake failure",
        "handshakefailure",
        "no shared",
        "no common",
        "no cipher",
        "no usable",
        "no suitable",
        "no app protocol",
        "no application protocol",
        "peer is incompatible",
        "incompatible",
    ]) {
        return TlsFailKind::NoSharedParams;
    }
    if contains(&[
        "unrecognized name",
        "unknown name",
        "unknown server name",
        "no site for",
        "unknown sni",
        "no certificate for the requested name",
    ]) {
        return TlsFailKind::UnknownName;
    }
    if contains(&[
        "protocol version",
        "protocolversion",
        "plaintext",
        "not a tls",
        "http request",
        "ssl v2",
        "sslv2",
        "legacy record",
        "malformed",
        "invalid record",
        "invalid message",
        "record overflow",
        "too many",
    ]) {
        return TlsFailKind::NotTls;
    }
    if contains(&["alert"]) {
        return TlsFailKind::Alert;
    }
    TlsFailKind::Other
}

/// Whether a TLS jail counts the failure: the listener matches (the
/// jail's empty target = all listeners), the kind is selected, and the
/// hard exclusions hold — trusted-proxy sources, whitelisted addresses
/// and already banned addresses never accumulate.
pub fn tls_jail_counts(
    target: &str,
    kinds: &[TlsFailKind],
    fail: &TlsFail<'_>,
    whitelisted: bool,
    already_banned: bool,
) -> bool {
    if fail.trusted_proxy || whitelisted || already_banned {
        return false;
    }
    if !target.is_empty() && fail.listener != target {
        return false;
    }
    kinds.contains(&fail.kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn fail(kind: TlsFailKind) -> TlsFail<'static> {
        TlsFail {
            listener: "web",
            ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            kind,
            reason: "",
            trusted_proxy: false,
        }
    }

    #[test]
    fn tls_kinds_classified() {
        // All eight kinds have stable tags that round-trip.
        for kind in TlsFailKind::ALL {
            assert_eq!(TlsFailKind::from_tag(kind.tag()), Some(kind));
        }
        assert_eq!(TlsFailKind::from_tag("bogus"), None);

        // The rustls-style mapping covers every category.
        assert_eq!(
            classify("unexpected EOF during handshake"),
            TlsFailKind::Eof
        );
        assert_eq!(classify("connection reset by peer"), TlsFailKind::Reset);
        assert_eq!(classify("client handshake timed out"), TlsFailKind::Timeout);
        assert_eq!(
            classify("received plaintext HTTP request"),
            TlsFailKind::NotTls
        );
        assert_eq!(
            classify("peer is incompatible; no shared curves"),
            TlsFailKind::NoSharedParams
        );
        assert_eq!(classify("unrecognized name"), TlsFailKind::UnknownName);
        assert_eq!(
            classify("received fatal alert: CertificateUnknown"),
            TlsFailKind::Alert
        );
        assert_eq!(
            classify("something completely different"),
            TlsFailKind::Other
        );
        // Alert flavors map before the generic alert catch-all.
        assert_eq!(
            classify("received fatal alert: HandshakeFailure"),
            TlsFailKind::NoSharedParams
        );
        assert_eq!(
            classify("received fatal alert: ProtocolVersion"),
            TlsFailKind::NotTls
        );
    }

    #[test]
    fn tls_fail_from_trusted_proxy_not_counted() {
        let kinds = [TlsFailKind::Eof, TlsFailKind::Reset, TlsFailKind::Timeout];
        let mut probe = fail(TlsFailKind::Eof);
        assert!(tls_jail_counts("", &kinds, &probe, false, false));
        // Hard rule: CDN origin nodes never accumulate failures.
        probe.trusted_proxy = true;
        assert!(!tls_jail_counts("", &kinds, &probe, false, false));
        // Whitelisted and banned addresses do not count either.
        probe.trusted_proxy = false;
        assert!(!tls_jail_counts("", &kinds, &probe, true, false));
        assert!(!tls_jail_counts("", &kinds, &probe, false, true));
        // Listener scoping: empty target matches all, a named target only
        // its own listener.
        assert!(!tls_jail_counts("metrics", &kinds, &probe, false, false));
        probe.listener = "metrics";
        assert!(tls_jail_counts("metrics", &kinds, &probe, false, false));
        // Only selected kinds count.
        probe.listener = "web";
        probe.kind = TlsFailKind::Alert;
        assert!(!tls_jail_counts("", &kinds, &probe, false, false));
    }
}
