//! Real client-address resolution behind (possibly chained) trusted
//! proxies, and the internal-address predicate behind LAN-only access.
//! Pure functions: the caller supplies the proxy-trust configuration and
//! the local NIC addresses (refreshed periodically elsewhere).

use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use ipnet::IpNet;
use serde::Serialize;

/// Addresses of proxies whose forwarded headers may be believed. Loopback
/// is always trusted; `local` holds the machine's NIC addresses (the
/// caller refreshes the cache as DHCP and IPv6 prefixes change) and
/// `extra` holds operator-configured ranges.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyTrust {
    /// `disableProxyHeaders` off means enabled.
    pub enabled: bool,
    /// This machine's current addresses.
    pub local: Vec<IpAddr>,
    /// Operator-configured trusted ranges.
    pub extra: Vec<IpNet>,
}

/// The resolved origin of a request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientAddr {
    pub ip: IpAddr,
    /// The forwarding proxy's address when the chain ends at a proxy we
    /// cannot verify further (e.g. a gateway); absent for direct or fully
    /// verified chains.
    pub via: Option<SocketAddr>,
    /// The address was established over a trusted link.
    pub verified: bool,
}

/// Loopback, private, link-local, carrier-grade NAT (100.64.0.0/10) and
/// IPv6 unique-local addresses.
pub fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || is_cgnat(v4)
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_unspecified()
        }
    }
}

/// 100.64.0.0/10.
pub fn is_cgnat(v4: std::net::Ipv4Addr) -> bool {
    let octets = v4.octets();
    octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
}

/// Whether a TCP peer may have its forwarded headers believed.
pub fn trusts_peer(peer: IpAddr, trust: &ProxyTrust) -> bool {
    if !trust.enabled {
        return false;
    }
    if peer.is_loopback() || trust.local.contains(&peer) {
        return true;
    }
    trust.extra.iter().any(|range| range.contains(&peer))
}

/// Resolves the client address. Forwarded headers are believed only when
/// the TCP peer is a trusted proxy; `X-Forwarded-For` is walked right to
/// left, skipping trusted proxies, taking the first untrusted address.
pub fn resolve(
    peer: SocketAddr,
    forwarded_for: Option<&str>,
    real_ip: Option<&str>,
    trust: &ProxyTrust,
) -> ClientAddr {
    if !trusts_peer(peer.ip(), trust) {
        return ClientAddr {
            ip: peer.ip(),
            via: None,
            verified: false,
        };
    }
    let from_forwarded = forwarded_for
        .map(parse_chain)
        .filter(|chain| !chain.is_empty())
        .map(|chain| walk_chain(chain, peer, trust));
    let from_real = real_ip.and_then(parse_address);
    match (from_forwarded, from_real) {
        (None, None) => ClientAddr {
            ip: peer.ip(),
            via: Some(peer),
            verified: false,
        },
        (Some(found), None) => finish(found, peer),
        (None, Some(ip)) => ClientAddr {
            ip,
            via: Some(peer),
            verified: true,
        },
        (Some(forwarded_ip), Some(real_ip)) => {
            // When the two headers disagree, a public address beats an
            // internal one: a forged internal value must not bypass
            // LAN-only access. Otherwise X-Forwarded-For wins.
            let ip =
                if forwarded_ip != real_ip && is_internal(forwarded_ip) && !is_internal(real_ip) {
                    real_ip
                } else {
                    forwarded_ip
                };
            ClientAddr {
                ip,
                via: Some(peer),
                verified: true,
            }
        }
    }
}

type ChainEnd = IpAddr;

fn finish(found: ChainEnd, peer: SocketAddr) -> ClientAddr {
    ClientAddr {
        ip: found,
        via: Some(peer),
        // Both walk outcomes report an address vouched for by a proxy we
        // operate, so either way the link was trusted end to end.
        verified: true,
    }
}

fn parse_chain(value: &str) -> Vec<IpAddr> {
    value
        .split(',')
        .filter_map(|item| parse_address(item.trim()))
        .collect()
}

fn parse_address(text: &str) -> Option<IpAddr> {
    // Bracketed IPv6 with a port suffix is not valid here; the proxy list
    // carries bare addresses.
    text.parse().ok()
}

fn walk_chain(chain: Vec<IpAddr>, peer: SocketAddr, trust: &ProxyTrust) -> ChainEnd {
    let trusted = |ip: IpAddr| {
        ip == peer.ip()
            || ip.is_loopback()
            || trust.local.contains(&ip)
            || trust.extra.iter().any(|range| range.contains(&ip))
    };
    // Right to left: skip proxies we operate, take the first untrusted.
    for ip in chain.iter().rev() {
        if !trusted(*ip) {
            return *ip;
        }
    }
    // Every hop was ours: the leftmost claim is the most specific we have.
    *chain.first().unwrap_or(&peer.ip())
}

/// How often the caller should refresh the local-address cache.
pub const LOCAL_REFRESH: Duration = Duration::from_secs(30);

/// Snapshot helper kept next to the trust config so callers share one
/// refresh cadence.
#[derive(Debug)]
pub struct LocalCache {
    addresses: Vec<IpAddr>,
    refreshed: Instant,
}

impl LocalCache {
    pub fn expired(&self) -> bool {
        self.refreshed.elapsed() >= LOCAL_REFRESH
    }

    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn trust() -> ProxyTrust {
        ProxyTrust {
            enabled: true,
            local: vec!["192.168.1.2".parse().unwrap()],
            extra: vec!["10.0.0.0/8".parse().unwrap()],
        }
    }

    fn peer() -> SocketAddr {
        "127.0.0.1:5000".parse().unwrap()
    }

    #[test]
    fn resolve_ignores_headers_from_untrusted_peer() {
        let outsider: SocketAddr = "203.0.113.9:4434".parse().unwrap();
        let resolved = resolve(
            outsider,
            Some("198.51.100.7"),
            Some("198.51.100.8"),
            &trust(),
        );
        assert_eq!(resolved.ip, "203.0.113.9".parse::<IpAddr>().unwrap());
        assert!(!resolved.verified);
        assert_eq!(resolved.via, None);
        // Disabled trust behaves the same even for loopback peers.
        let mut disabled = trust();
        disabled.enabled = false;
        let resolved = resolve(peer(), Some("198.51.100.7"), None, &disabled);
        assert_eq!(resolved.ip, "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn resolve_walks_forwarded_for_right_to_left() {
        // client → proxy1(10.0.0.5) → proxy2(10.0.0.6) → us
        let resolved = resolve(
            peer(),
            Some("198.51.100.7, 10.0.0.5, 10.0.0.6"),
            None,
            &trust(),
        );
        assert_eq!(resolved.ip, "198.51.100.7".parse::<IpAddr>().unwrap());
        assert!(resolved.verified);
        assert_eq!(resolved.via, Some(peer()));
        // A forged client-side claim of a public address with everything
        // else trusted still resolves to the first untrusted hop.
        let resolved = resolve(
            peer(),
            Some("203.0.113.99, 198.51.100.7, 10.0.0.5"),
            None,
            &trust(),
        );
        assert_eq!(resolved.ip, "198.51.100.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn resolve_prefers_public_when_one_is_internal() {
        // Real-IP internal, forwarded public: the public one wins.
        let resolved = resolve(peer(), Some("203.0.113.4"), Some("192.168.1.50"), &trust());
        assert_eq!(resolved.ip, "203.0.113.4".parse::<IpAddr>().unwrap());
        // Real-IP public, forwarded internal: still the public one.
        let resolved = resolve(peer(), Some("192.168.1.50"), Some("203.0.113.4"), &trust());
        assert_eq!(resolved.ip, "203.0.113.4".parse::<IpAddr>().unwrap());
        // Disagreeing but both public: X-Forwarded-For wins.
        let resolved = resolve(peer(), Some("203.0.113.4"), Some("203.0.113.5"), &trust());
        assert_eq!(resolved.ip, "203.0.113.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn resolve_marks_unverifiable_via() {
        // Headers from a trusted peer but an empty chain: nothing verified.
        let resolved = resolve(peer(), Some(""), Some(""), &trust());
        assert_eq!(resolved.ip, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(resolved.via, Some(peer()));
        assert!(!resolved.verified);
        // A trusted-only chain is verified but still via the proxy.
        let resolved = resolve(peer(), Some("10.0.0.5"), None, &trust());
        assert!(resolved.verified);
        assert_eq!(resolved.via, Some(peer()));
    }

    #[test]
    fn is_internal_covers_cgnat_and_ula() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.9.9",
            "192.168.0.20",
            "169.254.1.2",
            "100.64.0.1",
            "100.127.255.254",
            "fe80::1",
            "fd00::5",
            "::1",
        ] {
            assert!(is_internal(ip.parse().unwrap()), "{ip} should be internal");
        }
        for ip in [
            "203.0.113.1",
            "198.51.100.2",
            "8.8.8.8",
            "100.63.255.254", // just below CGNAT
            "100.128.0.0",    // just above CGNAT
            "2606:4700::1",
        ] {
            assert!(!is_internal(ip.parse().unwrap()), "{ip} should be public");
        }
        let _ = Ipv4Addr::LOCALHOST;
    }

    #[test]
    fn local_addresses_are_trusted_peers() {
        let nic: SocketAddr = "192.168.1.2:8123".parse().unwrap();
        let resolved = resolve(nic, Some("203.0.113.4"), None, &trust());
        assert_eq!(resolved.ip, "203.0.113.4".parse::<IpAddr>().unwrap());
        // Extra ranges count as trusted too.
        let relay: SocketAddr = "10.0.0.6:9000".parse().unwrap();
        let resolved = resolve(relay, Some("203.0.113.4"), None, &trust());
        assert_eq!(resolved.ip, "203.0.113.4".parse::<IpAddr>().unwrap());
    }
}
