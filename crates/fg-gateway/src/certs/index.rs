//! The SNI certificate index (WP-31 step 3): exact names (domains and IP
//! literals), wildcards keyed by their parent suffix (one label only) and
//! the IP default. Built from enabled loaded certificates; overlapping
//! names keep the latest-expiry entry. Hot path: read-only snapshot,
//! zero allocation per lookup.
#![allow(dead_code)]

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

/// A loaded certificate as the index stores it: the provider's parsed
/// chain + key + facts (the index reads only the facts).
pub type LoadedCert = crate::certs::provider::LoadedCert;

#[derive(Default)]
pub struct CertIndex {
    /// Exact domains and IP literals.
    exact: HashMap<Arc<str>, Arc<LoadedCert>>,
    /// `*.example.com` → key `example.com`, covering one label.
    wildcard: HashMap<Arc<str>, Arc<LoadedCert>>,
    /// Latest-expiry IP certificate, used when the local address is not
    /// in any certificate (NAT / port forwarding).
    ip_default: Option<Arc<LoadedCert>>,
}

impl CertIndex {
    /// Builds the index from parsed certificates. Entries whose expiry is
    /// later win on name conflicts.
    pub fn build(certs: impl Iterator<Item = Arc<LoadedCert>>) -> Self {
        let mut index = Self::default();
        for cert in certs {
            index.add(&cert);
        }
        index
    }

    /// Selects a certificate for a TLS handshake: normalized SNI exact
    /// match, then one-label wildcard, then (no SNI) the local address,
    /// then `ip_default`.
    pub fn select(&self, server_name: &str, conn_local: Option<IpAddr>) -> Option<Arc<LoadedCert>> {
        let name = normalize_name(server_name);
        if name.is_empty() {
            // No SNI: the client connected by address. Match the local
            // address against IP SANs; when it is not in any certificate
            // (NAT / port forwarding) serve the latest-expiry IP cert.
            if let Some(ip) = conn_local {
                let key = canonical_ip(ip).to_string();
                if let Some(cert) = self.exact.get(key.as_str()) {
                    return Some(Arc::clone(cert));
                }
            }
            return self.ip_default.clone();
        }
        if let Some(cert) = self.exact.get(name.as_ref()) {
            return Some(Arc::clone(cert));
        }
        // `*.example.com` covers one extra label, so the wildcard key is
        // everything after the first dot of the queried name.
        if let Some((_, suffix)) = name.split_once('.')
            && let Some(cert) = self.wildcard.get(suffix)
        {
            return Some(Arc::clone(cert));
        }
        None
    }

    /// Self-check / UI: is a name covered? Empty names are never.
    pub fn has(&self, name: &str) -> bool {
        let name = normalize_name(name);
        if name.is_empty() {
            return false;
        }
        if self.exact.contains_key(name.as_ref()) {
            return true;
        }
        name.split_once('.')
            .is_some_and(|(_, suffix)| self.wildcard.contains_key(suffix))
    }

    /// Is any IP certificate loaded?
    pub fn has_ip(&self) -> bool {
        self.ip_default.is_some()
    }

    /// Indexes one certificate: every DNS SAN as an exact or one-label
    /// wildcard entry, every IP SAN as an exact entry; certificates with
    /// IP SANs compete for `ip_default` by latest expiry.
    fn add(&mut self, cert: &Arc<LoadedCert>) {
        let mut has_ips = false;
        for san in &cert.info.dns_names {
            let name = normalize_name(san);
            if name.is_empty() || name.as_ref() == "*" {
                continue;
            }
            if let Some(parent) = name.strip_prefix("*.") {
                if !parent.is_empty() {
                    keep_latest(&mut self.wildcard, parent, cert);
                }
                continue;
            }
            has_ips |= parse_ip_literal(&name).is_some();
            keep_latest(&mut self.exact, &name, cert);
        }
        for ip in &cert.info.ip_addresses {
            has_ips = true;
            keep_latest(&mut self.exact, &canonical_ip(*ip).to_string(), cert);
        }
        if has_ips {
            let replace = match &self.ip_default {
                Some(current) => later_expiry(cert.not_after, current.not_after),
                None => true,
            };
            if replace {
                self.ip_default = Some(Arc::clone(cert));
            }
        }
    }
}

/// Inserts `cert` under `key` unless the current entry expires later.
fn keep_latest(map: &mut HashMap<Arc<str>, Arc<LoadedCert>>, key: &str, cert: &Arc<LoadedCert>) {
    let replace = match map.get(key) {
        Some(current) => later_expiry(cert.not_after, current.not_after),
        None => true,
    };
    if replace {
        map.insert(Arc::from(key), Arc::clone(cert));
    }
}

/// Does `candidate` expire strictly later than `current`? A certificate
/// with unknown expiry loses against one with a known expiry.
fn later_expiry(candidate: Option<SystemTime>, current: Option<SystemTime>) -> bool {
    match (candidate, current) {
        (Some(candidate), Some(current)) => candidate > current,
        (Some(_), None) => true,
        _ => false,
    }
}

/// Normalizes a name for indexing and lookup: lowercase ASCII, no
/// trailing dot, IP literals (with or without brackets) in canonical
/// form. Borrowed when nothing changes, so canonical SNI lookups do not
/// allocate.
fn normalize_name(name: &str) -> Cow<'_, str> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if let Some(ip) = parse_ip_literal(name) {
        return Cow::Owned(ip.to_string());
    }
    if name.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Cow::Owned(name.to_ascii_lowercase());
    }
    Cow::Borrowed(name)
}

/// Parses an IP literal as it appears in SNI, SANs or local addresses
/// (`1.2.3.4`, `::1`, `[::1]`); IPv4-mapped IPv6 collapses to plain IPv4.
fn parse_ip_literal(name: &str) -> Option<IpAddr> {
    let bare = name
        .strip_prefix('[')
        .and_then(|name| name.strip_suffix(']'))
        .unwrap_or(name);
    bare.parse().ok().map(canonical_ip)
}

/// Canonical form for index keys: IPv4-mapped IPv6 collapses to IPv4.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| IpAddr::V6(v6), IpAddr::V4),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("valid IP literal")
    }

    fn expires_at(days: u64) -> Option<SystemTime> {
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(days * 24 * 60 * 60))
    }

    fn cert(names: &[&str], ips: &[IpAddr], not_after: Option<SystemTime>) -> Arc<LoadedCert> {
        Arc::new(LoadedCert::fixture(
            names.iter().map(|name| (*name).to_string()).collect(),
            ips.to_vec(),
            not_after,
        ))
    }

    #[test]
    fn index_exact_wins_over_wildcard() {
        let exact = cert(&["a.example.com"], &[], expires_at(30));
        let wild = cert(&["*.example.com"], &[], expires_at(40));
        let index = CertIndex::build([exact.clone(), wild.clone()].into_iter());
        let got = index.select("a.example.com", None).expect("exact covered");
        assert!(Arc::ptr_eq(&got, &exact));
        let got = index
            .select("b.example.com", None)
            .expect("wildcard covered");
        assert!(Arc::ptr_eq(&got, &wild));
    }

    #[test]
    fn index_wildcard_covers_one_label_only() {
        let wild = cert(&["*.example.com"], &[], expires_at(30));
        let index = CertIndex::build([wild].into_iter());
        assert!(index.select("b.example.com", None).is_some());
        // Two extra labels are not covered, nor the bare parent domain.
        assert!(index.select("a.b.example.com", None).is_none());
        assert!(index.select("example.com", None).is_none());
    }

    #[test]
    fn index_prefers_latest_expiry_on_overlap() {
        let older = cert(&["shared.example.com"], &[], expires_at(30));
        let newer = cert(
            &["shared.example.com", "*.example.com"],
            &[],
            expires_at(60),
        );
        let index = CertIndex::build([older, newer.clone()].into_iter());
        let got = index.select("shared.example.com", None).expect("covered");
        assert!(Arc::ptr_eq(&got, &newer));
        let got = index.select("any.example.com", None).expect("covered");
        assert!(Arc::ptr_eq(&got, &newer));

        // Unknown expiry never displaces a known one, in either order.
        let known = cert(&["dup.example.com"], &[], expires_at(30));
        let unknown = cert(&["dup.example.com"], &[], None);
        let index = CertIndex::build([unknown.clone(), known.clone()].into_iter());
        let got = index.select("dup.example.com", None).expect("covered");
        assert!(Arc::ptr_eq(&got, &known));
        let index = CertIndex::build([known.clone(), unknown].into_iter());
        let got = index.select("dup.example.com", None).expect("covered");
        assert!(Arc::ptr_eq(&got, &known));
    }

    #[test]
    fn select_normalizes_case_trailing_dot_and_ip_sni() {
        let c = cert(
            &["Example.COM", "Sub.Example.COM"],
            &[ip("192.0.2.10"), ip("2001:db8::1")],
            expires_at(30),
        );
        let index = CertIndex::build([c.clone()].into_iter());
        for name in ["EXAMPLE.com.", "example.Com", "EXAMPLE.COM"] {
            let got = index.select(name, None).expect("domain normalized");
            assert!(Arc::ptr_eq(&got, &c), "{name} should hit exactly");
        }
        let got = index.select("sub.EXAMPLE.com.", None).expect("normalized");
        assert!(Arc::ptr_eq(&got, &c));
        // IP SNI spellings all collapse to the canonical SAN form.
        for name in [
            "192.0.2.10",
            "192.0.2.10.",
            "::ffff:192.0.2.10",
            "[2001:0db8::0001]",
            "2001:DB8::1",
        ] {
            let got = index.select(name, None).expect("ip sni normalized");
            assert!(Arc::ptr_eq(&got, &c), "{name} should hit the IP SAN");
        }
    }

    #[test]
    fn select_without_sni_uses_local_ip_then_default() {
        let a = cert(&[], &[ip("192.0.2.10")], expires_at(30));
        let b = cert(&[], &[ip("192.0.2.11")], expires_at(60));
        let index = CertIndex::build([a.clone(), b.clone()].into_iter());
        assert!(index.has_ip());
        // Local address in a certificate → that certificate.
        let got = index.select("", Some(ip("192.0.2.10"))).expect("local ip");
        assert!(Arc::ptr_eq(&got, &a));
        // IPv4-mapped local address (dual-stack socket) matches the v4 SAN.
        let got = index
            .select("", Some(ip("::ffff:192.0.2.10")))
            .expect("mapped");
        assert!(Arc::ptr_eq(&got, &a));
        // NAT: local address not in any certificate → latest-expiry IP cert.
        let got = index.select("", Some(ip("203.0.113.9"))).expect("default");
        assert!(Arc::ptr_eq(&got, &b));
        // No address at all → same default.
        let got = index.select("", None).expect("default");
        assert!(Arc::ptr_eq(&got, &b));
    }

    #[test]
    fn select_unknown_name_is_none() {
        let index = CertIndex::build([cert(&["example.com"], &[], expires_at(30))].into_iter());
        assert!(index.select("other.example", None).is_none());
        // No wildcard loaded: subdomains do not match the exact entry.
        assert!(index.select("sub.example.com", None).is_none());
        // No IP certificate: the no-SNI path has nothing to fall back to.
        assert!(index.select("", None).is_none());
    }

    #[test]
    fn has_certificate_false_for_empty_name() {
        let index = CertIndex::build(
            [cert(
                &["example.com", "*.example.net"],
                &[ip("192.0.2.10")],
                expires_at(30),
            )]
            .into_iter(),
        );
        assert!(!index.has(""));
        assert!(index.has("example.com"));
        assert!(index.has("a.example.net"));
        assert!(index.has("EXAMPLE.com."));
        assert!(index.has("192.0.2.10"));
        // Wildcards cover one label only.
        assert!(!index.has("a.b.example.net"));
        assert!(!index.has("example.net"));
        assert!(!index.has("192.0.2.99"));
    }
}
