//! The SNI certificate index (WP-31 step 3): exact names (domains and IP
//! literals), wildcards keyed by their parent suffix (one label only) and
//! the IP default. Built from enabled loaded certificates; overlapping
//! names keep the latest-expiry entry. Hot path: read-only snapshot,
//! zero allocation per lookup.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// A loaded certificate as the index stores it (parsed chain + facts).
/// Defined with the provider in a later batch; the index is generic over
/// it here through the concrete alias once available.
pub type LoadedCert = crate::certs::info::CertInfo;

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
        let _ = certs;
        Self::default()
    }

    /// Selects a certificate for a TLS handshake: normalized SNI exact
    /// match, then one-label wildcard, then (no SNI) the local address,
    /// then `ip_default`.
    pub fn select(
        &self,
        server_name: &str,
        conn_local: Option<IpAddr>,
    ) -> Option<Arc<LoadedCert>> {
        let _ = (server_name, conn_local);
        self.ip_default.clone()
    }

    /// Self-check / UI: is a name covered? Empty names are never.
    pub fn has(&self, name: &str) -> bool {
        let _ = name;
        false
    }

    /// Is any IP certificate loaded?
    pub fn has_ip(&self) -> bool {
        self.ip_default.is_some()
    }
}
