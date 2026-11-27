//! Certificate information parsing (WP-31 step 2): leaf-certificate DNS
//! and IP SANs, issuer, validity, fingerprint and key matching. The
//! parsing logic migrates from the legacy `crate::tls` (which keeps
//! serving until this module replaces it).
#![allow(dead_code)]

use std::time::SystemTime;

/// Parsed leaf-certificate facts for display, renewal decisions and the
/// SNI index.
#[derive(Clone, Debug, Default)]
pub struct CertInfo {
    /// DNS SANs (exact form as in the cert).
    pub dns_names: Vec<String>,
    /// IP SANs, rendered canonically.
    pub ip_addresses: Vec<std::net::IpAddr>,
    pub issuer: String,
    pub not_before: Option<SystemTime>,
    pub not_after: Option<SystemTime>,
    /// SHA-256 fingerprint, lowercase hex.
    pub fingerprint: String,
}

impl CertInfo {
    /// Parses the first certificate of a full-chain PEM.
    pub fn parse(cert_pem: &str) -> Result<Self, InfoError> {
        let _ = cert_pem;
        Err(InfoError::Unparseable)
    }

    /// Does `cert_pem`'s leaf public key match `key_pem`?
    pub fn key_matches(cert_pem: &str, key_pem: &str) -> Result<bool, InfoError> {
        let _ = (cert_pem, key_pem);
        Err(InfoError::Unparseable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfoError {
    Unparseable,
}

impl std::fmt::Display for InfoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "证书内容无法解析")
    }
}

impl std::error::Error for InfoError {}
