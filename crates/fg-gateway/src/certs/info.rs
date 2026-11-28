//! Certificate information parsing (WP-31 step 2): leaf-certificate DNS
//! and IP SANs, issuer, validity, fingerprint and key matching. The
//! parsing logic migrates from the legacy `crate::tls` (which keeps
//! serving until this module replaces it).
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::sign::CertifiedKey;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

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
        let certificate = first_certificate(cert_pem)?;
        let (_, x509) =
            X509Certificate::from_der(certificate.as_ref()).map_err(|_| InfoError::Unparseable)?;
        let mut info = Self {
            issuer: issuer_name(&x509),
            not_before: unix_time(x509.validity().not_before.timestamp()),
            not_after: unix_time(x509.validity().not_after.timestamp()),
            fingerprint: sha256_fingerprint(certificate.as_ref()),
            ..Self::default()
        };
        let san = x509
            .subject_alternative_name()
            .map_err(|_| InfoError::Unparseable)?;
        for name in san
            .map(|san| &san.value.general_names)
            .into_iter()
            .flatten()
        {
            match name {
                GeneralName::DNSName(dns) => info.dns_names.push(dns.to_string()),
                GeneralName::IPAddress(bytes) => {
                    if let Some(ip) = canonical_ip(bytes) {
                        info.ip_addresses.push(ip);
                    }
                }
                _ => {}
            }
        }
        Ok(info)
    }

    /// Does `cert_pem`'s leaf public key match `key_pem`?
    pub fn key_matches(cert_pem: &str, key_pem: &str) -> Result<bool, InfoError> {
        let certificate = first_certificate(cert_pem)?;
        let key = PrivateKeyDer::pem_slice_iter(key_pem.as_bytes())
            .next()
            .ok_or(InfoError::Unparseable)?
            .map_err(|_| InfoError::Unparseable)?;
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        match CertifiedKey::from_der(vec![certificate], key, &provider) {
            // rustls reports a leaf/key mismatch as an error; surface it
            // as `false` while unparseable material stays an error.
            Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::KeyMismatch)) => {
                Ok(false)
            }
            result => result.map(|_| true).map_err(|_| InfoError::Unparseable),
        }
    }
}

/// The first `CERTIFICATE` section of a PEM (full-chain files carry the
/// leaf first).
fn first_certificate(cert_pem: &str) -> Result<CertificateDer<'static>, InfoError> {
    CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .next()
        .transpose()
        .map_err(|_| InfoError::Unparseable)?
        .ok_or(InfoError::Unparseable)
}

/// The issuer common name, falling back to the whole distinguished name
/// when the certificate has none.
fn issuer_name(x509: &X509Certificate<'_>) -> String {
    let issuer = x509.issuer();
    issuer
        .iter_common_name()
        .next()
        .and_then(|cn| <&str>::try_from(cn).ok())
        .map(str::to_owned)
        .unwrap_or_else(|| issuer.to_string())
}

/// Renders an IP SAN (4 or 16 bytes) in its canonical `IpAddr` form;
/// other lengths are invalid and skipped.
fn canonical_ip(bytes: &[u8]) -> Option<IpAddr> {
    if let Ok(octets) = <[u8; 4]>::try_from(bytes) {
        return Some(IpAddr::V4(Ipv4Addr::from(octets)));
    }
    <[u8; 16]>::try_from(bytes)
        .ok()
        .map(|octets| IpAddr::V6(Ipv6Addr::from(octets)))
}

/// An ASN.1 seconds-since-epoch stamp as `SystemTime`; a few extreme
/// years are out of range, hence the `Option`.
fn unix_time(timestamp: i64) -> Option<SystemTime> {
    match u64::try_from(timestamp) {
        Ok(seconds) => SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds)),
        Err(_) => SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(timestamp.unsigned_abs())),
    }
}

/// SHA-256 of the DER certificate, lowercase hex.
fn sha256_fingerprint(der: &[u8]) -> String {
    use std::fmt::Write as _;

    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der);
    let mut fingerprint = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        let _ = write!(fingerprint, "{byte:02x}");
    }
    fingerprint
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

#[cfg(test)]
mod tests {
    use super::*;

    // Generated offline with rcgen 0.14 (ECDSA P-256, self-signed).
    // Leaf: CN=Ferrumgate Test, O=Ferrumgate; DNS SANs example.com,
    // *.example.com, api.example.com; IP SANs 127.0.0.1, ::1,
    // 192.168.1.10; valid 2026-01-01 .. 2027-01-01 UTC.
    const LEAF_CERT: &str = concat!(
        "-----BEGIN CERTIFICATE-----\n",
        "MIIBuDCCAV6gAwIBAgIUKWPssCtDhk0af/SNCDoOC+yKA0MwCgYIKoZIzj0EAwIw\n",
        "LzEYMBYGA1UEAwwPRmVycnVtZ2F0ZSBUZXN0MRMwEQYDVQQKDApGZXJydW1nYXRl\n",
        "MB4XDTI2MDEwMTAwMDAwMFoXDTI3MDEwMTAwMDAwMFowLzEYMBYGA1UEAwwPRmVy\n",
        "cnVtZ2F0ZSBUZXN0MRMwEQYDVQQKDApGZXJydW1nYXRlMFkwEwYHKoZIzj0CAQYI\n",
        "KoZIzj0DAQcDQgAEZDHpKn6g7Iq0ZWQ4SdgR9VRrlTu4UrPzLb/6odKh4wFA0FO7\n",
        "0eEVoXGUE/vHpyrCmHnvxuF8o0nObqODd3HCB6NYMFYwVAYDVR0RBE0wS4ILZXhh\n",
        "bXBsZS5jb22CDSouZXhhbXBsZS5jb22CD2FwaS5leGFtcGxlLmNvbYcEfwAAAYcQ\n",
        "AAAAAAAAAAAAAAAAAAAAAYcEwKgBCjAKBggqhkjOPQQDAgNIADBFAiB6CQiFvFIN\n",
        "yyavz02N2eggngsf9EuVssIWGDQkTLQZvAIhAIG+MRRcdGdO5+5ROYK5LdkIDHwn\n",
        "MdqKKm63LI10WlT3\n",
        "-----END CERTIFICATE-----\n",
    );
    const LEAF_KEY: &str = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgoYMpTv1DiLy7nFn3\n",
        "GdMhgYq8XlBBMoAbI11CcvBRU+uhRANCAARkMekqfqDsirRlZDhJ2BH1VGuVO7hS\n",
        "s/Mtv/qh0qHjAUDQU7vR4RWhcZQT+8enKsKYee/G4XyjSc5uo4N3ccIH\n",
        "-----END PRIVATE KEY-----\n",
    );
    // Other: no CN (only O=Other Org), DNS SAN other.example.test, valid
    // 2025-01-01 .. 2026-01-01 UTC, distinct key pair.
    const OTHER_CERT: &str = concat!(
        "-----BEGIN CERTIFICATE-----\n",
        "MIIBSzCB8aADAgECAhQ7LwJ92R1N4BFF+HlZZ7JIif8igTAKBggqhkjOPQQDAjAU\n",
        "MRIwEAYDVQQKDAlPdGhlciBPcmcwHhcNMjUwMTAxMDAwMDAwWhcNMjYwMTAxMDAw\n",
        "MDAwWjAUMRIwEAYDVQQKDAlPdGhlciBPcmcwWTATBgcqhkjOPQIBBggqhkjOPQMB\n",
        "BwNCAATVEhw1xwpG8fOOqtYm8yUCzL191ip48siQ2M2Y1IC6/WB4hBuE88aOdtFH\n",
        "oA60jujTsajKtQEEa+Il6LSrkKrpoyEwHzAdBgNVHREEFjAUghJvdGhlci5leGFt\n",
        "cGxlLnRlc3QwCgYIKoZIzj0EAwIDSQAwRgIhALaqSb9HztztnwaZcEVuj0AXWQc4\n",
        "920DGmImNB4KZ8TUAiEAwrF8j4tRh0X4ziw2IsyMKxSPnQ2Wa+XPh8iqseNo/3A=\n",
        "-----END CERTIFICATE-----\n",
    );
    const OTHER_KEY: &str = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgKCxceufc66njRmhY\n",
        "VZrEJ0EPAVGZiz/i3Do4pyL41EChRANCAATVEhw1xwpG8fOOqtYm8yUCzL191ip4\n",
        "8siQ2M2Y1IC6/WB4hBuE88aOdtFHoA60jujTsajKtQEEa+Il6LSrkKrp\n",
        "-----END PRIVATE KEY-----\n",
    );
    const LEAF_FINGERPRINT: &str =
        "ef325ab974a8c16b0a04cba55c948d557e895950dc694bcaf71b3f61a6689f64";
    const OTHER_FINGERPRINT: &str =
        "fed667990758be8f84de4fa97af02ad0523c378354585525c10aa3a159fbd363";

    #[test]
    fn info_parses_san_issuer_and_validity() {
        let info = CertInfo::parse(LEAF_CERT).unwrap();
        assert_eq!(
            info.dns_names,
            ["example.com", "*.example.com", "api.example.com"]
        );
        assert_eq!(
            info.ip_addresses,
            [
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            ]
        );
        assert_eq!(info.issuer, "Ferrumgate Test");
        assert_eq!(
            info.not_before,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1767225600))
        );
        assert_eq!(
            info.not_after,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1798761600))
        );
        assert_eq!(info.fingerprint, LEAF_FINGERPRINT);
    }

    #[test]
    fn info_falls_back_to_distinguished_name_without_cn() {
        let info = CertInfo::parse(OTHER_CERT).unwrap();
        assert_eq!(info.issuer, "O=Other Org");
        assert_eq!(info.dns_names, ["other.example.test"]);
        assert_eq!(info.fingerprint, OTHER_FINGERPRINT);
    }

    #[test]
    fn info_parses_first_certificate_of_full_chain() {
        let info = CertInfo::parse(&format!("{LEAF_CERT}\n{OTHER_CERT}")).unwrap();
        assert_eq!(info.fingerprint, LEAF_FINGERPRINT);
        assert_eq!(info.issuer, "Ferrumgate Test");
        assert_eq!(
            info.dns_names.first().map(String::as_str),
            Some("example.com")
        );
    }

    #[test]
    fn key_matches_pair_and_rejects_mismatch() {
        assert!(CertInfo::key_matches(LEAF_CERT, LEAF_KEY).unwrap());
        assert!(CertInfo::key_matches(OTHER_CERT, OTHER_KEY).unwrap());
        assert!(!CertInfo::key_matches(LEAF_CERT, OTHER_KEY).unwrap());
        assert!(!CertInfo::key_matches(OTHER_CERT, LEAF_KEY).unwrap());
    }

    #[test]
    fn info_rejects_unparseable_pem() {
        assert_eq!(CertInfo::parse("").unwrap_err(), InfoError::Unparseable);
        assert_eq!(
            CertInfo::parse("garbage").unwrap_err(),
            InfoError::Unparseable
        );
        // A private key is not a certificate.
        assert_eq!(
            CertInfo::parse(LEAF_KEY).unwrap_err(),
            InfoError::Unparseable
        );
        assert_eq!(
            CertInfo::key_matches(LEAF_CERT, "").unwrap_err(),
            InfoError::Unparseable
        );
        assert_eq!(
            CertInfo::key_matches(LEAF_CERT, "garbage").unwrap_err(),
            InfoError::Unparseable
        );
        // A certificate is not a private key.
        assert_eq!(
            CertInfo::key_matches(LEAF_CERT, LEAF_CERT).unwrap_err(),
            InfoError::Unparseable
        );
        assert_eq!(InfoError::Unparseable.to_string(), "证书内容无法解析");
    }
}
