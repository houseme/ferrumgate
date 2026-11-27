//! Certificate sources (WP-31 step 4): acme and upload load the entry's
//! stored PEM; file reads `certFile`/`keyFile` (re-read periodically);
//! fnos follows the system certificate registry. Every loader yields a
//! [`provider::LoadedCert`] or a per-entry error string.
#![allow(dead_code)]

use std::path::Path;
use std::sync::Arc;

use super::model::{Cert, CertSource};
use super::provider::LoadedCert;

/// Loads one enabled entry from its source. `config_dir` anchors relative
/// `certFile`/`keyFile` paths. `None` = nothing loadable yet (an ACME
/// entry that never issued) — not an error.
pub async fn load_entry(
    cert: &Cert,
    config_dir: &Path,
) -> Result<Option<Arc<LoadedCert>>, String> {
    match cert.source {
        CertSource::Acme | CertSource::Upload => super::source::stored::load(cert),
        CertSource::File => super::source::file::load(cert, config_dir).await,
        CertSource::FnOS => super::source::fnos::load(cert).await,
    }
}

/// The system registry file for fnOS certificates; missing → the fnos
/// source is unavailable (option hidden in the UI).
pub fn fnos_registry_path() -> &'static Path {
    Path::new("/usr/trim/etc/network_cert_all.conf")
}

pub(crate) mod stored;
pub mod file;
pub mod fnos;
