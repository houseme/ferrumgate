//! The `file` source (WP-31 step 4): reads `certFile`/`keyFile` under the
//! config dir. The scheduler re-reads every 30 minutes (first pass 30 s
//! after start); content changes reload, unchanged content keeps the old
//! `Arc` (cheap no-op for the index swap).
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::certs::model::Cert;
use crate::certs::provider::LoadedCert;

/// Reads the pair and parses. An entry that is not wired up yet (empty
/// paths, or a certificate file with no content) → `Ok(None)`, same
/// spirit as the stored sources' empty PEM. Missing/unreadable files →
/// error (the entry is configured but broken; the index keeps the last
/// good one).
pub async fn load(cert: &Cert, config_dir: &Path) -> Result<Option<Arc<LoadedCert>>, String> {
    let cert_file = cert.cert_file.trim();
    let key_file = cert.key_file.trim();
    if cert_file.is_empty() || key_file.is_empty() {
        return Ok(None); // not configured yet — nothing loadable
    }
    let cert_path = resolve(config_dir, cert_file);
    let key_path = resolve(config_dir, key_file);
    let cert_pem = tokio::fs::read_to_string(&cert_path)
        .await
        .map_err(|error| format!("读取证书文件失败 {}: {error}", cert_path.display()))?;
    if cert_pem.trim().is_empty() {
        return Ok(None); // entry exists but has no content yet
    }
    let key_pem = tokio::fs::read_to_string(&key_path)
        .await
        .map_err(|error| format!("读取私钥文件失败 {}: {error}", key_path.display()))?;
    LoadedCert::parse(&cert.key, &cert_pem, &key_pem)
        .map(|loaded| Some(Arc::new(loaded)))
        .map_err(|error| error.0)
}

/// Absolute paths pass through unchanged; relative paths anchor at
/// `config_dir`.
fn resolve(config_dir: &Path, raw: &str) -> PathBuf {
    let path = Path::new(raw);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_dir.join(path)
    }
}

/// 64-bit FNV-1a over the file bytes — cheap change detection between
/// scheduler passes (a hash match almost certainly means unchanged).
pub(crate) fn content_hash(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{content_hash, load};
    use crate::certs::model::{Cert, CertSource};

    /// The provider fixture (full chain + private key in one file) split
    /// into its certificate and private key PEM sections.
    fn fixture_pair() -> (String, String) {
        const COMBINED: &str = include_str!("../fixture_key.pem");
        let split = COMBINED
            .find("-----BEGIN PRIVATE KEY-----")
            .expect("fixture carries a private key section");
        let (cert, key) = COMBINED.split_at(split);
        (cert.to_owned(), key.to_owned())
    }

    fn file_cert(cert_file: &str, key_file: &str) -> Cert {
        Cert {
            key: "file-entry".into(),
            source: CertSource::File,
            cert_file: cert_file.into(),
            key_file: key_file.into(),
            ..Cert::default()
        }
    }

    #[tokio::test]
    async fn file_source_loads_pair() {
        let dir = tempdir().unwrap();
        let (cert_pem, key_pem) = fixture_pair();
        let cert_path = dir.path().join("example.pem");
        let key_path = dir.path().join("example.key");
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let cert = file_cert(cert_path.to_str().unwrap(), key_path.to_str().unwrap());
        let loaded = load(&cert, dir.path()).await.unwrap().expect("loads");
        assert_eq!(&*loaded.entry, "file-entry");
        assert!(
            loaded.info.dns_names.iter().any(|name| name == "example.com"),
            "SANs must include example.com: {:?}",
            loaded.info.dns_names
        );
    }

    #[tokio::test]
    async fn file_source_relative_paths() {
        let dir = tempdir().unwrap();
        let (cert_pem, key_pem) = fixture_pair();
        std::fs::create_dir_all(dir.path().join("certs")).unwrap();
        std::fs::create_dir_all(dir.path().join("keys")).unwrap();
        std::fs::write(dir.path().join("certs/example.pem"), &cert_pem).unwrap();
        std::fs::write(dir.path().join("keys/example.key"), &key_pem).unwrap();

        let cert = file_cert("certs/example.pem", "keys/example.key");
        let loaded = load(&cert, dir.path()).await.unwrap().expect("loads");
        assert!(
            loaded.info.dns_names.iter().any(|name| name == "example.com"),
            "relative paths must resolve under config_dir: {:?}",
            loaded.info.dns_names
        );
    }

    #[tokio::test]
    async fn file_source_missing_file() {
        let dir = tempdir().unwrap();
        let (_, key_pem) = fixture_pair();
        let missing = dir.path().join("absent.pem");
        let key_path = dir.path().join("example.key");
        std::fs::write(&key_path, &key_pem).unwrap();

        let cert = file_cert(missing.to_str().unwrap(), key_path.to_str().unwrap());
        // `LoadedCert` has no `Debug`, so no `unwrap_err` here.
        let error = match load(&cert, dir.path()).await {
            Ok(_) => panic!("a missing certificate file must be an error"),
            Err(error) => error,
        };
        assert!(
            error.contains(missing.to_str().unwrap()),
            "error must name the missing path: {error}"
        );
    }

    #[tokio::test]
    async fn file_source_empty_content_is_none() {
        let dir = tempdir().unwrap();
        let (_, key_pem) = fixture_pair();
        let cert_path = dir.path().join("example.pem");
        let key_path = dir.path().join("example.key");
        std::fs::write(&cert_path, "").unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let cert = file_cert(cert_path.to_str().unwrap(), key_path.to_str().unwrap());
        assert!(load(&cert, dir.path()).await.unwrap().is_none());
    }

    #[test]
    fn content_hash_changes_on_content() {
        assert_ne!(content_hash(b"one"), content_hash(b"two"));
        assert_eq!(content_hash(b"same"), content_hash(b"same"));
        // Any single-byte change moves the hash.
        assert_ne!(content_hash(b"same"), content_hash(b"samf"));
    }
}
