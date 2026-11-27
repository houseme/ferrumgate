//! The fnOS system-certificate source (WP-31 step 10, optional slice):
//! fnOS renews system certificates into fresh directories and registers
//! them in `/usr/trim/etc/network_cert_all.conf`. We look the entry's
//! domain up in that registry every scheduler pass and load whatever
//! location it now points at; a domain removed from the registry yields
//! `Ok(None)` — the caller keeps the last loaded `Arc` and reports the
//! removal as an error in status.
//!
//! # Registry format assumptions
//!
//! No upstream `fnos.go` snapshot is available in this repository, so
//! the registry is read with a deliberately lenient line parser
//! (WP-31 §3.3). The assumptions, each enforced in [`parse_registry`]:
//!
//! * every non-blank line whose first non-blank character is not `#`
//!   is `domain path` separated by whitespace; fields beyond the first
//!   two are ignored and lines with fewer than two fields are skipped;
//! * `path` must be absolute — relative paths are skipped;
//! * domains are compared lowercased with trailing dots removed (see
//!   [`normalize_domain`]); a later line for the same domain overwrites
//!   the earlier one (renewals land in fresh directories);
//! * the file is capped at [`FNOS_INDEX_LIMIT`] bytes: everything past
//!   the cap is ignored, including a line cut mid-way.
//!
//! Certificate locations (assumed file names too): a directory
//! registration is expected to hold `privkey.pem` plus either
//! `fullchain.pem` (preferred) or `cert.pem`; a plain file is read as
//! the full chain with the private key expected beside it as
//! `privkey.pem`.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::AsyncReadExt as _;

use crate::certs::model::Cert;
use crate::certs::provider::LoadedCert;

/// Registry read cap: 4 MiB (WP-31 §3.3, upstream `fnosIndexLimit`).
/// Content past the cap — including a line cut mid-way — is ignored.
pub(crate) const FNOS_INDEX_LIMIT: usize = 4 * 1024 * 1024;

/// Is the fnOS source available on this host? The registry file must
/// exist (absent → the option is hidden, never an error).
pub fn available() -> bool {
    crate::certs::source::fnos_registry_path().exists()
}

/// Parses the registry into (domain, certificate-location) pairs under
/// the assumptions documented at the module root; a later line for the
/// same domain overwrites the earlier one.
pub fn parse_registry(bytes: &str) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = Vec::new();
    for line in bytes.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(domain), Some(path)) = (fields.next(), fields.next()) else {
            continue;
        };
        if !Path::new(path).is_absolute() {
            continue;
        }
        let domain = normalize_domain(domain);
        let path = path.to_string();
        if let Some(entry) = entries.iter_mut().find(|(known, _)| *known == domain) {
            entry.1 = path;
        } else {
            entries.push((domain, path));
        }
    }
    entries
}

/// Lowercases and strips trailing dots — registry keys and the entry's
/// `fnos_domain` are compared in this form.
fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Truncates `bytes` to `limit` bytes; a cut that lands inside a line
/// drops that partial trailing line as well (it belongs to the ignored
/// remainder).
fn truncate_at_limit(bytes: &[u8], limit: usize) -> &[u8] {
    if bytes.len() <= limit {
        return bytes;
    }
    let cut = &bytes[..limit];
    match cut.iter().rposition(|byte| *byte == b'\n') {
        Some(position) => &cut[..=position],
        None => &[],
    }
}

/// [`parse_registry`] over bytes capped at `limit` bytes.
fn parse_registry_capped(bytes: &[u8], limit: usize) -> Vec<(String, String)> {
    parse_registry(&String::from_utf8_lossy(truncate_at_limit(bytes, limit)))
}

/// Reads at most `limit` bytes; up to `limit + 1` bytes come back so
/// [`truncate_at_limit`] can cap without reading the whole file into
/// memory.
async fn read_capped(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    let file = tokio::fs::File::open(path).await?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes).await?;
    Ok(bytes)
}

/// Loads the current certificate for the entry's domain: reads the
/// registry (capped at [`FNOS_INDEX_LIMIT`]; read failure → error),
/// looks up `fnos_domain` (lowercased, trailing dots ignored) and parses
/// the location's chain + key. An unregistered domain → `Ok(None)` (the
/// caller keeps its last loaded `Arc`).
pub async fn load(cert: &Cert) -> Result<Option<Arc<LoadedCert>>, String> {
    load_from(cert, crate::certs::source::fnos_registry_path()).await
}

/// [`load`] against an explicit registry file (the real fixed path comes
/// from [`load`]; tests pass a tempdir fixture).
async fn load_from(cert: &Cert, registry: &Path) -> Result<Option<Arc<LoadedCert>>, String> {
    let bytes = read_capped(registry, FNOS_INDEX_LIMIT)
        .await
        .map_err(|error| format!("读取飞牛证书登记失败：{error}"))?;
    let domain = normalize_domain(&cert.fnos_domain);
    let entries = parse_registry_capped(&bytes, FNOS_INDEX_LIMIT);
    let Some((_, location)) = entries.iter().find(|(known, _)| *known == domain) else {
        return Ok(None);
    };
    let (chain_path, key_path) = resolve_location(Path::new(location))?;
    let chain = tokio::fs::read_to_string(&chain_path)
        .await
        .map_err(|error| format!("读取飞牛证书 {} 失败：{error}", chain_path.display()))?;
    let key = tokio::fs::read_to_string(&key_path)
        .await
        .map_err(|error| format!("读取飞牛私钥 {} 失败：{error}", key_path.display()))?;
    LoadedCert::parse(&cert.key, &chain, &key)
        .map(|loaded| Some(Arc::new(loaded)))
        .map_err(|error| format!("解析飞牛证书失败：{}", error.0))
}

/// Turns a registry location into (chain, private-key) paths. Some
/// registrations point at a directory: prefer `privkey.pem` +
/// `fullchain.pem`, fall back to `privkey.pem` + `cert.pem`. A plain
/// file is taken as the chain with the key expected beside it as
/// `privkey.pem`.
fn resolve_location(location: &Path) -> Result<(PathBuf, PathBuf), String> {
    if location.is_dir() {
        let privkey = location.join("privkey.pem");
        let fullchain = location.join("fullchain.pem");
        let cert = location.join("cert.pem");
        if fullchain.is_file() && privkey.is_file() {
            return Ok((fullchain, privkey));
        }
        if cert.is_file() && privkey.is_file() {
            return Ok((cert, privkey));
        }
        return Err(format!(
            "飞牛证书目录 {} 缺少 privkey.pem/fullchain.pem 或 cert.pem",
            location.display()
        ));
    }
    let key = location.with_file_name("privkey.pem");
    if !key.is_file() {
        return Err(format!(
            "飞牛证书 {} 缺少私钥文件 privkey.pem",
            location.display()
        ));
    }
    Ok((location.to_path_buf(), key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::model::CertSource;

    /// Splits the provider fixture (certificate followed by private key)
    /// into the two PEM halves.
    fn fixture_halves() -> (String, String) {
        let fixture = include_str!("../fixture_key.pem");
        let (cert, key) = fixture
            .split_once("-----END CERTIFICATE-----")
            .expect("fixture contains a certificate");
        (
            format!("{cert}-----END CERTIFICATE-----\n"),
            key.to_string(),
        )
    }

    fn entry(domain: &str) -> Cert {
        Cert {
            key: "test".to_string(),
            source: CertSource::FnOS,
            fnos_domain: domain.to_string(),
            ..Cert::default()
        }
    }

    /// A registry-style certificate directory holding the fixture chain
    /// under `chain_file` plus `privkey.pem`.
    fn cert_dir(root: &Path, name: &str, chain_file: &str) -> PathBuf {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).expect("create cert dir");
        let (chain, key) = fixture_halves();
        std::fs::write(dir.join(chain_file), chain).expect("write chain");
        std::fs::write(dir.join("privkey.pem"), key).expect("write key");
        dir
    }

    #[test]
    fn fnos_registry_parses_lines() {
        let text = "# 注释行\n\
                    \n\
                    Example.COM. /certs/a extra\n\
                    dup.example /one\n\
                    dup.example /two\n\
                    relative.example certs/b\n";
        assert_eq!(
            parse_registry(text),
            vec![
                ("example.com".to_string(), "/certs/a".to_string()),
                ("dup.example".to_string(), "/two".to_string()),
            ]
        );
    }

    #[test]
    fn fnos_registry_truncates_at_limit() {
        assert_eq!(FNOS_INDEX_LIMIT, 4 * 1024 * 1024);
        let mut text = "first.example /first\n".to_string();
        text.push_str(&"x".repeat(64));
        text.push_str(" second.example /second\n");
        let first = vec![("first.example".to_string(), "/first".to_string())];
        // Cut inside the filler line: the partial trailing line is
        // dropped, the second entry is never parsed.
        let mid_line = text.find(" second").expect("second entry present");
        assert_eq!(parse_registry_capped(text.as_bytes(), mid_line), first);
        // Cut exactly at the line boundary keeps line one only.
        let boundary = "first.example /first\n".len();
        assert_eq!(parse_registry_capped(text.as_bytes(), boundary), first);
        // A cap above the file size parses everything.
        assert_eq!(
            parse_registry_capped(text.as_bytes(), usize::MAX),
            parse_registry(&text)
        );
    }

    #[tokio::test]
    async fn fnos_load_follows_registry() {
        let root = tempfile::tempdir().expect("tempdir");
        let primary = cert_dir(root.path(), "renew-001", "fullchain.pem");
        let fallback = cert_dir(root.path(), "renew-002", "cert.pem");
        let registry = root.path().join("network_cert_all.conf");
        std::fs::write(
            &registry,
            format!(
                "# renewed\nExample.COM. {}\n*.fallback.example {}\n",
                primary.display(),
                fallback.display()
            ),
        )
        .expect("write registry");

        // Lookup folds case and strips the trailing dot.
        let loaded = load_from(&entry("example.com."), &registry)
            .await
            .expect("load succeeds")
            .expect("domain registered");
        assert_eq!(loaded.entry.as_ref(), "test");
        assert_eq!(loaded.chain.len(), 1);

        // The cert.pem fallback combo resolves too.
        let loaded = load_from(&entry("*.FALLBACK.example"), &registry)
            .await
            .expect("load succeeds")
            .expect("fallback combo");
        assert_eq!(loaded.chain.len(), 1);
    }

    #[tokio::test]
    async fn fnos_domain_missing_is_none() {
        let root = tempfile::tempdir().expect("tempdir");
        let registry = root.path().join("network_cert_all.conf");
        std::fs::write(&registry, "other.example /elsewhere\n").expect("write registry");
        let loaded = load_from(&entry("missing.example"), &registry)
            .await
            .expect("no error");
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn fnos_removed_cert_errors() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = cert_dir(root.path(), "renew-001", "fullchain.pem");
        let registry = root.path().join("network_cert_all.conf");
        std::fs::write(
            &registry,
            format!("example.com {}\n", dir.display()),
        )
        .expect("write registry");

        let cert = entry("example.com");
        let first = load_from(&cert, &registry)
            .await
            .expect("initial load")
            .expect("registered");
        // fnOS deletes the certificate: the registry no longer lists the
        // domain, the source reports `Ok(None)` and the caller keeps
        // `first` (the last loaded Arc).
        std::fs::write(&registry, "new.example /new-location\n").expect("rewrite registry");
        let second = load_from(&cert, &registry)
            .await
            .expect("load after removal");
        assert!(second.is_none());
        assert_eq!(first.entry.as_ref(), "test");
    }
}
