//! `CertProvider` (WP-31 step 5): the certificate surface the web
//! listeners and the admin HTTPS consume. The provider owns an immutable
//! [`CertIndex`] snapshot swapped wholesale on change, plus a `watch`
//! version counter so TLS acceptors know a reload happened. Hot path:
//! one atomic snapshot read, zero allocation per handshake.
#![allow(dead_code)]

use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    sign::CertifiedKey,
};
use tokio::sync::watch;

use super::index::CertIndex;
use super::info::CertInfo;

/// A fully loaded certificate: parsed chain and key, the entry key it
/// came from and its parsed facts.
pub struct LoadedCert {
    pub entry: Arc<str>,
    pub chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
    pub info: CertInfo,
    /// Latest expiry among chain entries (`info.not_after`).
    pub not_after: Option<std::time::SystemTime>,
    /// Signing key + chain ready for a rustls server config.
    pub tls: Arc<CertifiedKey>,
}

impl Clone for LoadedCert {
    fn clone(&self) -> Self {
        Self {
            entry: self.entry.clone(),
            chain: self.chain.clone(),
            // Zeroizing key material has no `Clone`; `clone_key` copies
            // the owned DER explicitly.
            private_key: self.private_key.clone_key(),
            info: self.info.clone(),
            not_after: self.not_after,
            tls: self.tls.clone(),
        }
    }
}

impl LoadedCert {
    /// Parses full-chain PEM + key PEM into a loadable certificate.
    /// Fails when either does not parse or the key does not match.
    pub fn parse(entry: &str, cert_pem: &str, key_pem: &str) -> Result<Self, LoadError> {
        let info = CertInfo::parse(cert_pem).map_err(|_| LoadError("证书无法解析".into()))?;
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>()
                .map_err(|_| LoadError("证书链无法解析".into()))?;
        if chain.is_empty() {
            return Err(LoadError("证书链为空".into()));
        }
        let mut keys = PrivateKeyDer::pem_slice_iter(key_pem.as_bytes());
        let private_key = keys
            .next()
            .ok_or_else(|| LoadError("缺少 PEM 私钥".into()))?
            .map_err(|_| LoadError("私钥无法解析".into()))?;
        if keys.next().is_some() {
            return Err(LoadError("期望只有一个 PEM 私钥".into()));
        }
        let tls = CertifiedKey::from_der(chain.clone(), private_key.clone_key(), &rustls::crypto::ring::default_provider())
            .map_err(|_| LoadError("证书与私钥无法装配".into()))?;
        tls.keys_match().map_err(|_| LoadError("私钥与证书不匹配".into()))?;
        Ok(Self {
            entry: entry.into(),
            chain,
            private_key,
            not_after: info.not_after,
            info,
            tls: Arc::new(tls),
        })
    }

    /// Index-test fixture: real signing key material with a stand-in
    /// chain, carrying the given facts. The index never signs, so the
    /// chain bytes do not matter — only that the key loads.
    #[cfg(test)]
    pub(crate) fn fixture(dns: Vec<String>, ips: Vec<std::net::IpAddr>, not_after: Option<std::time::SystemTime>) -> LoadedCert {
        use rustls::pki_types::PrivatePkcs8KeyDer;
        use std::sync::OnceLock;
        static KEY_PEM: &str = include_str!("fixture_key.pem");
        static KEY: OnceLock<Option<Arc<CertifiedKey>>> = OnceLock::new();
        let key = KEY.get_or_init(|| {
            let certs: Vec<CertificateDer<'static>> =
                CertificateDer::pem_slice_iter(KEY_PEM.as_bytes())
                    .collect::<Result<_, _>>()
                    .expect("fixture chain parses");
            let Some(Ok(key)) = PrivateKeyDer::pem_slice_iter(KEY_PEM.as_bytes()).next() else {
                panic!("fixture key PEM does not parse");
            };
            match CertifiedKey::from_der(
                certs,
                key,
                &rustls::crypto::ring::default_provider(),
            ) {
                Ok(key) => Some(Arc::new(key)),
                Err(error) => panic!("fixture key does not assemble: {error}"),
            }
        });
        LoadedCert {
            entry: "fixture".into(),
            chain: Vec::new(),
            private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![])),
            info: CertInfo {
                dns_names: dns,
                ip_addresses: ips,
                not_after,
                ..CertInfo::default()
            },
            not_after,
            tls: key.clone().expect("embedded fixture key must load"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError(pub String);

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for LoadError {}

/// The certificate surface consumed by TLS acceptors and the admin UI.
pub trait CertificateSource: Send + Sync {
    /// SNI selection: exact → one-label wildcard → (no SNI) local address
    /// → IP default. `local` is the accepted connection's local address
    /// (None on transports without it).
    fn select(&self, server_name: Option<&str>, local: Option<std::net::IpAddr>) -> Option<Arc<LoadedCert>>;
    /// Self-check / UI coverage query; empty names are never covered.
    fn has_certificate(&self, name: &str) -> bool;
    fn has_ip_certificate(&self) -> bool;
    /// Bumped whenever the index is replaced (reload, renewal, upload).
    fn subscribe(&self) -> watch::Receiver<u64>;
}

/// The provider implementation behind [`CertificateSource`].
pub struct Provider {
    index: ArcSwap<CertIndex>,
    version: watch::Sender<u64>,
}

impl Provider {
    pub fn empty() -> Self {
        let (version, _) = watch::channel(0);
        Self {
            index: ArcSwap::from_pointee(CertIndex::default()),
            version,
        }
    }

    /// Replaces the whole index and wakes subscribers.
    pub fn publish(&self, index: CertIndex) {
        self.index.store(Arc::new(index));
        self.version.send_modify(|version| *version += 1);
    }

    fn snapshot(&self) -> Arc<CertIndex> {
        self.index.load_full()
    }
}

impl CertificateSource for Provider {
    fn select(&self, server_name: Option<&str>, local: Option<std::net::IpAddr>) -> Option<Arc<LoadedCert>> {
        match server_name {
            Some(name) => self.snapshot().select(name, local),
            None => self.snapshot().select("", local),
        }
    }

    fn has_certificate(&self, name: &str) -> bool {
        self.snapshot().has(name)
    }

    fn has_ip_certificate(&self) -> bool {
        self.snapshot().has_ip()
    }

    fn subscribe(&self) -> watch::Receiver<u64> {
        self.version.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::index::CertIndex;

    /// fixture_key.pem 的整链 + 私钥（真实自签 ECDSA P-256：SAN 含
    /// example.com / *.example.com / api.example.com 与三个 IP）。
    const FIXTURE_PEM: &str = include_str!("fixture_key.pem");

    /// 一把合法但与 fixture 证书不配对的 ECDSA P-256 私钥（PKCS#8）。
    const OTHER_KEY_PEM: &str = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgKCxceufc66njRmhY\n",
        "VZrEJ0EPAVGZiz/i3Do4pyL41EChRANCAATVEhw1xwpG8fOOqtYm8yUCzL191ip4\n",
        "8siQ2M2Y1IC6/WB4hBuE88aOdtFHoA60jujTsajKtQEEa+Il6LSrkKrp\n",
        "-----END PRIVATE KEY-----\n",
    );

    /// 把 fixture 按段拆成（证书 PEM，私钥 PEM）。
    fn fixture_pems() -> (String, String) {
        let (cert_pem, key_pem) = FIXTURE_PEM
            .split_once("-----BEGIN PRIVATE KEY-----")
            .expect("fixture holds one certificate and one key");
        (cert_pem.to_string(), format!("-----BEGIN PRIVATE KEY-----{key_pem}"))
    }

    #[test]
    fn parse_loads_full_chain_and_facts() {
        let (cert_pem, key_pem) = fixture_pems();
        let loaded = LoadedCert::parse("entry-1", &cert_pem, &key_pem).expect("fixture parses");
        assert_eq!(loaded.entry.as_ref(), "entry-1");
        assert!(!loaded.chain.is_empty(), "the full chain must load");
        assert_eq!(
            loaded.info.dns_names,
            ["example.com", "*.example.com", "api.example.com"]
        );
        assert!(loaded.info.not_after.is_some());
        // 装配成功即证明 keys_match（rustls 在 from_der 内完成该校验）。
        loaded.tls.keys_match().expect("fixture key matches");
    }

    /// `LoadedCert` 未实现 `Debug`，用匹配而非 `unwrap_err` 取错误消息。
    #[track_caller]
    fn parse_error(cert_pem: &str, key_pem: &str) -> String {
        match LoadedCert::parse("entry-1", cert_pem, key_pem) {
            Ok(_) => panic!("expected parse to fail"),
            Err(LoadError(message)) => message,
        }
    }

    #[test]
    fn parse_rejects_mismatched_key() {
        let (cert_pem, _) = fixture_pems();
        // rustls 0.23 的 `from_der` 内部就做 keys_match 校验，私钥不匹配
        // 在装配一步即被拒绝。
        assert_eq!(parse_error(&cert_pem, OTHER_KEY_PEM), "证书与私钥无法装配");
    }

    #[test]
    fn parse_rejects_garbage() {
        assert_eq!(parse_error("", ""), "证书无法解析");
        assert_eq!(parse_error("garbage", "garbage"), "证书无法解析");
        // 证书有效、私钥是乱码：无 PEM 段 → 缺少私钥；有段但内容坏 → 解析失败。
        let (cert_pem, _) = fixture_pems();
        assert_eq!(parse_error(&cert_pem, "garbage"), "缺少 PEM 私钥");
        assert_eq!(
            parse_error(
                &cert_pem,
                "-----BEGIN PRIVATE KEY-----\nnot base64!!\n-----END PRIVATE KEY-----\n"
            ),
            "私钥无法解析"
        );
    }

    #[tokio::test]
    async fn provider_publish_bumps_version() {
        let provider = Provider::empty();
        let mut watcher = provider.subscribe();
        assert_eq!(*watcher.borrow(), 0);

        let index = CertIndex::build(
            [Arc::new(LoadedCert::fixture(
                vec!["a.example.com".to_string()],
                Vec::new(),
                None,
            ))]
            .into_iter(),
        );
        provider.publish(index);

        watcher.changed().await.expect("watch stays open");
        assert_eq!(*watcher.borrow(), 1);
    }

    #[test]
    fn provider_select_routes_to_index() {
        let provider = Provider::empty();
        assert!(provider.select(Some("a.example.com"), None).is_none());
        assert!(!provider.has_certificate("a.example.com"));
        assert!(!provider.has_ip_certificate());

        let cert = Arc::new(LoadedCert::fixture(
            vec!["a.example.com".to_string()],
            Vec::new(),
            None,
        ));
        provider.publish(CertIndex::build([Arc::clone(&cert)].into_iter()));

        // SNI 命中的就是索引里那份证书（同一个 Arc）。
        let got = provider.select(Some("a.example.com"), None).expect("covered");
        assert!(Arc::ptr_eq(&got, &cert));
        assert!(provider.has_certificate("a.example.com"));
        // 大小写与结尾点被归一化。
        assert!(provider.has_certificate("A.EXAMPLE.COM."));
        assert!(!provider.has_certificate("b.example.com"));
        assert!(provider.select(Some("b.example.com"), None).is_none());
        // fixture 未带 IP SAN：没有 IP 证书。
        assert!(!provider.has_ip_certificate());
    }
}
