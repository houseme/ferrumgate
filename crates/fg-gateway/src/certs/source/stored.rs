//! Entry-stored sources (WP-31 step 4): ACME entries keep their issued
//! chain in `certPem`/`issuerPem`, uploads keep whatever the user
//! submitted. Both load from the entry itself.
#![allow(dead_code)]

use std::sync::Arc;

use crate::certs::model::Cert;
use crate::certs::provider::LoadedCert;

/// Loads an entry's stored PEM (chain first, issuer appended when
/// present). Empty PEM → `Ok(None)` (never issued / not uploaded yet).
pub fn load(cert: &Cert) -> Result<Option<Arc<LoadedCert>>, String> {
    if cert.cert_pem.trim().is_empty() {
        return Ok(None);
    }
    let mut chain = cert.cert_pem.clone();
    if !cert.issuer_pem.trim().is_empty() && !chain.contains("END CERTIFICATE-----\n-----BEGIN") {
        chain.push('\n');
        chain.push_str(&cert.issuer_pem);
    }
    LoadedCert::parse(&cert.key, &chain, &cert.key_pem)
        .map(|cert| Some(Arc::new(cert)))
        .map_err(|error| error.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// fixture_key.pem（真实自签 ECDSA P-256 链 + 配对私钥）。
    const FIXTURE_PEM: &str = include_str!("../fixture_key.pem");

    /// 把 fixture 按段拆成（证书 PEM，私钥 PEM）。
    fn fixture_pems() -> (String, String) {
        let (cert_pem, key_pem) = FIXTURE_PEM
            .split_once("-----BEGIN PRIVATE KEY-----")
            .expect("fixture holds one certificate and one key");
        (cert_pem.to_string(), format!("-----BEGIN PRIVATE KEY-----{key_pem}"))
    }

    /// 一个只填了 stored PEM 字段的条目。
    fn entry(cert_pem: &str, issuer_pem: &str, key_pem: &str) -> Cert {
        Cert {
            key: "entry-1".to_string(),
            cert_pem: cert_pem.to_string(),
            issuer_pem: issuer_pem.to_string(),
            key_pem: key_pem.to_string(),
            ..Cert::default()
        }
    }

    #[test]
    fn stored_loads_chain_with_issuer() {
        let (cert_pem, key_pem) = fixture_pems();
        // 签发者暂用同一张证书顶替：load 只关心结构，不校验签名关系。
        let loaded = load(&entry(&cert_pem, &cert_pem, &key_pem))
            .expect("stored entry loads")
            .expect("issued entry yields a cert");
        assert_eq!(loaded.entry.as_ref(), "entry-1");
        assert_eq!(
            loaded.info.dns_names,
            ["example.com", "*.example.com", "api.example.com"]
        );
        assert!(loaded.not_after.is_some());
    }

    #[test]
    fn stored_empty_pem_is_none() {
        assert!(load(&entry("", "", "")).unwrap().is_none());
        // 纯空白同样视为未签发。
        assert!(load(&entry("  \n\t", "  \n\t", "  \n\t")).unwrap().is_none());
    }

    /// `LoadedCert` 未实现 `Debug`，用匹配而非 `unwrap_err` 取错误消息。
    #[track_caller]
    fn load_error(cert: &Cert) -> String {
        match load(cert) {
            Ok(_) => panic!("expected stored load to fail"),
            Err(error) => error,
        }
    }

    #[test]
    fn stored_rejects_bad_pem() {
        let (_, key_pem) = fixture_pems();
        assert_eq!(load_error(&entry("garbage", "", &key_pem)), "证书无法解析");
    }

    #[test]
    fn stored_appends_issuer_only_when_missing() {
        let (cert_pem, key_pem) = fixture_pems();

        // 链里只有叶子 → 拼入签发者，结果链长 2。
        let loaded = load(&entry(&cert_pem, &cert_pem, &key_pem))
            .expect("loads")
            .expect("issued");
        assert_eq!(loaded.chain.len(), 2);

        // 链里已带第二段（fullchain）→ 不再拼入，仍是 2 段而非 3 段。
        let fullchain = format!("{cert_pem}{cert_pem}");
        let loaded = load(&entry(&fullchain, &cert_pem, &key_pem))
            .expect("loads")
            .expect("issued");
        assert_eq!(loaded.chain.len(), 2);
    }
}
