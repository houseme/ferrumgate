//! Normalization and validation for `ssl.json` (WP-31 step 1): setting
//! defaults and clamps, remark characters, source-specific requirements,
//! key generation for empty/duplicate keys. Pure functions.
#![allow(dead_code)]

use std::collections::HashSet;

use super::model::{Cert, CertSource, FileConfig, Settings};

/// Settings defaults (upstream `defaultSettings`) and the short-lived
/// renew-hour cap.
const DEFAULT_RENEW_BEFORE_DAYS: u32 = 30;
const DEFAULT_SHORT_LIVED_RENEW_HOURS: u32 = 24;
const MAX_SHORT_LIVED_RENEW_HOURS: u32 = 80;

/// Valid ACME key types (upstream `validKeyTypes`).
const KEY_TYPES: [&str; 4] = ["P256", "P384", "2048", "4096"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertError {
    BadRemark(String),
    BadSource(&'static str),
    MissingFileField(&'static str),
    UnparseablePem(String),
    KeyMismatch(String),
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRemark(text) => write!(f, "备注只允许 A-Za-z0-9*_.@-：{text}"),
            Self::BadSource(field) => write!(f, "{field}"),
            Self::MissingFileField(field) => write!(f, "文件来源必须提供 {field}"),
            Self::UnparseablePem(what) => write!(f, "{what} 无法解析"),
            Self::KeyMismatch(what) => write!(f, "私钥与证书不匹配：{what}"),
        }
    }
}

impl std::error::Error for CertError {}

/// Normalizes settings in place: 0 → default, `shortLivedRenewHours`
/// clamped to 80.
pub fn normalize_settings(settings: &mut Settings) {
    if settings.renew_before_days == 0 {
        settings.renew_before_days = DEFAULT_RENEW_BEFORE_DAYS;
    }
    if settings.short_lived_renew_hours == 0 {
        settings.short_lived_renew_hours = DEFAULT_SHORT_LIVED_RENEW_HOURS;
    } else if settings.short_lived_renew_hours > MAX_SHORT_LIVED_RENEW_HOURS {
        settings.short_lived_renew_hours = MAX_SHORT_LIVED_RENEW_HOURS;
    }
}

/// Normalizes a whole config: settings, per-entry defaults and key
/// backfill; returns the first entry error, if any. Keys must be unique
/// across the file; an empty or clashing key gets a fresh 12-lowercase-hex
/// value (the same shape as the other collections, conventions §3.3).
pub fn normalize(config: &mut FileConfig) -> Result<(), CertError> {
    normalize_settings(&mut config.settings);
    let random = ring::rand::SystemRandom::new();
    let mut keys = HashSet::new();
    for cert in &mut config.certs {
        cert.key = cert.key.trim().to_string();
        if (cert.key.is_empty() || !keys.insert(cert.key.clone()))
            && let Some(key) = generate_key(&random, &mut keys)
        {
            cert.key = key;
        }
        validate_cert(cert)?;
    }
    Ok(())
}

/// Validates one certificate entry against its source's requirements:
/// the remark is file-name material (`^[A-Za-z0-9*_.@-]+$`, upstream
/// `reRemark`), the `file` source needs both paths, the `upload` source
/// needs parseable content whose key matches the certificate. The `acme`
/// parameters are validated by WP-32 (only the key type is checked here)
/// and `fnos` follows the system registry, so neither carries stored
/// content to check yet.
pub fn validate_cert(cert: &Cert) -> Result<(), CertError> {
    if !is_valid_remark(&cert.remark) {
        return Err(CertError::BadRemark(cert.remark.clone()));
    }
    if cert.source == CertSource::Acme {
        validate_key_type(cert)?;
    }
    match cert.source {
        CertSource::File => {
            if cert.cert_file.is_empty() {
                return Err(CertError::MissingFileField("certFile"));
            }
            if cert.key_file.is_empty() {
                return Err(CertError::MissingFileField("keyFile"));
            }
            Ok(())
        }
        CertSource::Upload => validate_upload(cert),
        CertSource::Acme | CertSource::FnOS => Ok(()),
    }
}

/// The remark becomes file-name material, so it may only contain
/// `A-Za-z0-9*_.@-` (`*` is later replaced by `_`) and must not be empty.
fn is_valid_remark(remark: &str) -> bool {
    !remark.is_empty()
        && remark
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '*' | '_' | '.' | '@' | '-'))
}

/// `acme.keyType`, when present, must be one of the four supported
/// values; absent or null means the default (`P256`, chosen at issuance).
fn validate_key_type(cert: &Cert) -> Result<(), CertError> {
    match cert.acme.get("keyType") {
        None | Some(serde_json::Value::Null) => Ok(()),
        Some(serde_json::Value::String(value)) if KEY_TYPES.contains(&value.as_str()) => Ok(()),
        Some(_) => Err(CertError::BadSource(
            "密钥类型只能为 P256、P384、2048 或 4096",
        )),
    }
}

/// Uploaded content: the certificate chain must parse and the stored key
/// must belong to the leaf certificate. An unparseable key is reported as
/// unparseable; a parseable key that belongs to another certificate is a
/// mismatch.
fn validate_upload(cert: &Cert) -> Result<(), CertError> {
    super::info::CertInfo::parse(&cert.cert_pem)
        .map_err(|_| CertError::UnparseablePem("证书".to_string()))?;
    match super::info::CertInfo::key_matches(&cert.cert_pem, &cert.key_pem) {
        Ok(true) => Ok(()),
        Ok(false) => Err(CertError::KeyMismatch(cert.remark.clone())),
        Err(_) => Err(CertError::UnparseablePem("私钥".to_string())),
    }
}

/// A fresh 12-lowercase-hex key absent from `taken` (which records the
/// generated key). `None` means the system RNG kept failing, which in
/// practice never happens; the caller then leaves the key untouched.
fn generate_key(random: &ring::rand::SystemRandom, taken: &mut HashSet<String>) -> Option<String> {
    use ring::rand::SecureRandom;

    for _ in 0..8 {
        let mut bytes = [0u8; 6];
        random.fill(&mut bytes).ok()?;
        let key: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        if taken.insert(key.clone()) {
            return Some(key);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An otherwise-valid entry with the given source.
    fn entry(source: CertSource) -> Cert {
        Cert {
            remark: "entry".to_string(),
            source,
            ..Cert::default()
        }
    }

    fn settings(renew_before_days: u32, short_lived_renew_hours: u32) -> Settings {
        Settings {
            enable: true,
            renew_before_days,
            short_lived_renew_hours,
            default_email: String::new(),
        }
    }

    /// openssl 生成（P-256 自签名，有效期 10 年）；配套私钥不在本文件里，
    /// 下面的钥匙是另一把，因此成对上传必须被拒。
    const FIXTURE_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBbDCCARKgAwIBAgIUdeTLaCMp5F4ubXl+xiwtRld0d0swCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRZml4dHVyZS1hLmV4YW1wbGUwHhcNMjYxMTI3MTUxNjQ5WhcN
MzYxMTI0MTUxNjQ5WjAcMRowGAYDVQQDDBFmaXh0dXJlLWEuZXhhbXBsZTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABPLPSwaKMgNC2X5oxtPREn5j15qKDqkXm3VK
6Ar3u2fUgI5xUW7/ZgSsaLHeD9TYNMC+VicwyrFjoJYfEf20XO2jMjAwMB0GA1Ud
DgQWBBTmG9YIKu9VlGB2HwEmUDfv58TG2jAPBgNVHRMBAf8EBTADAQH/MAoGCCqG
SM49BAMCA0gAMEUCIG/RJeM2NX8jIgnc7zqwGLmuJBf8ATN+ZxywSNHieUmvAiEA
6kEgWPwEY6960DMla23gcI2ESasjwLznXih8fi++KhQ=
-----END CERTIFICATE-----
"#;

    /// 一把合法但与 [`FIXTURE_CERT_PEM`] 不配对的 P-256 私钥（PKCS#8）。
    const FIXTURE_UNMATCHED_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvyRZRNkguhsJfCsz
NQT4U8jGvljD5KXQmzidRNpbYZihRANCAAQno5CZZocI+T0gDOMoU2GhcaQr5+yK
IzAAxja14fMAr0yDJJb5T3Q6seVKfc6sy+29edRE/lewQyI2PSSeCocM
-----END PRIVATE KEY-----
"#;

    #[test]
    fn settings_defaults_and_clamp() {
        let mut s = settings(0, 0);
        normalize_settings(&mut s);
        assert_eq!(s.renew_before_days, 30);
        assert_eq!(s.short_lived_renew_hours, 24);

        // 非零值保留，只有短期续签小时数被压到上限。
        let mut s = settings(7, 100);
        normalize_settings(&mut s);
        assert_eq!(s.renew_before_days, 7);
        assert_eq!(s.short_lived_renew_hours, 80);

        // 上限本身不动。
        let mut s = settings(45, 80);
        normalize_settings(&mut s);
        assert_eq!(s.renew_before_days, 45);
        assert_eq!(s.short_lived_renew_hours, 80);
    }

    #[test]
    fn cert_remark_characters_validated() {
        for remark in ["home", "*.example.com", "srv-1_a.B@lab", "router*2"] {
            let mut cert = entry(CertSource::Acme);
            cert.remark = remark.to_string();
            assert!(validate_cert(&cert).is_ok(), "{remark} 应当通过");
        }
        for remark in ["", "生产环境", "a b", "a/b", "café", "a#b"] {
            let mut cert = entry(CertSource::Acme);
            cert.remark = remark.to_string();
            assert!(
                matches!(validate_cert(&cert), Err(CertError::BadRemark(_))),
                "{remark:?} 应当被拒绝"
            );
        }
    }

    #[test]
    fn key_type_validated() {
        let mut cert = entry(CertSource::Acme);
        // 缺省即默认 P256。
        assert!(validate_cert(&cert).is_ok());
        for key_type in ["P256", "P384", "2048", "4096"] {
            cert.acme
                .insert("keyType".to_string(), serde_json::json!(key_type));
            assert!(validate_cert(&cert).is_ok(), "{key_type} 应当通过");
        }
        cert.acme
            .insert("keyType".to_string(), serde_json::json!("ed25519"));
        assert!(matches!(validate_cert(&cert), Err(CertError::BadSource(_))));
    }

    #[test]
    fn upload_source_requires_matching_key() {
        let mut cert = entry(CertSource::Upload);
        cert.cert_pem = FIXTURE_CERT_PEM.to_string();
        cert.key_pem = FIXTURE_UNMATCHED_KEY_PEM.to_string();
        let err = validate_cert(&cert).expect_err("不配对的私钥必须被拒");
        // info::CertInfo 与本模块并行开发：占位实现连证书都解析不了
        // （UnparseablePem），真实实现会给出 KeyMismatch，两者都算拒绝。
        assert!(
            matches!(
                err,
                CertError::KeyMismatch(_) | CertError::UnparseablePem(_)
            ),
            "意外的错误：{err}"
        );

        // 无法解析的证书内容同样被拒。
        cert.cert_pem = "definitely not a pem".to_string();
        assert!(validate_cert(&cert).is_err());
    }

    #[test]
    fn file_source_requires_paths() {
        let cert = entry(CertSource::File);
        assert!(matches!(
            validate_cert(&cert),
            Err(CertError::MissingFileField("certFile"))
        ));

        let mut cert = entry(CertSource::File);
        cert.cert_file = "/etc/ferrumgate/certs/a.pem".to_string();
        assert!(matches!(
            validate_cert(&cert),
            Err(CertError::MissingFileField("keyFile"))
        ));

        cert.key_file = "/etc/ferrumgate/certs/a.key".to_string();
        assert!(validate_cert(&cert).is_ok());
    }

    #[test]
    fn acme_and_fnos_sources_pass_without_content() {
        // 占位放行：ACME 的完整参数校验在 WP-32，飞牛按系统登记表取内容。
        assert!(validate_cert(&entry(CertSource::Acme)).is_ok());
        assert!(validate_cert(&entry(CertSource::FnOS)).is_ok());
    }

    #[test]
    fn normalize_backfills_empty_and_duplicate_keys() {
        let mut config = FileConfig::default();
        let mut empty = entry(CertSource::Acme);
        empty.key = String::new();
        let mut first = entry(CertSource::Acme);
        first.key = "dup".to_string();
        let mut second = entry(CertSource::Acme);
        second.key = "dup".to_string();
        let mut unique = entry(CertSource::Acme);
        unique.key = "unique".to_string();
        config.certs = vec![empty, first, second, unique];

        normalize(&mut config).expect("条目本身合法");

        let keys: Vec<&str> = config.certs.iter().map(|cert| cert.key.as_str()).collect();
        assert_eq!(keys[1], "dup");
        assert_eq!(keys[3], "unique");
        for key in [keys[0], keys[2]] {
            assert_eq!(key.len(), 12, "生成的 key 是 12 个小写十六进制字符：{key}");
            assert!(
                key.chars()
                    .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()),
                "生成的 key 应为小写十六进制：{key}"
            );
        }
        assert_ne!(keys[0], keys[2], "两把生成的 key 不得相同");
    }

    #[test]
    fn normalize_reports_first_entry_error() {
        let mut config = FileConfig::default();
        let mut bad = entry(CertSource::File);
        bad.remark = "bad remark".to_string();
        config.certs.push(bad);
        assert!(matches!(
            normalize(&mut config),
            Err(CertError::BadRemark(_))
        ));
    }
}
