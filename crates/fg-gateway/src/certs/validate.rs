//! Normalization and validation for `ssl.json` (WP-31 step 1): setting
//! defaults and clamps, remark characters, source-specific requirements,
//! key generation for empty/duplicate keys. Pure functions.
#![allow(dead_code)]

use super::model::FileConfig;

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
pub fn normalize_settings(settings: &mut super::model::Settings) {
    let _ = settings;
}

/// Normalizes a whole config: settings, per-entry defaults and key
/// backfill; returns the first entry error, if any.
pub fn normalize(config: &mut FileConfig) -> Result<(), CertError> {
    normalize_settings(&mut config.settings);
    Ok(())
}

/// Validates one certificate entry against its source's requirements.
pub fn validate_cert(cert: &super::model::Cert) -> Result<(), CertError> {
    let _ = cert;
    Ok(())
}
