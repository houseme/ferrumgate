//! SSH authentication (WP-61 §3.3): password, pasted or file-backed private
//! keys, and authentication presets. Presets are resolved against the
//! stored credential list at connect time, so editing a preset updates
//! every connection that references it on its next connect.

use std::sync::Arc;

use russh::keys::{HashAlg, PrivateKeyWithHashAlg};

use crate::model::{Auth, AuthKind, Preset};

/// The credentials a handshake authenticates with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedAuth {
    Password(String),
    Key {
        /// The OpenSSH PEM text (pasted or read from `keyFile`).
        pem: String,
        /// Optional key decryption passphrase.
        passphrase: Option<String>,
    },
}

/// Why the credentials could not be prepared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// The referenced preset does not exist.
    PresetNotFound(String),
    /// The connection's auth kind carries no usable secret.
    Missing(String),
    /// Reading `keyFile` failed.
    KeyFile(String, String),
    /// Decoding the private key failed.
    Decode(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PresetNotFound(key) => write!(f, "凭据预设 {key} 不存在"),
            Self::Missing(detail) => write!(f, "缺少认证凭据：{detail}"),
            Self::KeyFile(path, error) => write!(f, "读取私钥文件 {path} 失败：{error}"),
            Self::Decode(error) => write!(f, "私钥无法解析：{error}"),
        }
    }
}

/// Resolves a connection's auth against the stored presets. A preset kind
/// looks the referenced preset up now, so preset edits apply to the next
/// connect. A pasted key wins over `keyFile`; the file is on the
/// FerrumGate machine.
pub fn resolve(auth: &Auth, presets: &[Preset]) -> Result<ResolvedAuth, AuthError> {
    match auth.kind {
        AuthKind::Password => Ok(ResolvedAuth::Password(auth.password.clone())),
        AuthKind::Key => {
            let pem = if auth.pasted.trim().is_empty() {
                if auth.key_file.trim().is_empty() {
                    return Err(AuthError::Missing("未提供私钥".into()));
                }
                std::fs::read_to_string(auth.key_file.trim())
                    .map_err(|error| AuthError::KeyFile(auth.key_file.clone(), error.to_string()))?
            } else {
                auth.pasted.clone()
            };
            let passphrase = (!auth.passphrase.is_empty()).then(|| auth.passphrase.clone());
            Ok(ResolvedAuth::Key { pem, passphrase })
        }
        AuthKind::Preset => {
            let preset = presets
                .iter()
                .find(|preset| preset.key == auth.preset)
                .ok_or_else(|| AuthError::PresetNotFound(auth.preset.clone()))?;
            match preset.kind {
                AuthKind::Password => Ok(ResolvedAuth::Password(preset.password.clone())),
                _ => {
                    let passphrase =
                        (!preset.passphrase.is_empty()).then(|| preset.passphrase.clone());
                    Ok(ResolvedAuth::Key {
                        pem: preset.pasted.clone(),
                        passphrase,
                    })
                }
            }
        }
    }
}

/// Authenticates a connected handle. The host key has already been
/// accepted at this point (verification happens during the handshake,
/// before any credential is sent).
pub async fn authenticate<H>(
    handle: &mut russh::client::Handle<H>,
    username: &str,
    resolved: &ResolvedAuth,
) -> Result<(), AuthError>
where
    H: russh::client::Handler,
{
    let result = match resolved {
        ResolvedAuth::Password(password) => handle
            .authenticate_password(username, password.as_str())
            .await
            .map_err(|error| AuthError::Decode(error.to_string()))?,
        ResolvedAuth::Key { pem, passphrase } => {
            let key = russh::keys::decode_secret_key(pem, passphrase.as_deref())
                .map_err(|error| AuthError::Decode(error.to_string()))?;
            // RSA needs an explicit modern hash; other key types ignore it.
            let hash = key.algorithm().is_rsa().then_some(HashAlg::Sha256);
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
            handle
                .authenticate_publickey(username, key)
                .await
                .map_err(|error| AuthError::Decode(error.to_string()))?
        }
    };
    match result {
        russh::client::AuthResult::Success => Ok(()),
        russh::client::AuthResult::Failure { .. } => Err(AuthError::Missing(
            "认证失败：用户名或凭据被服务器拒绝".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::limits;

    const TEST_KEY: &str =
        "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----\n";

    fn preset(key: &str, kind: AuthKind, password: &str, pasted: &str) -> Preset {
        Preset {
            key: key.into(),
            name: "预设".into(),
            kind,
            username: "root".into(),
            password: password.into(),
            pasted: pasted.into(),
            passphrase: String::new(),
        }
    }

    #[test]
    fn auth_resolve_password_and_key_shapes() {
        let resolved = resolve(
            &Auth {
                kind: AuthKind::Password,
                password: "pw".into(),
                ..Auth::default()
            },
            &[],
        )
        .expect("password");
        assert_eq!(resolved, ResolvedAuth::Password("pw".into()));

        let resolved = resolve(
            &Auth {
                kind: AuthKind::Key,
                pasted: TEST_KEY.into(),
                passphrase: "enc".into(),
                ..Auth::default()
            },
            &[],
        )
        .expect("key");
        assert_eq!(
            resolved,
            ResolvedAuth::Key {
                pem: TEST_KEY.into(),
                passphrase: Some("enc".into())
            }
        );
    }

    #[test]
    fn auth_resolve_preset_uses_stored_credentials() {
        let presets = vec![
            preset("0123456789ab", AuthKind::Password, "preset-pw", ""),
            preset("111111111111", AuthKind::Key, "", TEST_KEY),
        ];
        let resolved = resolve(
            &Auth {
                kind: AuthKind::Preset,
                preset: "0123456789ab".into(),
                ..Auth::default()
            },
            &presets,
        )
        .expect("preset");
        assert_eq!(resolved, ResolvedAuth::Password("preset-pw".into()));
        let resolved = resolve(
            &Auth {
                kind: AuthKind::Preset,
                preset: "111111111111".into(),
                ..Auth::default()
            },
            &presets,
        )
        .expect("preset key");
        assert_eq!(
            resolved,
            ResolvedAuth::Key {
                pem: TEST_KEY.into(),
                passphrase: None
            }
        );
        let error = resolve(
            &Auth {
                kind: AuthKind::Preset,
                preset: "missing000000".into(),
                ..Auth::default()
            },
            &presets,
        )
        .expect_err("missing preset");
        assert_eq!(error, AuthError::PresetNotFound("missing000000".into()));
    }

    #[test]
    fn auth_resolve_empty_key_without_pasted_or_file_is_missing() {
        let error = resolve(
            &Auth {
                kind: AuthKind::Key,
                ..Auth::default()
            },
            &[],
        )
        .expect_err("missing key");
        assert!(matches!(error, AuthError::Missing(_)));
    }

    #[test]
    fn auth_resolve_reads_key_file_when_pasted_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("id_test");
        std::fs::write(&path, TEST_KEY).expect("write key file");
        let resolved = resolve(
            &Auth {
                kind: AuthKind::Key,
                key_file: path.to_string_lossy().into_owned(),
                ..Auth::default()
            },
            &[],
        )
        .expect("key from file");
        assert_eq!(
            resolved,
            ResolvedAuth::Key {
                pem: TEST_KEY.into(),
                passphrase: None
            }
        );
        let error = resolve(
            &Auth {
                kind: AuthKind::Key,
                key_file: dir.path().join("absent").to_string_lossy().into_owned(),
                ..Auth::default()
            },
            &[],
        )
        .expect_err("missing file");
        assert!(matches!(error, AuthError::KeyFile(_, _)));
    }

    #[test]
    fn auth_defaults_are_password_kind() {
        let auth = Auth::default();
        assert_eq!(auth.kind, AuthKind::Password);
        assert!(auth.password.is_empty());
        assert_eq!(limits::CONNECT_TIMEOUT_DEFAULT, 15);
    }
}
