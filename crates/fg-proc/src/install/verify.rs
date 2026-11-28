//! SHA-256 校验（WP-43 §3.3）：下载完成后与发布元数据中的校验值比较；
//! 不一致时失败并由调用方删除暂存文件。上游没有提供校验值时记录一条
//! 警告后放行（界面显示「未提供校验值」）——下载并运行外部二进制是高
//! 风险操作，有校验值时必须通过。

use std::{io::Read, path::Path};

use sha2::{Digest, Sha256};

use super::InstallError;

/// 流式计算文件的 SHA-256。
pub fn sha256_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hasher.finalize().into())
}

/// 解析摘要文本：`sha256:<hex>`、裸 `<hex>`（64 位十六进制，大小写均可）。
pub fn parse_digest(text: &str) -> Option<[u8; 32]> {
    let hex = text.trim().strip_prefix("sha256:").unwrap_or(text.trim());
    decode_hex(hex)
}

/// 从校验和文件内容中找 `asset_name` 对应的条目，形如
/// `<sha256>  <文件名>` 或 `<sha256> *<文件名>`。
pub fn checksum_file_entry(content: &str, asset_name: &str) -> Option<[u8; 32]> {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let Some(hex) = parts.next() else {
            continue;
        };
        let Some(name) = parts.next().map(str::trim) else {
            continue;
        };
        let name = name.trim_start_matches('*');
        if name == asset_name
            && let Some(digest) = decode_hex(hex)
        {
            return Some(digest);
        }
    }
    None
}

fn decode_hex(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// 校验下载产物；`expected` 为 None 时记录警告并放行，返回值表示是否
/// 发生了这次告警。
pub fn verify(path: &Path, expected: Option<[u8; 32]>) -> Result<bool, InstallError> {
    let actual = sha256_file(path).map_err(|error| InstallError::Io(error.to_string()))?;
    let Some(expected) = expected else {
        tracing::warn!(
            file = %path.display(),
            "上游未提供校验值，跳过 SHA-256 校验"
        );
        return Ok(true);
    };
    if actual != expected {
        return Err(InstallError::Checksum);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_payload(dir: &Path, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join("payload.bin");
        std::fs::write(&path, bytes).expect("write payload");
        path
    }

    #[test]
    fn no_checksum_records_warning() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_payload(dir.path(), b"hello ferrogate");
        // 没有校验值：告警并放行（返回 true 表示已告警）。
        let warned = verify(&path, None).expect("no checksum passes with warning");
        assert!(warned);
        // 有校验值且一致：正常通过，无告警。
        use sha2::Digest as _;
        let digest: [u8; 32] = Sha256::digest(b"hello ferrogate").into();
        let warned = verify(&path, Some(digest)).expect("matching checksum passes");
        assert!(!warned);
    }

    #[test]
    fn digest_parsing_and_checksum_file_entries() {
        let hex = "a".repeat(64);
        assert_eq!(parse_digest(&format!("sha256:{hex}")), Some([0xaa; 32]));
        assert_eq!(parse_digest(&hex.to_uppercase()), Some([0xaa; 32]));
        assert_eq!(parse_digest("short"), None);
        assert_eq!(parse_digest("zzzz"), None);

        let content = format!("bbbb  other-file.zip\n{hex}  frp_0.61.1_linux_arm64.tar.gz\n");
        assert_eq!(
            checksum_file_entry(&content, "frp_0.61.1_linux_arm64.tar.gz"),
            Some([0xaa; 32])
        );
        assert_eq!(checksum_file_entry(&content, "missing"), None);
        let starred = format!("{}  *starred.bin", "dd".repeat(32));
        assert_eq!(
            checksum_file_entry(&starred, "starred.bin"),
            Some([0xdd; 32]),
            "二进制模式的星号被去掉"
        );
    }

    #[test]
    fn verify_rejects_wrong_digest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_payload(dir.path(), b"payload");
        use sha2::Digest as _;
        let digest: [u8; 32] = Sha256::digest(b"other").into();
        assert!(matches!(
            verify(&path, Some(digest)),
            Err(InstallError::Checksum)
        ));
    }
}
