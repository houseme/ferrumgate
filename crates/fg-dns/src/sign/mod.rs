//! 请求签名工具（WP-41 §5 步骤 7）：SigV4（Route 53）、TC3-HMAC-SHA256
//! （腾讯云 DNSPod / EdgeOne）、阿里云 RPC 签名（云解析与 ESA）、华为云
//! AK/SK（SDK-HMAC-SHA256）、OVH 三步签名。每个算法在各自的模块里用
//! 官方文档或上游测试中的向量做金标准测试；出处见各模块的测试注释。
//!
//! 全部函数都是纯函数：时间戳由调用方传入（生产环境用 [`now_unix`]），
//! 不依赖时钟，测试可直接用固定向量。

pub mod aliyun;
pub mod huawei;
pub mod ovh;
pub mod sigv4;
pub mod tc3;

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// 当前 Unix 秒（生产环境的取时入口，签名函数本身不取时）。
pub fn now_unix() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => 0,
    }
}

/// 12 字节随机数的十六进制写法（阿里云 RPC 签名的 SignatureNonce）。
pub fn nonce_hex() -> String {
    let mut buf = [0u8; 12];
    let _ = getrandom::fill(&mut buf);
    hex::encode(buf)
}

/// HMAC-SHA256（腾讯云、华为云、百度云、火山引擎签名的基础件）。
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// SHA-256 的小写十六进制（SigV4/TC3/华为云的规范化请求摘要）。
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// HMAC-SHA1（阿里云 RPC 签名 v1.0）。
pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac =
        <Hmac<sha1::Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// SHA-1 的小写十六进制（OVH API 签名规定使用 SHA-1）。
pub fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// 标准 Base64（Basic 认证头与时代互联系列的 HMAC-SHA1 签名值）。
pub fn base64_std(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// 把 Unix 秒转成 UTC 的 (年, 月, 日, 时, 分, 秒)。不引入日期库，
/// 按天数到公历日期的换算（Howard Hinnant 的 civil_from_days 算法）。
pub fn utc_parts(unix: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (
        year,
        m,
        d,
        (secs / 3600) as u32,
        ((secs % 3600) / 60) as u32,
        (secs % 60) as u32,
    )
}

/// `YYYYMMDDTHHMMSSZ`（SigV4 的 x-amz-date、华为云 X-Sdk-Date、火山引擎 X-Date）。
pub fn amz_date(unix: i64) -> String {
    let (y, m, d, h, mi, s) = utc_parts(unix);
    format!("{y:04}{m:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

/// `YYYY-MM-DD`（TC3 与火山引擎凭证范围的日期段、百度云认证前缀）。
pub fn ymd_date(unix: i64) -> String {
    let (y, m, d, _, _, _) = utc_parts(unix);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DDTHH:MM:SSZ`（阿里云 Timestamp、百度云认证前缀）。
pub fn iso_z(unix: i64) -> String {
    let (y, m, d, h, mi, s) = utc_parts(unix);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_parts_matches_known_dates() {
        // 2023-11-14T22:13:20Z（华为云上游测试使用的固定时间）
        assert_eq!(utc_parts(1_700_000_000), (2023, 11, 14, 22, 13, 20));
        // 2019-02-25T16:44:25Z（腾讯云 TC3 官方文档示例的 X-TC-Timestamp）
        assert_eq!(utc_parts(1_551_113_065), (2019, 2, 25, 16, 44, 25));
        // Unix 纪元起点
        assert_eq!(utc_parts(0), (1970, 1, 1, 0, 0, 0));
        // 闰年 2024-02-29T00:00:00Z
        assert_eq!(utc_parts(1_709_164_800), (2024, 2, 29, 0, 0, 0));
    }

    #[test]
    fn amz_date_formats_compact_utc() {
        assert_eq!(amz_date(1_700_000_000), "20231114T221320Z");
        // AWS 官方 get-vanilla 向量的时间。
        assert_eq!(amz_date(1_440_938_160), "20150830T123600Z");
    }

    #[test]
    fn ymd_date_and_iso_z_format_dash_forms() {
        assert_eq!(ymd_date(1_551_113_065), "2019-02-25");
        assert_eq!(iso_z(1_551_113_065), "2019-02-25T16:44:25Z");
        assert_eq!(iso_z(1_700_000_000), "2023-11-14T22:13:20Z");
    }
}
