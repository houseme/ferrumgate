//! 华为云 AK/SK 请求签名（SDK-HMAC-SHA256，APIG 规范）。与上游
//! huaweicloud.go 的 huaweiSign 一致：签名头为 host 与 x-sdk-date，规范 URI
//! 必须以 / 结尾，查询串按 RFC3986 编码后排序。
//!
//! 出处：华为云 APIG 签名算法文档（support.huaweicloud.com/devg-apisign
//! 《计算签名》）；官方文档未提供可直接复用的端到端数值向量，测试向量按
//! 该算法用独立实现（Python hmac/hashlib）计算并注明输入。

use super::{hmac_sha256, sha256_hex};

/// RFC3986 编码（空格 %20），与华为云 APIG SDK 一致。
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// 计算签名并返回 Authorization 头。`path` 为请求的转义路径（内部保证以
/// / 结尾）；`query_pairs` 为已编码的原始键值对，函数内排序。
#[allow(clippy::too_many_arguments)] // 与华为云 APIG 签名要素一一对应
pub fn authorization(
    access_key: &str,
    secret_key: &str,
    method: &str,
    path: &str,
    query_pairs: &[(String, String)],
    host: &str,
    x_sdk_date: &str,
    payload: &[u8],
) -> String {
    let mut path = path.to_owned();
    if !path.ends_with('/') {
        path.push('/');
    }
    let mut encoded: Vec<(String, String)> = query_pairs
        .iter()
        .map(|(k, v)| (escape(k), escape(v)))
        .collect();
    encoded.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let query = encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let signed_headers = "host;x-sdk-date";
    let canonical_request = format!(
        "{method}\n{path}\n{query}\nhost:{host}\nx-sdk-date:{x_sdk_date}\n\n{signed_headers}\n{}",
        sha256_hex(payload)
    );
    let string_to_sign = format!(
        "SDK-HMAC-SHA256\n{x_sdk_date}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let signature = hex::encode(hmac_sha256(
        secret_key.as_bytes(),
        string_to_sign.as_bytes(),
    ));
    format!(
        "SDK-HMAC-SHA256 Access={access_key}, SignedHeaders={signed_headers}, Signature={signature}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 按华为云 APIG 签名文档的算法用独立实现（Python hmac/hashlib）计算的
    /// 向量：GET /v2/zones?name=example.com.&search_mode=equal，空请求体。
    /// 输入与期望输出均固定；华为云官方文档无公开的端到端数值示例，此处
    /// 用于锁定实现的规范化细节（路径补 /、查询排序、头名小写）。
    #[test]
    fn huawei_sign_matches_independently_computed_vector() {
        let auth = authorization(
            "AK",
            "SK",
            "GET",
            "/v2/zones",
            &[
                ("name".to_owned(), "example.com.".to_owned()),
                ("search_mode".to_owned(), "equal".to_owned()),
            ],
            "dns.myhuaweicloud.com",
            "20231114T221320Z",
            b"",
        );
        assert_eq!(
            auth,
            "SDK-HMAC-SHA256 Access=AK, SignedHeaders=host;x-sdk-date, \
             Signature=2bd882b747a703b90b540f09b00a4bd9f707c64f939121ffbe7a232af531dc5b"
        );
    }

    #[test]
    fn huawei_escape_encodes_space_and_keeps_unreserved() {
        assert_eq!(escape("a b&c=d~e"), "a%20b%26c%3Dd~e");
        assert_eq!(escape("example.com."), "example.com.");
    }

    /// 规范 URI 必须以 / 结尾：路径不以 / 结尾时与补齐后的签名一致。
    #[test]
    fn huawei_path_without_trailing_slash_is_normalized() {
        let a = authorization(
            "ak",
            "SK",
            "GET",
            "/v2/zones",
            &[],
            "host",
            "20231114T221320Z",
            b"",
        );
        let b = authorization(
            "ak",
            "SK",
            "GET",
            "/v2/zones/",
            &[],
            "host",
            "20231114T221320Z",
            b"",
        );
        assert_eq!(a, b);
    }
}
