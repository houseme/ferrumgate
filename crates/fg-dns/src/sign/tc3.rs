//! TC3-HMAC-SHA256（腾讯云 API 3.0：DNSPod、EdgeOne）。与上游
//! tencentcloud.go 的 tc3Authorization 一致：POST /、JSON 请求体、签名头
//! content-type + host + x-tc-action。
//!
//! 出处：腾讯云官方文档《签名方法 v3》（cloud.tencent.com/document/api/213/30654）
//! 的 DescribeInstances 示例。文档页渲染时隐藏了示例密钥，测试用文档中的
//! canonical request 与 string-to-sign 两级哈希（与密钥无关）对照官方值，
//! 再用固定测试密钥对照完整签名（向量用独立实现交叉验证）。

use super::{hmac_sha256, sha256_hex, ymd_date};

/// 计算 TC3-HMAC-SHA256 的 Authorization 头。`unix` 为 X-TC-Timestamp。
pub fn authorization(
    secret_id: &str,
    secret_key: &str,
    service: &str,
    host: &str,
    action: &str,
    payload: &[u8],
    unix: i64,
) -> String {
    let date = ymd_date(unix);
    let canonical_headers = format!(
        "content-type:application/json; charset=utf-8\nhost:{host}\nx-tc-action:{}\n",
        action.to_ascii_lowercase()
    );
    let signed_headers = "content-type;host;x-tc-action";
    let canonical_request = format!(
        "POST\n/\n\n{canonical_headers}\n{signed_headers}\n{}",
        sha256_hex(payload)
    );
    let scope = format!("{date}/{service}/tc3_request");
    let string_to_sign = format!(
        "TC3-HMAC-SHA256\n{unix}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let mut key = hmac_sha256(format!("TC3{secret_key}").as_bytes(), date.as_bytes());
    key = hmac_sha256(&key, service.as_bytes());
    key = hmac_sha256(&key, b"tc3_request");
    let signature = hex::encode(hmac_sha256(&key, string_to_sign.as_bytes()));
    format!(
        "TC3-HMAC-SHA256 Credential={secret_id}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &str =
        r#"{"Limit": 1, "Filters": [{"Values": ["\u672a\u547d\u540d"], "Name": "instance-name"}]}"#;
    const CANONICAL_HASH: &str = "35e9c5b0e3ae67532d3c9f17ead6c90222632e5b1ff7f6e89887f1398934f064";
    const STS_HASH: &str = "7019a55be8395899b900fb5564e4200d984910f34794a27cb3fb7d10ff6a1e84";

    /// 文档示例的两级哈希：canonical request 与 string-to-sign 的摘要
    /// （腾讯云官方文档《签名方法 v3》的 DescribeInstances 示例）。
    #[test]
    fn tc3_documented_hash_chain_matches_official_doc() {
        let canonical_request = format!(
            "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:cvm.tencentcloudapi.com\n\
             x-tc-action:describeinstances\n\ncontent-type;host;x-tc-action\n{}",
            sha256_hex(PAYLOAD.as_bytes())
        );
        assert_eq!(sha256_hex(PAYLOAD.as_bytes()), CANONICAL_HASH);
        assert_eq!(
            sha256_hex(canonical_request.as_bytes()),
            STS_HASH,
            "canonical request hash 与官方文档不一致"
        );
    }

    /// 完整签名：文档的完整示例密钥在页面渲染时被隐藏，这里用固定测试密钥
    /// （Canonical hash 与 string-to-sign 哈希仍取官方文档值）；期望值经独立
    /// HMAC-SHA256 实现交叉验证。
    #[test]
    fn tc3_full_signature_matches_cross_checked_vector() {
        let auth = authorization(
            "AKIDz8krbsJ5yKBZQpn74WFkmLPx5EXAMPLE",
            "Gu5t9xGARNpq86cd98joQYCN3oCOm1NEG",
            "cvm",
            "cvm.tencentcloudapi.com",
            "DescribeInstances",
            PAYLOAD.as_bytes(),
            1_551_113_065,
        );
        assert_eq!(
            auth,
            "TC3-HMAC-SHA256 Credential=AKIDz8krbsJ5yKBZQpn74WFkmLPx5EXAMPLE/2019-02-25/cvm/tc3_request, \
             SignedHeaders=content-type;host;x-tc-action, \
             Signature=bc791e4e4aa0288485c5c75b40605accb58bdd4a6d788c8883213c02798b3823"
        );
    }

    #[test]
    fn tc3_action_header_is_lowercased() {
        let auth = authorization(
            "id",
            "key",
            "dnspod",
            "dnspod.tencentcloudapi.com",
            "CreateRecord",
            b"{}",
            1_700_000_000,
        );
        assert!(auth.contains("/dnspod/tc3_request"), "{auth}");
        assert!(
            auth.starts_with("TC3-HMAC-SHA256 Credential=id/2023-11-14/dnspod/tc3_request"),
            "{auth}"
        );
    }
}
