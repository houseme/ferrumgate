//! OVH API 请求签名（三步：取服务器时间 → 计算签名 → 调用）。与上游
//! ovh.go 一致：`$1$` + SHA1(AppSecret + "+" + ConsumerKey + "+" + METHOD +
//! "+" + 完整 URL + "+" + 请求体 + "+" + 时间戳)。
//!
//! 出处：OVH API 签名文档（api.ovh.com《First use of the API》规定的 SHA-1
//! 拼接公式）；官方文档未给数值示例，测试向量按该公式用独立实现计算并注明
//! 输入。

use super::sha1_hex;

/// 计算请求签名，返回 `X-Ovh-Signature` 的取值（带 `$1$` 前缀）。
/// `url` 为包含查询串的完整地址（与实际发出的请求一致）。
pub fn signature(
    app_secret: &str,
    consumer_key: &str,
    method: &str,
    url: &str,
    body: &str,
    timestamp: i64,
) -> String {
    let joined = [
        app_secret,
        consumer_key,
        method,
        url,
        body,
        &timestamp.to_string(),
    ]
    .join("+");
    format!("$1${}", sha1_hex(joined.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 按官方文档的拼接公式用独立实现（Python hashlib.sha1）计算的向量。
    #[test]
    fn ovh_signature_matches_independently_computed_vector() {
        let sig = signature(
            "sec",
            "ck",
            "GET",
            "https://eu.api.ovh.com/1.0/domain/zone/example.com/record?fieldType=TXT&subDomain=_acme-challenge",
            "",
            1_700_000_000,
        );
        assert_eq!(sig, "$1$946939397787fb08fe5966aad84c154600f55b66");
    }

    /// 请求体参与签名：带请求体的 POST 与空请求体的 GET 签名不同。
    #[test]
    fn ovh_signature_covers_body_and_method() {
        let get_sig = signature("s", "c", "GET", "https://eu.api.ovh.com/1.0/me", "", 1);
        let post_sig = signature(
            "s",
            "c",
            "POST",
            "https://eu.api.ovh.com/1.0/me",
            r#"{"a":1}"#,
            1,
        );
        assert_ne!(get_sig, post_sig);
        assert!(get_sig.starts_with("$1$") && get_sig.len() == "$1$".len() + 40);
    }
}
