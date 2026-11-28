//! AWS Signature Version 4（Amazon Route 53）。与上游 route53.go 的 signV4
//! 一致：headers 已是小写且包含 host 与 x-amz-date（以及 x-amz-content-sha256），
//! canonical query 已按 RFC 3986 编码并排序。
//!
//! 出处：AWS 官方测试套件 get-vanilla（上游 TestSignV4Vector 使用同一向量）。

use super::{hmac_sha256, sha256_hex};

/// 计算 SigV4 的 Authorization 头。`amz_date` 形如 `20150830T123600Z`；
/// `query` 为空的 canonical query 串；headers 的键必须已小写。
#[allow(clippy::too_many_arguments)] // 与 SigV4 规范的签名要素一一对应
pub fn authorization(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(&str, &str)],
    payload: &[u8],
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    amz_date: &str,
) -> String {
    let mut names: Vec<&str> = headers.iter().map(|(k, _)| *k).collect();
    names.sort_unstable();
    let mut canon_headers = String::new();
    for k in &names {
        let value = headers
            .iter()
            .find(|(hk, _)| hk == k)
            .map(|(_, hv)| hv.trim())
            .unwrap_or_default();
        canon_headers.push_str(k);
        canon_headers.push(':');
        canon_headers.push_str(value);
        canon_headers.push('\n');
    }
    let signed = names.join(";");
    let payload_hash = sha256_hex(payload);
    let canonical_request = [
        method,
        path,
        query,
        canon_headers.as_str(),
        signed.as_str(),
        payload_hash.as_str(),
    ]
    .join("\n");
    let date = amz_date.get(..8).unwrap_or_default();
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let mut key = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    key = hmac_sha256(&key, region.as_bytes());
    key = hmac_sha256(&key, service.as_bytes());
    key = hmac_sha256(&key, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&key, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={signature}"
    )
}

/// SigV4 的 canonical query：参数名排序，名与值按 RFC 3986 编码（空格 %20）。
pub fn canonical_query(pairs: &[(String, String)]) -> String {
    let mut encoded: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| (aws_escape(k), aws_escape(v)))
        .collect();
    encoded.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// RFC 3986 编码：unreserved 字符原样，空格 %20，其余字节 %XX 大写。
pub fn aws_escape(s: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS 官方测试套件 get-vanilla（上游 TestSignV4Vector 同一向量）：
    /// GET /，空请求体，host 与 x-amz-date 两个签名头。
    #[test]
    fn sigv4_get_vanilla_official_vector_matches() {
        let auth = authorization(
            "GET",
            "/",
            "",
            &[
                ("host", "example.amazonaws.com"),
                ("x-amz-date", "20150830T123600Z"),
            ],
            b"",
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "service",
            "20150830T123600Z",
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn sigv4_headers_signed_sorted_and_trimmed() {
        // 头部顺序打乱时签名头按名称排序；值首尾空白被裁剪（与 SigV4 规范一致）。
        let auth = authorization(
            "GET",
            "/",
            "",
            &[
                ("x-amz-date", "20150830T123600Z"),
                ("host", " example.amazonaws.com "),
            ],
            b"",
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "service",
            "20150830T123600Z",
        );
        assert!(auth.contains("SignedHeaders=host;x-amz-date"), "{auth}");
        assert!(
            auth.ends_with(
                "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
            ),
            "{auth}"
        );
    }

    #[test]
    fn sigv4_canonical_query_sorts_and_escapes() {
        let pairs = vec![
            ("name".to_owned(), "example.com.".to_owned()),
            ("type".to_owned(), "TXT".to_owned()),
            ("comment".to_owned(), "a b&c".to_owned()),
        ];
        let q = canonical_query(&pairs);
        assert_eq!(q, "comment=a%20b%26c&name=example.com.&type=TXT");
    }
}
