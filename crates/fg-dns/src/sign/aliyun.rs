//! 阿里云 RPC 风格签名（Signature Version 1.0，HMAC-SHA1）：云解析 DNS 与
//! ESA。与上游 alidns.go 的 aliSign / aliesa.go 的 aliESASign 一致：参数按键
//! 字典序排列后做 RFC3986 编码，`方法&%2F&编码后的规范化串` 用 `Secret&` 作
//! HMAC-SHA1 的密钥，签名 Base64 后附在查询串尾。
//!
//! 出处：阿里云官方文档《RPC API 签名机制》示例（上游 TestAliSignOfficialExample
//! 使用同一向量）。

use base64::Engine as _;

/// 阿里云规范编码：RFC3986，空格为 %20，保留 ~（其余字节 %XX 大写）。
pub fn percent_encode(s: &str) -> String {
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

/// 计算签名并返回完整查询串：参数按名字典序排列、编码后拼成规范化串，
/// 追加 `&Signature=...`。`method` 为参与签名的 HTTP 方法（云解析读取接口为
/// GET，ESA 的写入接口为 POST）。
pub fn signed_query(method: &str, params: &[(String, String)], secret: &str) -> String {
    let mut pairs: Vec<(&str, &str)> = params
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    pairs.sort_unstable();
    let canonical = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let string_to_sign = format!("{method}&%2F&{}", percent_encode(&canonical));
    let mac = super::hmac_sha1(format!("{secret}&").as_bytes(), string_to_sign.as_bytes());
    // HMAC-SHA1 摘要（20 字节）Base64（标准字母表）编码后整体 URL 编码。
    let sig = base64::engine::general_purpose::STANDARD.encode(&mac);
    format!("{canonical}&Signature={}", percent_encode(&sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(k: &str, v: &str) -> (String, String) {
        (k.to_owned(), v.to_owned())
    }

    /// 阿里云官方文档《RPC API 签名机制》中的示例（上游 TestAliSignOfficialExample
    /// 同一向量）：Signature = uRpHwaSEt3J+6KQD//svCh/x+pI=。
    #[test]
    fn aliyun_rpc_signature_matches_official_doc_example() {
        let params = vec![
            pair("Format", "XML"),
            pair("AccessKeyId", "testid"),
            pair("Action", "DescribeDomainRecords"),
            pair("SignatureMethod", "HMAC-SHA1"),
            pair("DomainName", "example.com"),
            pair("SignatureNonce", "f59ed6a9-83fc-473b-9cc6-99c95df3856e"),
            pair("SignatureVersion", "1.0"),
            pair("Version", "2015-01-09"),
            pair("Timestamp", "2016-03-24T16:41:54Z"),
        ];
        let q = signed_query("GET", &params, "testsecret");
        assert_eq!(
            q,
            "AccessKeyId=testid&Action=DescribeDomainRecords&DomainName=example.com&Format=XML&\
             SignatureMethod=HMAC-SHA1&SignatureNonce=f59ed6a9-83fc-473b-9cc6-99c95df3856e&\
             SignatureVersion=1.0&Timestamp=2016-03-24T16%3A41%3A54Z&Version=2015-01-09&\
             Signature=uRpHwaSEt3J%2B6KQD%2F%2FsvCh%2Fx%2BpI%3D"
        );
    }

    #[test]
    fn aliyun_percent_encode_keeps_unreserved_only() {
        assert_eq!(percent_encode("a b+c*d/e~f"), "a%20b%2Bc%2Ad%2Fe~f");
        assert_eq!(percent_encode("汉字"), "%E6%B1%89%E5%AD%97");
    }

    /// ESA 的写操作用 POST，参与签名的方法随之变化（与 GET 签名不同）。
    #[test]
    fn aliyun_signed_query_depends_on_method() {
        let params = vec![pair("Action", "CreateRecord")];
        let get_q = signed_query("GET", &params, "sk");
        let post_q = signed_query("POST", &params, "sk");
        assert_ne!(get_q, post_q);
        assert!(get_q.starts_with("Action=CreateRecord&"));
    }
}
