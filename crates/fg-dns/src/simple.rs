//! 简单 REST 提供商的通用骨架（上游 simple.go 的通用部分）：发送与解析、
//! 表单与 URL 编码、错误信息截断。各提供商文件只写自己的端点与请求体。

use hyper::{Method, body::Bytes};
use serde::de::DeserializeOwned;

use crate::{
    ProviderError,
    http::{HttpReply, OutboundHttp},
};

/// 发送请求并把传输层失败按七类错误归类。
pub async fn send(
    http: &OutboundHttp,
    provider: &'static str,
    method: Method,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<Bytes>,
) -> Result<HttpReply, ProviderError> {
    http.send(method, url, headers, body)
        .await
        .map_err(|fail| ProviderError::from_http(provider, fail))
}

/// 把 2xx 响应体解析为 JSON；失败时归类为 `Parse` 并带上截断的原文。
pub fn json<T: DeserializeOwned>(provider: &'static str, body: &[u8]) -> Result<T, ProviderError> {
    serde_json::from_slice(body).map_err(|e| {
        ProviderError::parse(
            provider,
            format!(
                "解析响应失败: {e}: {}",
                truncate(&String::from_utf8_lossy(body), 300)
            ),
        )
    })
}

/// 序列化 JSON 请求体（本 crate 的载荷都是普通对象，序列化不会失败）。
pub fn json_body<T: serde::Serialize>(value: &T) -> Bytes {
    serde_json::to_vec(value)
        .unwrap_or_else(|_| serde_json::Value::Null.to_string().into_bytes())
        .into()
}

/// 折叠空白并截断，避免把整页 HTML 写进日志。
pub fn truncate(s: &str, n: usize) -> String {
    let folded = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if folded.chars().count() <= n {
        return folded;
    }
    let head: String = folded.chars().take(n).collect();
    format!("{head}...")
}

/// Go `url.QueryEscape` 的等价实现：空格转 `+`，其余非标记字符转 `%XX`。
pub fn query_escape(s: &str) -> String {
    escape_bytes(s, b'+')
}

/// Go `url.PathEscape` 的近似实现：主机记录只含字母数字与 `- _ .`，行为一致；
/// 空格转 `%20`。
pub fn path_escape(s: &str) -> String {
    escape_bytes(s, b'%')
}

fn escape_bytes(s: &str, space_replacement: u8) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' if space_replacement == b'+' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// `application/x-www-form-urlencoded` 表单编码（与 Go `url.Values.Encode` 一致）。
pub fn form_encode(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", query_escape(k), query_escape(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// 按行拆分多行配置（请求头、成功标识等），跳过空行。
pub fn split_lines(s: &str) -> Vec<String> {
    s.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// 取 JSON 值的字符串形态：字符串取原值，数字等标量转文本。
pub fn value_str(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        other if !other.is_null() => other.to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_escape_matches_go_behavior() {
        assert_eq!(query_escape("a b"), "a+b");
        assert_eq!(query_escape("a&b=c/d?e"), "a%26b%3Dc%2Fd%3Fe");
        assert_eq!(query_escape("汉字"), "%E6%B1%89%E5%AD%97");
        assert_eq!(query_escape("a~b.c_d-e"), "a~b.c_d-e");
        assert_eq!(query_escape(""), "");
    }

    #[test]
    fn path_escape_keeps_dns_label_characters() {
        assert_eq!(path_escape("_acme-challenge"), "_acme-challenge");
        assert_eq!(path_escape("a b"), "a%20b");
        assert_eq!(path_escape("@x"), "%40x");
    }

    #[test]
    fn form_encode_encodes_pairs_in_order() {
        let pairs = vec![
            ("login_token".to_owned(), "12,ab".to_owned()),
            ("value".to_owned(), "1.1.1.1".to_owned()),
        ];
        assert_eq!(form_encode(&pairs), "login_token=12%2Cab&value=1.1.1.1");
    }

    #[test]
    fn split_lines_skips_blank_lines() {
        assert_eq!(split_lines("a: 1\n\n  b: 2  \n"), vec!["a: 1", "b: 2"]);
        assert!(split_lines("   \n").is_empty());
    }

    #[test]
    fn truncate_folds_whitespace_and_limits() {
        assert_eq!(truncate("  a\n b\tc  ", 10), "a b c");
        let long = truncate("abcdefghijk", 5);
        assert_eq!(long, "abcde...");
    }

    #[test]
    fn value_str_handles_strings_and_numbers() {
        assert_eq!(value_str(&serde_json::json!("600")), "600");
        assert_eq!(value_str(&serde_json::json!(600)), "600");
        assert_eq!(value_str(&serde_json::Value::Null), "");
    }

    #[test]
    fn json_invalid_body_is_parse_error() {
        let err = json::<serde_json::Value>("p", b"not json").expect_err("parse");
        assert_eq!(err.kind, crate::ProviderErrorKind::Parse);
        assert!(err.detail.contains("解析响应失败"));
    }
}
