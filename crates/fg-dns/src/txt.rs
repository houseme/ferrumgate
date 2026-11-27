//! TXT 记录增删的公共部分（上游 txt.go）。
//!
//! 同一主机名可能同时存在多个验证值（例如同时申请 example.com 与
//! *.example.com），因此 [`TxtRecords::add_txt`] 总是新增，
//! [`TxtRecords::delete_txt`] 按值删除。

use crate::{BoxFut, ProviderError};

/// ACME 验证记录使用较短的 TTL，加快传播。
pub const TXT_TTL: u32 = 600;

/// 去掉部分服务商在 TXT 值两侧加的引号。
pub fn unquote(s: &str) -> &str {
    s.trim_matches('"')
}

/// 可选能力：TXT 记录增删（ACME DNS-01 验证）。
pub trait TxtRecords: crate::DnsProvider {
    fn add_txt<'a>(
        &'a self,
        zone: &'a str,
        sub: &'a str,
        value: &'a str,
    ) -> BoxFut<'a, Result<(), ProviderError>>;
    fn delete_txt<'a>(
        &'a self,
        zone: &'a str,
        sub: &'a str,
        value: &'a str,
    ) -> BoxFut<'a, Result<(), ProviderError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unquote_strips_outer_quotes_only() {
        assert_eq!(unquote(r#""hello""#), "hello");
        assert_eq!(unquote("hello"), "hello");
        assert_eq!(unquote(r#""a"b""#), r#"a"b"#);
        assert_eq!(unquote(r#""""#), "");
        assert_eq!(unquote(""), "");
    }

    #[test]
    fn txt_ttl_is_short_for_propagation() {
        assert_eq!(TXT_TTL, 600);
    }
}
