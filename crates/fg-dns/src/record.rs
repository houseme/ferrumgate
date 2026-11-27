//! 记录与凭据的公共类型（WP-41 §3.2）。

use std::collections::BTreeMap;

/// 记录类型。DDNS 与 ACME DNS-01 只用到其中一部分。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RecordType {
    #[default]
    A,
    AAAA,
    CNAME,
    TXT,
    NS,
    MX,
    SRV,
    CAA,
}

impl RecordType {
    pub fn as_str(self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::TXT => "TXT",
            RecordType::NS => "NS",
            RecordType::MX => "MX",
            RecordType::SRV => "SRV",
            RecordType::CAA => "CAA",
        }
    }

    /// 不区分大小写解析；未知类型返回 None。
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "A" => Some(RecordType::A),
            "AAAA" => Some(RecordType::AAAA),
            "CNAME" => Some(RecordType::CNAME),
            "TXT" => Some(RecordType::TXT),
            "NS" => Some(RecordType::NS),
            "MX" => Some(RecordType::MX),
            "SRV" => Some(RecordType::SRV),
            "CAA" => Some(RecordType::CAA),
            _ => None,
        }
    }
}

/// 要同步的一条解析记录。
#[derive(Clone, Debug, Default)]
pub struct Record {
    /// 主域名，例如 example.com
    pub zone: String,
    /// 主机记录；根域名用 "@"（空串等价于 "@"）
    pub sub: String,
    pub typ: RecordType,
    pub value: String,
    /// TTL 为 0 时使用服务商默认值
    pub ttl: u32,
    /// 解析线路，仅部分国内服务商支持，空表示默认
    pub line: String,
    /// 写到服务商处的记录备注；空表示不修改服务商处已有的备注
    pub remark: String,
}

impl Record {
    /// 完整域名（不带结尾点）。
    pub fn fqdn(&self) -> String {
        owner_fqdn(&self.zone, &self.sub)
    }

    /// 主机记录，根域名为 "@"。
    pub fn rr(&self) -> &str {
        owner_rr(&self.sub)
    }
}

/// 由主域名与主机记录拼出完整域名；主机记录为空或 "@" 时返回主域名本身。
pub fn owner_fqdn(zone: &str, sub: &str) -> String {
    if sub.is_empty() || sub == "@" {
        zone.to_owned()
    } else {
        format!("{sub}.{zone}")
    }
}

/// 主机记录的规范化写法：空串视为根域名 "@"。
pub fn owner_rr(sub: &str) -> &str {
    if sub.is_empty() { "@" } else { sub }
}

/// 服务商凭据。不同服务商对 ID/Secret 的含义不同，见 `Meta` 中的标签；
/// 接入点、区域 ID、代理状态等其余配置放进 `extra`。
#[derive(Clone, Debug, Default)]
pub struct Credentials {
    pub id: String,
    pub secret: String,
    pub extra: BTreeMap<String, String>,
}

impl Credentials {
    pub fn extra(&self, key: &str) -> Option<&str> {
        self.extra.get(key).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fqdn_root_sub_returns_zone() {
        let rec = Record {
            zone: "example.com".into(),
            sub: "@".into(),
            typ: RecordType::A,
            ..Record::default()
        };
        assert_eq!(rec.fqdn(), "example.com");
        assert_eq!(rec.rr(), "@");
    }

    #[test]
    fn fqdn_sub_joins_with_dot() {
        let rec = Record {
            zone: "example.com".into(),
            sub: "home".into(),
            typ: RecordType::AAAA,
            ..Record::default()
        };
        assert_eq!(rec.fqdn(), "home.example.com");
        assert_eq!(rec.rr(), "home");
    }

    #[test]
    fn record_type_parse_is_case_insensitive() {
        assert_eq!(RecordType::parse("txt"), Some(RecordType::TXT));
        assert_eq!(RecordType::parse("Aaaa"), Some(RecordType::AAAA));
        assert_eq!(RecordType::parse("MX").map(RecordType::as_str), Some("MX"));
        assert_eq!(RecordType::parse("nope"), None);
    }

    #[test]
    fn credentials_extra_lookup_returns_value() {
        let creds = Credentials {
            extra: [("proxied".to_owned(), "true".to_owned())].into(),
            ..Credentials::default()
        };
        assert_eq!(creds.extra("proxied"), Some("true"));
        assert_eq!(creds.extra("missing"), None);
    }
}
