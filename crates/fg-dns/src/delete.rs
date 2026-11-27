//! 删除 DDNS 同步记录的通用流程（上游 delete.go）。
//!
//! [`Deleter::find_records`] 列出服务商处同名同类型（同线路）的记录，
//! [`pick_targets`] 选出要删除的：只删值与 `Record.value`（最近一次同步写入
//! 的值）相同的；值未知时无法确认记录由本程序写入，一条都不删并返回错误；
//! 按记录集管理的服务商，记录集里还有其他值时同样不删；没有同名记录时返回
//! 删除 0 条（视为成功）。

use crate::{BoxFut, DnsProvider, ProviderError, ProviderErrorKind, Record, RecordType, msg, txt};

/// 服务商处与要删除的记录同名、同类型（同线路）的一条解析。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RemoteRecord {
    /// 服务商的记录 ID，按记录集管理的服务商可为空。
    pub id: String,
    /// 删除时需要的上下文，例如 Cloudflare / 华为云的 zone ID。
    pub scope: String,
    /// 该条记录的值；按记录集管理的服务商是记录集里的全部值。
    pub values: Vec<String>,
    pub ttl: u32,
}

/// 可选能力：删除 DDNS 同步的记录。
pub trait Deleter: DnsProvider {
    fn find_records<'a>(
        &'a self,
        rec: &'a Record,
    ) -> BoxFut<'a, Result<Vec<RemoteRecord>, ProviderError>>;
    fn remove_record<'a>(
        &'a self,
        rec: &'a Record,
        remote: &'a RemoteRecord,
    ) -> BoxFut<'a, Result<(), ProviderError>>;
}

/// 删除服务商处由动态域名同步的这条记录，返回删除的条数，记录不存在时返回 0。
pub async fn delete_records(p: &dyn Deleter, rec: &Record) -> Result<usize, ProviderError> {
    let provider = p.meta().name;
    let recs = p.find_records(rec).await?;
    let targets = pick_targets(provider, &recs, rec)?;
    for target in &targets {
        p.remove_record(rec, target).await?;
    }
    Ok(targets.len())
}

/// 按 [`delete_records`] 的规则选出要删除的记录；没有同名记录时返回空切片，
/// 无法确认时返回错误。
pub fn pick_targets<'a>(
    provider: &'static str,
    recs: &'a [RemoteRecord],
    rec: &'a Record,
) -> Result<Vec<&'a RemoteRecord>, ProviderError> {
    if recs.is_empty() {
        return Ok(Vec::new());
    }
    if rec.value.is_empty() {
        return Err(ProviderError::new(provider, ProviderErrorKind::InvalidInput, msg::DELETE_VALUE_UNKNOWN)
            .with_detail(format!(
                "还没有同步过 {} {}，无法确认服务商处的记录由本程序写入，未删除；请先同步一次，或到服务商控制台删除",
                rec.typ.as_str(),
                rec.fqdn()
            )));
    }
    let mut out = Vec::new();
    for remote in recs {
        if !remote
            .values
            .iter()
            .any(|v| same_value(rec.typ, v, &rec.value))
        {
            continue;
        }
        if remote.values.len() > 1 {
            return Err(ProviderError::new(
                provider,
                ProviderErrorKind::InvalidInput,
                msg::DELETE_RECORDSET_HAS_OTHERS,
            )
            .with_detail(format!(
                "服务商处的 {} {} 记录集还有其他 {} 个值，删除会一并删掉它们，未删除",
                rec.typ.as_str(),
                rec.fqdn(),
                remote.values.len() - 1
            )));
        }
        out.push(remote);
    }
    if out.is_empty() {
        return Err(ProviderError::new(
            provider,
            ProviderErrorKind::InvalidInput,
            msg::DELETE_VALUE_MISMATCH,
        )
        .with_detail(format!(
            "服务商处的 {} {} 记录值与最近同步的 {} 不一致，可能已被修改，未删除",
            rec.typ.as_str(),
            rec.fqdn(),
            rec.value
        )));
    }
    Ok(out)
}

/// 比较记录值：A/AAAA 按解析后的地址比较（IPv6 可能以展开或大写写法返回，
/// IPv4 映射地址与 IPv4 相同）；无法解析为地址时退回字符串比较；
/// 其他类型去掉 TXT 的引号与 CNAME 结尾的点，CNAME 不区分大小写。
pub fn same_value(typ: RecordType, a: &str, b: &str) -> bool {
    if matches!(typ, RecordType::A | RecordType::AAAA)
        && let (Ok(pa), Ok(pb)) = (
            a.trim().parse::<std::net::IpAddr>(),
            b.trim().parse::<std::net::IpAddr>(),
        )
    {
        return pa.to_canonical() == pb.to_canonical();
    }
    fn norm(s: &str) -> &str {
        txt::unquote(s.trim()).trim_end_matches('.')
    }
    if typ == RecordType::CNAME {
        norm(a).eq_ignore_ascii_case(norm(b))
    } else {
        norm(a) == norm(b)
    }
}

/// 判断服务商记录的线路是否与要同步的记录一致；未填线路对应默认线路。
pub fn line_match(got: &str, want: &str, default_line: &str) -> bool {
    if want.is_empty() {
        got.is_empty() || got == default_line
    } else {
        got == want
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(id: &str, values: &[&str]) -> RemoteRecord {
        RemoteRecord {
            id: id.to_owned(),
            scope: String::new(),
            values: values.iter().map(|v| (*v).to_owned()).collect(),
            ttl: 0,
        }
    }

    fn rec(value: &str) -> Record {
        Record {
            zone: "example.com".into(),
            sub: "www".into(),
            typ: RecordType::A,
            value: value.into(),
            ..Record::default()
        }
    }

    fn picked(recs: &[RemoteRecord], rec: &Record) -> Result<Vec<String>, ()> {
        pick_targets("test", recs, rec)
            .map(|out| out.iter().map(|r| r.id.clone()).collect())
            .map_err(|_| ())
    }

    #[test]
    fn pick_targets_no_records_returns_empty() {
        assert_eq!(picked(&[], &rec("1.1.1.1")), Ok(vec![]));
        assert_eq!(picked(&[], &rec("")), Ok(vec![]));
    }

    #[test]
    fn pick_targets_single_matching_returns_it() {
        let one = vec![remote("1", &["1.1.1.1"])];
        assert_eq!(picked(&one, &rec("1.1.1.1")), Ok(vec!["1".into()]));
    }

    #[test]
    fn pick_targets_single_unknown_value_errors() {
        let one = vec![remote("1", &["1.1.1.1"])];
        assert_eq!(picked(&one, &rec("")), Err(()));
    }

    #[test]
    fn pick_targets_single_changed_value_errors() {
        let one = vec![remote("1", &["1.1.1.1"])];
        assert_eq!(picked(&one, &rec("9.9.9.9")), Err(()));
    }

    #[test]
    fn pick_targets_multi_picks_by_value() {
        let two = vec![remote("1", &["1.1.1.1"]), remote("2", &["2.2.2.2"])];
        assert_eq!(picked(&two, &rec("2.2.2.2")), Ok(vec!["2".into()]));
        assert_eq!(picked(&two, &rec("9.9.9.9")), Err(()));
        assert_eq!(picked(&two, &rec("")), Err(()));
    }

    #[test]
    fn pick_targets_multi_same_value_deletes_all() {
        let dup = vec![remote("1", &["1.1.1.1"]), remote("2", &["1.1.1.1"])];
        assert_eq!(
            picked(&dup, &rec("1.1.1.1")),
            Ok(vec!["1".into(), "2".into()])
        );
    }

    #[test]
    fn pick_targets_recordset_with_other_values_errors() {
        let set = vec![remote("rs", &["1.1.1.1", "3.3.3.3"])];
        assert_eq!(picked(&set, &rec("1.1.1.1")), Err(()));
    }

    #[test]
    fn same_value_txt_unquotes() {
        assert!(same_value(RecordType::TXT, r#""hello""#, "hello"));
        assert!(!same_value(RecordType::TXT, r#""Hello""#, "hello"));
    }

    #[test]
    fn same_value_cname_ignores_case_and_trailing_dot() {
        assert!(same_value(
            RecordType::CNAME,
            "Target.Example.com.",
            "target.example.com"
        ));
        assert!(!same_value(
            RecordType::CNAME,
            "a.example.com",
            "b.example.com"
        ));
    }

    #[test]
    fn same_value_aaaa_expanded_and_uppercase_match() {
        assert!(same_value(
            RecordType::AAAA,
            "2001:0DB8:0000:0000:0000:0000:0000:0001",
            "2001:db8::1"
        ));
        assert!(!same_value(RecordType::AAAA, "2001:db8::1", "2001:db8::2"));
    }

    #[test]
    fn same_value_ipv4_mapped_matches_ipv4() {
        assert!(same_value(
            RecordType::A,
            "::ffff:203.0.113.1",
            "203.0.113.1"
        ));
        assert!(same_value(RecordType::A, " 203.0.113.1 ", "203.0.113.1"));
    }

    #[test]
    fn same_value_non_address_falls_back_to_string() {
        assert!(same_value(RecordType::A, "not-an-ip", "not-an-ip"));
        assert!(!same_value(RecordType::A, "not-an-ip", "203.0.113.1"));
    }

    #[test]
    fn same_value_plain_addresses_must_match() {
        assert!(!same_value(RecordType::A, "1.1.1.1", "1.1.1.2"));
    }

    #[test]
    fn line_match_default_line() {
        assert!(line_match("", "", "默认"));
        assert!(line_match("默认", "", "默认"));
        assert!(!line_match("telecom", "", "默认"));
        assert!(line_match("telecom", "telecom", "默认"));
        assert!(!line_match("默认", "telecom", "默认"));
    }

    struct Stub {
        recs: Vec<RemoteRecord>,
        removed: std::sync::Mutex<Vec<String>>,
    }

    static META: crate::Meta = crate::Meta::new("stub", "Stub");

    impl crate::DnsProvider for Stub {
        fn meta(&self) -> &'static crate::Meta {
            &META
        }
        fn upsert<'a>(
            &'a self,
            _rec: &'a Record,
        ) -> BoxFut<'a, Result<crate::UpsertAction, ProviderError>> {
            Box::pin(async { unreachable!("delete test does not upsert") })
        }
    }

    impl Deleter for Stub {
        fn find_records<'a>(
            &'a self,
            _rec: &'a Record,
        ) -> BoxFut<'a, Result<Vec<RemoteRecord>, ProviderError>> {
            Box::pin(async { Ok(self.recs.clone()) })
        }
        fn remove_record<'a>(
            &'a self,
            _rec: &'a Record,
            remote: &'a RemoteRecord,
        ) -> BoxFut<'a, Result<(), ProviderError>> {
            Box::pin(async {
                self.removed.lock().expect("lock").push(remote.id.clone());
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn delete_records_removes_only_matching_targets() {
        let stub = Stub {
            recs: vec![remote("1", &["1.1.1.1"]), remote("2", &["2.2.2.2"])],
            removed: std::sync::Mutex::new(Vec::new()),
        };
        let n = delete_records(&stub, &rec("2.2.2.2"))
            .await
            .expect("delete");
        assert_eq!(n, 1);
        assert_eq!(*stub.removed.lock().expect("lock"), vec!["2".to_owned()]);
    }

    #[tokio::test]
    async fn delete_records_zero_when_no_remote_records() {
        let stub = Stub {
            recs: Vec::new(),
            removed: std::sync::Mutex::new(Vec::new()),
        };
        let n = delete_records(&stub, &rec("")).await.expect("delete");
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn delete_records_unknown_value_removes_nothing() {
        let stub = Stub {
            recs: vec![remote("1", &["1.1.1.1"])],
            removed: std::sync::Mutex::new(Vec::new()),
        };
        let err = delete_records(&stub, &rec("")).await.expect_err("unknown");
        assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
        assert!(stub.removed.lock().expect("lock").is_empty());
    }
}
