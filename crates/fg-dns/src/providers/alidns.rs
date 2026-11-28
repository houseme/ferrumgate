//! 阿里云云解析 DNS（上游 alidns.go）：RPC 风格接口，签名算法 HMAC-SHA1
//! （Signature Version 1.0），文档 help.aliyun.com/document_detail/29745.html。
//!
//! 契约（端点 `https://alidns.aliyuncs.com/`，全部动作 GET，参数与签名在查询
//! 串里）：公共参数 Format=JSON、Version=2015-01-09、AccessKeyId、
//! SignatureMethod=HMAC-SHA1、SignatureVersion=1.0、SignatureNonce（12 字节
//! 随机 hex）、Timestamp（UTC `YYYY-MM-DDTHH:MM:SSZ`）、Action，末尾
//! `Signature=`。
//!
//! - 动作：`DescribeSubDomainRecords`（SubDomain=FQDN/DomainName/Type/PageSize=100）、
//!   `AddDomainRecord`（DomainName/RR/Type/Value[/TTL][/Line]）、
//!   `UpdateDomainRecord`（RecordId + 同上）、`UpdateDomainRecordRemark`、
//!   `DeleteDomainRecord`（RecordId）。
//! - 线路（LINE）：Line，空对应默认线路 `default`；未指定线路时只处理默认
//!   线路的记录，避免误改分线路记录。
//! - TTL：>0 时按值发送；未指定时新建不发送，更新发送 600。
//! - 备注（REMARK）：格式受限（数字/中文/字母与 `_ -,.`，最多 50 字符），
//!   其他字符换成 `_` 并合并连续 `_`；新增接口不接受备注，创建成功后用
//!   返回的 RecordId 调 UpdateDomainRecordRemark。
//! - TXT：AddDomainRecord（TTL 600）新增；DescribeSubDomainRecords 后按值
//!   （去引号）DeleteDomainRecord。
//! - 删除（DEL）：DescribeSubDomainRecords 按类型与线路过滤后按值挑选，
//!   DeleteDomainRecord 逐条。
//! - 业务错误：响应体 {Code, Message}，SignatureDoesNotMatch 等认证类错误
//!   归类 Auth，其余按 HTTP 状态或无效输入。

use std::sync::Arc;

use hyper::Method;

use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, RemoteRecord, UpsertAction, msg,
    sign, simple,
};

pub static META: Meta = Meta::new("alidns", "阿里云 DNS")
    .labels("AccessKey ID", "AccessKey Secret")
    .doc("https://ram.console.aliyun.com/manage/ak")
    .line()
    .remark()
    .acme()
    .delete();

/// 阿里云解析记录备注的最大字符数。
const REMARK_MAX: usize = 50;

pub struct AliDns {
    id: String,
    secret: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

/// 记录列表里的一条（含服务商线路写法）。
struct AliRecord {
    id: String,
    rr: String,
    typ: String,
    value: String,
    ttl: u32,
    line: String,
    remark: String,
}

impl AliDns {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://alidns.aliyuncs.com/")
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, true, true)?;
        Ok(Self {
            id: creds.id.trim().to_owned(),
            secret: creds.secret.trim().to_owned(),
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    async fn call(
        &self,
        action: &str,
        params: &[(String, String)],
    ) -> Result<serde_json::Value, ProviderError> {
        let mut all = vec![
            ("Format".to_owned(), "JSON".to_owned()),
            ("Version".to_owned(), "2015-01-09".to_owned()),
            ("AccessKeyId".to_owned(), self.id.clone()),
            ("SignatureMethod".to_owned(), "HMAC-SHA1".to_owned()),
            ("SignatureVersion".to_owned(), "1.0".to_owned()),
            ("SignatureNonce".to_owned(), sign::nonce_hex()),
            ("Timestamp".to_owned(), sign::iso_z(sign::now_unix())),
            ("Action".to_owned(), action.to_owned()),
        ];
        all.extend(params.iter().cloned());
        let query = sign::aliyun::signed_query("GET", &all, &self.secret);
        let url = format!("{}/?{query}", self.endpoint);
        let reply = match self.http.send(Method::GET, &url, &[], None).await {
            Ok(reply) => reply,
            Err(fail) => return Err(ali_error(fail, action)),
        };
        simple::json(META.name, &reply.body)
    }

    /// 解析 DescribeSubDomainRecords 的记录列表。
    fn records_of(v: &serde_json::Value) -> Vec<AliRecord> {
        v["DomainRecords"]["Record"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|r| AliRecord {
                        id: simple::value_str(&r["RecordId"]),
                        rr: simple::value_str(&r["RR"]),
                        typ: simple::value_str(&r["Type"]),
                        value: simple::value_str(&r["Value"]),
                        ttl: simple::value_str(&r["TTL"]).parse().unwrap_or(0),
                        line: simple::value_str(&r["Line"]),
                        remark: simple::value_str(&r["Remark"]),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 未指定线路时只处理默认线路的记录（rec.Line 为空或等于 default）。
    fn want_line(rec: &Record) -> &str {
        if rec.line.is_empty() {
            "default"
        } else {
            &rec.line
        }
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let list_form = vec![
            ("SubDomain".to_owned(), rec.fqdn()),
            ("DomainName".to_owned(), rec.zone.clone()),
            ("Type".to_owned(), rec.typ.as_str().to_owned()),
            ("PageSize".to_owned(), "100".to_owned()),
        ];
        let v = self.call("DescribeSubDomainRecords", &list_form).await?;
        let remark = ali_remark(&rec.remark);
        let mut params: Vec<(String, String)> = vec![
            ("RR".to_owned(), rec.rr().to_owned()),
            ("Type".to_owned(), rec.typ.as_str().to_owned()),
            ("Value".to_owned(), rec.value.clone()),
        ];
        if rec.ttl > 0 {
            params.push(("TTL".to_owned(), rec.ttl.to_string()));
        }
        if !rec.line.is_empty() {
            params.push(("Line".to_owned(), rec.line.clone()));
        }
        let want_line = Self::want_line(rec);
        for cur in Self::records_of(&v) {
            if cur.typ != rec.typ.as_str() || (!cur.line.is_empty() && cur.line != want_line) {
                continue;
            }
            let value_same = cur.value == rec.value && (rec.ttl == 0 || cur.ttl == rec.ttl);
            let remark_same = rec.remark.is_empty() || cur.remark == remark;
            if value_same && remark_same {
                return Ok(UpsertAction::Unchanged);
            }
            // 值与 TTL 都没变时 UpdateDomainRecord 会报 DomainRecordDuplicate，
            // 只改备注时跳过更新。
            if !value_same {
                let mut upd = params.clone();
                if rec.ttl == 0 {
                    // 未指定 TTL 时更新为默认的 600。
                    set_param(&mut upd, "TTL", "600");
                }
                upd.push(("RecordId".to_owned(), cur.id.clone()));
                self.call("UpdateDomainRecord", &upd).await?;
            }
            if !remark_same {
                self.set_remark(&cur.id, &remark).await?;
            }
            return Ok(UpsertAction::Updated);
        }
        let mut add = params;
        add.push(("DomainName".to_owned(), rec.zone.clone()));
        let created = self.call("AddDomainRecord", &add).await?;
        // 新增接口不接受备注，创建后再单独设置。
        let id = simple::value_str(&created["RecordId"]);
        if !remark.is_empty()
            && !id.is_empty()
            && let Err(e) = self.set_remark(&id, &remark).await
        {
            let detail = format!("记录已创建，设置备注失败: {}", e.detail);
            return Err(e.with_detail(detail));
        }
        Ok(UpsertAction::Created)
    }

    async fn set_remark(&self, id: &str, remark: &str) -> Result<(), ProviderError> {
        self.call(
            "UpdateDomainRecordRemark",
            &[
                ("RecordId".to_owned(), id.to_owned()),
                ("Remark".to_owned(), remark.to_owned()),
            ],
        )
        .await
        .map(drop)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        self.call(
            "AddDomainRecord",
            &[
                ("DomainName".to_owned(), zone.to_owned()),
                ("RR".to_owned(), sub.to_owned()),
                ("Type".to_owned(), "TXT".to_owned()),
                ("Value".to_owned(), value.to_owned()),
                ("TTL".to_owned(), crate::txt::TXT_TTL.to_string()),
            ],
        )
        .await
        .map(drop)
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        let list_form = vec![
            ("SubDomain".to_owned(), crate::record::owner_fqdn(zone, sub)),
            ("DomainName".to_owned(), zone.to_owned()),
            ("Type".to_owned(), "TXT".to_owned()),
            ("PageSize".to_owned(), "100".to_owned()),
        ];
        let v = self.call("DescribeSubDomainRecords", &list_form).await?;
        for cur in Self::records_of(&v) {
            if crate::txt::unquote(&cur.value) == value {
                self.call("DeleteDomainRecord", &[("RecordId".to_owned(), cur.id)])
                    .await?;
                return Ok(());
            }
        }
        Ok(())
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let list_form = vec![
            ("SubDomain".to_owned(), rec.fqdn()),
            ("DomainName".to_owned(), rec.zone.clone()),
            ("Type".to_owned(), rec.typ.as_str().to_owned()),
            ("PageSize".to_owned(), "100".to_owned()),
        ];
        let v = self.call("DescribeSubDomainRecords", &list_form).await?;
        let want_line = Self::want_line(rec);
        let mut out = Vec::new();
        for cur in Self::records_of(&v) {
            if cur.typ != rec.typ.as_str()
                || cur.rr != rec.rr()
                || (!cur.line.is_empty() && cur.line != want_line)
            {
                continue;
            }
            out.push(RemoteRecord {
                id: cur.id,
                scope: rec.zone.clone(),
                values: vec![cur.value],
                ttl: cur.ttl,
            });
        }
        Ok(out)
    }

    pub async fn remove_record(
        &self,
        _rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.call(
            "DeleteDomainRecord",
            &[("RecordId".to_owned(), remote.id.clone())],
        )
        .await
        .map(drop)
    }
}

/// 传输层失败时把阿里云业务错误码（{Code, Message}）透出为详情；认证类
/// 错误码按认证失败归类（HTTP 状态可能不是 401/403），其余按 HTTP 状态。
fn ali_error(fail: crate::http::HttpFail, action: &str) -> ProviderError {
    if let crate::http::HttpFail::Status { status, body, .. } = &fail
        && let Ok(v) = serde_json::from_slice::<serde_json::Value>(body)
        && v.get("Code").map(|c| !c.is_null()).unwrap_or(false)
    {
        let code = simple::value_str(&v["Code"]);
        let message = simple::value_str(&v["Message"]);
        let (kind, key) = if code.contains("SignatureDoesNotMatch")
            || code.contains("InvalidAccessKeyId")
            || code.contains("InvalidSecurityToken")
        {
            (ProviderErrorKind::Auth, msg::AUTH_FAILED)
        } else {
            (crate::http::kind_for_status(*status), msg::API_ERROR)
        };
        return ProviderError::new(META.name, kind, key)
            .with_detail(format!("阿里云 {action}: {message} ({code})"));
    }
    ProviderError::from_http(META.name, fail)
}

fn set_param(form: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some(entry) = form.iter_mut().find(|(k, _)| k == key) {
        entry.1 = value.to_owned();
    } else {
        form.push((key.to_owned(), value.to_owned()));
    }
}

/// 把备注转换为阿里云接受的格式：只能含数字、中文、英文字母与 `_ -,.`，最多
/// 50 个字符。其他字符换成 `_` 并合并连续的 `_`，避免因备注格式导致更新失败。
fn ali_remark(s: &str) -> String {
    let mut out = String::new();
    let mut last_underscore = false;
    for c in s.chars() {
        let ok = c.is_ascii_alphanumeric()
            || matches!(c, '_' | '-' | ',' | '.')
            || is_han(c)
            || c == '，'
            || c == '。';
        let replaced = if ok { c } else { '_' };
        if replaced == '_' && last_underscore {
            continue;
        }
        if out.chars().count() == REMARK_MAX {
            break;
        }
        last_underscore = replaced == '_';
        out.push(replaced);
    }
    out.trim_matches('_').to_owned()
}

/// 是否为汉字（Unicode Han 区段，与 Go unicode.Han 对齐的主要范围）。
fn is_han(c: char) -> bool {
    matches!(c, '\u{4E00}'..='\u{9FFF}' | '\u{3400}'..='\u{4DBF}' | '\u{F900}'..='\u{FAFF}')
}

crate::impl_provider!(AliDns, META);
crate::impl_txt!(AliDns);
crate::impl_deleter!(AliDns);

#[cfg(test)]
mod tests {
    use super::*;

    /// 备注格式转换（上游 TestAliRemarkFormat 的样例）：不接受的字符换成
    /// `_` 并合并连续 `_`，首尾 `_` 去掉。
    #[test]
    fn ali_remark_replaces_unsupported_characters() {
        assert_eq!(
            ali_remark("Gately 备注测试：阿里云"),
            "Gately_备注测试_阿里云"
        );
        assert_eq!(ali_remark("家里 NAS，书房。"), "家里_NAS，书房。");
        assert_eq!(ali_remark("  a  b  "), "a_b");
        assert_eq!(ali_remark("v1.2-test_ok,x"), "v1.2-test_ok,x");
        assert_eq!(ali_remark("!!!"), "");
    }

    /// 备注最多 50 个字符。
    #[test]
    fn ali_remark_truncated_to_max_chars() {
        let long = ali_remark(&"长".repeat(80));
        assert_eq!(long.chars().count(), REMARK_MAX);
    }
}
