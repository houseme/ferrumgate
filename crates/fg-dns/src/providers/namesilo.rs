//! NameSilo DNS（上游 namesilo.go）：文档 namesilo.com/api-reference。所有
//! 操作都是带 key 的 GET 请求，业务结果在响应 XML 的 reply.code 中（300 表示
//! 成功）。
//!
//! 契约（端点 `https://www.namesilo.com/api/{op}?version=1&type=xml&key=…&…`，
//! key 在查询串里，错误信息要先抹掉它）：
//!
//! - 列表：`dnsListRecords?domain={zone}`，响应 `<resource_record>` 列表
//!   （record_id/type/host/value/ttl）；host 可能是相对名也可能是完整域名
//!   （带结尾点），两种都接受（hostMatches 先去结尾点再比较，根域名兼容
//!   空、@ 与主域名本身三种写法）。
//! - 新建：`dnsAddRecord?domain&rrtype&rrhost&rrvalue&rrttl`（rrhost 只写
//!   子域名部分，根域名写 "@"）。
//! - 修改：`dnsUpdateRecord?domain&rrid&rrhost&rrvalue&rrttl`。
//! - 删除：`dnsDeleteRecord?domain&rrid`。
//! - TTL：接口要求 3600..=2592000，超出范围取边界值；未指定 TTL 时更新沿用
//!   记录原有 TTL。
//! - 未变化判断：值（不区分大小写）与 TTL 一致；同名多条时优先选值相同的。
//! - TXT：dnsAddRecord 新增（txtTTL 经下限取整为 3600）；按值（去引号）
//!   删除全部同名 TXT。
//! - 删除（DEL）：列表过滤后逐条 dnsDeleteRecord。
//! - 错误：reply.code != 300 → 「NameSilo {op}: {detail} ({code})」，
//!   Invalid API Key 归类为认证失败；传输层错误抹掉 key。

use std::sync::Arc;

use hyper::Method;

use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, RemoteRecord, UpsertAction, msg,
    simple, txt,
};

pub static META: Meta = Meta::new("namesilo", "NameSilo")
    .labels("", "API Key")
    .doc("https://www.namesilo.com/account/api-manager")
    .acme()
    .delete();

pub struct NameSilo {
    key: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

/// 提交的 TTL：接口要求 3600 到 2592000 秒。
fn clamp_ttl(ttl: u32) -> u32 {
    ttl.clamp(3_600, 2_592_000)
}

/// 记录：record_id/type/host/value/ttl。
struct NsRecord {
    id: String,
    typ: String,
    host: String,
    value: String,
    ttl: u32,
}

/// 业务应答：记录列表（code/detail 在 call 里校验后不再携带）。
struct NsReply {
    records: Vec<NsRecord>,
}

impl NameSilo {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://www.namesilo.com/api")
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, false, true)?;
        Ok(Self {
            key: creds.secret.trim().to_owned(),
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    /// 调用一个操作并检查 reply.code；传输层错误先抹掉 key。
    async fn call(&self, op: &str, query: &[(&str, &str)]) -> Result<NsReply, ProviderError> {
        let mut url = format!("{}/{}?", self.endpoint, op);
        url.push_str(
            &query
                .iter()
                .copied()
                .chain([
                    ("version", "1"),
                    ("type", "xml"),
                    ("key", self.key.as_str()),
                ])
                .map(|(k, v)| format!("{}={}", simple::query_escape(k), simple::query_escape(v)))
                .collect::<Vec<_>>()
                .join("&"),
        );
        let reply = match simple::send(&self.http, META.name, Method::GET, &url, &[], None).await {
            Ok(reply) => reply,
            // 传输层失败与 HTTP 状态错误都可能带出完整地址（key 在查询串里），先抹掉。
            Err(mut e) => {
                e.redact(&self.key);
                return Err(e);
            }
        };
        let xml = reply.text();
        let reply_block = simple::xml_text(&xml, "reply").unwrap_or_else(|| xml.to_string());
        let code = simple::xml_text(&reply_block, "code")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        let detail = simple::xml_text(&reply_block, "detail").unwrap_or_default();
        if code != 300 {
            let kind = if detail.contains("Invalid API Key") {
                ProviderErrorKind::Auth
            } else {
                ProviderErrorKind::InvalidInput
            };
            return Err(ProviderError::new(META.name, kind, msg::API_ERROR)
                .with_detail(format!("NameSilo {op}: {detail} ({code})")));
        }
        // <resource_record> 列表。
        let mut records = Vec::new();
        let mut rest = reply_block.as_str();
        while let Some(start) = rest.find("<resource_record>") {
            let after = &rest[start + "<resource_record>".len()..];
            let Some(end) = after.find("</resource_record>") else {
                break;
            };
            let block = &after[..end];
            records.push(NsRecord {
                id: simple::xml_text(block, "record_id").unwrap_or_default(),
                typ: simple::xml_text(block, "type").unwrap_or_default(),
                host: simple::xml_text(block, "host").unwrap_or_default(),
                value: simple::xml_text(block, "value").unwrap_or_default(),
                ttl: simple::xml_text(block, "ttl")
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0),
            });
            rest = &after[end + "</resource_record>".len()..];
        }
        Ok(NsReply { records })
    }

    /// 判断列表中的 host 是否对应目标主机记录（文档示例写完整域名，也有实现
    /// 按相对名返回，两种都接受）。
    fn host_matches(&self, host: &str, zone: &str, sub: &str) -> bool {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let zone = zone.to_ascii_lowercase();
        if sub == "@" || sub.is_empty() {
            return host.is_empty() || host == "@" || host == zone;
        }
        let sub = sub.to_ascii_lowercase();
        host == sub || host == format!("{sub}.{zone}")
    }

    async fn list(&self, zone: &str, sub: &str, typ: &str) -> Result<Vec<NsRecord>, ProviderError> {
        let reply = self.call("dnsListRecords", &[("domain", zone)]).await?;
        Ok(reply
            .records
            .into_iter()
            .filter(|r| r.typ == typ && self.host_matches(&r.host, zone, sub))
            .collect())
    }

    async fn add(
        &self,
        zone: &str,
        sub: &str,
        typ: &str,
        value: &str,
        ttl: u32,
    ) -> Result<(), ProviderError> {
        self.call(
            "dnsAddRecord",
            &[
                ("domain", zone),
                ("rrtype", typ),
                ("rrhost", host_of(sub)),
                ("rrvalue", value),
                ("rrttl", &clamp_ttl(ttl).to_string()),
            ],
        )
        .await
        .map(drop)
    }

    async fn remove(&self, zone: &str, id: &str) -> Result<(), ProviderError> {
        self.call("dnsDeleteRecord", &[("domain", zone), ("rrid", id)])
            .await
            .map(drop)
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let cur = self.list(&rec.zone, rec.rr(), rec.typ.as_str()).await?;
        if cur.is_empty() {
            self.add(&rec.zone, rec.rr(), rec.typ.as_str(), &rec.value, rec.ttl)
                .await?;
            return Ok(UpsertAction::Created);
        }
        // 多条同名时优先选值相同的那条。
        let target = cur
            .iter()
            .find(|r| r.value.eq_ignore_ascii_case(&rec.value))
            .unwrap_or(&cur[0]);
        let ttl = clamp_ttl(rec.ttl);
        if target.value.eq_ignore_ascii_case(&rec.value) && (rec.ttl == 0 || target.ttl == ttl) {
            return Ok(UpsertAction::Unchanged);
        }
        // 未指定 TTL 时沿用记录原有的 TTL。
        let ttl = if rec.ttl == 0 && target.ttl > 0 {
            target.ttl
        } else {
            ttl
        };
        self.call(
            "dnsUpdateRecord",
            &[
                ("domain", rec.zone.as_str()),
                ("rrid", target.id.as_str()),
                ("rrhost", host_of(rec.rr())),
                ("rrvalue", rec.value.as_str()),
                ("rrttl", &ttl.to_string()),
            ],
        )
        .await?;
        Ok(UpsertAction::Updated)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        self.add(zone, sub, "TXT", value, txt::TXT_TTL).await
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        for rec in self.list(zone, sub, "TXT").await? {
            if txt::unquote(&rec.value) == value {
                self.remove(zone, &rec.id).await?;
            }
        }
        Ok(())
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        Ok(self
            .list(&rec.zone, rec.rr(), rec.typ.as_str())
            .await?
            .into_iter()
            .map(|r| RemoteRecord {
                id: r.id,
                scope: rec.zone.clone(),
                values: vec![r.value],
                ttl: r.ttl,
            })
            .collect())
    }

    pub async fn remove_record(
        &self,
        rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.remove(&rec.zone, &remote.id).await
    }
}

/// add/update 使用的 rrhost：只写子域名部分，根域名写 "@"。
fn host_of(sub: &str) -> &str {
    if sub.is_empty() { "@" } else { sub }
}

crate::impl_provider!(NameSilo, META);
crate::impl_txt!(NameSilo);
crate::impl_deleter!(NameSilo);
