//! DNS.LA（上游 dnsla.go）：接口基地址 `https://api.dns.la/api`，APIID/
//! APISecret 做 Basic 认证。记录类型使用枚举数值（A=1、CNAME=5、TXT=16、
//! AAAA=28），域名与记录 ID 均为字符串（兼容数字与字符串两种写法）。
//!
//! 契约：响应统一为 {code, msg, data}，code 为 200 表示成功；HTTP 401 表示
//! 认证失败。
//!
//! - 动作：`GET /domain?domain={zone}`（域名定位，兼容单对象与列表两种
//!   响应写法）、`GET /recordList?domainId&host&type&pageIndex&pageSize=100`
//!   （自动翻页，本地再按主机与类型精确过滤）、`POST /record`（新建：
//!   domainId/host/type/data/ttl）、`PUT /record`（更新：id/host/type/data/
//!   ttl）、`DELETE /record?id={id}`（删除）。
//! - TTL：新建未指定时用 600；更新未指定时沿用现有值，仍无有效值则 600。
//!   接口未返回 TTL（为 0）时无法比较，只按值判断。
//! - TXT：POST /record（type 16、TTL 600）新增；返回「与已有记录冲突」说明
//!   同样的验证值已存在，视为成功；recordList 后按值（去引号）删除。
//! - 删除（DEL）：recordList 过滤后按值挑选，DELETE /record 逐条。

use std::sync::Arc;

use hyper::Method;
use serde_json::{Value, json};

use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, RemoteRecord, UpsertAction, msg,
    simple, txt,
};

pub static META: Meta = Meta::new("dnsla", "DNS.LA")
    .labels("APIID", "APISecret")
    .doc("https://www.dns.la/docs/ApiDoc")
    .acme()
    .delete();

/// 记录类型对应的枚举值（上游 dnslaType）。
fn type_code(typ: crate::RecordType) -> Result<i64, ProviderError> {
    match typ {
        crate::RecordType::A => Ok(1),
        crate::RecordType::CNAME => Ok(5),
        crate::RecordType::TXT => Ok(16),
        crate::RecordType::AAAA => Ok(28),
        other => Err(ProviderError::invalid_input(
            META.name,
            format!("DNS.LA 不支持记录类型 {}", other.as_str()),
        )),
    }
}

pub struct Dnsla {
    id: String,
    secret: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

struct LaRecord {
    id: String,
    host: String,
    typ: i64,
    data: String,
    ttl: u32,
}

impl Dnsla {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://api.dns.la/api")
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

    /// 发送请求（Basic 认证）并校验业务状态码，返回 data 原文。
    async fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<Value>,
    ) -> Result<Value, ProviderError> {
        let mut url = format!("{}{}", self.endpoint, path);
        if !query.is_empty() {
            let qs = query
                .iter()
                .map(|(k, v)| format!("{}={}", simple::query_escape(k), simple::query_escape(v)))
                .collect::<Vec<_>>()
                .join("&");
            url.push('?');
            url.push_str(&qs);
        }
        let auth = basic_auth(&self.id, &self.secret);
        let mut headers: Vec<(&'static str, String)> = vec![("Authorization", auth)];
        let sent = body.map(|b| simple::json_body(&b));
        if sent.is_some() {
            headers.push(("Content-Type", "application/json;charset=utf-8".to_owned()));
        }
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let reply = simple::send(&self.http, META.name, method, &url, &refs, sent).await?;
        let out: Value = simple::json(META.name, &reply.body)?;
        let code = out.get("code").and_then(Value::as_i64).unwrap_or(0);
        if code != 200 {
            let msg = simple::value_str(&out["msg"]);
            let (kind, key) = if code == 401 || code == 403 {
                (ProviderErrorKind::Auth, msg::AUTH_FAILED)
            } else {
                (ProviderErrorKind::InvalidInput, msg::API_ERROR)
            };
            return Err(ProviderError::new(META.name, kind, key)
                .with_detail(format!("DNS.LA: {msg} (code {code})")));
        }
        Ok(out.get("data").cloned().unwrap_or(Value::Null))
    }

    /// 域名定位：兼容单对象与列表两种响应写法，ID 兼容数字与字符串。
    async fn domain_id(&self, zone: &str) -> Result<String, ProviderError> {
        let data = self
            .call(
                Method::GET,
                "/domain",
                &[("domain".to_owned(), zone.to_owned())],
                None,
            )
            .await?;
        let one = data.get("id").map(simple::value_str).unwrap_or_default();
        if !one.is_empty() {
            return Ok(one);
        }
        if let Some(list) = data.get("results").and_then(Value::as_array) {
            for it in list {
                let id = it.get("id").map(simple::value_str).unwrap_or_default();
                if !id.is_empty()
                    && it
                        .get("domain")
                        .map(simple::value_str)
                        .is_some_and(|d| d.eq_ignore_ascii_case(zone))
                {
                    return Ok(id);
                }
            }
        }
        Err(ProviderError::zone_not_found(
            META.name,
            format!("DNS.LA 账号下未找到域名 {zone}"),
        ))
    }

    /// 列出域名下指定主机记录与类型的记录，自动翻页后本地精确过滤。
    async fn list(
        &self,
        domain_id: &str,
        host: &str,
        typ: i64,
    ) -> Result<Vec<LaRecord>, ProviderError> {
        const PAGE_SIZE: u32 = 100;
        let mut out = Vec::new();
        let mut total = 0i64;
        for page in 1..=50u32 {
            let query = vec![
                ("domainId".to_owned(), domain_id.to_owned()),
                ("host".to_owned(), host.to_owned()),
                ("type".to_owned(), typ.to_string()),
                ("pageIndex".to_owned(), page.to_string()),
                ("pageSize".to_owned(), PAGE_SIZE.to_string()),
            ];
            let data = self.call(Method::GET, "/recordList", &query, None).await?;
            let results = data
                .get("results")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            total = data.get("total").and_then(Value::as_i64).unwrap_or(total);
            let n = results.len();
            for r in results {
                out.push(LaRecord {
                    id: r.get("id").map(simple::value_str).unwrap_or_default(),
                    host: r.get("host").map(simple::value_str).unwrap_or_default(),
                    typ: r.get("type").and_then(Value::as_i64).unwrap_or(0),
                    data: r.get("data").map(simple::value_str).unwrap_or_default(),
                    ttl: r
                        .get("ttl")
                        .and_then(Value::as_i64)
                        .map(|v| v.max(0) as u32)
                        .unwrap_or(0),
                });
            }
            if n < PAGE_SIZE as usize || (total > 0 && out.len() as i64 >= total) {
                break;
            }
        }
        // 服务端的主机/类型过滤可能是模糊匹配，这里再精确过滤一遍（空值视为
        // 根域名 @）。
        Ok(out
            .into_iter()
            .filter(|r| r.typ == typ && same_host(&r.host, host))
            .collect())
    }

    async fn create(
        &self,
        domain_id: &str,
        host: &str,
        typ: i64,
        data: &str,
        ttl: u32,
    ) -> Result<(), ProviderError> {
        self.call(
            Method::POST,
            "/record",
            &[],
            Some(json!({
                "domainId": domain_id,
                "host": host,
                "type": typ,
                "data": data,
                "ttl": ttl,
            })),
        )
        .await
        .map(drop)
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let typ = type_code(rec.typ)?;
        let did = self.domain_id(&rec.zone).await?;
        let host = rec.rr();
        let recs = self.list(&did, host, typ).await?;
        let mut ttl = rec.ttl;
        if let Some(cur) = recs.first() {
            if ttl == 0 {
                ttl = cur.ttl;
            }
            if ttl == 0 {
                ttl = 600;
            }
            // 接口未返回 TTL（为 0）时无法比较，只按值判断。
            if cur.data == rec.value && (rec.ttl == 0 || cur.ttl == 0 || cur.ttl == ttl) {
                return Ok(UpsertAction::Unchanged);
            }
            self.call(
                Method::PUT,
                "/record",
                &[],
                Some(json!({
                    "id": cur.id,
                    "host": host,
                    "type": typ,
                    "data": rec.value,
                    "ttl": ttl,
                })),
            )
            .await?;
            return Ok(UpsertAction::Updated);
        }
        if ttl == 0 {
            ttl = 600;
        }
        self.create(&did, host, typ, &rec.value, ttl).await?;
        Ok(UpsertAction::Created)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let did = self.domain_id(zone).await?;
        match self
            .create(&did, crate::record::owner_rr(sub), 16, value, txt::TXT_TTL)
            .await
        {
            // 与已有记录冲突说明同样的验证值已存在，视为成功。
            Err(e) if e.detail.contains("与已有记录冲突") => Ok(()),
            other => other,
        }
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        let did = self.domain_id(zone).await?;
        let recs = self.list(&did, crate::record::owner_rr(sub), 16).await?;
        for r in recs {
            if txt::unquote(&r.data) == value {
                return self.remove(&r.id).await;
            }
        }
        Ok(())
    }

    async fn remove(&self, id: &str) -> Result<(), ProviderError> {
        self.call(
            Method::DELETE,
            "/record",
            &[("id".to_owned(), id.to_owned())],
            None,
        )
        .await
        .map(drop)
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let typ = type_code(rec.typ)?;
        let did = self.domain_id(&rec.zone).await?;
        let recs = self.list(&did, rec.rr(), typ).await?;
        Ok(recs
            .into_iter()
            .map(|r| RemoteRecord {
                id: r.id,
                scope: did.clone(),
                values: vec![r.data],
                ttl: r.ttl,
            })
            .collect())
    }

    pub async fn remove_record(
        &self,
        _rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.remove(&remote.id).await
    }
}

/// Basic 认证头的 Base64 值（APIID:APISecret）。
fn basic_auth(id: &str, secret: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"))
    )
}

/// 比较主机记录，空值视为根域名 "@"。
fn same_host(a: &str, b: &str) -> bool {
    let a = if a.is_empty() { "@" } else { a };
    let b = if b.is_empty() { "@" } else { b };
    a.eq_ignore_ascii_case(b)
}

crate::impl_provider!(Dnsla, META);
crate::impl_txt!(Dnsla);
crate::impl_deleter!(Dnsla);
