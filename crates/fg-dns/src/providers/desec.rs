//! deSEC（上游 desec.go）：以记录集（RRset）管理，同 subname 同类型的全部
//! 值在一个记录集里，TXT 值必须带引号。文档 desec.readthedocs.io/en/latest/
//! dns/rrsets.html。
//!
//! 契约（端点 `https://desec.io/api/v1`，请求头 Authorization: Token {token}
//! 与 Content-Type: application/json）：
//!
//! - 记录集路径 `/domains/{zone}/rrsets/{subname}/{type}/`（根域名的 subname
//!   在路径里写作 `@`，在请求体里是空字符串）；GET 读取，404 视为不存在；
//!   POST `/domains/{zone}/rrsets/` 创建，PUT 整体替换，DELETE 删除。
//! - 记录集请求体 `{subname, type, records:[值], ttl}`。
//! - TTL：下限由域名的 minimum_ttl 决定（`GET /domains/{zone}/` 读取，读取
//!   失败或未返回时用保守下限 3600），上限 86400；指定的 TTL 低于保守下限
//!   时读取域名实际允许的最小值，避免把 60、300 这类值一律抬到 3600；
//!   未指定 TTL 时沿用记录集现有的 TTL。
//! - TXT：值带引号写入；add_txt 合并新值（已有该值时不重复添加）；
//!   delete_txt 按值（去引号）挑选，全部移除时 DELETE 整个记录集。
//! - 删除（DEL）：记录集里有其他值时由通用删除流程拒绝；单值记录集整体
//!   DELETE。

use std::sync::Arc;

use hyper::Method;
use serde_json::{Value, json};

use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, RemoteRecord, UpsertAction,
    simple, txt,
};

pub static META: Meta = Meta::new("desec", "deSEC")
    .labels("", "API Token")
    .doc("https://desec.readthedocs.io/en/latest/auth/tokens.html")
    .acme()
    .delete();

/// 读不到域名的 minimum_ttl 时的保守下限，也是未指定 TTL 时新建记录集的值。
const MIN_TTL: u32 = 3600;
const MAX_TTL: u32 = 86_400;

pub struct Desec {
    token: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

impl Desec {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://desec.io/api/v1")
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, false, true)?;
        Ok(Self {
            token: creds.secret.trim().to_owned(),
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    async fn call(
        &self,
        method: Method,
        url: &str,
        body: Option<Value>,
    ) -> Result<Value, ProviderError> {
        let sent = body.map(|b| simple::json_body(&b));
        let mut headers: Vec<(&'static str, String)> =
            vec![("Authorization", format!("Token {}", self.token))];
        if sent.is_some() {
            headers.push(("Content-Type", "application/json".to_owned()));
        }
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let reply = simple::send(&self.http, META.name, method, url, &refs, sent).await?;
        if reply.body.is_empty() {
            return Ok(Value::Null);
        }
        simple::json(META.name, &reply.body)
    }

    /// 单个记录集的地址，根域名的 subname 在路径里写作 @。
    fn rrset_url(&self, zone: &str, sub: &str, typ: &str) -> String {
        let name = if sub.is_empty() { "@" } else { sub };
        format!(
            "{}/domains/{}/rrsets/{}/{}/",
            self.endpoint,
            simple::path_escape(zone),
            simple::path_escape(name),
            simple::path_escape(typ)
        )
    }

    /// 读取域名的 minimum_ttl；读取失败或未返回时使用保守下限 3600。
    async fn min_ttl(&self, zone: &str) -> u32 {
        let url = format!("{}/domains/{}/", self.endpoint, simple::path_escape(zone));
        match self.call(Method::GET, &url, None).await {
            Ok(v) => {
                let ttl = v
                    .get("minimum_ttl")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    .max(0) as u32;
                if ttl == 0 { MIN_TTL } else { ttl }
            }
            Err(_) => MIN_TTL,
        }
    }

    /// 查询记录集，不存在（404）时返回 None。域名本身不存在时同样是 404，
    /// 会在后续写入时报错。
    async fn get_rrset(
        &self,
        zone: &str,
        sub: &str,
        typ: &str,
    ) -> Result<Option<Value>, ProviderError> {
        match self
            .call(Method::GET, &self.rrset_url(zone, sub, typ), None)
            .await
        {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind == ProviderErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn records_of(rrset: &Value) -> Vec<String> {
        rrset
            .get("records")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(simple::value_str).collect())
            .unwrap_or_default()
    }

    fn ttl_of(rrset: &Value) -> u32 {
        rrset.get("ttl").and_then(Value::as_i64).unwrap_or(0).max(0) as u32
    }

    /// 按记录类型整理要写入的值：TXT 需要带引号。
    fn typed_value(typ: crate::RecordType, v: &str) -> String {
        if typ == crate::RecordType::TXT {
            format!("\"{}\"", txt::unquote(v))
        } else {
            v.to_owned()
        }
    }

    /// 把 TTL 限制在 [floor, 86400] 内。
    fn ttl_clamp(ttl: u32, floor: u32) -> u32 {
        if ttl < floor {
            floor
        } else if ttl > MAX_TTL {
            MAX_TTL
        } else {
            ttl
        }
    }

    async fn create(
        &self,
        zone: &str,
        sub: &str,
        typ: &str,
        records: Vec<String>,
        ttl: u32,
    ) -> Result<(), ProviderError> {
        let url = format!(
            "{}/domains/{}/rrsets/",
            self.endpoint,
            simple::path_escape(zone)
        );
        self.call(
            Method::POST,
            &url,
            Some(json!({"subname": sub, "type": typ, "records": records, "ttl": ttl})),
        )
        .await
        .map(drop)
    }

    async fn replace(
        &self,
        zone: &str,
        sub: &str,
        typ: &str,
        records: Vec<String>,
        ttl: u32,
    ) -> Result<(), ProviderError> {
        let url = self.rrset_url(zone, sub, typ);
        self.call(
            Method::PUT,
            &url,
            Some(json!({"subname": sub, "type": typ, "records": records, "ttl": ttl})),
        )
        .await
        .map(drop)
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let sub = desec_sub(rec.rr());
        let cur = self.get_rrset(&rec.zone, sub, rec.typ.as_str()).await?;
        let want_value = Self::typed_value(rec.typ, &rec.value);
        let ttl;
        if rec.ttl > 0 {
            let floor = if rec.ttl < MIN_TTL {
                // 指定的 TTL 低于保守下限时，读取域名实际允许的最小值。
                self.min_ttl(&rec.zone).await
            } else {
                MIN_TTL
            };
            ttl = Self::ttl_clamp(rec.ttl, floor);
        } else if let Some(cur) = &cur {
            // 未指定 TTL 时沿用记录集现有的 TTL。
            ttl = if Self::ttl_of(cur) == 0 {
                MIN_TTL
            } else {
                Self::ttl_of(cur)
            };
        } else {
            ttl = MIN_TTL;
        }
        let Some(cur) = cur else {
            self.create(&rec.zone, sub, rec.typ.as_str(), vec![want_value], ttl)
                .await?;
            return Ok(UpsertAction::Created);
        };
        let records = Self::records_of(&cur);
        if records.len() == 1
            && crate::delete::same_value(rec.typ, &records[0], &rec.value)
            && (rec.ttl == 0 || Self::ttl_of(&cur) == ttl)
        {
            return Ok(UpsertAction::Unchanged);
        }
        self.replace(&rec.zone, sub, rec.typ.as_str(), vec![want_value], ttl)
            .await?;
        Ok(UpsertAction::Updated)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let sub = desec_sub(crate::record::owner_rr(sub));
        let cur = self.get_rrset(zone, sub, "TXT").await?;
        let quoted = format!("\"{value}\"");
        let Some(cur) = cur else {
            return self.create(zone, sub, "TXT", vec![quoted], MIN_TTL).await;
        };
        // 记录集已存在（例如同时申请泛域名与主域名）：合并新值，已有该值时
        // 不重复添加。
        let mut records = Self::records_of(&cur);
        if records.iter().any(|v| txt::unquote(v) == value) {
            return Ok(());
        }
        records.push(quoted);
        self.replace(zone, sub, "TXT", records, Self::ttl_of(&cur))
            .await
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        let sub = desec_sub(crate::record::owner_rr(sub));
        let cur = self.get_rrset(zone, sub, "TXT").await?;
        let Some(cur) = cur else {
            return Ok(());
        };
        let records = Self::records_of(&cur);
        let keep: Vec<String> = records
            .iter()
            .filter(|v| txt::unquote(v) != value)
            .cloned()
            .collect();
        if keep.len() == records.len() {
            return Ok(());
        }
        if keep.is_empty() {
            return self
                .call(Method::DELETE, &self.rrset_url(zone, sub, "TXT"), None)
                .await
                .map(drop);
        }
        self.replace(zone, sub, "TXT", keep, Self::ttl_of(&cur))
            .await
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let cur = self
            .get_rrset(&rec.zone, desec_sub(rec.rr()), rec.typ.as_str())
            .await?;
        let Some(cur) = cur else {
            return Ok(Vec::new());
        };
        Ok(vec![RemoteRecord {
            id: String::new(),
            scope: rec.zone.clone(),
            values: Self::records_of(&cur),
            ttl: Self::ttl_of(&cur),
        }])
    }

    pub async fn remove_record(
        &self,
        rec: &Record,
        _remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.call(
            Method::DELETE,
            &self.rrset_url(&rec.zone, desec_sub(rec.rr()), rec.typ.as_str()),
            None,
        )
        .await
        .map(drop)
    }
}

/// deSEC 的 subname，根域名为空字符串。
fn desec_sub(sub: &str) -> &str {
    if sub == "@" { "" } else { sub }
}

crate::impl_provider!(Desec, META);
crate::impl_txt!(Desec);
crate::impl_deleter!(Desec);
