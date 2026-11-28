//! Gcore DNS（上游 gcore.go）：以记录集（rrset）管理，同名同类型的全部值在
//! 一个记录集里。文档 api.gcore.com/docs/dns。
//!
//! 契约（端点 `https://api.gcore.com/dns/v2`，请求头 Authorization:
//! APIKey {token} 与 Content-Type: application/json）：
//!
//! - 记录集路径 `/zones/{zone}/{rrsetName}/{type}`（rrsetName 为完整域名）；
//!   GET 读取，404 视为不存在；POST 创建，PUT 整体替换，DELETE 删除。
//! - 记录集请求体 `{ttl, resource_records:[{content:[值], enabled:bool}]}`；
//!   content 对 A/AAAA/TXT 为只含一个字符串的数组。写回时只保留 content 与
//!   enabled，丢弃服务商附带的 id 与 meta。
//! - TTL：>0 时按值发送；未指定时用 120（免费版允许的最小 TTL）。
//! - TXT（ACME）：add_txt 在已有记录集上追加新值（沿用现有 TTL 与已有值的
//!   enabled 状态）；delete_txt 按值（去引号）挑选，全部移除时 DELETE 整个
//!   记录集。
//! - 删除（DEL）：记录集里有其他值时由通用删除流程拒绝；单值记录集整体
//!   DELETE。

use std::sync::Arc;

use hyper::Method;
use serde_json::{Value, json};

use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, RemoteRecord, UpsertAction,
    simple, txt,
};

pub static META: Meta = Meta::new("gcore", "Gcore")
    .labels("", "Permanent API Token")
    .doc("https://accounts.gcore.com/profile/api-tokens")
    .acme()
    .delete();

/// 免费版允许的最小 TTL（未指定 TTL 时使用）。
const DEFAULT_TTL: u32 = 120;

pub struct Gcore {
    token: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

impl Gcore {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://api.gcore.com/dns/v2")
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
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, ProviderError> {
        let sent = body.map(|b| simple::json_body(&b));
        let mut headers: Vec<(&'static str, String)> =
            vec![("Authorization", format!("APIKey {}", self.token))];
        if sent.is_some() {
            headers.push(("Content-Type", "application/json".to_owned()));
        }
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let url = format!("{}{}", self.endpoint, path);
        let reply = simple::send(&self.http, META.name, method, &url, &refs, sent).await?;
        if reply.body.is_empty() {
            return Ok(Value::Null);
        }
        simple::json(META.name, &reply.body)
    }

    /// 单个记录集的接口路径：/zones/{zone}/{rrsetName}/{type}。
    fn rrset_path(zone: &str, fqdn: &str, typ: &str) -> String {
        format!(
            "/zones/{}/{}/{}",
            simple::path_escape(zone),
            simple::path_escape(fqdn),
            simple::path_escape(typ)
        )
    }

    /// 查询记录集，不存在（404）时返回 None。
    async fn get_rrset(
        &self,
        zone: &str,
        fqdn: &str,
        typ: &str,
    ) -> Result<Option<Value>, ProviderError> {
        match self
            .call(Method::GET, &Self::rrset_path(zone, fqdn, typ), None)
            .await
        {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind == ProviderErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// 记录集里的 (值, enabled) 列表。
    fn rrs_of(rrset: &Value) -> Vec<(String, bool)> {
        rrset
            .get("resource_records")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .map(|rr| {
                        let value = rr
                            .get("content")
                            .and_then(Value::as_array)
                            .and_then(|c| c.first())
                            .map(simple::value_str)
                            .unwrap_or_default();
                        let enabled = rr.get("enabled").and_then(Value::as_bool).unwrap_or(true);
                        (value, enabled)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn ttl_of(rrset: &Value) -> u32 {
        rrset.get("ttl").and_then(Value::as_i64).unwrap_or(0).max(0) as u32
    }

    /// 记录集请求体；只保留 content 与 enabled 两个字段。
    fn body(ttl: u32, rrs: &[(String, bool)]) -> Value {
        let records: Vec<Value> = rrs
            .iter()
            .map(|(v, enabled)| json!({"content": [v], "enabled": enabled}))
            .collect();
        json!({"ttl": ttl, "resource_records": records})
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let fqdn = rec.fqdn();
        let path = Self::rrset_path(&rec.zone, &fqdn, rec.typ.as_str());
        let cur = self.get_rrset(&rec.zone, &fqdn, rec.typ.as_str()).await?;
        let ttl = if rec.ttl == 0 { DEFAULT_TTL } else { rec.ttl };
        let want = Self::body(ttl, &[(rec.value.clone(), true)]);
        let Some(cur) = cur else {
            self.call(Method::POST, &path, Some(want)).await?;
            return Ok(UpsertAction::Created);
        };
        let rrs = Self::rrs_of(&cur);
        if rrs.len() == 1 && rrs[0].0 == rec.value && (rec.ttl == 0 || Self::ttl_of(&cur) == ttl) {
            return Ok(UpsertAction::Unchanged);
        }
        self.call(Method::PUT, &path, Some(want)).await?;
        Ok(UpsertAction::Updated)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let fqdn = crate::record::owner_fqdn(zone, sub);
        let path = Self::rrset_path(zone, &fqdn, "TXT");
        let cur = self.get_rrset(zone, &fqdn, "TXT").await?;
        let Some(cur) = cur else {
            return self
                .call(
                    Method::POST,
                    &path,
                    Some(Self::body(txt::TXT_TTL, &[(value.to_owned(), true)])),
                )
                .await
                .map(drop);
        };
        // 同名已有验证值时保留，追加新值；沿用现有 TTL。
        let mut rrs = Self::rrs_of(&cur);
        rrs.push((value.to_owned(), true));
        let ttl = Self::ttl_of(&cur);
        let ttl = if ttl == 0 { txt::TXT_TTL } else { ttl };
        self.call(Method::PUT, &path, Some(Self::body(ttl, &rrs)))
            .await
            .map(drop)
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        let fqdn = crate::record::owner_fqdn(zone, sub);
        let path = Self::rrset_path(zone, &fqdn, "TXT");
        let cur = self.get_rrset(zone, &fqdn, "TXT").await?;
        let Some(cur) = cur else {
            return Ok(());
        };
        let rrs = Self::rrs_of(&cur);
        let keep: Vec<(String, bool)> = rrs
            .iter()
            .filter(|(v, _)| txt::unquote(v) != value)
            .cloned()
            .collect();
        if keep.len() == rrs.len() {
            return Ok(());
        }
        if keep.is_empty() {
            return self.call(Method::DELETE, &path, None).await.map(drop);
        }
        self.call(
            Method::PUT,
            &path,
            Some(Self::body(Self::ttl_of(&cur), &keep)),
        )
        .await
        .map(drop)
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let cur = self
            .get_rrset(&rec.zone, &rec.fqdn(), rec.typ.as_str())
            .await?;
        let Some(cur) = cur else {
            return Ok(Vec::new());
        };
        Ok(vec![RemoteRecord {
            id: String::new(),
            scope: rec.zone.clone(),
            values: Self::rrs_of(&cur).into_iter().map(|(v, _)| v).collect(),
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
            &Self::rrset_path(&rec.zone, &rec.fqdn(), rec.typ.as_str()),
            None,
        )
        .await
        .map(drop)
    }
}

crate::impl_provider!(Gcore, META);
crate::impl_txt!(Gcore);
crate::impl_deleter!(Gcore);
