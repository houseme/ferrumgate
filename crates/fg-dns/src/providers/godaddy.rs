//! GoDaddy（上游 simple.go 的 godaddy 节与 txt.go、delete.go 的对应分节）：
//! 文档 developer.godaddy.com/keys。认证 `Authorization: sso-key KEY:SECRET`；
//! 记录按名称整体管理——`/v1/domains/{zone}/records/{type}/{rr}` 上的数组就
//! 是该名称+类型的全部值。
//!
//! 契约（端点 `https://api.godaddy.com`；带请求体时 Content-Type:
//! application/json）：
//!
//! - 读取：GET 上述路径，返回 `[{data, ttl}, …]`。
//! - 写入：PUT 上述路径，请求体 `[{data, ttl}]` 整体替换；GoDaddy 最小 TTL
//!   为 600，未指定 TTL 时新建/更新都取 600。upsert 的未变化判断：数组只有
//!   一个值且 data 相同、且（TTL 未指定或相同）。
//! - TXT（ACME）：GET 当前值后 PUT 追加（新值 TTL 600，原有值保持原 TTL）；
//!   delete_txt 按值（去引号）过滤，全部移除时 DELETE 整个路径。
//! - 删除（DEL）：find_records 把该名称+类型的全部值当作一个记录集返回；
//!   记录集里还有其他值时由通用删除流程拒绝，单值时 DELETE 整个路径。
//! - 能力标记与 WP-41 §3.3 契约表（「—」）不同：上游 txt.go 实现了 GoDaddy
//!   的 TXT 增删（SupportsTXT 含 godaddy）、delete.go 实现了删除
//!   （SupportsDelete 含 godaddy），按 2026-11-28 注记的核对原则以上游源码
//!   为准，godaddy 同时支持 ACME 与删除。

use std::sync::Arc;

use hyper::Method;
use serde_json::{Value, json};

use crate::{Credentials, Meta, ProviderError, Record, RemoteRecord, UpsertAction, simple, txt};

pub static META: Meta = Meta::new("godaddy", "GoDaddy")
    .labels("API Key", "API Secret")
    .doc("https://developer.godaddy.com/keys")
    .acme()
    .delete();

pub struct GoDaddy {
    key: String,
    secret: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

/// GoDaddy 最小 TTL 为 600。
const MIN_TTL: u32 = 600;

impl GoDaddy {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://api.godaddy.com")
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, true, true)?;
        Ok(Self {
            key: creds.id.trim().to_owned(),
            secret: creds.secret.trim().to_owned(),
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    fn records_path(&self, zone: &str, typ: &str, rr: &str) -> String {
        format!(
            "{}/v1/domains/{}/records/{}/{}",
            self.endpoint,
            simple::path_escape(zone),
            simple::path_escape(typ),
            simple::path_escape(rr)
        )
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, ProviderError> {
        let mut headers: Vec<(&'static str, String)> = vec![(
            "Authorization",
            format!("sso-key {}:{}", self.key, self.secret),
        )];
        let sent = body.map(|b| simple::json_body(&b));
        if sent.is_some() {
            headers.push(("Content-Type", "application/json".to_owned()));
        }
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let reply = simple::send(&self.http, META.name, method, path, &refs, sent).await?;
        if reply.body.is_empty() {
            return Ok(Value::Null);
        }
        simple::json(META.name, &reply.body)
    }

    /// 读取一个名称+类型下的全部值。
    async fn get_values(
        &self,
        zone: &str,
        typ: &str,
        rr: &str,
    ) -> Result<Vec<Value>, ProviderError> {
        let out = self
            .call(Method::GET, &self.records_path(zone, typ, rr), None)
            .await?;
        Ok(out.as_array().cloned().unwrap_or_default())
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let path = self.records_path(&rec.zone, rec.typ.as_str(), rec.rr());
        let cur = self
            .get_values(&rec.zone, rec.typ.as_str(), rec.rr())
            .await?;
        if let [only] = cur.as_slice() {
            let data = simple::value_str(&only["data"]);
            let ttl = only.get("ttl").and_then(Value::as_i64).unwrap_or(0).max(0) as u32;
            if data == rec.value && (rec.ttl == 0 || ttl == rec.ttl) {
                return Ok(UpsertAction::Unchanged);
            }
        }
        // GoDaddy 最小 TTL 为 600；按名称整体替换。
        let body = json!([{ "data": rec.value, "ttl": rec.ttl.max(MIN_TTL) }]);
        self.call(Method::PUT, &path, Some(body)).await?;
        if cur.is_empty() {
            return Ok(UpsertAction::Created);
        }
        Ok(UpsertAction::Updated)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let path = self.records_path(zone, "TXT", crate::record::owner_rr(sub));
        let cur = self
            .get_values(zone, "TXT", crate::record::owner_rr(sub))
            .await?;
        let mut all = cur.clone();
        all.push(json!({"data": value, "ttl": txt::TXT_TTL}));
        self.call(Method::PUT, &path, Some(Value::Array(all)))
            .await
            .map(drop)
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        let path = self.records_path(zone, "TXT", crate::record::owner_rr(sub));
        let cur = self
            .get_values(zone, "TXT", crate::record::owner_rr(sub))
            .await?;
        let keep: Vec<Value> = cur
            .iter()
            .filter(|r| txt::unquote(&simple::value_str(&r["data"])) != value)
            .cloned()
            .collect();
        if keep.len() == cur.len() {
            return Ok(());
        }
        if keep.is_empty() {
            return self.call(Method::DELETE, &path, None).await.map(drop);
        }
        self.call(Method::PUT, &path, Some(Value::Array(keep)))
            .await
            .map(drop)
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let cur = self
            .get_values(&rec.zone, rec.typ.as_str(), rec.rr())
            .await?;
        if cur.is_empty() {
            return Ok(Vec::new());
        }
        // 同名同类型的全部值在一个记录集里；删除时由通用流程判断是否还有
        // 其他值。
        let values = cur.iter().map(|r| simple::value_str(&r["data"])).collect();
        Ok(vec![RemoteRecord {
            id: String::new(),
            scope: rec.zone.clone(),
            values,
            ttl: 0,
        }])
    }

    pub async fn remove_record(
        &self,
        rec: &Record,
        _remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.call(
            Method::DELETE,
            &self.records_path(&rec.zone, rec.typ.as_str(), rec.rr()),
            None,
        )
        .await
        .map(drop)
    }
}

crate::impl_provider!(GoDaddy, META);
crate::impl_txt!(GoDaddy);
crate::impl_deleter!(GoDaddy);
