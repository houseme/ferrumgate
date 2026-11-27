//! Gandi LiveDNS v5（上游 more.go）。
//!
//! 契约：`Authorization: Bearer {Personal Access Token}` 与
//! `Content-Type: application/json`，端点 `https://api.gandi.net/v5/livedns`。
//! 按记录集（rrset）管理：一个名称 + 类型对应一个记录集，值是数组。
//!
//! - 定位与更新：`GET|PUT|DELETE /domains/{zone}/records/{rr}/{type}`；
//!   GET 404 表示记录不存在（创建路径），其余方法 404 按未找到错误归类。
//! - 请求体：`{"rrset_values": [...], "rrset_ttl": n}`（TTL 为 0 时省略）。
//! - TTL：请求 TTL 为 0 时沿用记录现有值；Gandi 最小 TTL 为 300。
//! - 值相同（记录集只有一个值且精确相等）且 TTL 一致时不动。
//! - TXT：`add_txt` 把带引号的新值追加进记录集（TTL 300）；`delete_txt`
//!   过滤后剩余值为空则 DELETE 整个记录集，否则 PUT 剩余值（沿用原 TTL）。
//! - 删除（DEL）：记录集整体算一条 RemoteRecord；记录集里还有其他值时
//!   `pick_targets` 拒绝删除，只剩目标值时 DELETE 整个记录集。

use std::sync::Arc;

use hyper::{Method, StatusCode, body::Bytes};
use serde::{Deserialize, Serialize};

use crate::http::{HttpFail, OutboundHttp};
use crate::{
    Credentials, Meta, ProviderError, Record, RemoteRecord, UpsertAction, record, simple, txt,
};

/// Gandi 最小 TTL 为 300。
const MIN_TTL: u32 = 300;

pub static META: Meta = Meta::new("gandi", "Gandi")
    .labels("", "Personal Access Token")
    .doc("https://admin.gandi.net/organizations/account/pat")
    .acme()
    .delete();

pub struct Gandi {
    token: String,
    http: Arc<OutboundHttp>,
    endpoint: String,
}

#[derive(Serialize, Deserialize, Default)]
struct GandiRRSet {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rrset_values: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    rrset_ttl: i64,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

impl Gandi {
    pub fn new(creds: Credentials, http: Arc<OutboundHttp>) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://api.gandi.net/v5/livedns")
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, false, true)?;
        Ok(Self {
            token: creds.secret.trim().to_owned(),
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    /// 发送 rrset 请求；GET 404 返回 None 表示记录不存在。
    async fn rrset(
        &self,
        method: Method,
        zone: &str,
        rr: &str,
        typ: &str,
        body: Option<Bytes>,
    ) -> Result<Option<GandiRRSet>, ProviderError> {
        let url = format!(
            "{}/domains/{}/records/{}/{}",
            self.endpoint,
            zone,
            simple::path_escape(rr),
            typ
        );
        let is_get = method == Method::GET;
        let headers = [
            ("Authorization".to_owned(), format!("Bearer {}", self.token)),
            ("Content-Type".to_owned(), "application/json".to_owned()),
        ];
        let refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let reply = match self.http.send(method, &url, &refs, body).await {
            Ok(reply) => reply,
            Err(HttpFail::Status { status, .. }) if status == StatusCode::NOT_FOUND && is_get => {
                return Ok(None);
            }
            Err(fail) => return Err(ProviderError::from_http(META.name, fail)),
        };
        // 204 等响应没有消息体（hyper 对 204 不读 body）。
        if reply.body.is_empty() {
            return Ok(Some(GandiRRSet::default()));
        }
        Ok(Some(simple::json(META.name, &reply.body)?))
    }

    async fn put_rrset(
        &self,
        zone: &str,
        rr: &str,
        typ: &str,
        values: Vec<String>,
        ttl: i64,
    ) -> Result<(), ProviderError> {
        let body = simple::json_body(&GandiRRSet {
            rrset_values: values,
            rrset_ttl: ttl,
        });
        self.rrset(Method::PUT, zone, rr, typ, Some(body)).await?;
        Ok(())
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let rr = rec.rr();
        let cur = self
            .rrset(Method::GET, &rec.zone, rr, rec.typ.as_str(), None)
            .await?;
        let mut ttl = rec.ttl;
        if ttl == 0
            && let Some(cur) = &cur
        {
            // 未指定 TTL 时沿用记录现有值。
            ttl = u32::try_from(cur.rrset_ttl.max(0)).unwrap_or(0);
        }
        if ttl < MIN_TTL {
            ttl = MIN_TTL;
        }
        if let Some(cur) = &cur
            && cur.rrset_values.len() == 1
            && cur.rrset_values[0] == rec.value
            && (rec.ttl == 0 || cur.rrset_ttl == i64::from(ttl))
        {
            return Ok(UpsertAction::Unchanged);
        }
        self.put_rrset(
            &rec.zone,
            rr,
            rec.typ.as_str(),
            vec![rec.value.clone()],
            i64::from(ttl),
        )
        .await?;
        Ok(if cur.is_none() {
            UpsertAction::Created
        } else {
            UpsertAction::Updated
        })
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let rr = record::owner_rr(sub);
        let cur = self.rrset(Method::GET, zone, rr, "TXT", None).await?;
        // 新值追加在已有值之后（与上游一致），带引号写入。
        let mut vals = Vec::new();
        if let Some(cur) = cur {
            vals.extend(cur.rrset_values);
        }
        vals.push(format!("\"{value}\""));
        self.put_rrset(zone, rr, "TXT", vals, i64::from(MIN_TTL))
            .await
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        let rr = record::owner_rr(sub);
        let Some(cur) = self.rrset(Method::GET, zone, rr, "TXT", None).await? else {
            return Ok(());
        };
        let keep: Vec<String> = cur
            .rrset_values
            .iter()
            .filter(|v| txt::unquote(v) != value)
            .cloned()
            .collect();
        if keep.len() == cur.rrset_values.len() {
            return Ok(());
        }
        if keep.is_empty() {
            self.rrset(Method::DELETE, zone, rr, "TXT", None).await?;
            return Ok(());
        }
        self.put_rrset(zone, rr, "TXT", keep, cur.rrset_ttl).await
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let rr = rec.rr();
        let Some(cur) = self
            .rrset(Method::GET, &rec.zone, rr, rec.typ.as_str(), None)
            .await?
        else {
            return Ok(Vec::new());
        };
        Ok(vec![RemoteRecord {
            id: String::new(),
            scope: String::new(),
            values: cur.rrset_values.clone(),
            ttl: u32::try_from(cur.rrset_ttl.max(0)).unwrap_or(0),
        }])
    }

    pub async fn remove_record(
        &self,
        rec: &Record,
        _remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        // 记录集只剩目标值（pick_targets 已保证）时整体删除。
        self.rrset(Method::DELETE, &rec.zone, rec.rr(), rec.typ.as_str(), None)
            .await?;
        Ok(())
    }
}

crate::impl_provider!(Gandi, META);
crate::impl_txt!(Gandi);
crate::impl_deleter!(Gandi);
