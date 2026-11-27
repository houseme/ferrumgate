//! Bunny DNS API（上游 more.go）。
//!
//! 契约：`AccessKey: {Secret}` 与 `Content-Type: application/json`，端点
//! `https://api.bunny.net`；JSON 字段为 PascalCase（Id / Type / Ttl / Value /
//! Name）。记录类型用数字编号：A = 0、AAAA = 1、TXT = 3，其余类型不支持。
//!
//! - 区域定位：`GET /dnszone?search={zone}` 后按域名精确匹配（不区分大小写），
//!   再 `GET /dnszone/{id}` 取记录列表。
//! - 记录定位：按类型编号与名称（根域名为空串，不区分大小写）匹配。
//! - 更新：`POST /dnszone/{id}/records/{rid}`（带 Id 的整体更新）；创建：
//!   `PUT /dnszone/{id}/records`（省略 Id）。
//! - TTL：请求 TTL 为 0 时新建用 300、更新沿用记录现有值。
//! - TXT：`add_txt` PUT 创建（TTL 60）；`delete_txt` 列表后按值（去引号）
//!   `DELETE /dnszone/{id}/records/{rid}`。
//! - 删除（DEL）：按值挑选后逐条 `DELETE /dnszone/{scope}/records/{id}`。

use std::sync::Arc;

use hyper::{Method, body::Bytes};
use serde::Deserialize;
use serde_json::json;

use crate::http::{HttpReply, OutboundHttp};
use crate::{
    Credentials, Meta, ProviderError, Record, RecordType, RemoteRecord, UpsertAction, record,
    simple, txt,
};

/// 未指定 TTL 时新建记录的默认值。
const DEFAULT_TTL: u32 = 300;

/// Bunny 记录类型编号。
const TYPE_A: i64 = 0;
const TYPE_AAAA: i64 = 1;
const TYPE_TXT: i64 = 3;

pub static META: Meta = Meta::new("bunny", "Bunny DNS")
    .labels("", "Account API Key")
    .doc("https://dash.bunny.net/account/settings")
    .acme()
    .delete();

pub struct Bunny {
    key: String,
    http: Arc<OutboundHttp>,
    endpoint: String,
}

#[derive(serde::Serialize, Deserialize, Clone)]
struct BunnyRecord {
    /// 创建（PUT）时省略，更新（POST）时带上。
    #[serde(rename = "Id", default, skip_serializing_if = "is_zero")]
    id: i64,
    #[serde(rename = "Type", default)]
    typ: i64,
    #[serde(rename = "Ttl", default)]
    ttl: i64,
    #[serde(rename = "Value", default)]
    value: String,
    #[serde(rename = "Name", default)]
    name: String,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

#[derive(Deserialize)]
struct BunnyZoneList {
    #[serde(rename = "Items", default)]
    items: Vec<BunnyZoneItem>,
}

#[derive(Deserialize)]
struct BunnyZoneItem {
    #[serde(rename = "Id", default)]
    id: i64,
    #[serde(rename = "Domain", default)]
    domain: String,
}

#[derive(Deserialize)]
struct BunnyZoneDetail {
    #[serde(rename = "Records", default)]
    records: Vec<BunnyRecord>,
}

impl Bunny {
    pub fn new(creds: Credentials, http: Arc<OutboundHttp>) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://api.bunny.net")
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, false, true)?;
        Ok(Self {
            key: creds.secret.trim().to_owned(),
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
    ) -> Result<HttpReply, ProviderError> {
        let headers = [("AccessKey".to_owned(), self.key.clone())];
        let refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let url = format!("{}{}", self.endpoint, path);
        match self.http.send(method, &url, &refs, body).await {
            Ok(reply) => Ok(reply),
            // 上游会把传输与状态错误统一包上 "Bunny: " 前缀。
            Err(fail) => {
                let mut err = ProviderError::from_http(META.name, fail);
                err.detail = format!("Bunny: {}", err.detail);
                Err(err)
            }
        }
    }

    async fn zone(&self, zone: &str) -> Result<(i64, Vec<BunnyRecord>), ProviderError> {
        let reply = self
            .call(
                Method::GET,
                &format!("/dnszone?search={}", simple::query_escape(zone)),
                None,
            )
            .await?;
        let list: BunnyZoneList = simple::json(META.name, &reply.body)?;
        for z in &list.items {
            if z.domain.eq_ignore_ascii_case(zone) {
                let detail = self
                    .call(Method::GET, &format!("/dnszone/{}", z.id), None)
                    .await?;
                let detail: BunnyZoneDetail = simple::json(META.name, &detail.body)?;
                return Ok((z.id, detail.records));
            }
        }
        Err(ProviderError::zone_not_found(
            META.name,
            format!("Bunny 账号下未找到域名 {zone}"),
        ))
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let typ = bunny_type(rec.typ)?;
        let (zid, records) = self.zone(&rec.zone).await?;
        let name = bunny_name(rec.rr());
        let mut ttl = rec.ttl;
        if ttl == 0 {
            ttl = DEFAULT_TTL;
        }
        let base = format!("/dnszone/{zid}/records");
        for r in &records {
            if r.typ != typ || !r.name.eq_ignore_ascii_case(&name) {
                continue;
            }
            let mut ttl = ttl;
            if rec.ttl == 0 && r.ttl > 0 {
                // 未指定 TTL 时沿用记录现有值。
                ttl = u32::try_from(r.ttl).unwrap_or(DEFAULT_TTL);
            }
            if r.value == rec.value && (rec.ttl == 0 || r.ttl == i64::from(ttl)) {
                return Ok(UpsertAction::Unchanged);
            }
            let upd = BunnyRecord {
                id: r.id,
                typ,
                ttl: i64::from(ttl),
                value: rec.value.clone(),
                name: name.clone(),
            };
            self.call(
                Method::POST,
                &format!("{base}/{}", r.id),
                Some(simple::json_body(&json!(upd))),
            )
            .await?;
            return Ok(UpsertAction::Updated);
        }
        let created = BunnyRecord {
            id: 0,
            typ,
            ttl: i64::from(ttl),
            value: rec.value.clone(),
            name,
        };
        self.call(Method::PUT, &base, Some(simple::json_body(&json!(created))))
            .await?;
        Ok(UpsertAction::Created)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let (zid, _) = self.zone(zone).await?;
        let created = BunnyRecord {
            id: 0,
            typ: TYPE_TXT,
            ttl: 60,
            value: value.to_owned(),
            name: bunny_name(record::owner_rr(sub)),
        };
        self.call(
            Method::PUT,
            &format!("/dnszone/{zid}/records"),
            Some(simple::json_body(&json!(created))),
        )
        .await?;
        Ok(())
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        let (zid, records) = self.zone(zone).await?;
        let name = bunny_name(record::owner_rr(sub));
        for r in &records {
            if r.typ == TYPE_TXT
                && r.name.eq_ignore_ascii_case(&name)
                && txt::unquote(&r.value) == value
            {
                self.call(
                    Method::DELETE,
                    &format!("/dnszone/{zid}/records/{}", r.id),
                    None,
                )
                .await?;
                return Ok(());
            }
        }
        Ok(())
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let typ = bunny_type(rec.typ)?;
        let (zid, records) = self.zone(&rec.zone).await?;
        let name = bunny_name(rec.rr());
        Ok(records
            .iter()
            .filter(|r| r.typ == typ && r.name.eq_ignore_ascii_case(&name))
            .map(|r| RemoteRecord {
                id: r.id.to_string(),
                scope: zid.to_string(),
                values: vec![r.value.clone()],
                ttl: u32::try_from(r.ttl.max(0)).unwrap_or(0),
            })
            .collect())
    }

    pub async fn remove_record(
        &self,
        _rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.call(
            Method::DELETE,
            &format!("/dnszone/{}/records/{}", remote.scope, remote.id),
            None,
        )
        .await?;
        Ok(())
    }
}

fn bunny_type(t: RecordType) -> Result<i64, ProviderError> {
    match t {
        RecordType::A => Ok(TYPE_A),
        RecordType::AAAA => Ok(TYPE_AAAA),
        RecordType::TXT => Ok(TYPE_TXT),
        other => Err(ProviderError::invalid_input(
            META.name,
            format!("Bunny 不支持记录类型 {}", other.as_str()),
        )),
    }
}

/// 主机记录名，根域名为空字符串。
fn bunny_name(sub: &str) -> String {
    if sub == "@" {
        String::new()
    } else {
        sub.to_owned()
    }
}

crate::impl_provider!(Bunny, META);
crate::impl_txt!(Bunny);
crate::impl_deleter!(Bunny);
