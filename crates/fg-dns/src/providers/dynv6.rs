//! dynv6 HTTP API v2（上游 simple.go）。
//!
//! 契约：`Authorization: Bearer {Secret}` 与 `Accept: application/json`，
//! 端点 `https://dynv6.com/api/v2`。zone 是用户自己的完整域名（如
//! `my.dynv6.net`）：`GET /zones/by-name/{zone}` 拿到 zone ID；主域名误填
//! 成 `dynv6.net` 时 404，此时把子域名最右侧的标签逐级并入 zone 重试。
//!
//! - 根域名的 A/AAAA 通过 `PATCH /zones/{id}` 的 `ipv4address` / `ipv6prefix`
//!   更新，不走 records 接口；根域名的 TXT、CNAME 等其他类型仍走 records
//!   接口。接口返回的 IPv6 可能是展开写法或带前缀长度，按解析后的地址比较。
//! - 子域名记录：`GET /zones/{id}/records` 定位 `name`+`type` 后，值相同不动，
//!   不同 `PATCH .../records/{rid}`（只发 data），不存在 `POST`（name/type/data）。
//! - TXT：`add_txt` POST（name 直接用传入的 sub），`delete_txt` 列表后按值
//!   （去引号）删除。
//! - 删除（DEL）：定位记录后 `DELETE /zones/{id}/records/{rid}`。

use std::{net::IpAddr, sync::Arc};

use hyper::{Method, body::Bytes};
use serde::Deserialize;
use serde_json::json;

use crate::http::{HttpReply, OutboundHttp};
use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, RecordType, RemoteRecord,
    UpsertAction, simple, txt,
};

pub static META: Meta = Meta::new("dynv6", "dynv6")
    .labels("", "HTTP Token")
    .doc("https://dynv6.com/keys")
    .acme()
    .delete();

pub struct Dynv6 {
    token: String,
    http: Arc<OutboundHttp>,
    endpoint: String,
}

#[derive(Deserialize, Default)]
struct Dynv6Zone {
    #[serde(default)]
    id: i64,
    #[serde(default)]
    ipv4address: String,
    #[serde(default)]
    ipv6prefix: String,
}

#[derive(Deserialize)]
struct Dynv6Record {
    #[serde(default)]
    id: i64,
    #[serde(default)]
    name: String,
    #[serde(rename = "type", default)]
    typ: String,
    #[serde(default)]
    data: String,
}

impl Dynv6 {
    pub fn new(creds: Credentials, http: Arc<OutboundHttp>) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://dynv6.com/api/v2")
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

    async fn do_req(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
    ) -> Result<HttpReply, ProviderError> {
        let mut headers = vec![
            ("Authorization".to_owned(), format!("Bearer {}", self.token)),
            ("Accept".to_owned(), "application/json".to_owned()),
        ];
        if body.is_some() {
            headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
        }
        let refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let url = format!("{}{}", self.endpoint, path);
        let reply = self.http.send(method, &url, &refs, body).await;
        match reply {
            Ok(r) => Ok(r),
            Err(fail) => {
                let mut err = ProviderError::from_http(META.name, fail);
                err.redact(&self.token);
                Err(err)
            }
        }
    }

    async fn zone_info(&self, zone: &str) -> Result<Dynv6Zone, ProviderError> {
        let reply = self
            .do_req(Method::GET, &format!("/zones/by-name/{zone}"), None)
            .await?;
        simple::json(META.name, &reply.body)
    }

    /// 返回 zone 信息与记录名（根记录为空串）。zone 查询 404 且子域名还有
    /// 标签时，把子域名最右侧的标签逐级并入 zone 重试。
    async fn resolve_zone_info(
        &self,
        zone_name: &str,
        sub: &str,
    ) -> Result<(Dynv6Zone, String), ProviderError> {
        let mut name = if sub == "@" {
            String::new()
        } else {
            sub.to_owned()
        };
        let mut zone = zone_name.to_owned();
        let mut first_err: Option<ProviderError> = None;
        loop {
            match self.zone_info(&zone).await {
                Ok(z) => return Ok((z, name)),
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e.clone());
                    }
                    if e.kind != ProviderErrorKind::NotFound || name.is_empty() {
                        return Err(first_err.expect("first error recorded"));
                    }
                    if let Some(i) = name.rfind('.') {
                        zone = format!("{}.{zone}", &name[i + 1..]);
                        name = name[..i].to_owned();
                    } else {
                        zone = format!("{name}.{zone}");
                        name = String::new();
                    }
                }
            }
        }
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let (zone, name) = self.resolve_zone_info(&rec.zone, rec.rr()).await?;
        let zone_path = format!("/zones/{}", zone.id);
        if name.is_empty() && matches!(rec.typ, RecordType::A | RecordType::AAAA) {
            // 根域名的地址通过 PATCH zone 更新；TXT、CNAME 等仍走 records 接口。
            let (cur, field) = if rec.typ == RecordType::AAAA {
                (zone.ipv6prefix.as_str(), "ipv6prefix")
            } else {
                (zone.ipv4address.as_str(), "ipv4address")
            };
            if dynv6_same_addr(cur, &rec.value) {
                return Ok(UpsertAction::Unchanged);
            }
            self.do_req(
                Method::PATCH,
                &zone_path,
                Some(simple::json_body(&json!({ field: rec.value }))),
            )
            .await?;
            return Ok(UpsertAction::Updated);
        }
        let zpath = format!("{zone_path}/records");
        let reply = self.do_req(Method::GET, &zpath, None).await?;
        let recs: Vec<Dynv6Record> = simple::json(META.name, &reply.body)?;
        for r in &recs {
            if r.name != name || r.typ != rec.typ.as_str() {
                continue;
            }
            if r.data == rec.value {
                return Ok(UpsertAction::Unchanged);
            }
            self.do_req(
                Method::PATCH,
                &format!("{zpath}/{}", r.id),
                Some(simple::json_body(&json!({ "data": rec.value }))),
            )
            .await?;
            return Ok(UpsertAction::Updated);
        }
        self.do_req(
            Method::POST,
            &zpath,
            Some(simple::json_body(&json!({
                "name": name,
                "type": rec.typ.as_str(),
                "data": rec.value,
            }))),
        )
        .await?;
        Ok(UpsertAction::Created)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let z = self.zone_info(zone).await?;
        let zpath = format!("/zones/{}/records", z.id);
        self.do_req(
            Method::POST,
            &zpath,
            Some(simple::json_body(
                &json!({ "name": sub, "type": "TXT", "data": value }),
            )),
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
        let z = self.zone_info(zone).await?;
        let zpath = format!("/zones/{}/records", z.id);
        let reply = self.do_req(Method::GET, &zpath, None).await?;
        let recs: Vec<Dynv6Record> = simple::json(META.name, &reply.body)?;
        for r in &recs {
            if r.typ == "TXT" && r.name == sub && txt::unquote(&r.data) == value {
                self.do_req(Method::DELETE, &format!("{zpath}/{}", r.id), None)
                    .await?;
                return Ok(());
            }
        }
        Ok(())
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let (zone, name) = self.resolve_zone_info(&rec.zone, rec.rr()).await?;
        let zpath = format!("/zones/{}/records", zone.id);
        let reply = self.do_req(Method::GET, &zpath, None).await?;
        let recs: Vec<Dynv6Record> = simple::json(META.name, &reply.body)?;
        Ok(recs
            .iter()
            .filter(|r| r.typ == rec.typ.as_str() && r.name == name)
            .map(|r| RemoteRecord {
                id: r.id.to_string(),
                scope: zpath.clone(),
                values: vec![r.data.clone()],
                ttl: 0,
            })
            .collect())
    }

    pub async fn remove_record(
        &self,
        _rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.do_req(
            Method::DELETE,
            &format!("{}/{}", remote.scope, remote.id),
            None,
        )
        .await?;
        Ok(())
    }
}

/// 接口返回的 IPv6 可能是展开写法（2001:0db8:…）或带前缀长度，按解析后的
/// 地址比较，避免每轮都误判为变化而重复 PATCH。
fn dynv6_same_addr(cur: &str, want: &str) -> bool {
    let cur = cur.trim();
    let cur = cur.split('/').next().unwrap_or(cur);
    match (cur.parse::<IpAddr>(), want.trim().parse::<IpAddr>()) {
        (Ok(a), Ok(b)) => a.to_canonical() == b.to_canonical(),
        _ => cur == want.trim(),
    }
}

crate::impl_provider!(Dynv6, META);
crate::impl_txt!(Dynv6);
crate::impl_deleter!(Dynv6);
