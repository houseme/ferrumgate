//! 华为云 DNS（上游 huaweicloud.go）：AK/SK 签名（SDK-HMAC-SHA256），文档
//! support.huaweicloud.com/api-dns/dns_api_64001.html。按记录集管理：一个
//! 名称 + 类型对应一个记录集，记录集里可以有多个值。
//!
//! 契约（端点 `https://dns.myhuaweicloud.com`，JSON 请求体，请求头
//! Content-Type: application/json、X-Sdk-Date、Authorization）：
//!
//! - 区域定位：`GET /v2/zones?name={zone}.&search_mode=equal`，按名称
//!   （去结尾点，不区分大小写）匹配取 zone id。
//! - 记录定位：`GET /v2/zones/{zid}/recordsets?name={fqdn}.&type={type}&search_mode=equal`，
//!   响应 name 也带结尾点，比较时忽略大小写。
//! - 创建：`POST /v2/zones/{zid}/recordsets`；更新（整体替换值）：`PUT
//!   .../{rsid}`；删除：`DELETE .../{rsid}`。
//! - TTL：>0 时按值发送；未指定时更新发送 300。
//! - 备注（REMARK）：写在记录集的 description，空时不发送。
//! - TXT（ACME）：值必须带引号；add_txt 在已有记录集上追加值（整体 PUT），
//!   delete_txt 按值移除（全部移除后 DELETE 整个记录集）。
//! - 删除（DEL）：记录集里有其他值时由通用删除流程拒绝；单值记录集
//!   DELETE 整体删除。
//! - 业务错误：响应体 {code, message}。

use std::sync::Arc;

use hyper::Method;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    Credentials, Meta, ProviderError, Record, RemoteRecord, UpsertAction, http::HttpFail, sign,
    simple, txt,
};

pub static META: Meta = Meta::new("huaweicloud", "华为云 DNS")
    .labels("Access Key ID", "Secret Access Key")
    .doc("https://console.huaweicloud.com/iam/#/mine/accessKey")
    .remark()
    .acme()
    .delete();

/// 未指定 TTL 时更新使用的默认值。
const DEFAULT_TTL: u32 = 300;

pub struct HuaweiCloud {
    ak: String,
    sk: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

#[derive(Serialize, Deserialize)]
struct HwRecordset {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    typ: String,
    #[serde(default, skip_serializing_if = "num_zero")]
    ttl: u32,
    #[serde(default)]
    records: Vec<String>,
    /// 记录集备注，空时不发送。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    description: String,
}

#[allow(non_snake_case)]
fn num_zero(v: &u32) -> bool {
    *v == 0
}

#[derive(Deserialize)]
struct HwZoneList {
    #[serde(default)]
    zones: Vec<HwZone>,
}

#[derive(Deserialize)]
struct HwZone {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct HwSetList {
    #[serde(default)]
    recordsets: Vec<HwRecordset>,
}

impl HuaweiCloud {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://dns.myhuaweicloud.com")
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, true, true)?;
        Ok(Self {
            ak: creds.id.trim().to_owned(),
            sk: creds.secret.trim().to_owned(),
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    /// 发送一次请求：设置 X-Sdk-Date 与 Authorization 后发出，业务错误
    /// {code, message} 透出为详情。
    async fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ProviderError> {
        let payload = body.map(|b| simple::json_body(&b)).unwrap_or_default();
        let x_sdk_date = sign::amz_date(sign::now_unix());
        let host = self
            .endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or_default()
            .to_owned();
        let auth = sign::huawei::authorization(
            &self.ak,
            &self.sk,
            method.as_str(),
            path,
            query,
            &host,
            &x_sdk_date,
            &payload,
        );
        let url = format!("{}{}{}", self.endpoint, path, build_query(query));
        let headers: Vec<(&'static str, String)> = vec![
            ("Content-Type", "application/json".to_owned()),
            ("X-Sdk-Date", x_sdk_date),
            ("Authorization", auth),
        ];
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let sent = if payload.is_empty() {
            None
        } else {
            Some(payload)
        };
        let reply = match self.http.send(method, &url, &refs, sent).await {
            Ok(reply) => reply,
            Err(fail) => return Err(ProviderError::from_http(META.name, hw_fail(fail))),
        };
        simple::json(META.name, &reply.body)
    }

    /// 区域定位：name 带 . 且精确匹配，响应名称带结尾点，去掉后不区分大小写比较。
    async fn zone_id(&self, zone: &str) -> Result<String, ProviderError> {
        let query = vec![
            ("name".to_owned(), format!("{zone}.")),
            ("search_mode".to_owned(), "equal".to_owned()),
        ];
        let v = self.call(Method::GET, "/v2/zones", &query, None).await?;
        let zones: HwZoneList = serde_json::from_value(v)
            .map_err(|e| ProviderError::parse(META.name, format!("解析区域列表失败: {e}")))?;
        zones
            .zones
            .iter()
            .find(|z| z.name.trim_end_matches('.').eq_ignore_ascii_case(zone))
            .map(|z| z.id.clone())
            .ok_or_else(|| {
                ProviderError::zone_not_found(META.name, format!("华为云账号下未找到域名 {zone}"))
            })
    }

    /// 记录集定位：按名称与类型精确查询后在本地再比对一次。
    async fn find_set(
        &self,
        zid: &str,
        fqdn_dot: &str,
        typ: &str,
    ) -> Result<Option<HwRecordset>, ProviderError> {
        let path = format!("/v2/zones/{zid}/recordsets");
        let query = vec![
            ("name".to_owned(), fqdn_dot.to_owned()),
            ("type".to_owned(), typ.to_owned()),
            ("search_mode".to_owned(), "equal".to_owned()),
        ];
        let v = self.call(Method::GET, &path, &query, None).await?;
        let sets: HwSetList = serde_json::from_value(v)
            .map_err(|e| ProviderError::parse(META.name, format!("解析记录集列表失败: {e}")))?;
        Ok(sets
            .recordsets
            .into_iter()
            .find(|s| s.name.eq_ignore_ascii_case(fqdn_dot) && s.typ == typ))
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let zid = self.zone_id(&rec.zone).await?;
        let fqdn_dot = format!("{}.", rec.fqdn());
        let mut body = HwRecordset {
            id: String::new(),
            name: fqdn_dot.clone(),
            typ: rec.typ.as_str().to_owned(),
            ttl: rec.ttl,
            records: vec![rec.value.clone()],
            description: rec.remark.clone(),
        };
        let cur = self.find_set(&zid, &fqdn_dot, rec.typ.as_str()).await?;
        let Some(cur) = cur else {
            let path = format!("/v2/zones/{zid}/recordsets");
            self.call(Method::POST, &path, &[], Some(json!(body)))
                .await?;
            return Ok(UpsertAction::Created);
        };
        if rec.ttl == 0 {
            // 未指定 TTL 时更新为默认的 300。
            body.ttl = DEFAULT_TTL;
        }
        let value_same = cur.records.len() == 1
            && cur.records[0] == rec.value
            && (rec.ttl == 0 || cur.ttl == rec.ttl);
        if value_same && (rec.remark.is_empty() || cur.description == rec.remark) {
            return Ok(UpsertAction::Unchanged);
        }
        let path = format!("/v2/zones/{zid}/recordsets/{}", cur.id);
        self.call(Method::PUT, &path, &[], Some(json!(body)))
            .await?;
        Ok(UpsertAction::Updated)
    }

    /// 定位 TXT 记录集（ACME 用，值需带引号）。
    async fn txt_set(
        &self,
        zone: &str,
        sub: &str,
    ) -> Result<(String, Option<HwRecordset>), ProviderError> {
        let zid = self.zone_id(zone).await?;
        let fqdn_dot = format!("{}.", crate::record::owner_fqdn(zone, sub));
        let cur = self.find_set(&zid, &fqdn_dot, "TXT").await?;
        Ok((zid, cur))
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let (zid, cur) = self.txt_set(zone, sub).await?;
        let quoted = format!("\"{value}\"");
        let fqdn_dot = format!("{}.", crate::record::owner_fqdn(zone, sub));
        let Some(cur) = cur else {
            let path = format!("/v2/zones/{zid}/recordsets");
            let body = HwRecordset {
                id: String::new(),
                name: fqdn_dot,
                typ: "TXT".to_owned(),
                ttl: txt::TXT_TTL,
                records: vec![quoted],
                description: String::new(),
            };
            return self
                .call(Method::POST, &path, &[], Some(json!(body)))
                .await
                .map(drop);
        };
        let mut records = cur.records.clone();
        records.push(quoted);
        let body = HwRecordset {
            id: cur.id.clone(),
            name: cur.name.clone(),
            typ: "TXT".to_owned(),
            ttl: txt::TXT_TTL,
            records,
            description: String::new(),
        };
        let path = format!("/v2/zones/{zid}/recordsets/{}", cur.id);
        self.call(Method::PUT, &path, &[], Some(json!(body)))
            .await
            .map(drop)
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        let (zid, cur) = self.txt_set(zone, sub).await?;
        let Some(cur) = cur else {
            return Ok(());
        };
        let remain: Vec<String> = cur
            .records
            .iter()
            .filter(|v| txt::unquote(v) != value)
            .cloned()
            .collect();
        let path = format!("/v2/zones/{zid}/recordsets/{}", cur.id);
        if remain.is_empty() {
            return self.call(Method::DELETE, &path, &[], None).await.map(drop);
        }
        let body = HwRecordset {
            id: cur.id.clone(),
            name: cur.name.clone(),
            typ: "TXT".to_owned(),
            ttl: cur.ttl,
            records: remain,
            description: cur.description.clone(),
        };
        self.call(Method::PUT, &path, &[], Some(json!(body)))
            .await
            .map(drop)
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let zid = self.zone_id(&rec.zone).await?;
        let fqdn_dot = format!("{}.", rec.fqdn());
        let cur = self.find_set(&zid, &fqdn_dot, rec.typ.as_str()).await?;
        Ok(cur
            .map(|s| RemoteRecord {
                id: s.id,
                scope: zid.clone(),
                values: s.records,
                ttl: s.ttl,
            })
            .into_iter()
            .collect())
    }

    pub async fn remove_record(
        &self,
        _rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        let path = format!("/v2/zones/{}/recordsets/{}", remote.scope, remote.id);
        self.call(Method::DELETE, &path, &[], None).await.map(drop)
    }
}

/// 组装查询串（键值先编码再排序由签名函数保证一致，这里按原样拼接）。
fn build_query(query: &[(String, String)]) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut encoded: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (sign::huawei::escape(k), sign::huawei::escape(v)))
        .collect();
    encoded.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let qs = encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    format!("?{qs}")
}

/// 传输层失败时把华为云业务错误 {code, message} 透出为详情。
fn hw_fail(fail: HttpFail) -> HttpFail {
    if let HttpFail::Status {
        status,
        body,
        retry_after,
    } = &fail
        && let Ok(v) = serde_json::from_slice::<serde_json::Value>(body)
        && let Some(code) = v.get("code").and_then(|c| c.as_str())
        && !code.is_empty()
    {
        let message = format!(
            "华为云: {} ({code})",
            v.get("message")
                .and_then(|m| m.as_str())
                .unwrap_or_default()
        );
        return HttpFail::Status {
            status: *status,
            body: message.into_bytes().into(),
            retry_after: *retry_after,
        };
    }
    fail
}

crate::impl_provider!(HuaweiCloud, META);
crate::impl_txt!(HuaweiCloud);
crate::impl_deleter!(HuaweiCloud);
