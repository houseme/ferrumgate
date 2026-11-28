//! 雨云（上游 rainyun.go）：接口基地址 `https://api.v2.rainyun.com/product`，
//! 请求头 x-api-key 携带 API 密钥。记录按域名产品 ID 管理，域名 ID 通过域名
//! 列表按名称查得，不需要用户填写。响应统一为 {code, message, data}，code
//! 为 200 表示成功。
//!
//! 契约：
//!
//! - 域名定位：GET `/domain?options={json}`，options 为
//!   `{"columnFilters":{"domains.Domain":zone},"sort":[],"page":N,"perPage":100}`，
//!   data 为 `{TotalRecords, Records:[{id, domain}]}`；按名称（不分大小写）
//!   匹配，翻页直到找完或找满。
//! - 记录列表：GET `/domain/{id}/dns/?limit=100&page_no=N`，data 为
//!   `{TotalRecords, Records:[{record_id, host, type, value, line, ttl,
//!   level}]}`；Records 可能为 null。
//! - 新建：POST `/domain/{id}/dns`，请求体 `{host, line, level, ttl, type,
//!   value}`（level 固定 10；未指定 TTL 取 600）。
//! - 修改：PATCH `/domain/{id}/dns`，请求体加 `record_id`。
//! - 删除：DELETE `/domain/{id}/dns?record_id={id}`。
//! - 线路（LINE）：line 为大写线路代码，未指定对应默认线路 DEFAULT；同名同
//!   类型不同线路视为另一条记录。
//! - TTL：更新未指定时沿用现有值，仍无有效值则 600。
//! - TXT：POST 新增（host=主机记录、line=DEFAULT、level=10、TTL 600）；
//!   按值（去引号）删除。
//! - 删除（DEL）：列表按主机/类型/线路过滤后逐条 DELETE。
//! - 错误：HTTP 401/403 归类认证失败；HTTP 200 但业务 code != 200 时按消息
//!   透出（401/403 归类认证失败，其余无效输入）。

use std::sync::Arc;

use hyper::Method;
use serde_json::{Value, json};

use crate::providers::same_host;
use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, RemoteRecord, UpsertAction, msg,
    simple, txt,
};

pub static META: Meta = Meta::new("rainyun", "雨云")
    .labels("", "API 密钥")
    .doc("https://app.rainyun.com/account/settings/api-key")
    .line()
    .acme()
    .delete();

pub struct Rainyun {
    key: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

/// 线路代码，未指定时为默认线路 DEFAULT（统一大写）。
fn line_of(line: &str) -> String {
    if line.is_empty() {
        "DEFAULT".to_owned()
    } else {
        line.to_ascii_uppercase()
    }
}

impl Rainyun {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://api.v2.rainyun.com/product")
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

    /// 发送请求并校验业务状态码，返回 data。
    async fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> Result<Value, ProviderError> {
        let mut url = format!("{}{}", self.endpoint, path);
        if !query.is_empty() {
            url.push('?');
            url.push_str(
                &query
                    .iter()
                    .map(|(k, v)| {
                        format!("{}={}", simple::query_escape(k), simple::query_escape(v))
                    })
                    .collect::<Vec<_>>()
                    .join("&"),
            );
        }
        let mut headers: Vec<(&'static str, String)> = vec![("x-api-key", self.key.clone())];
        let sent = body.map(|b| simple::json_body(&b));
        if sent.is_some() {
            headers.push(("Content-Type", "application/json".to_owned()));
        }
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let reply = simple::send(&self.http, META.name, method, &url, &refs, sent).await?;
        let env: Value = simple::json(META.name, &reply.body)?;
        let code = env.get("code").and_then(Value::as_i64).unwrap_or(0);
        if code != 200 {
            let message = simple::value_str(&env["message"]);
            let (kind, key) = if code == 401 || code == 403 {
                (ProviderErrorKind::Auth, msg::AUTH_FAILED)
            } else {
                (ProviderErrorKind::InvalidInput, msg::API_ERROR)
            };
            let detail = if message.is_empty() {
                format!("雨云: 接口返回错误 code={code}")
            } else {
                format!("雨云: {message} (code {code})")
            };
            return Err(ProviderError::new(META.name, kind, key).with_detail(detail));
        }
        Ok(env.get("data").cloned().unwrap_or(Value::Null))
    }

    /// 按域名名称查询雨云的域名产品 ID。
    async fn domain_id(&self, zone: &str) -> Result<i64, ProviderError> {
        const PER_PAGE: u32 = 100;
        let mut total = 0usize;
        for page in 1..=50u32 {
            let options = json!({
                "columnFilters": {"domains.Domain": zone},
                "sort": [],
                "page": page,
                "perPage": PER_PAGE,
            });
            let options_str = options.to_string();
            let data = self
                .call(
                    Method::GET,
                    "/domain",
                    &[("options", options_str.as_str())],
                    None,
                )
                .await?;
            let records = data
                .get("Records")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for d in &records {
                if d.get("domain")
                    .map(simple::value_str)
                    .is_some_and(|name| name.eq_ignore_ascii_case(zone))
                {
                    let id = d.get("id").and_then(Value::as_i64).unwrap_or(0);
                    if id > 0 {
                        return Ok(id);
                    }
                }
            }
            total += records.len();
            if records.len() < PER_PAGE as usize
                || (data
                    .get("TotalRecords")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    > 0
                    && total as i64 >= data["TotalRecords"].as_i64().unwrap_or(0))
            {
                break;
            }
        }
        Err(ProviderError::zone_not_found(
            META.name,
            format!("雨云账号下未找到域名 {zone}"),
        ))
    }

    fn dns_path(domain_id: i64) -> String {
        format!("/domain/{domain_id}/dns")
    }

    /// 列出域名下的全部解析记录，自动翻页。
    async fn list(&self, domain_id: i64) -> Result<Vec<Value>, ProviderError> {
        const LIMIT: u32 = 100;
        let path = format!("{}/", Self::dns_path(domain_id));
        let mut out = Vec::new();
        for page in 1..=50u32 {
            let data = self
                .call(
                    Method::GET,
                    &path,
                    &[("limit", "100"), ("page_no", &page.to_string())],
                    None,
                )
                .await?;
            let recs = data
                .get("Records")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let total = data
                .get("TotalRecords")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let n = recs.len();
            out.extend(recs);
            if n < LIMIT as usize || (total > 0 && out.len() as i64 >= total) {
                break;
            }
        }
        Ok(out)
    }

    /// 选出主机记录、类型与线路都相同的记录。
    fn matched<'a>(recs: &'a [Value], host: &str, typ: &str, line: &str) -> Vec<&'a Value> {
        recs.iter()
            .filter(|rec| {
                same_host(&simple::value_str(&rec["host"]), host)
                    && simple::value_str(&rec["type"]).eq_ignore_ascii_case(typ)
                    && line_of(&simple::value_str(&rec["line"])) == line
            })
            .collect()
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let did = self.domain_id(&rec.zone).await?;
        let recs = self.list(did).await?;
        let host = rec.rr();
        let line = line_of(&rec.line);
        let found = Self::matched(&recs, host, rec.typ.as_str(), &line);
        let mut ttl = rec.ttl;
        if let Some(cur) = found.first() {
            if ttl == 0 {
                ttl = cur.get("ttl").and_then(Value::as_i64).unwrap_or(0).max(0) as u32;
            }
            if ttl == 0 {
                ttl = 600;
            }
            let level = {
                let lv = cur.get("level").and_then(Value::as_i64).unwrap_or(0);
                if lv <= 0 { 10 } else { lv }
            };
            let cur_value = simple::value_str(&cur["value"]);
            let cur_id = simple::value_str(&cur["record_id"]);
            if cur_value == rec.value
                && (rec.ttl == 0 || {
                    let cur_ttl = cur.get("ttl").and_then(Value::as_i64).unwrap_or(0).max(0) as u32;
                    cur_ttl == ttl
                })
            {
                return Ok(UpsertAction::Unchanged);
            }
            self.call(
                Method::PATCH,
                &Self::dns_path(did),
                &[],
                Some(json!({
                    "record_id": cur_id.parse::<i64>().unwrap_or(0),
                    "host": host,
                    "line": line,
                    "level": level,
                    "ttl": ttl,
                    "type": rec.typ.as_str(),
                    "value": rec.value,
                })),
            )
            .await?;
            return Ok(UpsertAction::Updated);
        }
        if ttl == 0 {
            ttl = 600;
        }
        self.call(
            Method::POST,
            &Self::dns_path(did),
            &[],
            Some(json!({
                "host": host,
                "line": line,
                "level": 10,
                "ttl": ttl,
                "type": rec.typ.as_str(),
                "value": rec.value,
            })),
        )
        .await?;
        Ok(UpsertAction::Created)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let did = self.domain_id(zone).await?;
        self.call(
            Method::POST,
            &Self::dns_path(did),
            &[],
            Some(json!({
                "host": crate::record::owner_rr(sub),
                "line": "DEFAULT",
                "level": 10,
                "ttl": txt::TXT_TTL,
                "type": "TXT",
                "value": value,
            })),
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
        let did = self.domain_id(zone).await?;
        let recs = self.list(did).await?;
        let host = crate::record::owner_rr(sub);
        for rec in &recs {
            if same_host(&simple::value_str(&rec["host"]), host)
                && simple::value_str(&rec["type"]).eq_ignore_ascii_case("TXT")
                && txt::unquote(&simple::value_str(&rec["value"])) == value
            {
                return self
                    .remove(did, &simple::value_str(&rec["record_id"]))
                    .await;
            }
        }
        Ok(())
    }

    async fn remove(&self, domain_id: i64, record_id: &str) -> Result<(), ProviderError> {
        self.call(
            Method::DELETE,
            &Self::dns_path(domain_id),
            &[("record_id", record_id)],
            None,
        )
        .await
        .map(drop)
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let did = self.domain_id(&rec.zone).await?;
        let recs = self.list(did).await?;
        Ok(
            Self::matched(&recs, rec.rr(), rec.typ.as_str(), &line_of(&rec.line))
                .into_iter()
                .map(|r| RemoteRecord {
                    id: simple::value_str(&r["record_id"]),
                    scope: did.to_string(),
                    values: vec![simple::value_str(&r["value"])],
                    ttl: r.get("ttl").and_then(Value::as_i64).unwrap_or(0).max(0) as u32,
                })
                .collect(),
        )
    }

    pub async fn remove_record(
        &self,
        _rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        let did: i64 = remote
            .scope
            .parse()
            .map_err(|e| ProviderError::invalid_input(META.name, format!("域名 ID 不合法: {e}")))?;
        self.remove(did, &remote.id).await
    }
}

crate::impl_provider!(Rainyun, META);
crate::impl_txt!(Rainyun);
crate::impl_deleter!(Rainyun);
