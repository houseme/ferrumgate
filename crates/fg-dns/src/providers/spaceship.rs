//! Spaceship DNS（上游 spaceship.go）：文档 docs.spaceship.dev。记录接口按
//! 域名整体操作：GET 列表（take/skip 分页）、PUT 保存（新增或更新）、DELETE
//! 按内容删除。
//!
//! 契约（端点 `https://spaceship.dev/api/v1`，请求头 X-API-Key、
//! X-API-Secret、Accept: application/json，带请求体时 Content-Type:
//! application/json；路径 `/dns/records/{zone}`）：
//!
//! - 列表：GET `?take=500&skip=N`（接口上限 500），响应
//!   `{items:[…], total}`；服务端返回条数可能少于 take，按实际条数推进偏移。
//! - 记录条目 `{type, name, ttl}` 加一个内容字段：TXT 用 `value`，CNAME 用
//!   `cname`（接口要求的必填字段），其余（A/AAAA）用 `address`；ttl 为 0 时
//!   不发送（omitempty，DELETE 请求不能带 ttl）。
//! - 保存：PUT 请求体 `{"items":[条目]}`，A/AAAA 的 Upsert 再带
//!   `"force": true`（允许覆盖冲突记录）；TXT（add_txt）不带 force。
//! - 删除：DELETE 请求体 `[{type, name, cname|value|address}]`（不带 ttl），
//!   按类型、名称与内容删除，不影响其他记录。
//! - TTL：0 取 600，限制在 60..=3600。
//! - 名称：name 用主机记录，根域名写 "@"；比较不区分大小写。
//! - Upsert：同名同类型多条时先写入新值再删除旧值（避免中途失败时记录
//!   消失），收敛为一条；只有一条且值与 TTL 一致时不变；未指定 TTL 时沿用
//!   现有 TTL。
//! - TXT：PUT 保存（TTL 600）；按值（去引号）删除全部匹配。
//! - 删除（DEL）：列表过滤后逐条按内容 DELETE。
//! - 错误：非 2xx 的错误体为 problem+json `{"detail":"…","data":[…]}`，
//!   按 HTTP 状态归类。

use std::sync::Arc;

use hyper::Method;
use serde_json::{Value, json};

use crate::{Credentials, Meta, ProviderError, Record, RemoteRecord, UpsertAction, simple, txt};

pub static META: Meta = Meta::new("spaceship", "Spaceship")
    .labels("API Key", "API Secret")
    .doc("https://www.spaceship.com/application/api-manager/")
    .acme()
    .delete();

pub struct Spaceship {
    key: String,
    secret: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

/// 提交的 TTL：0 取 600，并限制在接口允许的 60 到 3600 秒内。
fn clamp_ttl(ttl: u32) -> u32 {
    if ttl == 0 { 600 } else { ttl.clamp(60, 3_600) }
}

/// 按类型构造记录条目：TXT 用 value，CNAME 用 cname，其余用 address；
/// ttl 为 0 时不发送（DELETE 请求不能带 ttl）。
fn item_json(typ: &str, name: &str, content: &str, ttl: u32) -> Value {
    let mut item = json!({"type": typ, "name": name});
    match typ {
        "TXT" => item["value"] = json!(content),
        "CNAME" => item["cname"] = json!(content),
        _ => item["address"] = json!(content),
    }
    if ttl > 0 {
        item["ttl"] = json!(ttl);
    }
    item
}

/// 列表条目的内容字段。
fn content_of(item: &Value) -> String {
    match simple::value_str(&item["type"]).as_str() {
        "TXT" => simple::value_str(&item["value"]),
        "CNAME" => simple::value_str(&item["cname"]),
        _ => simple::value_str(&item["address"]),
    }
}

impl Spaceship {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://spaceship.dev/api/v1")
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

    async fn call(
        &self,
        method: Method,
        query: &[(&str, &str)],
        zone: &str,
        body: Option<Value>,
    ) -> Result<Value, ProviderError> {
        let mut url = format!(
            "{}/dns/records/{}",
            self.endpoint,
            simple::path_escape(zone)
        );
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
        let mut headers: Vec<(&'static str, String)> = vec![
            ("X-API-Key", self.key.clone()),
            ("X-API-Secret", self.secret.clone()),
            ("Accept", "application/json".to_owned()),
        ];
        let sent = body.map(|b| simple::json_body(&b));
        if sent.is_some() {
            headers.push(("Content-Type", "application/json".to_owned()));
        }
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let reply = simple::send(&self.http, META.name, method, &url, &refs, sent).await?;
        if reply.body.is_empty() {
            return Ok(Value::Null);
        }
        simple::json(META.name, &reply.body)
    }

    /// 列出域名下的全部记录，每页最多 500 条（接口上限），按 skip 翻页。
    async fn list(&self, zone: &str) -> Result<Vec<Value>, ProviderError> {
        let mut all = Vec::new();
        let mut skip: u32 = 0;
        for _ in 0..100 {
            let take_str = "500";
            let resp = self
                .call(
                    Method::GET,
                    &[("take", take_str), ("skip", &skip.to_string())],
                    zone,
                    None,
                )
                .await?;
            let items = resp
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let total = resp.get("total").and_then(Value::as_i64).unwrap_or(0);
            let n = items.len() as u32;
            all.extend(items);
            if n == 0 || (all.len() as i64) >= total {
                break;
            }
            skip += n;
        }
        Ok(all)
    }

    /// 按 type 与 name（不分大小写）过滤。
    fn matched<'a>(items: &'a [Value], sub: &str, typ: &str) -> Vec<&'a Value> {
        items
            .iter()
            .filter(|it| {
                simple::value_str(&it["type"]) == typ
                    && simple::value_str(&it["name"]).eq_ignore_ascii_case(sub)
            })
            .collect()
    }

    /// 保存一条记录。force 为 true 时请求体带 "force": true（A / AAAA 的
    /// Upsert 使用），TXT 不带。
    async fn save(&self, zone: &str, item: Value, force: bool) -> Result<(), ProviderError> {
        let mut body = json!({"items": [item]});
        if force {
            body["force"] = json!(true);
        }
        self.call(Method::PUT, &[], zone, Some(body))
            .await
            .map(drop)
    }

    /// 按类型、名称和内容删除记录，不会影响其他记录（不带 ttl）。
    async fn del(&self, zone: &str, item: Value) -> Result<(), ProviderError> {
        self.call(Method::DELETE, &[], zone, Some(json!([item])))
            .await
            .map(drop)
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let items = self.list(&rec.zone).await?;
        let name = rec.rr();
        let cur = Self::matched(&items, name, rec.typ.as_str());
        let ttl = clamp_ttl(rec.ttl);
        let mut same: Option<&Value> = None;
        let mut others: Vec<Value> = Vec::new();
        for it in &cur {
            if same.is_none() && content_of(it).eq_ignore_ascii_case(&rec.value) {
                same = Some(it);
            } else {
                others.push((*it).clone());
            }
        }
        let same_ttl: u32 = same
            .map(|it| it.get("ttl").and_then(Value::as_i64).unwrap_or(0).max(0) as u32)
            .unwrap_or(0);
        if same.is_some() && others.is_empty() && (rec.ttl == 0 || same_ttl == ttl) {
            return Ok(UpsertAction::Unchanged);
        }
        // 未指定 TTL 时沿用现有 TTL。
        let ttl = if same.is_some() && rec.ttl == 0 {
            same_ttl
        } else {
            ttl
        };
        // 先写入新值，再删除旧值，避免中途失败时记录消失。
        self.save(
            &rec.zone,
            item_json(rec.typ.as_str(), name, &rec.value, ttl),
            true,
        )
        .await?;
        for o in &others {
            self.del(
                &rec.zone,
                item_json(
                    o["type"].as_str().unwrap_or_default(),
                    name,
                    &content_of(o),
                    0,
                ),
            )
            .await?;
        }
        if cur.is_empty() {
            return Ok(UpsertAction::Created);
        }
        Ok(UpsertAction::Updated)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        self.save(
            zone,
            item_json("TXT", crate::record::owner_rr(sub), value, txt::TXT_TTL),
            false,
        )
        .await
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        let items = self.list(zone).await?;
        for it in Self::matched(&items, crate::record::owner_rr(sub), "TXT") {
            if txt::unquote(&simple::value_str(&it["value"])) == value {
                self.del(
                    zone,
                    item_json(
                        "TXT",
                        crate::record::owner_rr(sub),
                        &simple::value_str(&it["value"]),
                        0,
                    ),
                )
                .await?;
            }
        }
        Ok(())
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let items = self.list(&rec.zone).await?;
        Ok(Self::matched(&items, rec.rr(), rec.typ.as_str())
            .into_iter()
            .map(|it| RemoteRecord {
                id: String::new(),
                scope: rec.zone.clone(),
                values: vec![content_of(it)],
                ttl: it.get("ttl").and_then(Value::as_i64).unwrap_or(0).max(0) as u32,
            })
            .collect())
    }

    pub async fn remove_record(
        &self,
        rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.del(
            &rec.zone,
            item_json(rec.typ.as_str(), rec.rr(), &remote.values[0], 0),
        )
        .await
    }
}

crate::impl_provider!(Spaceship, META);
crate::impl_txt!(Spaceship);
crate::impl_deleter!(Spaceship);
