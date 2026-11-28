//! OVHcloud（上游 ovh.go）：ID 为 Application Key，Secret 为 Application
//! Secret，Consumer Key 与接入点在额外参数中填写。文档
//! api.ovh.com/createToken/。
//!
//! 契约（接入点 ovh-eu → `https://eu.api.ovh.com/1.0`、ovh-ca →
//! `https://ca.api.ovh.com/1.0`、ovh-us → `https://api.us.ovhcloud.com/1.0`，
//! 其余按完整 API 地址；三步签名：先 `GET /auth/time` 取服务器时间并算出
//! 本机与服务器的时间差，之后每个请求带 X-Ovh-Application、X-Ovh-Consumer、
//! X-Ovh-Timestamp（服务器时间）与 X-Ovh-Signature =
//! `$1$` + SHA1(AppSecret + "+" + ConsumerKey + "+" + METHOD + "+" + 完整
//! URL（含查询串）+ "+" + 请求体 + "+" + 时间戳)，见 `sign::ovh`）：
//!
//! - 记录查询：`GET /domain/zone/{zone}/record?fieldType={typ}&subDomain={sub}`
//!   返回 ID 列表，再逐个 `GET /domain/zone/{zone}/record/{id}` 读详情
//!   （根域名的 subDomain 为空串）。
//! - 新建：`POST /domain/zone/{zone}/record`，请求体 `{fieldType, subDomain,
//!   target}`（TTL > 0 时带 `ttl`，否则用服务商默认值）；修改：`PUT
//!   /domain/zone/{zone}/record/{id}`，请求体 `{target}`（TTL > 0 时带）。
//!   写入后必须 `POST /domain/zone/{zone}/refresh` 让修改生效。
//! - 定位（TXT、DEL）：OVH 不做记录集管理，同名同类型的每条解析一个 ID；
//!   upsert 只处理第一条。
//! - TXT：POST 新增（target 带引号、TTL 60）后 refresh；按值（去引号）
//!   找到后 DELETE 并 refresh。
//! - 删除（DEL，上游注册表 SupportsDelete 含 ovh，delete.go 有对应实现）：
//!   find 逐条，DELETE /record/{id} 后 refresh。
//! - 能力标记与 WP-41 §3.3 契约表（只标 TXT）不同：按 2026-11-28 注记的
//!   核对原则以上游源码为准，ovh 同时支持删除。

use std::sync::{Arc, Mutex};

use hyper::Method;
use serde_json::{Value, json};

use crate::sign;
use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, RemoteRecord, UpsertAction,
    simple, txt,
};

/// 接入点候选（界面表单元数据）。
pub static EXTRA_FIELDS: &[crate::Field] = &[
    crate::Field::new("consumerKey", "Consumer Key", "").required(),
    crate::Field::new(
        "endpoint",
        "接入点",
        "ovh-eu（默认）、ovh-ca、ovh-us 或完整 API 地址",
    ),
];

pub static META: Meta = Meta::new("ovh", "OVHcloud")
    .labels("Application Key", "Application Secret")
    .extra(EXTRA_FIELDS)
    .doc("https://api.ovh.com/createToken/")
    .acme()
    .delete();

pub struct Ovh {
    app: String,
    secret: String,
    consumer: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
    /// 本机与 OVH 服务器的时间差（秒），首次请求时经 /auth/time 校准。
    delta: Mutex<Option<i64>>,
    /// 取当前 Unix 秒（生产环境取系统时间，测试可注入固定时钟）。
    now: fn() -> i64,
}

impl Ovh {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        let endpoint = creds.extra("endpoint").unwrap_or("").to_owned();
        Self::with_endpoint(creds, http, &endpoint)
    }

    /// 接入点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint_and_clock(creds, http, endpoint, sign::now_unix)
    }

    /// 时钟可注入（假服务器契约测试用固定时间，避免跨秒抖动）。
    pub fn with_endpoint_and_clock(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        endpoint: &str,
        now: fn() -> i64,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, true, true)?;
        let consumer = creds.extra("consumerKey").unwrap_or("").trim().to_owned();
        if consumer.is_empty() {
            return Err(ProviderError::new(
                META.name,
                ProviderErrorKind::InvalidInput,
                crate::msg::CREDS_MISSING,
            )
            .with_detail("缺少 Consumer Key"));
        }
        Ok(Self {
            app: creds.id.trim().to_owned(),
            secret: creds.secret.trim().to_owned(),
            consumer,
            http,
            endpoint: resolve_endpoint(endpoint)?.trim_end_matches('/').to_owned(),
            delta: Mutex::new(None),
            now,
        })
    }

    /// GET /auth/time 校准时间差（只做一次；锁不跨 await 持有）。
    async fn sync_time(&self) -> Result<i64, ProviderError> {
        if let Some(delta) = *self.delta.lock().expect("ovh delta lock") {
            return Ok(delta);
        }
        let reply = simple::send(
            &self.http,
            META.name,
            Method::GET,
            &format!("{}/auth/time", self.endpoint),
            &[],
            None,
        )
        .await
        .map_err(|e| {
            let detail = format!("OVH: 获取服务器时间失败: {}", e.detail);
            e.with_detail(detail)
        })?;
        let server: i64 = simple::json(META.name, &reply.body)?;
        let delta = server - (self.now)();
        *self.delta.lock().expect("ovh delta lock") = Some(delta);
        Ok(delta)
    }

    /// 签名并调用。查询串按键排序（与 Go url.Values.Encode 一致），签名与
    /// 请求使用同一个完整地址。
    async fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> Result<Value, ProviderError> {
        let delta = self.sync_time().await?;
        let mut full = format!("{}{}", self.endpoint, path);
        if !query.is_empty() {
            let mut pairs: Vec<(&str, &str)> = query.to_vec();
            pairs.sort_by(|a, b| a.0.cmp(b.0));
            full.push('?');
            full.push_str(
                &pairs
                    .iter()
                    .map(|(k, v)| {
                        format!("{}={}", simple::query_escape(k), simple::query_escape(v))
                    })
                    .collect::<Vec<_>>()
                    .join("&"),
            );
        }
        let payload = body
            .as_ref()
            .map(|b| String::from_utf8_lossy(&simple::json_body(b)).into_owned())
            .unwrap_or_default();
        let ts = (self.now)() + delta;
        let signature = sign::ovh::signature(
            &self.secret,
            &self.consumer,
            method.as_str(),
            &full,
            &payload,
            ts,
        );
        let headers: Vec<(&'static str, String)> = vec![
            ("X-Ovh-Application", self.app.clone()),
            ("X-Ovh-Consumer", self.consumer.clone()),
            ("X-Ovh-Timestamp", ts.to_string()),
            ("X-Ovh-Signature", signature),
            ("Content-Type", "application/json".to_owned()),
        ];
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let sent = body.map(|b| simple::json_body(&b));
        let reply = simple::send(&self.http, META.name, method, &full, &refs, sent).await?;
        if reply.body.is_empty() {
            return Ok(Value::Null);
        }
        simple::json(META.name, &reply.body)
    }

    /// 列出同名同类型的全部记录（先取 ID，再逐条读详情）。
    async fn find(
        &self,
        zone: &str,
        sub: &str,
        typ: &str,
    ) -> Result<Vec<OvhRecord>, ProviderError> {
        let ids: Vec<i64> = serde_json::from_value(
            self.call(
                Method::GET,
                &format!("/domain/zone/{}/record", simple::path_escape(zone)),
                &[("fieldType", typ), ("subDomain", ovh_sub(sub))],
                None,
            )
            .await?,
        )
        .map_err(|e| ProviderError::parse(META.name, format!("解析记录 ID 列表失败: {e}")))?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let rec: Value = self
                .call(
                    Method::GET,
                    &format!("/domain/zone/{}/record/{id}", simple::path_escape(zone)),
                    &[],
                    None,
                )
                .await?;
            out.push(OvhRecord {
                id,
                target: simple::value_str(&rec["target"]),
                ttl: rec.get("ttl").and_then(Value::as_i64).unwrap_or(0).max(0) as u32,
            });
        }
        Ok(out)
    }

    /// 让修改在 DNS 区域中生效。
    async fn refresh(&self, zone: &str) -> Result<(), ProviderError> {
        self.call(
            Method::POST,
            &format!("/domain/zone/{}/refresh", simple::path_escape(zone)),
            &[],
            None,
        )
        .await
        .map(drop)
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let recs = self.find(&rec.zone, rec.rr(), rec.typ.as_str()).await?;
        if let Some(cur) = recs.first() {
            if cur.target == rec.value && (rec.ttl == 0 || cur.ttl == rec.ttl) {
                return Ok(UpsertAction::Unchanged);
            }
            let mut body = json!({"target": rec.value});
            if rec.ttl > 0 {
                body["ttl"] = json!(rec.ttl);
            }
            self.call(
                Method::PUT,
                &format!(
                    "/domain/zone/{}/record/{}",
                    simple::path_escape(&rec.zone),
                    cur.id
                ),
                &[],
                Some(body),
            )
            .await?;
            self.refresh(&rec.zone).await?;
            return Ok(UpsertAction::Updated);
        }
        let mut body = json!({
            "fieldType": rec.typ.as_str(),
            "subDomain": ovh_sub(rec.rr()),
            "target": rec.value,
        });
        if rec.ttl > 0 {
            body["ttl"] = json!(rec.ttl);
        }
        self.call(
            Method::POST,
            &format!("/domain/zone/{}/record", simple::path_escape(&rec.zone)),
            &[],
            Some(body),
        )
        .await?;
        self.refresh(&rec.zone).await?;
        Ok(UpsertAction::Created)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        self.call(
            Method::POST,
            &format!("/domain/zone/{}/record", simple::path_escape(zone)),
            &[],
            Some(json!({
                "fieldType": "TXT",
                "subDomain": ovh_sub(crate::record::owner_rr(sub)),
                "target": format!("\"{value}\""),
                "ttl": 60,
            })),
        )
        .await?;
        self.refresh(zone).await
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        for rec in self.find(zone, crate::record::owner_rr(sub), "TXT").await? {
            if txt::unquote(&rec.target) == value {
                self.remove_id(zone, rec.id).await?;
                return Ok(());
            }
        }
        Ok(())
    }

    async fn remove_id(&self, zone: &str, id: i64) -> Result<(), ProviderError> {
        self.call(
            Method::DELETE,
            &format!("/domain/zone/{}/record/{id}", simple::path_escape(zone)),
            &[],
            None,
        )
        .await?;
        self.refresh(zone).await
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        Ok(self
            .find(&rec.zone, rec.rr(), rec.typ.as_str())
            .await?
            .into_iter()
            .map(|r| RemoteRecord {
                id: r.id.to_string(),
                scope: rec.zone.clone(),
                values: vec![r.target],
                ttl: r.ttl,
            })
            .collect())
    }

    pub async fn remove_record(
        &self,
        rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        let id: i64 = remote
            .id
            .parse()
            .map_err(|e| ProviderError::invalid_input(META.name, format!("记录 ID 不合法: {e}")))?;
        self.remove_id(&rec.zone, id).await
    }
}

struct OvhRecord {
    id: i64,
    target: String,
    ttl: u32,
}

/// OVH 的 subDomain，根域名为空串。
fn ovh_sub(sub: &str) -> &str {
    if sub == "@" { "" } else { sub }
}

/// 接入点名称或完整地址 → API 根地址（上游 ovhEndpoint）。
fn resolve_endpoint(name: &str) -> Result<String, ProviderError> {
    match name.trim() {
        "" | "ovh-eu" => Ok("https://eu.api.ovh.com/1.0".to_owned()),
        "ovh-ca" => Ok("https://ca.api.ovh.com/1.0".to_owned()),
        "ovh-us" => Ok("https://api.us.ovhcloud.com/1.0".to_owned()),
        other => {
            if host_present(other) {
                Ok(other.to_owned())
            } else {
                Err(ProviderError::invalid_input(META.name, "OVH 接入点无效"))
            }
        }
    }
}

/// 检查地址以 http(s):// 开头且带主机部分。
fn host_present(url: &str) -> bool {
    let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    !host.is_empty()
}

crate::impl_provider!(Ovh, META);
crate::impl_txt!(Ovh);
crate::impl_deleter!(Ovh);
