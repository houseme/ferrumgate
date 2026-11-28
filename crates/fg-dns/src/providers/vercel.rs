//! Vercel DNS（上游 vercel.go）：凭据 Secret 为 Access Token，请求头
//! Authorization: Bearer {token} 与 Accept: application/json；团队账号下的
//! 域名需要在额外配置中填写团队 ID（teamId，自动附加到每个请求的查询串）。
//! 文档 vercel.com/docs/rest-api/reference/endpoints/dns。
//!
//! 契约（端点 `https://api.vercel.com`）：
//!
//! - 列表：`GET /v5/domains/{zone}/records?limit=100[&until={timestamp}]`，
//!   每页 100 条，按 pagination.next 的时间戳翻页。响应
//!   {records:[{id,name,type,value,ttl}], pagination:{count,next,prev}}。
//! - 创建：`POST /v2/domains/{zone}/records`，请求体
//!   {name,type,value,comment:"Created by FerrumGate"[,ttl]}；未指定 TTL
//!   时不发送（服务商默认 60）。
//! - 更新：`PATCH /v1/domains/records/{id}`，请求体 {type,value[,ttl]}；
//!   优先使用值相同的记录，其次取第一条。
//! - 删除：`DELETE /v2/domains/{zone}/records/{id}`。
//! - 名称写法：主机记录转成 Vercel 的写法——根域名是空字符串（不是 @）。
//! - TTL：0 表示不指定，最小 60。
//! - 错误体形如 {"error":{"code":"forbidden","message":"Not authorized"}}，
//!   透出其中的 message 并按 HTTP 状态归类。
//! - TXT：POST 创建（ttl 600）；列表后按值（去引号）逐条删除（同名多个
//!   同值记录全部删除）。
//! - 删除（DEL）：列表过滤后按值挑选，逐条 DELETE。

use std::sync::Arc;

use hyper::Method;
use serde_json::{Value, json};

use crate::{
    Credentials, Field, Meta, ProviderError, Record, RemoteRecord, UpsertAction, simple, txt,
};

pub static FIELDS: [Field; 1] = [Field::new(
    "teamId",
    "团队 ID（可选）",
    "域名在团队账号下时填写，形如 team_xxxx",
)];

pub static META: Meta = Meta::new("vercel", "Vercel")
    .labels("", "Access Token")
    .extra(&FIELDS)
    .doc("https://vercel.com/account/settings/tokens")
    .acme()
    .delete();

/// 创建记录时写的备注。
const CREATED_BY: &str = "Created by FerrumGate";

pub struct Vercel {
    token: String,
    team: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

struct VcRecord {
    id: String,
    name: String,
    typ: String,
    value: String,
    ttl: u32,
}

impl Vercel {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://api.vercel.com")
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
            team: creds.extra("teamId").unwrap_or_default().trim().to_owned(),
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        mut query: Vec<(String, String)>,
        body: Option<Value>,
    ) -> Result<Value, ProviderError> {
        if !self.team.is_empty() {
            query.push(("teamId".to_owned(), self.team.clone()));
        }
        let mut url = format!("{}{}", self.endpoint, path);
        if !query.is_empty() {
            let qs = query
                .iter()
                .map(|(k, v)| format!("{}={}", simple::query_escape(k), simple::query_escape(v)))
                .collect::<Vec<_>>()
                .join("&");
            url.push('?');
            url.push_str(&qs);
        }
        let sent = body.map(|b| simple::json_body(&b));
        let mut headers: Vec<(&'static str, String)> = vec![
            ("Authorization", format!("Bearer {}", self.token)),
            ("Accept", "application/json".to_owned()),
        ];
        if sent.is_some() {
            headers.push(("Content-Type", "application/json".to_owned()));
        }
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let reply = match self.http.send(method, &url, &refs, sent).await {
            Ok(reply) => reply,
            Err(fail) => return Err(ProviderError::from_http(META.name, vc_fail(fail))),
        };
        simple::json(META.name, &reply.body)
    }

    /// 返回域名下的全部记录。接口默认每页 20 条，这里每页取 100 条，按
    /// pagination.next 时间戳翻页。
    async fn list(&self, zone: &str) -> Result<Vec<VcRecord>, ProviderError> {
        let mut all = Vec::new();
        let mut until = String::new();
        for _ in 0..200u32 {
            let mut query = vec![("limit".to_owned(), "100".to_owned())];
            if !until.is_empty() {
                query.push(("until".to_owned(), until.clone()));
            }
            let path = format!("/v5/domains/{}/records", simple::path_escape(zone));
            let v = self.call(Method::GET, &path, query, None).await?;
            let records = v
                .get("records")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let n = records.len();
            for r in records {
                all.push(VcRecord {
                    id: r.get("id").map(simple::value_str).unwrap_or_default(),
                    name: r.get("name").map(simple::value_str).unwrap_or_default(),
                    typ: r.get("type").map(simple::value_str).unwrap_or_default(),
                    value: r.get("value").map(simple::value_str).unwrap_or_default(),
                    ttl: r
                        .get("ttl")
                        .and_then(Value::as_i64)
                        .map(|v| v.max(0) as u32)
                        .unwrap_or(0),
                });
            }
            let next = v
                .pointer("/pagination/next")
                .filter(|x| !x.is_null())
                .map(simple::value_str)
                .unwrap_or_default();
            if n == 0 || next.is_empty() || next == until {
                break;
            }
            until = next;
        }
        Ok(all)
    }

    /// 筛选出主机记录与类型都相同的记录（根域名的名称是空字符串）。
    fn matched<'a>(&self, recs: &'a [VcRecord], sub: &str, typ: &str) -> Vec<&'a VcRecord> {
        let want = vercel_name(sub);
        recs.iter()
            .filter(|r| r.typ == typ && r.name.eq_ignore_ascii_case(&want))
            .collect()
    }

    fn ttl_for(ttl: u32) -> u32 {
        // 0 表示不指定，最小 60。
        if (1..60).contains(&ttl) { 60 } else { ttl }
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let recs = self.list(&rec.zone).await?;
        let ttl = Self::ttl_for(rec.ttl);
        let cur = self.matched(&recs, rec.rr(), rec.typ.as_str());
        if cur.is_empty() {
            let mut body = json!({
                "name": vercel_name(rec.rr()),
                "type": rec.typ.as_str(),
                "value": rec.value,
                "comment": CREATED_BY,
            });
            if ttl > 0 {
                body["ttl"] = json!(ttl);
            }
            self.call(
                Method::POST,
                &format!("/v2/domains/{}/records", simple::path_escape(&rec.zone)),
                vec![],
                Some(body),
            )
            .await?;
            return Ok(UpsertAction::Created);
        }
        // 优先使用值相同的记录，其次取第一条。
        let target: &VcRecord = cur
            .iter()
            .copied()
            .find(|r| r.value.eq_ignore_ascii_case(&rec.value))
            .unwrap_or(cur[0]);
        if target.value.eq_ignore_ascii_case(&rec.value) && (ttl == 0 || target.ttl == ttl) {
            return Ok(UpsertAction::Unchanged);
        }
        let mut body = json!({"type": rec.typ.as_str(), "value": rec.value});
        if ttl > 0 {
            body["ttl"] = json!(ttl);
        }
        self.call(
            Method::PATCH,
            &format!("/v1/domains/records/{}", simple::path_escape(&target.id)),
            vec![],
            Some(body),
        )
        .await?;
        Ok(UpsertAction::Updated)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let body = json!({
            "name": vercel_name(crate::record::owner_rr(sub)),
            "type": "TXT",
            "value": value,
            "ttl": txt::TXT_TTL,
        });
        self.call(
            Method::POST,
            &format!("/v2/domains/{}/records", simple::path_escape(zone)),
            vec![],
            Some(body),
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
        let recs = self.list(zone).await?;
        for r in self.matched(&recs, sub, "TXT") {
            if txt::unquote(&r.value) == value {
                self.delete_by_id(zone, &r.id).await?;
            }
        }
        Ok(())
    }

    async fn delete_by_id(&self, zone: &str, id: &str) -> Result<(), ProviderError> {
        self.call(
            Method::DELETE,
            &format!(
                "/v2/domains/{}/records/{}",
                simple::path_escape(zone),
                simple::path_escape(id)
            ),
            vec![],
            None,
        )
        .await
        .map(drop)
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let recs = self.list(&rec.zone).await?;
        Ok(self
            .matched(&recs, rec.rr(), rec.typ.as_str())
            .into_iter()
            .map(|r| RemoteRecord {
                id: r.id.clone(),
                scope: rec.zone.clone(),
                values: vec![r.value.clone()],
                ttl: r.ttl,
            })
            .collect())
    }

    pub async fn remove_record(
        &self,
        rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.delete_by_id(&rec.zone, &remote.id).await
    }
}

/// 主机记录转成 Vercel 的写法：根域名为空字符串。
fn vercel_name(sub: &str) -> String {
    if sub == "@" {
        String::new()
    } else {
        sub.to_owned()
    }
}

/// 错误体形如 {"error":{"code":"forbidden","message":"..."}}，透出 message。
fn vc_fail(fail: crate::http::HttpFail) -> crate::http::HttpFail {
    if let crate::http::HttpFail::Status {
        status,
        body,
        retry_after,
    } = &fail
        && let Ok(v) = serde_json::from_slice::<Value>(body)
        && !simple::value_str(&v["error"]["message"]).is_empty()
    {
        let message = format!(
            "Vercel: HTTP {}: {} ({})",
            status.as_u16(),
            simple::value_str(&v["error"]["message"]),
            simple::value_str(&v["error"]["code"])
        );
        return crate::http::HttpFail::Status {
            status: *status,
            body: message.into_bytes().into(),
            retry_after: *retry_after,
        };
    }
    fail
}

crate::impl_provider!(Vercel, META);
crate::impl_txt!(Vercel);
crate::impl_deleter!(Vercel);
