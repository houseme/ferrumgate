//! Name.com Core API（上游 name_com.go）：文档 docs.name.com（OpenAPI 路径
//! 前缀 /core/v1）。使用用户名与 API Token 做 HTTP Basic 认证；记录以整数
//! ID 标识。
//!
//! 契约（端点 `https://api.name.com`，请求头 Authorization: Basic
//! base64(user:token)、Accept: application/json，带请求体时 Content-Type:
//! application/json；路径 `/core/v1/domains/{zone}/records[/id]`）：
//!
//! - 列表：GET `records?perPage=1000&page=N`，响应 `{records:[…], nextPage}`，
//!   nextPage 大于当前页时继续翻页；本地按 type 与 host（不分大小写）过滤。
//! - 新建：POST `records`，请求体 `{host, type, answer, ttl}`（未指定 TTL 时
//!   取 300，也是 Name.com 的最小值；TTL 1..300 一律抬到 300）。
//! - 修改：PUT `records/{id}`，同上请求体；未指定 TTL 时沿用记录原有的 TTL。
//! - 删除：DELETE `records/{id}`。
//! - 主机记录：根域名用空字符串。
//! - 未变化判断：值（不区分大小写）与 TTL 都一致。
//! - TXT：POST 新增（TTL 600）；按值（去引号）删除全部同名 TXT。
//! - 删除（DEL）：列表过滤后逐条 DELETE。
//! - 错误：非 2xx 的错误体形如 {"message":"…","details":"…"}，取出后按
//!   HTTP 状态归类（401/403 认证失败等）。

use std::sync::Arc;

use hyper::Method;
use serde_json::{Value, json};

use crate::{Credentials, Meta, ProviderError, Record, RemoteRecord, UpsertAction, simple, txt};

pub static META: Meta = Meta::new("namecom", "Name.com")
    .labels("Username", "API Token")
    .doc("https://www.name.com/account/settings/api")
    .acme()
    .delete();

pub struct NameCom {
    user: String,
    token: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

/// 提交的 TTL：0 表示不指定，最小 300。
fn clamp_ttl(ttl: u32) -> u32 {
    if ttl > 0 && ttl < 300 { 300 } else { ttl }
}

impl NameCom {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://api.name.com")
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, true, true)?;
        Ok(Self {
            user: creds.id.trim().to_owned(),
            token: creds.secret.trim().to_owned(),
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    fn basic_auth(&self) -> String {
        format!(
            "Basic {}",
            crate::sign::base64_std(format!("{}:{}", self.user, self.token).as_bytes())
        )
    }

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
        let mut headers: Vec<(&'static str, String)> = vec![
            ("Authorization", self.basic_auth()),
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

    fn records_path(zone: &str) -> String {
        format!("/core/v1/domains/{}/records", simple::path_escape(zone))
    }

    /// 列出域名下的全部记录，按 nextPage 翻页。
    async fn list(&self, zone: &str) -> Result<Vec<Value>, ProviderError> {
        let mut all = Vec::new();
        let mut page: u32 = 1;
        for _ in 0..200 {
            let resp = self
                .call(
                    Method::GET,
                    &Self::records_path(zone),
                    &[("perPage", "1000"), ("page", &page.to_string())],
                    None,
                )
                .await?;
            let records = resp
                .get("records")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let next = resp.get("nextPage").and_then(Value::as_i64).unwrap_or(0);
            all.extend(records);
            if next <= page as i64 {
                break;
            }
            page = next as u32;
        }
        Ok(all)
    }

    /// 按 type 与 host（不分大小写，根域名为空字符串）过滤。
    fn matched<'a>(recs: &'a [Value], sub: &str, typ: &str) -> Vec<&'a Value> {
        let want = name_com_host(sub);
        recs.iter()
            .filter(|rec| {
                simple::value_str(&rec["type"]) == typ
                    && name_com_host(&simple::value_str(&rec["host"])).eq_ignore_ascii_case(want)
            })
            .collect()
    }

    async fn create(
        &self,
        zone: &str,
        sub: &str,
        typ: &str,
        value: &str,
        ttl: u32,
    ) -> Result<(), ProviderError> {
        // 新建时未指定 TTL 取 300（也是 Name.com 的最小值）。
        let ttl = if ttl == 0 { 300 } else { clamp_ttl(ttl) };
        let body = json!({
            "host": name_com_host(sub),
            "type": typ,
            "answer": value,
            "ttl": ttl,
        });
        self.call(Method::POST, &Self::records_path(zone), &[], Some(body))
            .await
            .map(drop)
    }

    async fn remove(&self, zone: &str, id: &str) -> Result<(), ProviderError> {
        let path = format!("{}/{}", Self::records_path(zone), id);
        self.call(Method::DELETE, &path, &[], None).await.map(drop)
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let recs = self.list(&rec.zone).await?;
        let cur = Self::matched(&recs, rec.rr(), rec.typ.as_str());
        if cur.is_empty() {
            self.create(&rec.zone, rec.rr(), rec.typ.as_str(), &rec.value, rec.ttl)
                .await?;
            return Ok(UpsertAction::Created);
        }
        // 多条同名时优先选值相同的那条。
        let target = cur
            .iter()
            .copied()
            .find(|r| simple::value_str(&r["answer"]).eq_ignore_ascii_case(&rec.value))
            .unwrap_or(cur[0]);
        let target_ttl: u32 = simple::value_str(&target["ttl"]).parse().unwrap_or(0);
        let ttl = clamp_ttl(rec.ttl);
        let answer = simple::value_str(&target["answer"]);
        if answer.eq_ignore_ascii_case(&rec.value) && (ttl == 0 || target_ttl == ttl) {
            return Ok(UpsertAction::Unchanged);
        }
        // 未指定 TTL 时沿用记录原有的 TTL。
        let ttl = if ttl == 0 { target_ttl } else { ttl };
        let body = json!({
            "host": name_com_host(rec.rr()),
            "type": rec.typ.as_str(),
            "answer": rec.value,
            "ttl": ttl,
        });
        let path = format!(
            "{}/{}",
            Self::records_path(&rec.zone),
            simple::value_str(&target["id"])
        );
        self.call(Method::PUT, &path, &[], Some(body)).await?;
        Ok(UpsertAction::Updated)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        self.create(
            zone,
            crate::record::owner_rr(sub),
            "TXT",
            value,
            txt::TXT_TTL,
        )
        .await
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        let recs = self.list(zone).await?;
        for rec in Self::matched(&recs, crate::record::owner_rr(sub), "TXT") {
            if txt::unquote(&simple::value_str(&rec["answer"])) == value {
                self.remove(zone, &simple::value_str(&rec["id"])).await?;
            }
        }
        Ok(())
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let recs = self.list(&rec.zone).await?;
        Ok(Self::matched(&recs, rec.rr(), rec.typ.as_str())
            .into_iter()
            .map(|r| RemoteRecord {
                id: simple::value_str(&r["id"]),
                scope: rec.zone.clone(),
                values: vec![simple::value_str(&r["answer"])],
                ttl: simple::value_str(&r["ttl"]).parse().unwrap_or(0),
            })
            .collect())
    }

    pub async fn remove_record(
        &self,
        rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.remove(&rec.zone, &remote.id).await
    }
}

/// 主机记录：根域名用空字符串。
fn name_com_host(sub: &str) -> &str {
    if sub == "@" { "" } else { sub }
}

crate::impl_provider!(NameCom, META);
crate::impl_txt!(NameCom);
crate::impl_deleter!(NameCom);
