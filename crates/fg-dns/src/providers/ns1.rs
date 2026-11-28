//! NS1（上游 more.go 的 ns1 节）：记录按记录集管理，一个 zone + 域名 + 类型
//! 对应一条记录，answers 是二维数组（每行一个应答）。文档 my.nsone.net。
//!
//! 契约（端点 `https://api.nsone.net/v1`，请求头 X-NSONE-Key 与 Content-Type:
//! application/json；路径 `/zones/{zone}/{fqdn}/{type}`）：
//!
//! - GET 读取，404 视为不存在；PUT 创建（请求体 `{zone, domain, type, ttl,
//!   answers:[{answer:[值]}]}`）；POST 更新（请求体只带 `{ttl, answers}`，
//!   不带 zone/domain/type）；DELETE 删除整个记录集。
//! - TTL：指定时按值；未指定时更新用默认 60、新建用默认 3600（上游
//!   keepttl_test.go：NS1 未指定 TTL 时更新为 60）。
//! - 未变化判断：answers 只有一行一行值且与目标一致，且（TTL 未指定或
//!   现有 TTL 相同）。
//! - TXT：PUT/POST 合并 answers（值不带引号，NS1 返回也不带引号）；
//!   delete_txt 按值（去引号）过滤 answers，全部移除时 DELETE 整个记录集。
//! - 删除（DEL，上游注册表 SupportsDelete 含 ns1）：findRecords 把 answers
//!   展平成记录集的值集合；记录集里还有其他值时由通用删除流程拒绝；
//!   单值时 DELETE 整个记录集。

use std::sync::Arc;

use hyper::Method;
use serde_json::{Value, json};

use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, RemoteRecord, UpsertAction,
    simple, txt,
};

pub static META: Meta = Meta::new("ns1", "NS1")
    .labels("", "API Key")
    .doc("https://my.nsone.net/#/account/settings")
    .acme()
    .delete();

pub struct Ns1 {
    key: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

/// 记录集的一行应答。
#[derive(Clone)]
struct Answer(Vec<String>);

impl Ns1 {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://api.nsone.net/v1")
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

    /// 读取/写入一个记录集；GET 404 返回 None。
    async fn call(
        &self,
        method: Method,
        zone: &str,
        fqdn: &str,
        typ: &str,
        body: Option<Value>,
    ) -> Result<Option<Value>, ProviderError> {
        let is_get = method == Method::GET;
        let url = format!(
            "{}/zones/{}/{}/{}",
            self.endpoint,
            simple::path_escape(zone),
            simple::path_escape(fqdn),
            simple::path_escape(typ)
        );
        let mut headers: Vec<(&'static str, String)> = vec![("X-NSONE-Key", self.key.clone())];
        let sent = body.map(|b| simple::json_body(&b));
        if sent.is_some() {
            headers.push(("Content-Type", "application/json".to_owned()));
        }
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        match simple::send(&self.http, META.name, method, &url, &refs, sent).await {
            Ok(reply) => {
                if reply.body.is_empty() {
                    return Ok(Some(Value::Null));
                }
                simple::json(META.name, &reply.body).map(Some)
            }
            Err(e) if e.kind == ProviderErrorKind::NotFound && is_get => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn answers_of(record: &Value) -> Vec<Answer> {
        record
            .get("answers")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .map(|row| {
                        Answer(
                            row.get("answer")
                                .and_then(Value::as_array)
                                .map(|a| a.iter().map(simple::value_str).collect())
                                .unwrap_or_default(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn ttl_of(record: &Value) -> u32 {
        record
            .get("ttl")
            .and_then(Value::as_i64)
            .unwrap_or(0)
            .max(0) as u32
    }

    fn answers_json(answers: &[Answer]) -> Value {
        Value::Array(answers.iter().map(|a| json!({ "answer": a.0 })).collect())
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let fqdn = rec.fqdn();
        let cur = self
            .call(Method::GET, &rec.zone, &fqdn, rec.typ.as_str(), None)
            .await?;
        let ttl = if rec.ttl > 0 {
            rec.ttl
        } else if cur.is_some() {
            // 未指定 TTL 时更新为默认的 60。
            60
        } else {
            3600
        };
        let Some(cur) = cur else {
            let body = json!({
                "zone": rec.zone,
                "domain": fqdn,
                "type": rec.typ.as_str(),
                "ttl": ttl,
                "answers": [{"answer": [rec.value]}],
            });
            self.call(Method::PUT, &rec.zone, &fqdn, rec.typ.as_str(), Some(body))
                .await?;
            return Ok(UpsertAction::Created);
        };
        let answers = Self::answers_of(&cur);
        let single_same = answers.len() == 1
            && answers[0].0.len() == 1
            && answers[0].0[0] == rec.value
            && (rec.ttl == 0 || Self::ttl_of(&cur) == rec.ttl);
        if single_same {
            return Ok(UpsertAction::Unchanged);
        }
        let body = json!({"ttl": ttl, "answers": [{"answer": [rec.value]}]});
        self.call(Method::POST, &rec.zone, &fqdn, rec.typ.as_str(), Some(body))
            .await?;
        Ok(UpsertAction::Updated)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let fqdn = crate::record::owner_fqdn(zone, sub);
        let cur = self.call(Method::GET, zone, &fqdn, "TXT", None).await?;
        match cur {
            None => {
                let body = json!({
                    "zone": zone,
                    "domain": fqdn,
                    "type": "TXT",
                    "ttl": 60,
                    "answers": [{"answer": [value]}],
                });
                self.call(Method::PUT, zone, &fqdn, "TXT", Some(body)).await
            }
            Some(cur) => {
                // 已有记录集（例如同时申请泛域名与主域名）：合并 answers。
                let mut answers = Self::answers_of(&cur);
                answers.push(Answer(vec![value.to_owned()]));
                let body =
                    json!({"ttl": Self::ttl_of(&cur), "answers": Self::answers_json(&answers)});
                self.call(Method::POST, zone, &fqdn, "TXT", Some(body))
                    .await
            }
        }
        .map(drop)
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        let fqdn = crate::record::owner_fqdn(zone, sub);
        let Some(cur) = self.call(Method::GET, zone, &fqdn, "TXT", None).await? else {
            return Ok(());
        };
        let answers = Self::answers_of(&cur);
        let keep: Vec<Answer> = answers
            .iter()
            .filter(|a| !(a.0.len() == 1 && txt::unquote(&a.0[0]) == value))
            .cloned()
            .collect();
        if keep.len() == answers.len() {
            return Ok(());
        }
        if keep.is_empty() {
            return self
                .call(Method::DELETE, zone, &fqdn, "TXT", None)
                .await
                .map(drop);
        }
        let body = json!({"ttl": Self::ttl_of(&cur), "answers": Self::answers_json(&keep)});
        self.call(Method::POST, zone, &fqdn, "TXT", Some(body))
            .await
            .map(drop)
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let Some(cur) = self
            .call(Method::GET, &rec.zone, &rec.fqdn(), rec.typ.as_str(), None)
            .await?
        else {
            return Ok(Vec::new());
        };
        // 一个记录集算一条；值里是全部 answers。
        let mut values = Vec::new();
        for a in Self::answers_of(&cur) {
            values.extend(a.0);
        }
        Ok(vec![RemoteRecord {
            id: String::new(),
            scope: String::new(),
            values,
            ttl: Self::ttl_of(&cur),
        }])
    }

    pub async fn remove_record(
        &self,
        rec: &Record,
        _remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.call(
            Method::DELETE,
            &rec.zone,
            &rec.fqdn(),
            rec.typ.as_str(),
            None,
        )
        .await
        .map(drop)
    }
}

crate::impl_provider!(Ns1, META);
crate::impl_txt!(Ns1);
crate::impl_deleter!(Ns1);
