//! Porkbun API v3（上游 simple.go）。
//!
//! 契约：`POST https://api.porkbun.com/api/json/v3/{path}`，请求体统一带
//! `apikey` 与 `secretapikey`，`Content-Type: application/json`；响应
//! `{status, message, records}`，`status == "SUCCESS"` 视为成功；非 2xx 时
//! 优先透出响应体里的 `message`。
//!
//! - 主机记录：根域名为空串、统一小写——Porkbun 保存记录时把名称转成小写，
//!   按名称查询却区分大小写，带大写字母的主机记录会查不到已有记录。
//! - 定位：`POST /dns/retrieveByNameType/{zone}/{type}[/{sub}]`；返回空时再
//!   `POST /dns/retrieve/{zone}` 列出整个域名按名称核对一次（该接口偶有查
//!   不到已有记录的情况，直接创建会报「记录已存在」并每轮重试，issue #99）。
//! - 更新：`POST /dns/editByNameType/...`（content/ttl）；创建：
//!   `POST /dns/create/{zone}`（name/type/content/ttl）。两次查询都没找到却
//!   提示同值记录已存在时按「无需更新」处理。
//! - TTL：最小 600；请求 TTL 为 0 时用 600。
//! - TXT：create 新增（TTL 600）；retrieveByNameType 后按值（去引号）
//!   `POST /dns/delete/{zone}/{id}`。
//! - 删除（DEL）：定位后逐条 `POST /dns/delete/{zone}/{id}`。

use std::sync::Arc;

use hyper::{Method, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::http::{HttpFail, OutboundHttp};
use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, RemoteRecord, UpsertAction, msg,
    simple, txt,
};

/// Porkbun 最小 TTL 为 600。
const MIN_TTL: u32 = 600;

pub static META: Meta = Meta::new("porkbun", "Porkbun")
    .labels("API Key", "Secret API Key")
    .doc("https://porkbun.com/account/api")
    .acme()
    .delete();

pub struct Porkbun {
    key: String,
    secret: String,
    http: Arc<OutboundHttp>,
    endpoint: String,
}

#[derive(Deserialize, Default)]
struct PorkbunResp {
    #[serde(default)]
    status: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    records: Vec<PorkbunRecord>,
}

#[derive(Clone, Deserialize)]
struct PorkbunRecord {
    #[serde(default)]
    id: String,
    /// 读取时返回完整域名（FQDN），写入时只传主机记录。
    #[serde(default)]
    name: String,
    #[serde(rename = "type", default)]
    typ: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    ttl: String,
}

impl Porkbun {
    pub fn new(creds: Credentials, http: Arc<OutboundHttp>) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://api.porkbun.com/api/json/v3")
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<OutboundHttp>,
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

    async fn post(
        &self,
        path: &str,
        extra: &[(&str, Value)],
    ) -> Result<PorkbunResp, ProviderError> {
        let mut body = serde_json::Map::new();
        body.insert("apikey".into(), json!(self.key));
        body.insert("secretapikey".into(), json!(self.secret));
        for (key, value) in extra {
            body.insert((*key).into(), value.clone());
        }
        let url = format!("{}{}", self.endpoint, path);
        let reply = match self
            .http
            .send(
                Method::POST,
                &url,
                &[("Content-Type", "application/json")],
                Some(simple::json_body(&Value::Object(body))),
            )
            .await
        {
            Ok(reply) => reply,
            Err(fail) => {
                // 非两百时优先透出响应体里的 message（如「记录已存在」）。
                if let HttpFail::Status { status, body, .. } = &fail
                    && let Ok(resp) = serde_json::from_slice::<PorkbunResp>(body)
                    && !resp.message.is_empty()
                {
                    return Err(
                        ProviderError::new(META.name, kind_for(*status), msg::API_ERROR)
                            .with_detail(format!("Porkbun: {}", resp.message)),
                    );
                }
                return Err(ProviderError::from_http(META.name, fail));
            }
        };
        let resp: PorkbunResp = simple::json(META.name, &reply.body)?;
        if resp.status != "SUCCESS" {
            return Err(ProviderError::new(
                META.name,
                ProviderErrorKind::InvalidInput,
                msg::API_ERROR,
            )
            .with_detail(format!("Porkbun: {}", resp.message)));
        }
        Ok(resp)
    }

    /// Porkbun 接口使用的主机记录：根域名为空串，统一小写。
    fn sub_for(rec: &Record) -> String {
        let sub = rec.sub.trim().to_ascii_lowercase();
        if sub == "@" { String::new() } else { sub }
    }

    /// retrieveByNameType / editByNameType 等接口的路径后缀：/{zone}/{type}[/{sub}]。
    fn name_type_path(rec: &Record) -> String {
        let mut path = format!("/{}/{}", rec.zone, rec.typ.as_str());
        let sub = Self::sub_for(rec);
        if !sub.is_empty() {
            path = format!("{}/{}", path, simple::path_escape(&sub));
        }
        path
    }

    /// 查询同名同类型的记录；retrieveByNameType 返回空时再列出整个域名的
    /// 记录按名称核对一次（issue #99）。
    async fn find(&self, rec: &Record) -> Result<Vec<PorkbunRecord>, ProviderError> {
        let path = format!("/dns/retrieveByNameType{}", Self::name_type_path(rec));
        let cur = self.post(&path, &[]).await?;
        if !cur.records.is_empty() {
            return Ok(cur.records);
        }
        let all = self
            .post(&format!("/dns/retrieve/{}", rec.zone), &[])
            .await?;
        let sub = Self::sub_for(rec);
        let fqdn = if sub.is_empty() {
            rec.zone.to_ascii_lowercase()
        } else {
            format!("{sub}.{}", rec.zone).to_ascii_lowercase()
        };
        Ok(all
            .records
            .into_iter()
            .filter(|r| {
                r.typ.eq_ignore_ascii_case(rec.typ.as_str())
                    && r.name.trim_end_matches('.').eq_ignore_ascii_case(&fqdn)
            })
            .collect())
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let recs = self.find(rec).await?;
        let ttl = rec.ttl.max(MIN_TTL);
        if let Some(cur) = recs.first() {
            // IPv6 可能以不同写法返回，按地址比较。
            if crate::delete::same_value(rec.typ, &cur.content, &rec.value)
                && (rec.ttl == 0 || cur.ttl == ttl.to_string())
            {
                return Ok(UpsertAction::Unchanged);
            }
            self.post(
                &format!("/dns/editByNameType{}", Self::name_type_path(rec)),
                &[
                    ("content", json!(rec.value)),
                    ("ttl", json!(ttl.to_string())),
                ],
            )
            .await?;
            return Ok(UpsertAction::Updated);
        }
        let sub = Self::sub_for(rec);
        let created = self
            .post(
                &format!("/dns/create/{}", rec.zone),
                &[
                    ("name", json!(sub)),
                    ("type", json!(rec.typ.as_str())),
                    ("content", json!(rec.value)),
                    ("ttl", json!(ttl.to_string())),
                ],
            )
            .await;
        // 两次查询都没找到却提示已存在：记录已经是目标值，按无需更新处理。
        if let Err(e) = created {
            if porkbun_duplicate(&e) {
                return Ok(UpsertAction::Unchanged);
            }
            return Err(e);
        }
        Ok(UpsertAction::Created)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        self.post(
            &format!("/dns/create/{zone}"),
            &[
                ("name", json!(sub)),
                ("type", json!("TXT")),
                ("content", json!(value)),
                ("ttl", json!(txt::TXT_TTL.to_string())),
            ],
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
        let path = format!(
            "/dns/retrieveByNameType/{zone}/TXT/{}",
            simple::path_escape(sub)
        );
        let cur = self.post(&path, &[]).await?;
        for r in &cur.records {
            // 服务商返回的 TXT 值可能带引号。
            if txt::unquote(&r.content) == value {
                self.post(&format!("/dns/delete/{zone}/{}", r.id), &[])
                    .await?;
                return Ok(());
            }
        }
        Ok(())
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let recs = self.find(rec).await?;
        Ok(recs
            .into_iter()
            .map(|r| RemoteRecord {
                id: r.id,
                scope: rec.zone.clone(),
                values: vec![r.content],
                ttl: r.ttl.parse().unwrap_or(0),
            })
            .collect())
    }

    pub async fn remove_record(
        &self,
        rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.post(&format!("/dns/delete/{}/{}", rec.zone, remote.id), &[])
            .await?;
        Ok(())
    }
}

/// 判断创建失败是否因为同名同类型同值的记录已存在，此时服务商处已是目标值。
fn porkbun_duplicate(e: &ProviderError) -> bool {
    e.detail
        .to_lowercase()
        .contains("name, type, and content already exists")
}

fn kind_for(status: StatusCode) -> ProviderErrorKind {
    crate::http::kind_for_status(status)
}

crate::impl_provider!(Porkbun, META);
crate::impl_txt!(Porkbun);
crate::impl_deleter!(Porkbun);
