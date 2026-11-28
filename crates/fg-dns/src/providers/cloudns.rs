//! ClouDNS（上游 cloudns.go）：所有接口都是带认证参数的 POST 表单，失败时
//! 仍返回 HTTP 200，通过响应里的 `status=Failed` 与 `statusDescription` 说明
//! 原因。文档 cloudns.net/wiki/article/42/。
//!
//! 契约（端点 `https://api.cloudns.net/dns/`，Content-Type:
//! application/x-www-form-urlencoded；ID 为 Auth ID / Sub Auth ID / Sub Auth
//! User，extra 的 authType 决定认证参数名（auth-id 默认 / sub-auth-id /
//! sub-auth-user），密码参数固定 auth-password）：
//!
//! - 列表：POST `records.json`，参数 domain-name、host、type；响应是按记录
//!   ID 键的对象（没有记录时可能是空数组），本地再按 type 与 host 精确过滤
//!   （根域名兼容 "@" 与空字符串两种返回）。
//! - 新建：POST `add-record.json`，参数 domain-name、record-type、type、
//!   host、record、ttl。官方文档参数表写 type 但实际可用的客户端都发
//!   record-type，两者同时发送以兼容。
//! - 修改：POST `mod-record.json`，参数 domain-name、record-id、host、
//!   record、ttl。删除：POST `delete-record.json`，参数 domain-name、
//!   record-id。
//! - TTL：ClouDNS 只接受固定档位 [60, 300, 900, 1800, 3600, 21600, 43200,
//!   86400, 172800, 259200, 604800, 1209600, 2592000]，取整到不小于它的最近
//!   档位；0 表示默认 3600。未变化比较按取整后的字符串。
//! - TXT：add-record.json 新增（TTL 60）；按值（去引号）删除。
//! - 删除（DEL）：list 过滤后逐条 delete-record.json。
//! - 主机记录：根域名直接写 "@"。

use std::sync::Arc;

use hyper::{Method, body::Bytes};
use serde_json::Value;

use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, RemoteRecord, UpsertAction, msg,
    simple, txt,
};

pub static EXTRA_FIELDS: &[crate::Field] = &[crate::Field::new(
    "authType",
    "认证类型",
    "auth-id（默认）、sub-auth-id 或 sub-auth-user，与上面的 ID 对应",
)];

pub static META: Meta = Meta::new("cloudns", "ClouDNS")
    .labels("Auth ID / Sub Auth ID / Sub Auth User", "Auth Password")
    .extra(EXTRA_FIELDS)
    .doc("https://www.cloudns.net/wiki/article/42/")
    .acme()
    .delete();

/// ClouDNS 允许的 TTL 档位，其他值会被拒绝。
const TTL_STEPS: [u32; 13] = [
    60, 300, 900, 1_800, 3_600, 21_600, 43_200, 86_400, 172_800, 259_200, 604_800, 1_209_600,
    2_592_000,
];

pub struct Cloudns {
    auth_type: String,
    id: String,
    password: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

/// 把 TTL 取整到不小于它的最近的允许档位；0 表示默认 3600。
fn round_ttl(ttl: u32) -> u32 {
    if ttl == 0 {
        return 3_600;
    }
    TTL_STEPS
        .iter()
        .copied()
        .find(|step| ttl <= *step)
        .unwrap_or(TTL_STEPS[TTL_STEPS.len() - 1])
}

impl Cloudns {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://api.cloudns.net/dns/")
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, true, true)?;
        let auth_type = match creds.extra("authType").unwrap_or("").trim() {
            "" => "auth-id".to_owned(),
            v @ ("auth-id" | "sub-auth-id" | "sub-auth-user") => v.to_owned(),
            other => {
                return Err(ProviderError::invalid_input(
                    META.name,
                    format!(
                        "ClouDNS 认证类型只能是 auth-id、sub-auth-id 或 sub-auth-user，收到 {other:?}"
                    ),
                ));
            }
        };
        Ok(Self {
            auth_type,
            id: creds.id.trim().to_owned(),
            password: creds.secret.trim().to_owned(),
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    /// 发送表单请求；失败状态（status=Failed）转成错误。
    async fn call(&self, action: &str, params: &[(&str, &str)]) -> Result<Value, ProviderError> {
        let mut pairs: Vec<(String, String)> = params
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        pairs.push((self.auth_type.clone(), self.id.clone()));
        pairs.push(("auth-password".to_owned(), self.password.clone()));
        let body = simple::form_encode(&pairs);
        let url = format!("{}/{}", self.endpoint, action);
        let headers = [("Content-Type", "application/x-www-form-urlencoded")];
        let reply = simple::send(
            &self.http,
            META.name,
            Method::POST,
            &url,
            &headers,
            Some(Bytes::from(body)),
        )
        .await?;
        let out: Value = simple::json(META.name, &reply.body)?;
        let status = out.get("status").map(simple::value_str).unwrap_or_default();
        if status == "Failed" {
            let description = simple::value_str(&out["statusDescription"]);
            let kind = if description
                .to_ascii_lowercase()
                .contains("invalid authentication")
            {
                ProviderErrorKind::Auth
            } else {
                ProviderErrorKind::InvalidInput
            };
            return Err(
                ProviderError::new(META.name, kind, msg::API_ERROR).with_detail(format!(
                    "ClouDNS {action}: {}",
                    simple::value_str(&out["statusDescription"])
                )),
            );
        }
        Ok(out)
    }

    /// 列出指定主机与类型的记录（响应按记录 ID 键），本地再过滤一次。
    async fn list(
        &self,
        zone: &str,
        host: &str,
        typ: &str,
    ) -> Result<Vec<ClRecord>, ProviderError> {
        let out = self
            .call(
                "records.json",
                &[("domain-name", zone), ("type", typ), ("host", host)],
            )
            .await?;
        let map = match out.as_object() {
            Some(map) => map,
            None => return Ok(Vec::new()), // 没有记录时可能返回空数组
        };
        let mut recs = Vec::new();
        for (key, v) in map {
            let id = simple::value_str(&v["id"]);
            let rec = ClRecord {
                id: if id.is_empty() { key.clone() } else { id },
                typ: simple::value_str(&v["type"]),
                host: simple::value_str(&v["host"]),
                value: simple::value_str(&v["record"]),
                ttl: simple::value_str(&v["ttl"]),
            };
            if rec.typ == typ && host_equal(&rec.host, host) {
                recs.push(rec);
            }
        }
        Ok(recs)
    }

    async fn add(
        &self,
        zone: &str,
        host: &str,
        typ: &str,
        value: &str,
        ttl: u32,
    ) -> Result<(), ProviderError> {
        self.call(
            "add-record.json",
            &[
                ("domain-name", zone),
                ("record-type", typ),
                ("type", typ),
                ("host", host),
                ("record", value),
                ("ttl", &round_ttl(ttl).to_string()),
            ],
        )
        .await
        .map(drop)
    }

    async fn modify(
        &self,
        zone: &str,
        id: &str,
        host: &str,
        value: &str,
        ttl: u32,
    ) -> Result<(), ProviderError> {
        self.call(
            "mod-record.json",
            &[
                ("domain-name", zone),
                ("record-id", id),
                ("host", host),
                ("record", value),
                ("ttl", &round_ttl(ttl).to_string()),
            ],
        )
        .await
        .map(drop)
    }

    async fn remove(&self, zone: &str, id: &str) -> Result<(), ProviderError> {
        self.call(
            "delete-record.json",
            &[("domain-name", zone), ("record-id", id)],
        )
        .await
        .map(drop)
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let host = rec.rr();
        let recs = self.list(&rec.zone, host, rec.typ.as_str()).await?;
        let Some(cur) = recs.first() else {
            self.add(&rec.zone, host, rec.typ.as_str(), &rec.value, rec.ttl)
                .await?;
            return Ok(UpsertAction::Created);
        };
        let ttl_same = rec.ttl == 0 || cur.ttl == round_ttl(rec.ttl).to_string();
        if crate::delete::same_value(rec.typ, &cur.value, &rec.value) && ttl_same {
            return Ok(UpsertAction::Unchanged);
        }
        self.modify(&rec.zone, &cur.id, host, &rec.value, rec.ttl)
            .await?;
        Ok(UpsertAction::Updated)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        self.add(zone, crate::record::owner_rr(sub), "TXT", value, 60)
            .await
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        for rec in self.list(zone, crate::record::owner_rr(sub), "TXT").await? {
            if txt::unquote(&rec.value) == value {
                return self.remove(zone, &rec.id).await;
            }
        }
        Ok(())
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        Ok(self
            .list(&rec.zone, rec.rr(), rec.typ.as_str())
            .await?
            .into_iter()
            .map(|r| RemoteRecord {
                id: r.id,
                scope: rec.zone.clone(),
                values: vec![r.value],
                ttl: r.ttl.parse().unwrap_or(0),
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

struct ClRecord {
    id: String,
    typ: String,
    host: String,
    value: String,
    ttl: String,
}

/// 判断响应里的 host 是否对应目标主机；根域名兼容 "@" 与空字符串两种返回。
fn host_equal(got: &str, want: &str) -> bool {
    let got = if got.is_empty() { "@" } else { got };
    got == want
}

crate::impl_provider!(Cloudns, META);
crate::impl_txt!(Cloudns);
crate::impl_deleter!(Cloudns);

#[cfg(test)]
mod tests {
    use super::round_ttl;

    #[test]
    fn cloudns_ttl_rounds_up_to_allowed_step() {
        assert_eq!(round_ttl(0), 3_600);
        assert_eq!(round_ttl(100), 300);
        assert_eq!(round_ttl(300), 300);
        assert_eq!(round_ttl(301), 900);
        assert_eq!(round_ttl(86_400), 86_400);
        assert_eq!(round_ttl(9_999_999), 2_592_000);
    }
}
