//! 火山引擎 DNS（TrafficRoute）记录管理（上游 trafficroute.go）：接口版本
//! 2018-08-01，签名 HMAC-SHA256（服务 DNS，地域 cn-north-1），文档
//! www.volcengine.com/docs/6758/155088。
//!
//! 契约（端点 `https://open.volcengineapi.com`，Action/Version 在查询串里；
//! 读取类动作用 GET 且参数在查询串中，写入类动作用 POST 且参数为 JSON 请求
//! 体；请求头 Content-Type: application/json、X-Date、X-Content-Sha256、
//! Authorization；凭证范围 `{date8}/cn-north-1/DNS/request`）：
//!
//! - 动作：`ListZones`（Key/PageNumber/PageSize≤500）、`ListRecords`（ZID/
//!   Host/Type/SearchMode=exact/PageNumber/PageSize≤500）、`CreateRecord`
//!   （POST ZID/Host/Type/Value/Line/TTL——创建始终携带 TTL 与线路）、
//!   `UpdateRecord`（POST RecordID/Host/Line/Type/Value/TTL——必须带主机
//!   记录与线路，沿用现有值）、`DeleteRecord`（POST RecordID）。
//! - 线路（LINE）：Line，空对应 default；列出时按线路过滤（line_match）。
//! - TTL：创建未指定时取 600；更新未指定时沿用现有值，仍无有效值则 600。
//! - TXT：CreateRecord（TTL 600、default 线路）新增；ListRecords 后按值
//!   （去引号）DeleteRecord。
//! - 删除（DEL）：ListRecords 过滤后按值挑选，DeleteRecord 逐条。
//! - 业务错误：ResponseMetadata.Error {Code, Message}。
//! - 规范查询串空格编码为 %20（火山引擎要求）。

use std::sync::Arc;

use hyper::Method;
use serde_json::{Value, json};

use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, RemoteRecord, UpsertAction,
    http::HttpFail, msg, sign, simple, txt,
};

pub static META: Meta = Meta::new("trafficroute", "火山引擎 DNS")
    .labels("Access Key ID", "Secret Access Key")
    .doc("https://console.volcengine.com/iam/keymanage/")
    .line()
    .acme()
    .delete();

const VERSION: &str = "2018-08-01";
/// 凭证范围中的服务名使用大写 "DNS"。
const SERVICE: &str = "DNS";
const REGION: &str = "cn-north-1";
/// 创建记录未指定 TTL 时的默认值（创建/更新始终携带 TTL）。
const DEFAULT_TTL: u32 = 600;
/// 列表接口单页最大 500 条。
const PAGE_SIZE: u32 = 500;
const MAX_PAGES: u32 = 50;
const CONTENT_TYPE: &str = "application/json";

pub struct TrafficRoute {
    id: String,
    secret: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

struct TrRecord {
    record_id: String,
    host: String,
    value: String,
    ttl: u32,
    line: String,
}

impl TrafficRoute {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://open.volcengineapi.com")
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, true, true)?;
        Ok(Self {
            id: creds.id.trim().to_owned(),
            secret: creds.secret.trim().to_owned(),
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    /// 调用接口。读取类动作用 GET 且参数在查询串中，写入类动作用 POST 且
    /// 参数为 JSON 请求体。
    async fn call(
        &self,
        method: Method,
        action: &str,
        query: &[(String, String)],
        body: Option<Value>,
    ) -> Result<Value, ProviderError> {
        let mut q: Vec<(String, String)> = query.to_vec();
        q.push(("Action".to_owned(), action.to_owned()));
        q.push(("Version".to_owned(), VERSION.to_owned()));
        // 规范查询串要求空格编码为 %20。
        let raw_query = sign::sigv4::canonical_query(&q);
        let payload = body.map(|b| simple::json_body(&b)).unwrap_or_default();
        let host = self
            .endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or_default()
            .to_owned();
        let x_date = sign::amz_date(sign::now_unix());
        let body_hash = sign::sha256_hex(&payload);
        let auth = volc_authorization(
            &self.id,
            &self.secret,
            method.as_str(),
            &host,
            &raw_query,
            CONTENT_TYPE,
            &body_hash,
            &x_date,
        );
        let headers: Vec<(&'static str, String)> = vec![
            ("Content-Type", CONTENT_TYPE.to_owned()),
            ("X-Date", x_date),
            ("X-Content-Sha256", body_hash),
            ("Authorization", auth),
        ];
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let url = if raw_query.is_empty() {
            self.endpoint.clone()
        } else {
            format!("{}?{}", self.endpoint, raw_query)
        };
        let sent = if payload.is_empty() {
            None
        } else {
            Some(payload)
        };
        let reply = match self.http.send(method, &url, &refs, sent).await {
            Ok(reply) => reply,
            Err(fail) => return Err(ProviderError::from_http(META.name, tr_fail(fail, action))),
        };
        let env: Value = simple::json(META.name, &reply.body)?;
        if let Some(err) = env
            .get("ResponseMetadata")
            .and_then(|m| m.get("Error"))
            .filter(|e| {
                e.get("Code")
                    .map(|c| !simple::value_str(c).is_empty())
                    .unwrap_or(false)
            })
        {
            let code = simple::value_str(&err["Code"]);
            let message = simple::value_str(&err["Message"]);
            let (kind, key) = if code.contains("InvalidAccessKey")
                || code.contains("SignatureDoesNotMatch")
                || code.contains("AuthFailure")
            {
                (ProviderErrorKind::Auth, msg::AUTH_FAILED)
            } else if code.contains("NotFound") || code.contains("ZoneNotFound") {
                (ProviderErrorKind::NotFound, msg::NOT_FOUND)
            } else {
                (ProviderErrorKind::InvalidInput, msg::API_ERROR)
            };
            return Err(ProviderError::new(META.name, kind, key)
                .with_detail(format!("火山引擎 DNS {action}: {message} ({code})")));
        }
        Ok(env.get("Result").cloned().unwrap_or(Value::Null))
    }

    /// 区域定位：按域名查询 ZID，名称忽略大小写。
    async fn zone_id(&self, zone: &str) -> Result<i64, ProviderError> {
        let name = zone.trim().trim_end_matches('.');
        for page in 1..=MAX_PAGES {
            let query = vec![
                ("Key".to_owned(), name.to_owned()),
                ("PageNumber".to_owned(), page.to_string()),
                ("PageSize".to_owned(), PAGE_SIZE.to_string()),
            ];
            let v = self.call(Method::GET, "ListZones", &query, None).await?;
            let zones = v
                .get("Zones")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for z in &zones {
                if simple::value_str(&z["ZoneName"]).eq_ignore_ascii_case(name) {
                    return Ok(simple::value_str(&z["ZID"]).parse().unwrap_or(0));
                }
            }
            let total = v.get("Total").and_then(Value::as_i64).unwrap_or(0);
            if (zones.len() as u32) < PAGE_SIZE || page as i64 * PAGE_SIZE as i64 >= total {
                break;
            }
        }
        Err(ProviderError::zone_not_found(
            META.name,
            format!("火山引擎 DNS 账号下未找到域名 {zone}"),
        ))
    }

    /// 列出主机记录与类型都匹配的解析记录，并按线路过滤（未指定线路时取
    /// default）。接口可能按前缀匹配，本地再按主机记录与类型精确过滤。
    async fn list_records(&self, zid: i64, rec: &Record) -> Result<Vec<TrRecord>, ProviderError> {
        let mut out = Vec::new();
        for page in 1..=MAX_PAGES {
            let query = vec![
                ("ZID".to_owned(), zid.to_string()),
                ("Host".to_owned(), rec.rr().to_owned()),
                ("Type".to_owned(), rec.typ.as_str().to_owned()),
                ("SearchMode".to_owned(), "exact".to_owned()),
                ("PageNumber".to_owned(), page.to_string()),
                ("PageSize".to_owned(), PAGE_SIZE.to_string()),
            ];
            let v = self.call(Method::GET, "ListRecords", &query, None).await?;
            let list = v
                .get("Records")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for r in &list {
                let line = simple::value_str(&r["Line"]);
                if !simple::value_str(&r["Host"]).eq_ignore_ascii_case(rec.rr())
                    || simple::value_str(&r["Type"]) != rec.typ.as_str()
                    || !crate::delete::line_match(&line, &rec.line, "default")
                {
                    continue;
                }
                out.push(TrRecord {
                    record_id: simple::value_str(&r["RecordID"]),
                    host: simple::value_str(&r["Host"]),
                    value: simple::value_str(&r["Value"]),
                    ttl: simple::value_str(&r["TTL"]).parse().unwrap_or(0),
                    line,
                });
            }
            let total = v.get("TotalCount").and_then(Value::as_i64).unwrap_or(0);
            if (list.len() as u32) < PAGE_SIZE || page as i64 * PAGE_SIZE as i64 >= total {
                break;
            }
        }
        Ok(out)
    }

    /// 创建一条记录；创建时始终携带 TTL（默认 600）与线路。
    async fn create_record(&self, zid: i64, rec: &Record, ttl: u32) -> Result<(), ProviderError> {
        let line = if rec.line.is_empty() {
            "default"
        } else {
            &rec.line
        };
        let ttl = if ttl == 0 { DEFAULT_TTL } else { ttl };
        self.call(
            Method::POST,
            "CreateRecord",
            &[],
            Some(json!({
                "ZID": zid,
                "Host": rec.rr(),
                "Type": rec.typ.as_str(),
                "Value": rec.value,
                "Line": line,
                "TTL": ttl,
            })),
        )
        .await
        .map(drop)
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let zid = self.zone_id(&rec.zone).await?;
        let recs = self.list_records(zid, rec).await?;
        let Some(cur) = recs.first() else {
            self.create_record(zid, rec, rec.ttl).await?;
            return Ok(UpsertAction::Created);
        };
        if crate::delete::same_value(rec.typ, &cur.value, &rec.value)
            && (rec.ttl == 0 || cur.ttl == rec.ttl)
        {
            return Ok(UpsertAction::Unchanged);
        }
        // 更新接口必须带主机记录与线路，沿用现有记录的值；TTL 未指定时沿用
        // 现有记录的 TTL，仍无有效值则取默认 600。
        let ttl = if rec.ttl > 0 {
            rec.ttl
        } else if cur.ttl > 0 {
            cur.ttl
        } else {
            DEFAULT_TTL
        };
        self.call(
            Method::POST,
            "UpdateRecord",
            &[],
            Some(json!({
                "RecordID": cur.record_id,
                "Host": cur.host,
                "Line": cur.line,
                "Type": rec.typ.as_str(),
                "Value": rec.value,
                "TTL": ttl,
            })),
        )
        .await?;
        Ok(UpsertAction::Updated)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let zid = self.zone_id(zone).await?;
        self.create_record(
            zid,
            &Record {
                zone: zone.to_owned(),
                sub: sub.to_owned(),
                typ: crate::RecordType::TXT,
                value: value.to_owned(),
                ..Record::default()
            },
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
        let zid = self.zone_id(zone).await?;
        let recs = self
            .list_records(
                zid,
                &Record {
                    zone: zone.to_owned(),
                    sub: sub.to_owned(),
                    typ: crate::RecordType::TXT,
                    ..Record::default()
                },
            )
            .await?;
        for r in recs {
            if txt::unquote(&r.value) == value {
                return self.delete_record(&r.record_id).await;
            }
        }
        Ok(())
    }

    async fn delete_record(&self, id: &str) -> Result<(), ProviderError> {
        self.call(
            Method::POST,
            "DeleteRecord",
            &[],
            Some(json!({"RecordID": id})),
        )
        .await
        .map(drop)
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let zid = self.zone_id(&rec.zone).await?;
        let recs = self.list_records(zid, rec).await?;
        Ok(recs
            .into_iter()
            .map(|r| RemoteRecord {
                id: r.record_id,
                scope: zid.to_string(),
                values: vec![r.value],
                ttl: r.ttl,
            })
            .collect())
    }

    pub async fn remove_record(
        &self,
        _rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.delete_record(&remote.id).await
    }
}

/// 计算火山引擎请求头 Authorization。`query` 为已按 RFC3986 编码并排序的
/// 查询串；签名头为 content-type、host、x-content-sha256、x-date。
#[allow(clippy::too_many_arguments)] // 与火山引擎签名要素一一对应
fn volc_authorization(
    ak: &str,
    sk: &str,
    method: &str,
    host: &str,
    query: &str,
    content_type: &str,
    body_hash: &str,
    x_date: &str,
) -> String {
    let short = x_date.get(..8).unwrap_or_default();
    let signed_headers = "content-type;host;x-content-sha256;x-date";
    let canonical = format!(
        "{method}\n/\n{query}\ncontent-type:{content_type}\nhost:{host}\nx-content-sha256:{body_hash}\nx-date:{x_date}\n\n{signed_headers}\n{body_hash}"
    );
    let scope = format!("{short}/{REGION}/{SERVICE}/request");
    let string_to_sign = format!(
        "HMAC-SHA256\n{x_date}\n{scope}\n{}",
        sign::sha256_hex(canonical.as_bytes())
    );
    let mut key = sign::hmac_sha256(sk.as_bytes(), short.as_bytes());
    key = sign::hmac_sha256(&key, REGION.as_bytes());
    key = sign::hmac_sha256(&key, SERVICE.as_bytes());
    key = sign::hmac_sha256(&key, b"request");
    let signature = hex::encode(sign::hmac_sha256(&key, string_to_sign.as_bytes()));
    format!(
        "HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
}

/// 传输层失败时把火山引擎业务错误 {ResponseMetadata.Error} 透出为详情。
fn tr_fail(fail: HttpFail, action: &str) -> HttpFail {
    if let HttpFail::Status {
        status,
        body,
        retry_after,
    } = &fail
        && let Ok(v) = serde_json::from_slice::<Value>(body)
        && let Some(err) = v.pointer("/ResponseMetadata/Error")
        && !simple::value_str(&err["Code"]).is_empty()
    {
        let message = format!(
            "火山引擎 DNS {action}: {} ({})",
            simple::value_str(&err["Message"]),
            simple::value_str(&err["Code"])
        );
        return HttpFail::Status {
            status: *status,
            body: message.into_bytes().into(),
            retry_after: *retry_after,
        };
    }
    fail
}

crate::impl_provider!(TrafficRoute, META);
crate::impl_txt!(TrafficRoute);
crate::impl_deleter!(TrafficRoute);

#[cfg(test)]
mod tests {
    use super::*;

    /// 签名结构自检：凭证范围为大写 DNS 与 cn-north-1、request 后缀，四个
    /// 签名头与上游契约一致（上游契约测试用同一算法在假服务器端重算比对）。
    #[test]
    fn volc_authorization_scope_and_headers_match_contract() {
        let body_hash = sign::sha256_hex(b"{}");
        let auth = volc_authorization(
            "AK",
            "SK",
            "POST",
            "open.volcengineapi.com",
            "Action=CreateRecord&Version=2018-08-01",
            CONTENT_TYPE,
            &body_hash,
            "20231114T221320Z",
        );
        assert!(
            auth.contains(
                "/cn-north-1/DNS/request, SignedHeaders=content-type;host;x-content-sha256;x-date,"
            ),
            "{auth}"
        );
        assert!(
            auth.starts_with("HMAC-SHA256 Credential=AK/20231114/cn-north-1/DNS/request"),
            "{auth}"
        );
    }
}
