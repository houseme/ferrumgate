//! HiPM DNSMgr（HiDNS，上游 hipmdnsmgr.go）：自建的多服务商 DNS 管理面板，
//! Gately 通过它的 REST 接口写入解析。凭据：ID 为面板地址（例如
//! https://dnsmgr.example.com），Secret 为面板里创建的 API 令牌，以
//! Authorization: Bearer 发送。响应统一为 {code, msg, data}，code 为 0 表示
//! 成功。记录的 name 是相对主机记录（根域名为 @），更新不传线路，面板会
//! 保留记录原有线路。
//!
//! 契约（端点为面板地址 + `/api` 前缀，地址结尾的斜杠与 /api 会被规范化）：
//!
//! - 域名定位：GET `/api/domains?page=N&pageSize=100&keyword={zone}`，data
//!   可能是裸数组或 `{list, total}` 包装（API 令牌访问域名列表时返回裸数
//!   组）；按名称（不分大小写）匹配，翻页直到找完。
//! - 记录列表：GET `/api/domains/{id}/records?page=N&pageSize=100&type={typ}`
//!   （根域名不传 subdomain 过滤，其余传 subdomain={host}），data 同样兼容
//!   裸数组与 {list, total}；本地再按 name（空视为 @，不分大小写）与 type
//!   精确过滤。
//! - 新建：POST `/api/domains/{id}/records`，请求体 `{name, type, value,
//!   ttl}`（未指定 TTL 取 600）。
//! - 修改：PUT `/api/domains/{id}/records/{recordId}`，同上请求体（不带
//!   line）；未指定 TTL 时沿用现有值，仍无有效值则 600。
//! - 删除：DELETE `/api/domains/{id}/records/{recordId}`。
//! - TXT：POST 新增（TTL 600）；按值（去引号）删除。
//! - 删除（DEL）：列表过滤后逐条 DELETE。
//! - 错误：HTTP 401/403 归类认证失败；HTTP 200 但业务 code != 0 时按消息
//!   透出（401/403 归类认证失败，其余无效输入）。

use std::sync::Arc;

use hyper::Method;
use serde_json::{Value, json};

use crate::providers::same_host;
use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, RemoteRecord, UpsertAction, msg,
    simple, txt,
};

pub static META: Meta = Meta::new("hipmdnsmgr", "HiPM DNSMgr")
    .labels("面板地址 (Base URL)", "API 令牌")
    .doc("https://github.com/HiPM-Tech/HiDNS")
    .acme()
    .delete();

pub struct HipmDnsMgr {
    token: String,
    http: Arc<crate::http::OutboundHttp>,
    /// 面板地址（不含 /api 后缀）。
    endpoint: String,
}

/// 校验并规范化面板地址，去掉结尾的斜杠与 /api（上游 hipmBaseURL）。
pub fn base_url(s: &str) -> Result<String, ProviderError> {
    let s = s.trim();
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"));
    let Some(rest) = rest else {
        return Err(ProviderError::invalid_input(
            META.name,
            "面板地址无效，需要 http(s):// 开头的完整地址",
        ));
    };
    if rest.split(['/', '?', '#']).next().unwrap_or("").is_empty() {
        return Err(ProviderError::invalid_input(
            META.name,
            "面板地址无效，需要 http(s):// 开头的完整地址",
        ));
    }
    Ok(s.trim_end_matches('/')
        .trim_end_matches("/api")
        .trim_end_matches('/')
        .to_owned())
}

/// 解析列表类 data：API 令牌访问域名列表时返回裸数组，其余情况返回
/// {list, total}。返回 (列表, total)。
fn list_data(data: &Value) -> (Vec<Value>, i64) {
    if let Some(arr) = data.as_array() {
        return (arr.clone(), 0);
    }
    let list = data
        .get("list")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let total = data.get("total").and_then(Value::as_i64).unwrap_or(0);
    (list, total)
}

impl HipmDnsMgr {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        let base = creds.id.clone();
        Self::with_endpoint(creds, http, &base)
    }

    /// 面板地址可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        base: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, true, true)?;
        Ok(Self {
            token: creds.secret.trim().to_owned(),
            http,
            endpoint: base_url(base)?,
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
        let mut url = format!("{}/api{path}", self.endpoint);
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
        let mut headers: Vec<(&'static str, String)> =
            vec![("Authorization", format!("Bearer {}", self.token))];
        let sent = body.map(|b| simple::json_body(&b));
        if sent.is_some() {
            headers.push(("Content-Type", "application/json".to_owned()));
        }
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let reply = simple::send(&self.http, META.name, method, &url, &refs, sent).await?;
        let env: Value = simple::json(META.name, &reply.body)?;
        let code = env.get("code").and_then(Value::as_i64).unwrap_or(0);
        if code != 0 {
            let m = simple::value_str(&env["msg"]);
            let (kind, key) = if code == 401 || code == 403 {
                (ProviderErrorKind::Auth, msg::AUTH_FAILED)
            } else {
                (ProviderErrorKind::InvalidInput, msg::API_ERROR)
            };
            return Err(ProviderError::new(META.name, kind, key)
                .with_detail(format!("HiPM DNSMgr: {m} (code {code})")));
        }
        Ok(env.get("data").cloned().unwrap_or(Value::Null))
    }

    /// 按名称查询面板中的域名 ID。
    async fn domain_id(&self, zone: &str) -> Result<String, ProviderError> {
        const PAGE_SIZE: u32 = 100;
        for page in 1..=10u32 {
            let data = self
                .call(
                    Method::GET,
                    "/domains",
                    &[
                        ("page", &page.to_string()),
                        ("pageSize", "100"),
                        ("keyword", zone),
                    ],
                    None,
                )
                .await?;
            let (domains, _) = list_data(&data);
            for d in &domains {
                let id = simple::value_str(&d["id"]);
                if !id.is_empty() && simple::value_str(&d["name"]).eq_ignore_ascii_case(zone) {
                    return Ok(id);
                }
            }
            if domains.len() < PAGE_SIZE as usize {
                break;
            }
        }
        Err(ProviderError::zone_not_found(
            META.name,
            format!("HiPM DNSMgr 中未找到域名 {zone}"),
        ))
    }

    fn records_path(domain_id: &str) -> String {
        format!("/domains/{}/records", simple::path_escape(domain_id))
    }

    /// 列出域名下指定主机记录与类型的记录（根域名不传主机过滤，按名称精确
    /// 筛选）。
    async fn list(
        &self,
        domain_id: &str,
        host: &str,
        typ: &str,
    ) -> Result<Vec<Value>, ProviderError> {
        const PAGE_SIZE: u32 = 100;
        let mut all = Vec::new();
        for page in 1..=10u32 {
            let page_str = page.to_string();
            let mut query: Vec<(&str, &str)> = vec![
                ("page", page_str.as_str()),
                ("pageSize", "100"),
                ("type", typ),
            ];
            if host != "@" {
                query.push(("subdomain", host));
            }
            let data = self
                .call(Method::GET, &Self::records_path(domain_id), &query, None)
                .await?;
            let (recs, total) = list_data(&data);
            let n = recs.len();
            all.extend(recs);
            if n < PAGE_SIZE as usize || (total > 0 && all.len() as i64 >= total) {
                break;
            }
        }
        Ok(all
            .into_iter()
            .filter(|rec| {
                same_host(&simple::value_str(&rec["name"]), host)
                    && simple::value_str(&rec["type"]).eq_ignore_ascii_case(typ)
            })
            .collect())
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let did = self.domain_id(&rec.zone).await?;
        let host = rec.rr();
        let recs = self.list(&did, host, rec.typ.as_str()).await?;
        let mut ttl = rec.ttl;
        if let Some(cur) = recs.first() {
            if ttl == 0 {
                ttl = cur.get("ttl").and_then(Value::as_i64).unwrap_or(0).max(0) as u32;
            }
            if ttl == 0 {
                ttl = 600;
            }
            let cur_value = simple::value_str(&cur["value"]);
            let cur_ttl: u32 = simple::value_str(&cur["ttl"]).parse().unwrap_or(0);
            // 接口未返回 TTL 时无法比较，只按值判断。
            if cur_value == rec.value && (rec.ttl == 0 || cur_ttl == 0 || cur_ttl == ttl) {
                return Ok(UpsertAction::Unchanged);
            }
            // 更新不传线路，面板会保留记录原有线路。
            self.call(
                Method::PUT,
                &format!(
                    "{}/{}",
                    Self::records_path(&did),
                    simple::path_escape(&simple::value_str(&cur["id"]))
                ),
                &[],
                Some(json!({
                    "name": host,
                    "type": rec.typ.as_str(),
                    "value": rec.value,
                    "ttl": ttl,
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
            &Self::records_path(&did),
            &[],
            Some(json!({
                "name": host,
                "type": rec.typ.as_str(),
                "value": rec.value,
                "ttl": ttl,
            })),
        )
        .await?;
        Ok(UpsertAction::Created)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let did = self.domain_id(zone).await?;
        self.call(
            Method::POST,
            &Self::records_path(&did),
            &[],
            Some(json!({
                "name": crate::record::owner_rr(sub),
                "type": "TXT",
                "value": value,
                "ttl": txt::TXT_TTL,
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
        let recs = self.list(&did, crate::record::owner_rr(sub), "TXT").await?;
        for rec in &recs {
            if txt::unquote(&simple::value_str(&rec["value"])) == value {
                return self.remove(&did, &simple::value_str(&rec["id"])).await;
            }
        }
        Ok(())
    }

    async fn remove(&self, domain_id: &str, record_id: &str) -> Result<(), ProviderError> {
        self.call(
            Method::DELETE,
            &format!(
                "{}/{}",
                Self::records_path(domain_id),
                simple::path_escape(record_id)
            ),
            &[],
            None,
        )
        .await
        .map(drop)
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let did = self.domain_id(&rec.zone).await?;
        let recs = self.list(&did, rec.rr(), rec.typ.as_str()).await?;
        Ok(recs
            .iter()
            .map(|r| RemoteRecord {
                id: simple::value_str(&r["id"]),
                scope: did.clone(),
                values: vec![simple::value_str(&r["value"])],
                ttl: r.get("ttl").and_then(Value::as_i64).unwrap_or(0).max(0) as u32,
            })
            .collect())
    }

    pub async fn remove_record(
        &self,
        _rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.remove(&remote.scope, &remote.id).await
    }
}

crate::impl_provider!(HipmDnsMgr, META);
crate::impl_txt!(HipmDnsMgr);
crate::impl_deleter!(HipmDnsMgr);

#[cfg(test)]
mod tests {
    use super::*;

    /// 面板地址规范化：结尾斜杠与 /api 去除（上游 hipmBaseURL 语义）。
    #[test]
    fn hipm_base_url_normalizes_trailing_api_and_slash() {
        assert_eq!(
            base_url("https://x.com/api/").expect("base"),
            "https://x.com"
        );
        assert_eq!(base_url("https://x.com/").expect("base"), "https://x.com");
        assert_eq!(
            base_url("https://x.com/api").expect("base"),
            "https://x.com"
        );
        assert_eq!(
            base_url("http://dnsmgr.example.com").expect("base"),
            "http://dnsmgr.example.com"
        );
        assert!(base_url("dnsmgr.example.com").is_err(), "缺少协议应报错");
        assert!(base_url("https://").is_err(), "缺少主机应报错");
    }
}
