//! 时代互联 Now.cn、新网互联 Eranet、Tnet.hk 共用的「域名独立解析 API」
//! 客户端（上游 nowcn.go，eranet.go 与 tnethk.go 只提供各自的接口地址）。
//!
//! 契约（全部接口使用 GET，参数放在查询串里，按阿里云 RPC 风格用
//! HMAC-SHA1 签名；凭据 ID 为 AccessInstanceID，Secret 为 AccessKeySecret；
//! 端点分别为 `https://www.now.cn`、`https://www.eranet.com`、
//! `https://www.tnet.hk`）：
//!
//! - 公共参数：AccessInstanceID、SignatureMethod=HMAC-SHA1、
//!   SignatureNonce（12 字节随机数的十六进制）、Timestamp（UTC ISO 写法）。
//! - 签名：参数按键排序后拼成 k=v&…，对 k 与 v 做 RFC3986 百分号编码（空格
//!   为 %20、保留 ~），待签名串为
//!   `GET&%2F&<编码后的规范化查询串>`，密钥为 `AccessKeySecret + "&"`，
//!   HMAC-SHA1 后 Base64。签名后所有参数（含 Signature）再统一编码按序拼接。
//! - 动作：`/api/dns/DescribeRecordIndex`（Domain/Host/Type）、
//!   `AddDomainRecord`（Domain/Host/Type/Value/Ttl）、`UpdateDomainRecord`
//!   （同上 + Id）、`DeleteDomainRecord`（Domain/Id）。响应 `{error, Data}`。
//! - 鉴权失败时服务端可能返回 200 与空响应体，按认证失败处理；增删改接口
//!   可能返回对象以外的合法 JSON（如 true），视为成功。
//! - 列表过滤：服务端的主机/类型过滤可能不精确，本地再按主机（空视为
//!   根域名 @，不分大小写）与类型精确过滤一遍。
//! - TTL：更新未指定时沿用现有值，仍无有效值则 600；接口未返回 TTL（为 0）
//!   时无法比较，只按值判断。
//! - TXT：AddDomainRecord 新增（TTL 600）；按值（去引号）删除。
//! - 删除（DEL）：列表过滤后逐条 DeleteDomainRecord。

use std::sync::Arc;

use hyper::Method;
use serde_json::Value;

use crate::providers::same_host;
use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, RemoteRecord, UpsertAction, msg,
    sign, simple, txt,
};

/// 三家服务商共用的接口客户端。
pub(crate) struct NowcnApi {
    id: String,
    secret: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

impl NowcnApi {
    pub(crate) fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        let id = creds.id.trim().to_owned();
        let secret = creds.secret.trim().to_owned();
        if id.is_empty() || secret.is_empty() {
            return Err(ProviderError::new(
                "",
                ProviderErrorKind::InvalidInput,
                msg::CREDS_MISSING,
            )
            .with_detail("缺少凭据 ID 或 Secret（AccessInstanceID / AccessKeySecret）"));
        }
        Ok(Self {
            id,
            secret,
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    /// 加上公共参数与签名，生成查询串（签名后统一编码，按键排序拼接）。
    fn signed_query(&self, params: &[(String, String)]) -> String {
        let mut all: Vec<(String, String)> = vec![
            ("AccessInstanceID".to_owned(), self.id.clone()),
            ("SignatureMethod".to_owned(), "HMAC-SHA1".to_owned()),
            ("SignatureNonce".to_owned(), sign::nonce_hex()),
            ("Timestamp".to_owned(), sign::iso_z(sign::now_unix())),
        ];
        all.extend(params.iter().cloned());
        all.push(("Signature".to_owned(), nowcn_sign(&self.secret, &all)));
        all.sort_by(|a, b| a.0.cmp(&b.0));
        all.iter()
            .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// 调用接口。鉴权失败时服务端可能返回 200 与空响应体，这里按认证失败
    /// 处理；增删改接口可能返回对象以外的合法 JSON（如 true），视为成功。
    async fn call(
        &self,
        meta: &'static Meta,
        action: &str,
        params: &[(&str, &str)],
    ) -> Result<Value, ProviderError> {
        let pairs: Vec<(String, String)> = params
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let query = self.signed_query(&pairs);
        let url = format!("{}/api/dns/{action}?{query}", self.endpoint);
        let headers = [("Accept", "application/json")];
        let reply = simple::send(&self.http, meta.name, Method::GET, &url, &headers, None).await?;
        let body = reply.text();
        if body.trim().is_empty() {
            return Err(
                ProviderError::new(meta.name, ProviderErrorKind::Auth, msg::AUTH_FAILED)
                    .with_detail(format!(
                        "{}: 响应为空，请检查 AccessInstanceID 与 AccessKeySecret",
                        meta.title
                    )),
            );
        }
        let out: Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                // 增删改接口可能返回对象以外的合法 JSON（如 true），视为成功；
                // 列表接口必须是对象。
                if action == "DescribeRecordIndex" {
                    return Err(ProviderError::parse(
                        meta.name,
                        format!(
                            "{}: 解析响应失败: {e}: {}",
                            meta.title,
                            simple::truncate(&body, 300)
                        ),
                    ));
                }
                return Ok(Value::Null);
            }
        };
        let error = simple::value_str(&out["error"]);
        if !error.is_empty() {
            return Err(ProviderError::new(
                meta.name,
                ProviderErrorKind::InvalidInput,
                msg::API_ERROR,
            )
            .with_detail(format!("{}: {error}", meta.title)));
        }
        Ok(out)
    }

    /// 查询域名下指定主机记录与类型的记录，本地再精确过滤一遍。
    async fn list(
        &self,
        meta: &'static Meta,
        zone: &str,
        host: &str,
        typ: &str,
    ) -> Result<Vec<Value>, ProviderError> {
        let out = self
            .call(
                meta,
                "DescribeRecordIndex",
                &[("Domain", zone), ("Host", host), ("Type", typ)],
            )
            .await?;
        let data = out
            .get("Data")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(data
            .into_iter()
            .filter(|rec| {
                same_host(&simple::value_str(&rec["Host"]), host)
                    && simple::value_str(&rec["Type"]).eq_ignore_ascii_case(typ)
            })
            .collect())
    }

    pub(crate) async fn upsert(
        &self,
        meta: &'static Meta,
        rec: &Record,
    ) -> Result<UpsertAction, ProviderError> {
        let host = rec.rr();
        let recs = self.list(meta, &rec.zone, host, rec.typ.as_str()).await?;
        let mut ttl = rec.ttl;
        if let Some(cur) = recs.first() {
            if ttl == 0 {
                ttl = simple::value_str(&cur["Ttl"]).parse().unwrap_or(0);
            }
            if ttl == 0 {
                ttl = 600;
            }
            let cur_value = simple::value_str(&cur["Value"]);
            let cur_ttl: u32 = simple::value_str(&cur["Ttl"]).parse().unwrap_or(0);
            // 接口未返回 TTL 时无法比较，只按值判断。
            if cur_value == rec.value && (rec.ttl == 0 || cur_ttl == 0 || cur_ttl == ttl) {
                return Ok(UpsertAction::Unchanged);
            }
            self.call(
                meta,
                "UpdateDomainRecord",
                &[
                    ("Id", simple::value_str(&cur["id"]).as_str()),
                    ("Domain", rec.zone.as_str()),
                    ("Host", host),
                    ("Type", rec.typ.as_str()),
                    ("Value", rec.value.as_str()),
                    ("Ttl", &ttl.to_string()),
                ],
            )
            .await?;
            return Ok(UpsertAction::Updated);
        }
        if ttl == 0 {
            ttl = 600;
        }
        self.call(
            meta,
            "AddDomainRecord",
            &[
                ("Domain", rec.zone.as_str()),
                ("Host", host),
                ("Type", rec.typ.as_str()),
                ("Value", rec.value.as_str()),
                ("Ttl", &ttl.to_string()),
            ],
        )
        .await?;
        Ok(UpsertAction::Created)
    }

    pub(crate) async fn add_txt(
        &self,
        meta: &'static Meta,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        self.call(
            meta,
            "AddDomainRecord",
            &[
                ("Domain", zone),
                ("Host", crate::record::owner_rr(sub)),
                ("Type", "TXT"),
                ("Value", value),
                ("Ttl", &txt::TXT_TTL.to_string()),
            ],
        )
        .await
        .map(drop)
    }

    pub(crate) async fn delete_txt(
        &self,
        meta: &'static Meta,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        let recs = self
            .list(meta, zone, crate::record::owner_rr(sub), "TXT")
            .await?;
        for rec in &recs {
            if txt::unquote(&simple::value_str(&rec["Value"])) == value {
                return self
                    .remove(meta, zone, &simple::value_str(&rec["id"]))
                    .await;
            }
        }
        Ok(())
    }

    async fn remove(&self, meta: &'static Meta, zone: &str, id: &str) -> Result<(), ProviderError> {
        self.call(meta, "DeleteDomainRecord", &[("Domain", zone), ("Id", id)])
            .await
            .map(drop)
    }

    pub(crate) async fn find_records(
        &self,
        meta: &'static Meta,
        rec: &Record,
    ) -> Result<Vec<RemoteRecord>, ProviderError> {
        let recs = self
            .list(meta, &rec.zone, rec.rr(), rec.typ.as_str())
            .await?;
        Ok(recs
            .iter()
            .map(|r| RemoteRecord {
                id: simple::value_str(&r["id"]),
                scope: rec.zone.clone(),
                values: vec![simple::value_str(&r["Value"])],
                ttl: simple::value_str(&r["Ttl"]).parse().unwrap_or(0),
            })
            .collect())
    }

    pub(crate) async fn remove_record(
        &self,
        meta: &'static Meta,
        rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.remove(meta, &rec.zone, &remote.id).await
    }
}

/// 按签名规范编码：RFC3986，空格为 %20，保留 ~。
pub(crate) fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// 返回 params 的签名：按键排序拼成 k=v&…（k、v 都做 RFC3986 编码），待签名
/// 串为 `GET&%2F&<编码后的规范化查询串>`，密钥为 `secret + "&"`。
pub(crate) fn nowcn_sign(secret: &str, params: &[(String, String)]) -> String {
    let mut sorted = params.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let joined = sorted
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let to_sign = format!("GET&{}&{}", percent_encode("/"), percent_encode(&joined));
    let mac = sign::hmac_sha1(format!("{secret}&").as_bytes(), to_sign.as_bytes());
    sign::base64_std(&mac)
}

pub static META: Meta = Meta::new("nowcn", "时代互联 (Now.cn)")
    .labels("AccessInstanceID", "AccessKeySecret")
    .doc("https://help.now.cn/domain/resolve/20260310102214/")
    .acme()
    .delete();

/// 时代互联（Now.cn）。
pub struct Nowcn(NowcnApi);

impl Nowcn {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://www.now.cn")
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        Ok(Self(NowcnApi::new(creds, http, endpoint)?))
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        self.0.upsert(&META, rec).await
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        self.0.add_txt(&META, zone, sub, value).await
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        self.0.delete_txt(&META, zone, sub, value).await
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        self.0.find_records(&META, rec).await
    }

    pub async fn remove_record(
        &self,
        rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.0.remove_record(&META, rec, remote).await
    }
}

crate::impl_provider!(Nowcn, META);
crate::impl_txt!(Nowcn);
crate::impl_deleter!(Nowcn);

#[cfg(test)]
mod tests {
    use super::*;

    /// 签名与参数顺序无关；密钥不同签名不同；编码为 RFC3986（空格 %20、
    /// `*` %2A、保留 ~）。对照上游 nowcn_test.go::TestNowcnSignature。
    #[test]
    fn nowcn_signature_matches_upstream_semantics() {
        let params = vec![
            ("Domain".to_owned(), "example.com".to_owned()),
            ("Host".to_owned(), "a b*".to_owned()),
            ("AccessInstanceID".to_owned(), "inst".to_owned()),
        ];
        let got = nowcn_sign("sk", &params);
        let reordered = vec![
            ("AccessInstanceID".to_owned(), "inst".to_owned()),
            ("Host".to_owned(), "a b*".to_owned()),
            ("Domain".to_owned(), "example.com".to_owned()),
        ];
        assert_eq!(got, nowcn_sign("sk", &reordered));
        assert_ne!(got, nowcn_sign("other", &params));
        assert_eq!(percent_encode("a b*~/"), "a%20b%2A~%2F");
    }
}
