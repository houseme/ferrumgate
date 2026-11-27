//! DuckDNS（上游 simple.go）。
//!
//! 契约：`GET https://www.duckdns.org/update?domains={domain}&token={secret}`
//! AAAA 记录用 `ipv6=`，其余用 `ip=`；响应体为 `OK` 视为成功，其余（如
//! `KO`）视为失败。主域名固定为 duckdns.org，子域名即账号下的域名；
//! 不提供查询与删除接口，重复提交由调用方的缓存避免。

use std::sync::Arc;

use hyper::{Method, body::Bytes};

use crate::http::{HttpReply, OutboundHttp};
use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, RecordType, UpsertAction, msg,
    simple,
};

pub static META: Meta = Meta::new("duckdns", "DuckDNS")
    .labels("", "Token")
    .doc("https://www.duckdns.org/");

pub struct DuckDns {
    token: String,
    http: Arc<OutboundHttp>,
    endpoint: String,
}

impl DuckDns {
    pub fn new(creds: Credentials, http: Arc<OutboundHttp>) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://www.duckdns.org/update")
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, false, true)?;
        Ok(Self {
            token: creds.secret.trim().to_owned(),
            http,
            endpoint: endpoint.to_owned(),
        })
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let fqdn = rec.fqdn();
        // DuckDNS 的主域名固定为 duckdns.org，子域名即账号下的域名。
        let domain = fqdn.strip_suffix(".duckdns.org").unwrap_or(fqdn.as_str());
        let mut query = format!(
            "domains={}&token={}",
            simple::query_escape(domain),
            simple::query_escape(&self.token)
        );
        if rec.typ == RecordType::AAAA {
            query.push_str(&format!("&ipv6={}", simple::query_escape(&rec.value)));
        } else {
            query.push_str(&format!("&ip={}", simple::query_escape(&rec.value)));
        }
        let reply = self
            .send(Method::GET, &format!("{}?{}", self.endpoint, query), None)
            .await?;
        let text = reply.text().trim().to_owned();
        if text != "OK" {
            let mut err =
                ProviderError::new(META.name, ProviderErrorKind::InvalidInput, msg::API_ERROR)
                    .with_detail(format!("DuckDNS 返回 {text:?}"));
            err.redact(&self.token);
            return Err(err);
        }
        Ok(UpsertAction::Updated)
    }

    async fn send(
        &self,
        method: Method,
        url: &str,
        body: Option<Bytes>,
    ) -> Result<HttpReply, ProviderError> {
        self.http
            .send(method, url, &[], body)
            .await
            .map_err(|fail| {
                let mut err = ProviderError::from_http(META.name, fail);
                err.redact(&self.token);
                err
            })
    }
}

crate::impl_provider!(DuckDns, META);
