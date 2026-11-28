//! DynDNS2 协议（上游 more.go 的 dyndns2 节）：No-IP、Dynu、DynDNS 等更新
//! 接口共用的协议。文档 noip.com/integrate/request。凭据为用户名与密码
//! （HTTP Basic），更新地址在额外参数（server），默认
//! `https://dynupdate.no-ip.com/nic/update`（Dynu 为
//! `https://api.dynu.com/nic/update`）。没有 TXT 与删除接口。
//!
//! 契约：
//!
//! - 请求：GET `{server}?hostname={完整域名}&myip={值}`，Basic 认证。
//! - 响应文本按 dyndns2 协议解析：`good [ip]` → updated、`nochg [ip]` →
//!   unchanged、其余（nohost / badauth / abuse / 911 …）报错并带截断的原文；
//!   HTTP 401 报「用户名或密码错误」（认证失败）。

use std::sync::Arc;

use hyper::Method;

use crate::{Credentials, Meta, ProviderError, ProviderErrorKind, Record, UpsertAction, simple};

pub static EXTRA_FIELDS: &[crate::Field] = &[crate::Field::new(
    "server",
    "更新地址",
    "默认 https://dynupdate.no-ip.com/nic/update；Dynu 为 https://api.dynu.com/nic/update",
)];

pub static META: Meta = Meta::new("dyndns2", "DynDNS2 (No-IP / Dynu / DynDNS …)")
    .labels("用户名", "密码")
    .extra(EXTRA_FIELDS)
    .doc("https://www.noip.com/integrate/request");

/// 默认更新地址（No-IP）。
const DEFAULT_SERVER: &str = "https://dynupdate.no-ip.com/nic/update";

pub struct Dyndns2 {
    user: String,
    pass: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

impl Dyndns2 {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        let server = creds.extra("server").unwrap_or(DEFAULT_SERVER).to_owned();
        Self::with_endpoint(creds, http, &server)
    }

    /// 更新地址可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        server: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, true, true)?;
        let server = server.trim();
        let valid = server
            .strip_prefix("https://")
            .or_else(|| server.strip_prefix("http://"))
            .is_some_and(|rest| !rest.split(['/', '?', '#']).next().unwrap_or("").is_empty());
        if !valid {
            return Err(ProviderError::invalid_input(
                META.name,
                "更新地址无效，需要 http(s):// 开头的完整地址",
            ));
        }
        Ok(Self {
            user: creds.id.trim().to_owned(),
            pass: creds.secret.trim().to_owned(),
            http,
            endpoint: server.to_owned(),
        })
    }

    fn basic_auth(&self) -> String {
        format!(
            "Basic {}",
            crate::sign::base64_std(format!("{}:{}", self.user, self.pass).as_bytes())
        )
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let url = format!(
            "{}?hostname={}&myip={}",
            self.endpoint,
            simple::query_escape(&rec.fqdn()),
            simple::query_escape(&rec.value),
        );
        let auth = self.basic_auth();
        let headers = [("Authorization", auth.as_str())];
        let reply =
            match simple::send(&self.http, META.name, Method::GET, &url, &headers, None).await {
                Ok(reply) => reply,
                Err(mut e) => {
                    // 401：用户名或密码错误（dyndns2 的 badauth 走 HTTP 状态）。
                    if e.kind == ProviderErrorKind::Auth {
                        e.detail = "DynDNS2: 用户名或密码错误".to_owned();
                        return Err(e);
                    }
                    e.redact(&self.pass);
                    return Err(e);
                }
            };
        let body = reply.text().trim().to_owned();
        if body.starts_with("good") {
            return Ok(UpsertAction::Updated);
        }
        if body.starts_with("nochg") {
            return Ok(UpsertAction::Unchanged);
        }
        Err(ProviderError::new(
            META.name,
            ProviderErrorKind::InvalidInput,
            crate::msg::API_ERROR,
        )
        .with_detail(format!("DynDNS2: {}", simple::truncate(&body, 200))))
    }
}

crate::impl_provider!(Dyndns2, META);
