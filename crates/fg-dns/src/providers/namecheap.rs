//! Namecheap Dynamic DNS（上游 more.go 的 namecheap 节）：文档
//! namecheap.com/support/knowledgebase/article.aspx/29/11/。使用域名的
//! Dynamic DNS 密码调用更新接口，仅支持 A 记录（IPv4）；接口不返回旧值，
//! 无法区分是否变化，成功时一律返回 updated。没有 TXT 与删除接口。
//!
//! 契约（端点 `https://dynamicdns.park-your-domain.com/update`，参数在查询
//! 串里）：
//!
//! - 请求：GET `?host={主机记录}&domain={zone}&password={密码}&ip={value}`。
//! - 响应：XML `<interface-response>`；`ErrCount` 大于 0 时以
//!   `<errors><Err1>…</Err1></errors>` 的内容报错；XML 解析失败归类为
//!   Parse；非 200 状态按 HTTP 状态归类。

use std::sync::Arc;

use hyper::Method;

use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, UpsertAction, msg, simple,
};

pub static META: Meta = Meta::new("namecheap", "Namecheap")
    .labels("", "Dynamic DNS Password")
    .doc("https://www.namecheap.com/support/knowledgebase/article.aspx/29/11/how-to-dynamically-update-the-hosts-ip-with-an-http-request/");

pub struct Namecheap {
    password: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

impl Namecheap {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(
            creds,
            http,
            "https://dynamicdns.park-your-domain.com/update",
        )
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, false, true)?;
        Ok(Self {
            password: creds.secret.trim().to_owned(),
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        if rec.typ != crate::RecordType::A {
            return Err(ProviderError::invalid_input(
                META.name,
                "Namecheap 动态 DNS 仅支持 A 记录（IPv4）",
            ));
        }
        let url = format!(
            "{}?host={}&domain={}&password={}&ip={}",
            self.endpoint,
            simple::query_escape(rec.rr()),
            simple::query_escape(&rec.zone),
            simple::query_escape(&self.password),
            simple::query_escape(&rec.value),
        );
        let reply = match simple::send(&self.http, META.name, Method::GET, &url, &[], None).await {
            Ok(reply) => reply,
            // 密码在查询串里，错误信息要先抹掉。
            Err(mut e) => {
                e.redact(&self.password);
                return Err(e);
            }
        };
        let xml = reply.text();
        if !xml.contains("interface-response") {
            return Err(ProviderError::parse(
                META.name,
                format!("Namecheap: 无法解析响应: {}", simple::truncate(&xml, 200)),
            ));
        }
        let err_count: i64 = simple::xml_text(&xml, "ErrCount")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        if err_count > 0 {
            let message = simple::xml_text(&xml, "Err1").unwrap_or_default();
            return Err(ProviderError::new(
                META.name,
                ProviderErrorKind::InvalidInput,
                msg::API_ERROR,
            )
            .with_detail(format!("Namecheap: {message}")));
        }
        // 接口不返回旧值，无法区分是否变化。
        Ok(UpsertAction::Updated)
    }
}

crate::impl_provider!(Namecheap, META);
