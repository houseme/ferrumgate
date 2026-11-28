//! Dynadot 动态 DNS（上游 dynadot.go）：文档
//! dynadot.com/help/question/enable-DDNS。使用域名专属的 Dynamic DNS 密码调
//! 用 set_ddns，只能写 A / AAAA 记录，没有查询、删除和 TXT 接口，因此不实现
//! TXT 与删除。每个域名的密码不同，一个域名对应一份凭据。接口不提供查询，
//! 无法区分新增、更新与未变化，成功时一律返回 updated，重复提交由调用方的
//! 缓存避免。
//!
//! 契约（端点 `https://www.dynadot.com/set_ddns`，全部参数在查询串里，密码
//! 也在其中，传输层错误要先抹掉）：
//!
//! - 请求：GET `?domain={zone}&type={A|AAAA}&ip={value}&pwd={password}&
//!   ttl={档位}&subDomain={主机记录}&containRoot={true|false}`。subDomain 始终
//!   携带（根域名写 "@"），containRoot 仅在根域名时为 true。
//! - TTL：文档列出的可选值 [300, 600, 1800, 3600, 7200, 14400, 28800]；
//!   0 取 600，其余取整到不小于它的最近可选值，超过上限取 28800。
//! - 响应：`{"status": "...", "error_code": N, "content": [...]}`；error_code
//!   为 -1 或 status 为 error/fail 时报错（content 以逗号连接，为空时用截断
//!   的原文）。

use std::sync::Arc;

use hyper::Method;
use serde_json::Value;

use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, UpsertAction, msg, simple,
};

pub static META: Meta = Meta::new("dynadot", "Dynadot")
    .labels("", "Dynamic DNS 密码")
    .doc("https://www.dynadot.com/help/question/enable-DDNS");

/// set_ddns 文档列出的 TTL 可选值（5 分钟到 8 小时）。
const TTL_STEPS: [u32; 7] = [300, 600, 1_800, 3_600, 7_200, 14_400, 28_800];

/// 把 TTL 取整到不小于它的最近可选值：0 取 600，超过上限取 28800。
fn round_ttl(ttl: u32) -> u32 {
    if ttl == 0 {
        return 600;
    }
    TTL_STEPS
        .iter()
        .copied()
        .find(|step| ttl <= *step)
        .unwrap_or(TTL_STEPS[TTL_STEPS.len() - 1])
}

pub struct Dynadot {
    pwd: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

impl Dynadot {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://www.dynadot.com/set_ddns")
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, false, true)?;
        Ok(Self {
            pwd: creds.secret.trim().to_owned(),
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        if !matches!(rec.typ, crate::RecordType::A | crate::RecordType::AAAA) {
            return Err(ProviderError::invalid_input(
                META.name,
                "Dynadot 动态 DNS 仅支持 A 与 AAAA 记录",
            ));
        }
        let url = format!(
            "{}?domain={}&type={}&ip={}&pwd={}&ttl={}&subDomain={}&containRoot={}",
            self.endpoint,
            simple::query_escape(&rec.zone),
            rec.typ.as_str(),
            simple::query_escape(&rec.value),
            simple::query_escape(&self.pwd),
            round_ttl(rec.ttl),
            simple::query_escape(rec.rr()),
            if rec.rr() == "@" { "true" } else { "false" },
        );
        let reply = match simple::send(&self.http, META.name, Method::GET, &url, &[], None).await {
            Ok(reply) => reply,
            // 密码在查询串里，错误信息要先抹掉（原文与 URL 编码后的写法都要）。
            Err(mut e) => {
                e.redact(&self.pwd);
                return Err(e);
            }
        };
        if !reply.status.is_success() {
            let mut e = ProviderError::from_http(
                META.name,
                crate::http::HttpFail::Status {
                    status: reply.status,
                    body: reply.body.clone(),
                    retry_after: None,
                },
            );
            e.redact(&self.pwd);
            return Err(e);
        }
        let out: Value = simple::json(META.name, &reply.body)?;
        let error_code = out.get("error_code").and_then(Value::as_i64);
        let status = simple::value_str(&out["status"]);
        if error_code == Some(-1)
            || status.eq_ignore_ascii_case("error")
            || status.eq_ignore_ascii_case("fail")
        {
            let content = out
                .get("content")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(simple::value_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let detail = if content.is_empty() {
                simple::truncate(&reply.text(), 200)
            } else {
                content
            };
            return Err(ProviderError::new(
                META.name,
                ProviderErrorKind::InvalidInput,
                msg::API_ERROR,
            )
            .with_detail(format!("Dynadot: {detail}")));
        }
        Ok(UpsertAction::Updated)
    }
}

crate::impl_provider!(Dynadot, META);

#[cfg(test)]
mod tests {
    use super::round_ttl;

    /// TTL 取整到文档列出的可选值（上游 TestDynadot 的表）。
    #[test]
    fn dynadot_ttl_rounds_to_documented_steps() {
        let cases = [
            (60, 300),
            (0, 600),
            (301, 600),
            (3600, 3600),
            (5000, 7200),
            (86_400, 28_800),
        ];
        for (input, want) in cases {
            assert_eq!(round_ttl(input), want, "TTL {input}");
        }
    }
}
