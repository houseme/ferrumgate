//! DNSPod 传统 Token 接口（上游 dnspod.go）：国内站 `dnsapi.cn`（dnspod）
//! 与国际站 `api.dnspod.com`（dnspodcom）。
//!
//! 契约：ID 与 Token 拼接为 `login_token` 表单提交，附 `format=json` 与
//! `lang=cn`；`Content-Type: application/x-www-form-urlencoded`；业务状态码
//! `"1"` 成功、`"10"` 没有记录。User-Agent 必须可识别（程序名/版本 + 联系
//! 方式），不能含 "DDNS Client"（dnsapi.cn 网关对这类 UA 直接返回 403）。
//!
//! - 动作：`Record.List`（domain, sub_domain, record_type）、`Record.Create`、
//!   `Record.Modify`（带 record_id）、`Record.Remark`、`Record.Remove`。
//! - 线路（LINE）：国内站默认线路「默认」、国际站 `default`；值为空时对应
//!   默认线路。
//! - TTL：请求 TTL > 0 时按值发送；未指定时新建不发送（服务商默认），
//!   更新发送 600。
//! - 备注（REMARK）：创建接口不接受备注，创建成功后用返回的记录 ID 单独
//!   调 `Record.Remark`；值相同时只改备注不重复写值。
//! - TXT：`Record.Create`（TTL 600）新增；`Record.List` 后按值（去引号）
//!   `Record.Remove`。
//! - 删除（DEL）：`Record.List` 过滤类型/线路/名称后按值挑选，`Record.Remove`。

use std::sync::Arc;

use hyper::Method;
use serde_json::Value;

use crate::http::OutboundHttp;
use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, RemoteRecord, UpsertAction, msg,
    simple, txt,
};

pub static META: Meta = Meta::new("dnspod", "DNSPod (国内站 Token)")
    .labels("ID", "Token")
    .doc("https://console.dnspod.cn/account/token/token")
    .line()
    .remark()
    .acme()
    .delete();

pub static META_COM: Meta = Meta::new("dnspodcom", "DNSPod (国际站 Token)")
    .labels("ID", "Token")
    .doc("https://www.dnspod.com/")
    .remark()
    .acme()
    .delete();

/// 发给 DNSPod 的 UA（形如 FerrumGate/0.1.0 (+https://github.com/houseme/ferrumgate)）。
/// 网关会对含「DDNS Client」字样的 UA 直接返回 403，回归保护见契约测试。
pub fn dnspod_user_agent() -> &'static str {
    crate::http::USER_AGENT_VALUE
}

pub struct Dnspod {
    meta: &'static Meta,
    token: String,
    http: Arc<OutboundHttp>,
    endpoint: String,
    default_line: &'static str,
}

struct DnspodStatus {
    code: String,
    message: String,
}

impl DnspodStatus {
    fn parse(v: &Value) -> Self {
        let status = &v["status"];
        Self {
            code: simple::value_str(&status["code"]),
            message: simple::value_str(&status["message"]),
        }
    }
}

impl Dnspod {
    pub fn new(creds: Credentials, http: Arc<OutboundHttp>) -> Result<Self, ProviderError> {
        Self::build(&META, creds, http, "https://dnsapi.cn", "默认")
    }

    /// dnspodcom：国际站端点与默认线路。
    pub fn new_com(creds: Credentials, http: Arc<OutboundHttp>) -> Result<Self, ProviderError> {
        Self::build(&META_COM, creds, http, "https://api.dnspod.com", "default")
    }

    pub fn with_endpoint(
        meta: &'static Meta,
        creds: Credentials,
        http: Arc<OutboundHttp>,
        endpoint: &str,
        default_line: &'static str,
    ) -> Result<Self, ProviderError> {
        Self::build(meta, creds, http, endpoint, default_line)
    }

    fn build(
        meta: &'static Meta,
        creds: Credentials,
        http: Arc<OutboundHttp>,
        endpoint: &str,
        default_line: &'static str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(meta, &creds, true, true)?;
        Ok(Self {
            meta,
            token: format!("{},{}", creds.id.trim(), creds.secret.trim()),
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            default_line,
        })
    }

    fn line_for<'a>(&'a self, rec: &'a Record) -> &'a str {
        if rec.line.is_empty() {
            self.default_line
        } else {
            &rec.line
        }
    }

    async fn call(
        &self,
        action: &str,
        form: &[(String, String)],
    ) -> Result<(DnspodStatus, Value), ProviderError> {
        let mut pairs = form.to_vec();
        pairs.push(("login_token".to_owned(), self.token.clone()));
        pairs.push(("format".to_owned(), "json".to_owned()));
        pairs.push(("lang".to_owned(), "cn".to_owned()));
        let body = simple::form_encode(&pairs);
        let url = format!("{}/{}", self.endpoint, action);
        let reply = simple::send(
            &self.http,
            self.meta.name,
            Method::POST,
            &url,
            &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("User-Agent", dnspod_user_agent()),
            ],
            Some(body.into_bytes().into()),
        )
        .await?;
        let value: Value = simple::json(self.meta.name, &reply.body)?;
        Ok((DnspodStatus::parse(&value), value))
    }

    fn ensure_ok(&self, action: &str, status: &DnspodStatus) -> Result<(), ProviderError> {
        if status.code == "1" {
            return Ok(());
        }
        // 业务错误码按无效输入归类；网关层的 401/403/429 由传输层按状态归类。
        Err(ProviderError::new(
            self.meta.name,
            ProviderErrorKind::InvalidInput,
            msg::API_ERROR,
        )
        .with_detail(format!(
            "DNSPod {action}: {} ({})",
            status.message, status.code
        )))
    }

    fn list_form(rec: &Record, typ: &str) -> Vec<(String, String)> {
        vec![
            ("domain".to_owned(), rec.zone.clone()),
            ("sub_domain".to_owned(), rec.rr().to_owned()),
            ("record_type".to_owned(), typ.to_owned()),
        ]
    }

    fn records_of(v: &Value) -> Vec<&Value> {
        v.get("records")
            .and_then(Value::as_array)
            .map(|a| a.iter().collect())
            .unwrap_or_default()
    }

    fn upsert_form(rec: &Record, line: &str) -> Vec<(String, String)> {
        let mut form = vec![
            ("domain".to_owned(), rec.zone.clone()),
            ("sub_domain".to_owned(), rec.rr().to_owned()),
            ("record_type".to_owned(), rec.typ.as_str().to_owned()),
            ("record_line".to_owned(), line.to_owned()),
            ("value".to_owned(), rec.value.clone()),
        ];
        if rec.ttl > 0 {
            form.push(("ttl".to_owned(), rec.ttl.to_string()));
        }
        form
    }

    fn set_form(form: &mut Vec<(String, String)>, key: &str, value: &str) {
        if let Some(entry) = form.iter_mut().find(|(k, _)| k == key) {
            entry.1 = value.to_owned();
        } else {
            form.push((key.to_owned(), value.to_owned()));
        }
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let (st, v) = self
            .call("Record.List", &Self::list_form(rec, rec.typ.as_str()))
            .await?;
        // 10 表示没有记录。
        let no_records = st.code == "10";
        if !no_records {
            self.ensure_ok("Record.List", &st)?;
        }
        let line = self.line_for(rec);
        let mut form = Self::upsert_form(rec, line);
        for r in Self::records_of(&v) {
            let rtype = simple::value_str(&r["type"]);
            let rline = simple::value_str(&r["line"]);
            if rtype != rec.typ.as_str() || rline != line {
                continue;
            }
            let value_same = simple::value_str(&r["value"]) == rec.value
                && (rec.ttl == 0 || simple::value_str(&r["ttl"]) == rec.ttl.to_string());
            let remark_same =
                rec.remark.is_empty() || simple::value_str(&r["remark"]) == rec.remark;
            if value_same && remark_same {
                return Ok(UpsertAction::Unchanged);
            }
            let id = simple::value_str(&r["id"]);
            if !value_same {
                if rec.ttl == 0 {
                    // 未指定 TTL 时更新为默认的 600。
                    Self::set_form(&mut form, "ttl", "600");
                }
                Self::set_form(&mut form, "record_id", &id);
                let (st, _) = self.call("Record.Modify", &form).await?;
                self.ensure_ok("Record.Modify", &st)?;
            }
            if !remark_same {
                self.set_remark(&rec.zone, &id, &rec.remark).await?;
            }
            return Ok(UpsertAction::Updated);
        }
        let (st, created) = self.call("Record.Create", &form).await?;
        self.ensure_ok("Record.Create", &st)?;
        // 新增接口不接受备注，创建后再单独设置。
        if !rec.remark.is_empty() {
            let id = simple::value_str(&created["record"]["id"]);
            if !id.is_empty()
                && let Err(e) = self.set_remark(&rec.zone, &id, &rec.remark).await
            {
                let detail = format!("记录已创建，设置备注失败: {}", e.detail);
                return Err(e.with_detail(detail));
            }
        }
        Ok(UpsertAction::Created)
    }

    async fn set_remark(&self, zone: &str, id: &str, remark: &str) -> Result<(), ProviderError> {
        let form = vec![
            ("domain".to_owned(), zone.to_owned()),
            ("record_id".to_owned(), id.to_owned()),
            ("remark".to_owned(), remark.to_owned()),
        ];
        let (st, _) = self.call("Record.Remark", &form).await?;
        self.ensure_ok("Record.Remark", &st)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let form = vec![
            ("domain".to_owned(), zone.to_owned()),
            ("sub_domain".to_owned(), sub.to_owned()),
            ("record_type".to_owned(), "TXT".to_owned()),
            ("record_line".to_owned(), self.default_line.to_owned()),
            ("value".to_owned(), value.to_owned()),
            ("ttl".to_owned(), txt::TXT_TTL.to_string()),
        ];
        let (st, _) = self.call("Record.Create", &form).await?;
        self.ensure_ok("Record.Create", &st)
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        let (st, v) = self
            .call("Record.List", &list_form_from(zone, sub, "TXT"))
            .await?;
        if st.code == "10" {
            return Ok(());
        }
        self.ensure_ok("Record.List", &st)?;
        for r in Self::records_of(&v) {
            // 服务商返回的 TXT 值可能带引号。
            if txt::unquote(&simple::value_str(&r["value"])) == value {
                let (st, _) = self
                    .call(
                        "Record.Remove",
                        &[
                            ("domain".to_owned(), zone.to_owned()),
                            ("record_id".to_owned(), simple::value_str(&r["id"])),
                        ],
                    )
                    .await?;
                self.ensure_ok("Record.Remove", &st)?;
                return Ok(());
            }
        }
        Ok(())
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let (st, v) = self
            .call("Record.List", &Self::list_form(rec, rec.typ.as_str()))
            .await?;
        if st.code == "10" {
            return Ok(Vec::new());
        }
        self.ensure_ok("Record.List", &st)?;
        let line = self.line_for(rec);
        let mut out = Vec::new();
        for r in Self::records_of(&v) {
            // sub_domain 是精确匹配，但仍按名称与类型过滤一次。
            let rtype = simple::value_str(&r["type"]);
            let rline = simple::value_str(&r["line"]);
            let rname = simple::value_str(&r["name"]);
            if rtype != rec.typ.as_str() || rline != line || !rname.eq_ignore_ascii_case(rec.rr()) {
                continue;
            }
            out.push(RemoteRecord {
                id: simple::value_str(&r["id"]),
                scope: rec.zone.clone(),
                values: vec![simple::value_str(&r["value"])],
                ttl: simple::value_str(&r["ttl"]).parse().unwrap_or(0),
            });
        }
        Ok(out)
    }

    pub async fn remove_record(
        &self,
        rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        let (st, _) = self
            .call(
                "Record.Remove",
                &[
                    ("domain".to_owned(), rec.zone.clone()),
                    ("record_id".to_owned(), remote.id.clone()),
                ],
            )
            .await?;
        self.ensure_ok("Record.Remove", &st)
    }
}

fn list_form_from(zone: &str, sub: &str, typ: &str) -> Vec<(String, String)> {
    vec![
        ("domain".to_owned(), zone.to_owned()),
        ("sub_domain".to_owned(), sub.to_owned()),
        ("record_type".to_owned(), typ.to_owned()),
    ]
}

impl crate::DnsProvider for Dnspod {
    fn meta(&self) -> &'static Meta {
        self.meta
    }
    fn upsert<'a>(
        &'a self,
        rec: &'a Record,
    ) -> crate::BoxFut<'a, Result<UpsertAction, ProviderError>> {
        Box::pin(async move { Dnspod::upsert(self, rec).await })
    }
}

crate::impl_txt!(Dnspod);
crate::impl_deleter!(Dnspod);
