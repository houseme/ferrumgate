//! Cloudflare API v4（上游 cloudflare.go）。
//!
//! 契约：`Secret` 为 API Token，发送 `Authorization: Bearer {Secret}`；若
//! `ID` 是邮箱（含 `@`）则视为 Global API Key，改发 `X-Auth-Email` /
//! `X-Auth-Key`。端点 `https://api.cloudflare.com/client/v4`，全部请求带
//! `Content-Type: application/json`，响应为 `{success, errors, result}` 信封。
//!
//! - 区域定位：`GET /zones?name={zone}`，按名称精确匹配（不区分大小写）。
//! - 记录定位：`GET /zones/{zid}/dns_records?type={type}&name={fqdn}`。
//! - 创建：`POST /zones/{zid}/dns_records`；更新：`PATCH .../{id}`（只改给出
//!   的字段，不动代理状态与标签）；删除多余同名旧值记录：`DELETE .../{id}`。
//! - TTL：0 表示自动（发送 1）；开启代理的记录 TTL 只能是 1。
//! - 代理状态：extra `proxied` 填 true/false 时同步已有记录的代理状态；
//!   留空时沿用记录现状、新建按 false，PATCH 不带 proxied。
//! - 备注（REMARK）：创建与更新写 `comment`；未填备注时不改动。
//! - TXT：`add_txt` POST（TTL 120），`delete_txt` 列出后按值（去引号）删除。
//! - 删除（DEL）：列出同名同类型记录，按值挑选后逐条 DELETE。

use std::sync::Arc;

use hyper::{Method, body::Bytes};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    Credentials, Field, Meta, ProviderError, ProviderErrorKind, Record, RemoteRecord, UpsertAction,
    http::{HttpFail, OutboundHttp, kind_for_status},
    msg, record, simple, txt,
};

/// Cloudflare 的 TXT 记录使用 120（比通用 TXT_TTL 更短）。
const TXT_TTL_CF: u32 = 120;

pub static FIELDS: [Field; 1] = [Field::new(
    "proxied",
    "代理状态",
    "true 或 false；留空不管理已有记录的代理状态，新建记录默认 false",
)];

pub static META: Meta = Meta::new("cloudflare", "Cloudflare")
    .labels("账号邮箱", "API Token / Global API Key")
    .extra(&FIELDS)
    .doc("https://dash.cloudflare.com/profile/api-tokens")
    .remark()
    .acme()
    .delete();

pub struct Cloudflare {
    creds: Credentials,
    http: Arc<OutboundHttp>,
    endpoint: String,
}

impl Cloudflare {
    pub fn new(creds: Credentials, http: Arc<OutboundHttp>) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://api.cloudflare.com/client/v4")
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, false, true)?;
        Ok(Self {
            creds,
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    /// 只有 ID 是邮箱时才使用 Global API Key；导入配置残留的其他服务商
    /// AccessKey 不会误触发送邮箱认证（会被 Cloudflare 以 6003 拒绝）。
    fn global_key(&self) -> bool {
        self.creds.id.contains('@')
    }

    fn auth_headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = vec![("Content-Type", "application/json".to_owned())];
        if self.global_key() {
            headers.push(("X-Auth-Email", self.creds.id.clone()));
            headers.push(("X-Auth-Key", self.creds.secret.clone()));
        } else {
            headers.push(("Authorization", format!("Bearer {}", self.creds.secret)));
        }
        headers
    }

    /// 解析额外字段「代理状态」：managed 表示填写了 true/false 并需要同步
    /// 已有记录，desired 为期望的代理状态；留空时不管理，新建按 false。
    fn proxied_setting(&self) -> (bool, bool) {
        match self
            .creds
            .extra("proxied")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "true" => (true, true),
            "false" => (true, false),
            _ => (false, false),
        }
    }

    /// 发送请求并解包 `{success, errors, result}` 信封；非 2xx 时透出
    /// Cloudflare 的错误消息并按 HTTP 状态归类。
    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
    ) -> Result<Value, ProviderError> {
        let headers = self.auth_headers();
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let url = format!("{}{}", self.endpoint, path);
        let reply = match self.http.send(method, &url, &refs, body).await {
            Ok(reply) => reply,
            Err(fail @ HttpFail::Status { .. }) => {
                if let HttpFail::Status { status, body, .. } = &fail
                    && let Ok(env) = serde_json::from_slice::<CfEnvelope>(body)
                    && !env.success
                {
                    let msgs = env
                        .errors
                        .iter()
                        .map(|e| format!("{} {}", e.code, e.message))
                        .collect::<Vec<_>>()
                        .join("; ");
                    // 令牌只出现在请求头里，响应体不会回显，无需 redact。
                    let err =
                        ProviderError::new(META.name, kind_for_status(*status), msg::API_ERROR)
                            .with_detail(format!("Cloudflare: {msgs}"));
                    return Err(err);
                }
                return Err(ProviderError::from_http(META.name, fail));
            }
            Err(fail) => return Err(ProviderError::from_http(META.name, fail)),
        };
        let env: CfEnvelope = simple::json(META.name, &reply.body)?;
        if !env.success {
            let msgs = env
                .errors
                .iter()
                .map(|e| format!("{} {}", e.code, e.message))
                .collect::<Vec<_>>()
                .join("; ");
            let err =
                ProviderError::new(META.name, ProviderErrorKind::InvalidInput, msg::API_ERROR)
                    .with_detail(format!("Cloudflare: {msgs}"));
            return Err(err);
        }
        Ok(env.result.unwrap_or(Value::Null))
    }

    async fn zone_id(&self, zone: &str) -> Result<String, ProviderError> {
        let path = format!("/zones?name={}", simple::query_escape(zone));
        let result = self.call(Method::GET, &path, None).await?;
        let zones: Vec<CfZone> = serde_json::from_value(result)
            .map_err(|e| ProviderError::parse(META.name, format!("解析区域列表失败: {e}")))?;
        zones
            .iter()
            .find(|z| z.name.eq_ignore_ascii_case(zone))
            .map(|z| z.id.clone())
            .ok_or_else(|| {
                ProviderError::zone_not_found(
                    META.name,
                    format!("Cloudflare 账号下未找到域名 {zone}"),
                )
            })
    }

    async fn list_records(
        &self,
        zid: &str,
        typ: &str,
        name: &str,
    ) -> Result<Vec<CfRecord>, ProviderError> {
        let path = format!(
            "/zones/{zid}/dns_records?type={}&name={}",
            simple::query_escape(typ),
            simple::query_escape(name)
        );
        let result = self.call(Method::GET, &path, None).await?;
        serde_json::from_value(result)
            .map_err(|e| ProviderError::parse(META.name, format!("解析记录列表失败: {e}")))
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let zid = self.zone_id(&rec.zone).await?;
        let recs = self
            .list_records(&zid, rec.typ.as_str(), &rec.fqdn())
            .await?;
        if recs.is_empty() {
            let (_, desired) = self.proxied_setting();
            // 1 表示自动；开启代理时只能用自动。
            let mut ttl = rec.ttl;
            if ttl == 0 || desired {
                ttl = 1;
            }
            let body = CfRecord {
                id: String::new(),
                typ: rec.typ.as_str().to_owned(),
                name: rec.fqdn(),
                content: rec.value.clone(),
                ttl: i64::from(ttl),
                proxied: desired,
                comment: rec.remark.clone(),
            };
            let body = serde_json::to_value(body)
                .map_err(|e| ProviderError::parse(META.name, format!("序列化请求失败: {e}")))?;
            self.call(
                Method::POST,
                &format!("/zones/{zid}/dns_records"),
                Some(simple::json_body(&body)),
            )
            .await?;
            return Ok(UpsertAction::Created);
        }
        // 同名同类型的多条记录最终都解析到同一个目标值；Cloudflare 不允许
        // 同名同类型同值的重复记录（81058），所以只保留一条改成目标值：
        // 优先已经是目标值的那条，其余旧值记录删除。
        let mut recs = recs;
        let keep = recs
            .iter()
            .position(|x| x.content == rec.value)
            .unwrap_or(0);
        recs.swap(0, keep);
        let (managed, desired) = self.proxied_setting();
        let mut updated = false;
        for (i, cur) in recs.iter().enumerate() {
            if i > 0 {
                if cur.content == rec.value {
                    // 已是目标值的其他记录（理论上不会出现）不动。
                    continue;
                }
                self.call(
                    Method::DELETE,
                    &format!("/zones/{zid}/dns_records/{}", cur.id),
                    None,
                )
                .await?;
                updated = true;
                continue;
            }
            // 生效后的代理状态：配置了代理状态则以配置为准，否则沿用记录现状。
            let proxied = if managed { desired } else { cur.proxied };
            let mut ttl = rec.ttl;
            if ttl == 0 || proxied {
                ttl = 1;
            }
            let ttl_same = rec.ttl == 0 || proxied || cur.ttl == i64::from(ttl);
            let proxied_changed = managed && cur.proxied != desired;
            // 未配置 TTL 时只按记录值判断是否变化；代理记录读回的 TTL 恒为 1。
            if cur.content == rec.value
                && ttl_same
                && !proxied_changed
                && (rec.remark.is_empty() || cur.comment == rec.remark)
            {
                continue;
            }
            // PATCH 只改给出的字段，标签和未由本程序管理的备注保持不变。
            let mut upd = serde_json::Map::new();
            upd.insert("content".into(), json!(rec.value));
            upd.insert("ttl".into(), json!(ttl));
            if managed {
                upd.insert("proxied".into(), json!(desired));
            }
            if !rec.remark.is_empty() {
                upd.insert("comment".into(), json!(rec.remark));
            }
            self.call(
                Method::PATCH,
                &format!("/zones/{zid}/dns_records/{}", cur.id),
                Some(simple::json_body(&Value::Object(upd))),
            )
            .await?;
            updated = true;
        }
        Ok(if updated {
            UpsertAction::Updated
        } else {
            UpsertAction::Unchanged
        })
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let zid = self.zone_id(zone).await?;
        let body = CfRecord {
            id: String::new(),
            typ: "TXT".to_owned(),
            name: record::owner_fqdn(zone, sub),
            content: value.to_owned(),
            ttl: i64::from(TXT_TTL_CF),
            proxied: false,
            comment: String::new(),
        };
        let body = serde_json::to_value(body)
            .map_err(|e| ProviderError::parse(META.name, format!("序列化请求失败: {e}")))?;
        self.call(
            Method::POST,
            &format!("/zones/{zid}/dns_records"),
            Some(simple::json_body(&body)),
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
        let zid = self.zone_id(zone).await?;
        let recs = self
            .list_records(&zid, "TXT", &record::owner_fqdn(zone, sub))
            .await?;
        // 服务商返回的 TXT 值可能带引号。
        for r in &recs {
            if txt::unquote(&r.content) == value {
                self.call(
                    Method::DELETE,
                    &format!("/zones/{zid}/dns_records/{}", r.id),
                    None,
                )
                .await?;
                return Ok(());
            }
        }
        Ok(())
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let zid = self.zone_id(&rec.zone).await?;
        let recs = self
            .list_records(&zid, rec.typ.as_str(), &rec.fqdn())
            .await?;
        Ok(recs
            .into_iter()
            .map(|r| RemoteRecord {
                id: r.id,
                scope: zid.clone(),
                values: vec![r.content],
                ttl: u32::try_from(r.ttl.max(0)).unwrap_or(0),
            })
            .collect())
    }

    pub async fn remove_record(
        &self,
        _rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.call(
            Method::DELETE,
            &format!("/zones/{}/dns_records/{}", remote.scope, remote.id),
            None,
        )
        .await?;
        Ok(())
    }
}

#[derive(Deserialize)]
struct CfEnvelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    #[serde(default)]
    result: Option<Value>,
}

#[derive(Deserialize)]
struct CfError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Serialize, Deserialize)]
struct CfZone {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
}

#[derive(Serialize, Deserialize)]
struct CfRecord {
    #[serde(default, skip_serializing)]
    id: String,
    #[serde(rename = "type", default)]
    typ: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    ttl: i64,
    #[serde(default)]
    proxied: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    comment: String,
}

crate::impl_provider!(Cloudflare, META);
crate::impl_txt!(Cloudflare);
crate::impl_deleter!(Cloudflare);
