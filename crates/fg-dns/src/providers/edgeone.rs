//! 腾讯云 EdgeOne（TEO）DNS 记录管理（上游 edgeone.go）：API 3.0，签名
//! TC3-HMAC-SHA256（服务名 teo），文档 cloud.tencent.com/document/api/1552/80716。
//! 仅适用于以 NS 方式接入 EdgeOne 的站点。
//!
//! 契约（端点默认 `https://teo.tencentcloudapi.com`，extra `endpoint` 可覆盖；
//! 全部动作为 POST JSON，请求头与腾讯云 DNSPod 相同，X-TC-Version:
//! 2022-09-01）：
//!
//! - 站点定位：`DescribeZones`（Offset/Limit≤100/Filters[{Name:zone-name,
//!   Values:[name],Fuzzy:false}]），分页遍历后按名称不区分大小写匹配 ZoneId。
//! - 记录定位：`DescribeDnsRecords`（ZoneId/Offset/Limit≤1000/Filters[name,type]），
//!   名称过滤可能模糊，本地再按名称与类型精确过滤。
//! - 创建：`CreateDnsRecord`（ZoneId/Name/Type/Content/TTL[/Location]）；
//!   默认线路不传 Location（避免套餐不支持线路时报错）。
//! - 更新：`ModifyDnsRecords`（ZoneId/DnsRecords[{RecordId,Name,Type,Content,
//!   Location[,TTL]}]）；删除：`DeleteDnsRecords`（ZoneId/RecordIds[]）。
//! - 线路（LINE）：Location，空对应 Default；未指定线路时优先取已启用
//!   （Status=enable）的记录。
//! - TTL：限制在 60~86400；未指定时新建用 600，更新沿用记录现有值。
//! - TXT：CreateDnsRecord（TTL 600、默认线路）新增；DescribeDnsRecords 后
//!   按值（去引号）DeleteDnsRecords。
//! - 删除（DEL）：DescribeDnsRecords 过滤后按值挑选，DeleteDnsRecords 删除。
//! - 业务错误：Response.Error → AuthFailure.* 为认证失败，其余透出错误码。

use std::sync::Arc;

use hyper::Method;
use serde_json::{Value, json};

use crate::{
    Credentials, Field, Meta, ProviderError, ProviderErrorKind, Record, RemoteRecord, UpsertAction,
    msg, sign, simple, txt,
};

pub static FIELDS: [Field; 1] = [Field::new(
    "endpoint",
    "接口地址",
    "默认 https://teo.tencentcloudapi.com；国际站为 https://teo.intl.tencentcloudapi.com",
)];

pub static META: Meta = Meta::new("edgeone", "腾讯云 EdgeOne")
    .labels("SecretId", "SecretKey")
    .extra(&FIELDS)
    .doc("https://console.cloud.tencent.com/cam/capi")
    .line()
    .acme()
    .delete();

const VERSION: &str = "2022-09-01";
/// 新建记录未指定 TTL 时的默认值（接口允许 60~86400）。
const DEFAULT_TTL: u32 = 600;
const MIN_TTL: u32 = 60;
const MAX_TTL: u32 = 86_400;
/// DescribeZones / DescribeDnsRecords 单页上限与翻页上限。
const ZONE_PAGE: u32 = 100;
const RECORD_PAGE: u32 = 1000;
const MAX_PAGES: u32 = 50;

pub struct EdgeOne {
    id: String,
    secret: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

struct EoRecord {
    id: String,
    content: String,
    location: String,
    ttl: u32,
    status: String,
}

impl EdgeOne {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::build(creds, http, "https://teo.tencentcloudapi.com")
    }

    /// 端点可替换（本地假服务器测试，不校验 https，允许 http://127.0.0.1）。
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

    fn build(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, true, true)?;
        let endpoint = creds
            .extra("endpoint")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(endpoint);
        let endpoint = endpoint.trim_end_matches('/').to_owned();
        let host = endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or_default();
        if !endpoint.starts_with("https://") || host.is_empty() {
            return Err(ProviderError::invalid_input(
                META.name,
                "接口地址无效，需要 https:// 开头的完整地址",
            ));
        }
        Ok(Self {
            id: creds.id.trim().to_owned(),
            secret: creds.secret.trim().to_owned(),
            http,
            endpoint,
        })
    }

    async fn call(&self, action: &str, params: Value) -> Result<Value, ProviderError> {
        let payload = simple::json_body(&params);
        let host = self
            .endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or_default()
            .to_owned();
        let ts = sign::now_unix();
        let auth =
            sign::tc3::authorization(&self.id, &self.secret, "teo", &host, action, &payload, ts);
        let headers: Vec<(&'static str, String)> = vec![
            ("Content-Type", "application/json; charset=utf-8".to_owned()),
            ("X-TC-Action", action.to_owned()),
            ("X-TC-Version", VERSION.to_owned()),
            ("X-TC-Timestamp", ts.to_string()),
            ("Authorization", auth),
        ];
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let reply = match self
            .http
            .send(Method::POST, &self.endpoint, &refs, Some(payload))
            .await
        {
            Ok(reply) => reply,
            Err(fail) => return Err(ProviderError::from_http(META.name, fail)),
        };
        let env: Value = simple::json(META.name, &reply.body)?;
        let response = env.get("Response").cloned().unwrap_or(Value::Null);
        if let Some(err) = response.get("Error")
            && err.get("Code").is_some()
        {
            let code = simple::value_str(&err["Code"]);
            let message = simple::value_str(&err["Message"]);
            let (kind, key) =
                if code.starts_with("AuthFailure.") || code.starts_with("UnauthorizedOperation") {
                    (ProviderErrorKind::Auth, msg::AUTH_FAILED)
                } else {
                    (ProviderErrorKind::InvalidInput, msg::API_ERROR)
                };
            return Err(ProviderError::new(META.name, kind, key)
                .with_detail(format!("腾讯云 EdgeOne {action}: {message} ({code})")));
        }
        Ok(response)
    }

    /// 站点定位：分页遍历（服务端可能不按名称缩小范围），名称忽略大小写。
    async fn zone_id(&self, zone: &str) -> Result<String, ProviderError> {
        let name = zone.trim().trim_end_matches('.');
        let mut offset = 0u32;
        for _ in 0..MAX_PAGES {
            let params = json!({
                "Offset": offset,
                "Limit": ZONE_PAGE,
                "Filters": [{"Name": "zone-name", "Values": [name], "Fuzzy": false}],
            });
            let v = self.call("DescribeZones", params).await?;
            let zones = v
                .get("Zones")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let total = v.get("TotalCount").and_then(Value::as_i64).unwrap_or(0);
            for z in &zones {
                let zname = simple::value_str(&z["ZoneName"]);
                if zname.eq_ignore_ascii_case(name) {
                    return Ok(simple::value_str(&z["ZoneId"]));
                }
            }
            offset += zones.len() as u32;
            if zones.is_empty() || offset as i64 >= total {
                break;
            }
        }
        Err(ProviderError::zone_not_found(
            META.name,
            format!(
                "腾讯云 EdgeOne 账号下未找到站点 {zone}：该域名需以 NS 方式接入 EdgeOne 后才能管理解析记录"
            ),
        ))
    }

    /// 记录定位：名称过滤可能模糊，本地再按名称与类型精确过滤。
    async fn list_records(
        &self,
        zid: &str,
        fqdn: &str,
        typ: &str,
    ) -> Result<Vec<EoRecord>, ProviderError> {
        let name = fqdn.to_owned();
        let mut out = Vec::new();
        let mut offset = 0u32;
        for _ in 0..MAX_PAGES {
            let params = json!({
                "ZoneId": zid,
                "Offset": offset,
                "Limit": RECORD_PAGE,
                "Filters": [
                    {"Name": "name", "Values": [name], "Fuzzy": false},
                    {"Name": "type", "Values": [typ], "Fuzzy": false},
                ],
            });
            let v = self.call("DescribeDnsRecords", params).await?;
            let list = v
                .get("DnsRecords")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let total = v.get("TotalCount").and_then(Value::as_i64).unwrap_or(0);
            for r in &list {
                if simple::value_str(&r["Type"]) == typ
                    && simple::value_str(&r["Name"]).eq_ignore_ascii_case(&name)
                {
                    out.push(EoRecord {
                        id: simple::value_str(&r["RecordId"]),
                        content: simple::value_str(&r["Content"]),
                        location: simple::value_str(&r["Location"]),
                        ttl: simple::value_str(&r["TTL"]).parse().unwrap_or(0),
                        status: simple::value_str(&r["Status"]),
                    });
                }
            }
            offset += list.len() as u32;
            if list.is_empty() || offset as i64 >= total {
                break;
            }
        }
        Ok(out)
    }

    fn ttl_clamp(ttl: u32) -> u32 {
        if ttl == 0 {
            return 0;
        }
        ttl.clamp(MIN_TTL, MAX_TTL)
    }

    /// 新建一条记录。默认线路不传 Location，避免套餐不支持线路时报错。
    async fn create_record(
        &self,
        zid: &str,
        fqdn: &str,
        typ: &str,
        value: &str,
        line: &str,
        ttl: u32,
    ) -> Result<(), ProviderError> {
        let mut params = json!({
            "ZoneId": zid,
            "Name": fqdn,
            "Type": typ,
            "Content": value,
            "TTL": ttl,
        });
        if !line.is_empty() && !line.eq_ignore_ascii_case("Default") {
            params["Location"] = json!(line);
        }
        self.call("CreateDnsRecord", params).await.map(drop)
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let zid = self.zone_id(&rec.zone).await?;
        let recs = self
            .list_records(&zid, &rec.fqdn(), rec.typ.as_str())
            .await?;
        let ttl = Self::ttl_clamp(rec.ttl);
        // 线路一致（空线路对应 Default）时优先使用已启用的记录。
        let mut picked: Option<&EoRecord> = None;
        for r in &recs {
            if !crate::delete::line_match(&r.location, &rec.line, "Default") {
                continue;
            }
            if picked.is_none()
                || (picked.as_ref().is_some_and(|p| p.status != "enable") && r.status == "enable")
            {
                picked = Some(r);
            }
        }
        if let Some(cur) = picked {
            let same = crate::delete::same_value(rec.typ, &cur.content, &rec.value)
                && (ttl == 0 || cur.ttl == ttl);
            if same {
                return Ok(UpsertAction::Unchanged);
            }
            let mut item = json!({
                "RecordId": cur.id,
                "Name": rec.fqdn(),
                "Type": rec.typ.as_str(),
                "Content": rec.value,
                "Location": if cur.location.is_empty() { json!("Default") } else { json!(cur.location) },
            });
            let ttl = if ttl == 0 { cur.ttl } else { ttl };
            if ttl > 0 {
                item["TTL"] = json!(ttl);
            }
            self.call(
                "ModifyDnsRecords",
                json!({"ZoneId": zid, "DnsRecords": [item]}),
            )
            .await?;
            return Ok(UpsertAction::Updated);
        }
        let ttl = if ttl == 0 { DEFAULT_TTL } else { ttl };
        self.create_record(
            &zid,
            &rec.fqdn(),
            rec.typ.as_str(),
            &rec.value,
            &rec.line,
            ttl,
        )
        .await?;
        Ok(UpsertAction::Created)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let zid = self.zone_id(zone).await?;
        self.create_record(
            &zid,
            &crate::record::owner_fqdn(zone, sub),
            "TXT",
            value,
            "",
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
            .list_records(&zid, &crate::record::owner_fqdn(zone, sub), "TXT")
            .await?;
        for r in recs {
            if txt::unquote(&r.content) == value {
                return self.delete_records(&zid, &[r.id]).await;
            }
        }
        Ok(())
    }

    async fn delete_records(&self, zid: &str, ids: &[String]) -> Result<(), ProviderError> {
        self.call("DeleteDnsRecords", json!({"ZoneId": zid, "RecordIds": ids}))
            .await
            .map(drop)
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let zid = self.zone_id(&rec.zone).await?;
        let recs = self
            .list_records(&zid, &rec.fqdn(), rec.typ.as_str())
            .await?;
        Ok(recs
            .iter()
            .filter(|r| crate::delete::line_match(&r.location, &rec.line, "Default"))
            .map(|r| RemoteRecord {
                id: r.id.clone(),
                scope: zid.clone(),
                values: vec![r.content.clone()],
                ttl: r.ttl,
            })
            .collect())
    }

    pub async fn remove_record(
        &self,
        _rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.delete_records(&remote.scope, std::slice::from_ref(&remote.id))
            .await
    }
}

crate::impl_provider!(EdgeOne, META);
crate::impl_txt!(EdgeOne);
crate::impl_deleter!(EdgeOne);
