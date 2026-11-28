//! 阿里云 ESA（边缘安全加速）DNS 记录管理（上游 aliesa.go）：RPC 风格接口
//! 2024-09-10，签名 HMAC-SHA1（Signature Version 1.0），文档
//! help.aliyun.com/zh/edge-security-acceleration/esa/api-esa-2024-09-10-listrecords。
//!
//! 契约（端点默认 `https://esa.cn-hangzhou.aliyuncs.com`，extra `endpoint`
//! 可覆盖；参数全部在查询串里，读取动作用 GET、写入动作用 POST，签名串的
//! 方法随之变化）：
//!
//! - ESA 把同名的 A 与 AAAA 合并为一条类型为 `A/AAAA` 的记录，Data.Value
//!   是逗号分隔的多个 IP（IPv4 在前）；只替换本次同步的地址族，保留另一族。
//! - 站点定位：`ListSites`（SiteName/PageNumber/PageSize≤500）分页后按名称
//!   不区分大小写匹配 SiteId；CNAME 接入的站点创建地址记录需带
//!   Proxied=true、BizName=web。
//! - 记录定位：`ListRecords`（SiteId/RecordName/Type/PageNumber/PageSize≤500）。
//! - 写入：`CreateRecord`（SiteId/RecordName/Type/Data(JSON)/Ttl）、
//!   `UpdateRecord`（RecordId/Type/Data/Ttl）、`DeleteRecord`（RecordId）。
//! - TTL：限制在 30~86400，1 视为自动（未指定）；未指定时新建用 600，
//!   更新沿用记录现有值。
//! - TXT：CreateRecord（TTL 600）新增；ListRecords 后按值（去引号）
//!   DeleteRecord。
//! - 删除（DEL）：同名 A/AAAA 共用一条记录时，只去掉本记录的地址、其余值
//!   写回；全部移除后才删除整条记录。
//! - 业务错误：响应体 {Code, Message}。

use std::sync::Arc;

use hyper::Method;
use serde_json::{Value, json};

use crate::{
    Credentials, Field, Meta, ProviderError, Record, RemoteRecord, UpsertAction, http::HttpFail,
    sign, simple, txt,
};

pub static FIELDS: [Field; 1] = [Field::new(
    "endpoint",
    "接口地址",
    "默认 https://esa.cn-hangzhou.aliyuncs.com；国际站为 https://esa.ap-southeast-1.aliyuncs.com",
)];

pub static META: Meta = Meta::new("aliesa", "阿里云 ESA（边缘安全加速）")
    .labels("AccessKey ID", "AccessKey Secret")
    .extra(&FIELDS)
    .doc("https://ram.console.aliyun.com/manage/ak")
    .acme()
    .delete();

const VERSION: &str = "2024-09-10";
/// ESA 中 A 与 AAAA 合并后的记录类型。
const ADDR_TYPE: &str = "A/AAAA";
/// 新建记录未指定 TTL 时的默认值；接口允许 30~86400，1 表示自动。
const DEFAULT_TTL: u32 = 600;
const MIN_TTL: u32 = 30;
const MAX_TTL: u32 = 86_400;
/// ListSites / ListRecords 单页最大 500 条。
const PAGE_SIZE: u32 = 500;
const MAX_PAGES: u32 = 50;

pub struct AliEsa {
    id: String,
    secret: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

struct EsaSite {
    site_id: i64,
    access_type: String,
}

struct EsaRecord {
    record_id: i64,
    ttl: u32,
    data_value: String,
}

impl AliEsa {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::build(creds, http, "https://esa.cn-hangzhou.aliyuncs.com")
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
            .unwrap_or(endpoint)
            .trim_end_matches('/')
            .to_owned();
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

    /// 发送一次接口调用，参数全部放在查询串中（读取 GET、写入 POST）。
    async fn call(
        &self,
        method: Method,
        action: &str,
        params: &[(String, String)],
    ) -> Result<Value, ProviderError> {
        let mut all = vec![
            ("Format".to_owned(), "JSON".to_owned()),
            ("Version".to_owned(), VERSION.to_owned()),
            ("AccessKeyId".to_owned(), self.id.clone()),
            ("SignatureMethod".to_owned(), "HMAC-SHA1".to_owned()),
            ("SignatureVersion".to_owned(), "1.0".to_owned()),
            ("SignatureNonce".to_owned(), sign::nonce_hex()),
            ("Timestamp".to_owned(), sign::iso_z(sign::now_unix())),
            ("Action".to_owned(), action.to_owned()),
        ];
        all.extend(params.iter().cloned());
        let query = sign::aliyun::signed_query(method.as_str(), &all, &self.secret);
        let url = format!("{}/?{query}", self.endpoint);
        let reply = match self.http.send(method, &url, &[], None).await {
            Ok(reply) => reply,
            Err(fail) => {
                return Err(ProviderError::from_http(META.name, esa_fail(fail, action)));
            }
        };
        simple::json(META.name, &reply.body)
    }

    /// 站点定位：分页遍历后按名称不区分大小写匹配。
    async fn site(&self, zone: &str) -> Result<EsaSite, ProviderError> {
        let name = zone.trim().trim_end_matches('.');
        for page in 1..=MAX_PAGES {
            let params = vec![
                ("SiteName".to_owned(), name.to_owned()),
                ("PageNumber".to_owned(), page.to_string()),
                ("PageSize".to_owned(), PAGE_SIZE.to_string()),
            ];
            let v = self.call(Method::GET, "ListSites", &params).await?;
            let sites = v
                .get("Sites")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for s in &sites {
                if simple::value_str(&s["SiteName"]).eq_ignore_ascii_case(name) {
                    return Ok(EsaSite {
                        site_id: simple::value_str(&s["SiteId"]).parse().unwrap_or(0),
                        access_type: simple::value_str(&s["AccessType"]),
                    });
                }
            }
            let total = v.get("TotalCount").and_then(Value::as_i64).unwrap_or(0);
            if (sites.len() as u32) < PAGE_SIZE || page as i64 * PAGE_SIZE as i64 >= total {
                break;
            }
        }
        Err(ProviderError::zone_not_found(
            META.name,
            format!("阿里云 ESA 账号下未找到站点 {zone}"),
        ))
    }

    /// 记录定位：请求参数为 SiteId/RecordName/Type，名称在本地再精确比对。
    async fn list_records(
        &self,
        site_id: i64,
        fqdn: &str,
        typ: &str,
    ) -> Result<Vec<EsaRecord>, ProviderError> {
        let mut out = Vec::new();
        for page in 1..=MAX_PAGES {
            let params = vec![
                ("SiteId".to_owned(), site_id.to_string()),
                ("RecordName".to_owned(), fqdn.to_owned()),
                ("Type".to_owned(), typ.to_owned()),
                ("PageNumber".to_owned(), page.to_string()),
                ("PageSize".to_owned(), PAGE_SIZE.to_string()),
            ];
            let v = self.call(Method::GET, "ListRecords", &params).await?;
            let list = v
                .get("Records")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for r in &list {
                let rtype = simple::value_str(&r["RecordType"]);
                // 请求已按 Type 过滤；响应带有类型且明显不符时才丢弃，类型缺失视为匹配。
                let type_ok = rtype.is_empty()
                    || rtype == typ
                    || (typ == ADDR_TYPE && (rtype == "A" || rtype == "AAAA"));
                if !simple::value_str(&r["RecordName"]).eq_ignore_ascii_case(fqdn) || !type_ok {
                    continue;
                }
                out.push(EsaRecord {
                    record_id: simple::value_str(&r["RecordId"]).parse().unwrap_or(0),
                    ttl: simple::value_str(&r["Ttl"]).parse().unwrap_or(0),
                    data_value: simple::value_str(&r["Data"]["Value"]),
                });
            }
            let total = v.get("TotalCount").and_then(Value::as_i64).unwrap_or(0);
            if (list.len() as u32) < PAGE_SIZE || page as i64 * PAGE_SIZE as i64 >= total {
                break;
            }
        }
        Ok(out)
    }

    /// ESA 使用的记录类型：A 与 AAAA 合并为 A/AAAA。
    fn esa_type(typ: crate::RecordType) -> String {
        match typ {
            crate::RecordType::A | crate::RecordType::AAAA => ADDR_TYPE.to_owned(),
            other => other.as_str().to_owned(),
        }
    }

    /// TTL 限制在接口允许的范围内；0 表示未指定，1 视为自动。
    fn esa_ttl(ttl: u32) -> u32 {
        if ttl <= 1 {
            return 0;
        }
        ttl.clamp(MIN_TTL, MAX_TTL)
    }

    /// Data 参数：JSON 的 {"Value": ...}。
    fn data_param(value: &str) -> String {
        json!({"Value": value}).to_string()
    }

    async fn create_record(
        &self,
        site: &EsaSite,
        fqdn: &str,
        typ: &str,
        value: &str,
        ttl: u32,
    ) -> Result<(), ProviderError> {
        let mut params = vec![
            ("SiteId".to_owned(), site.site_id.to_string()),
            ("RecordName".to_owned(), fqdn.to_owned()),
            ("Type".to_owned(), typ.to_owned()),
            ("Data".to_owned(), Self::data_param(value)),
            ("Ttl".to_owned(), ttl.to_string()),
        ];
        // CNAME 接入的站点只能创建开启代理加速的地址记录。
        if typ == ADDR_TYPE && site.access_type.eq_ignore_ascii_case("CNAME") {
            params.push(("Proxied".to_owned(), "true".to_owned()));
            params.push(("BizName".to_owned(), "web".to_owned()));
        }
        self.call(Method::POST, "CreateRecord", &params)
            .await
            .map(drop)
    }

    async fn update_record(
        &self,
        id: i64,
        typ: &str,
        value: &str,
        ttl: u32,
    ) -> Result<(), ProviderError> {
        self.call(
            Method::POST,
            "UpdateRecord",
            &[
                ("RecordId".to_owned(), id.to_string()),
                ("Type".to_owned(), typ.to_owned()),
                ("Data".to_owned(), Self::data_param(value)),
                ("Ttl".to_owned(), ttl.to_string()),
            ],
        )
        .await
        .map(drop)
    }

    async fn delete_record(&self, id: i64) -> Result<(), ProviderError> {
        self.call(
            Method::POST,
            "DeleteRecord",
            &[("RecordId".to_owned(), id.to_string())],
        )
        .await
        .map(drop)
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let site = self.site(&rec.zone).await?;
        let typ = Self::esa_type(rec.typ);
        let recs = self.list_records(site.site_id, &rec.fqdn(), &typ).await?;
        let mut ttl = Self::esa_ttl(rec.ttl);
        let Some(first) = recs.first() else {
            if ttl == 0 {
                ttl = DEFAULT_TTL;
            }
            self.create_record(&site, &rec.fqdn(), &typ, &rec.value, ttl)
                .await?;
            return Ok(UpsertAction::Created);
        };
        let mut value = rec.value.clone();
        let same;
        if typ == ADDR_TYPE {
            // 同名 A 与 AAAA 共用一条记录：只替换本次同步的地址族，保留另一族。
            let want_v6 = rec.typ == crate::RecordType::AAAA;
            let mut keep = Vec::new();
            let mut cur = Vec::new();
            for v in split_values(&first.data_value) {
                if is_v6(&v) == want_v6 {
                    cur.push(v);
                } else {
                    keep.push(v);
                }
            }
            same = cur.len() == 1 && same_ip(&cur[0], &rec.value);
            keep.push(rec.value.clone());
            value = join_values(&keep);
        } else {
            same = crate::delete::same_value(rec.typ, &first.data_value, &rec.value);
        }
        if same && (ttl == 0 || first.ttl == ttl) {
            return Ok(UpsertAction::Unchanged);
        }
        let ttl = if ttl == 0 {
            if first.ttl > 0 {
                first.ttl
            } else {
                DEFAULT_TTL
            }
        } else {
            ttl
        };
        self.update_record(first.record_id, &typ, &value, ttl)
            .await?;
        Ok(UpsertAction::Updated)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let site = self.site(zone).await?;
        self.create_record(
            &site,
            &crate::record::owner_fqdn(zone, sub),
            "TXT",
            value,
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
        let site = self.site(zone).await?;
        let recs = self
            .list_records(site.site_id, &crate::record::owner_fqdn(zone, sub), "TXT")
            .await?;
        for r in recs {
            if txt::unquote(&r.data_value) == value {
                return self.delete_record(r.record_id).await;
            }
        }
        Ok(())
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let site = self.site(&rec.zone).await?;
        let typ = Self::esa_type(rec.typ);
        let recs = self.list_records(site.site_id, &rec.fqdn(), &typ).await?;
        let mut out = Vec::new();
        for r in recs {
            let mut vals = split_values(&r.data_value);
            if typ == ADDR_TYPE {
                // 只取与本记录同地址族的值，另一族的值不属于这条动态域名。
                let want_v6 = rec.typ == crate::RecordType::AAAA;
                vals.retain(|v| is_v6(v) == want_v6);
            } else {
                vals = vec![r.data_value.clone()];
            }
            if vals.is_empty() {
                continue;
            }
            out.push(RemoteRecord {
                id: r.record_id.to_string(),
                scope: site.site_id.to_string(),
                values: vals,
                ttl: r.ttl,
            });
        }
        Ok(out)
    }

    pub async fn remove_record(
        &self,
        rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        let id: i64 = remote.id.parse().unwrap_or(0);
        if Self::esa_type(rec.typ) != ADDR_TYPE {
            return self.delete_record(id).await;
        }
        // 同名记录还保留另一地址族的值时，只去掉本记录的地址，其余值写回；
        // 全部移除后才删除整条记录。
        let site_id: i64 = remote.scope.parse().unwrap_or(0);
        let recs = self.list_records(site_id, &rec.fqdn(), ADDR_TYPE).await?;
        for cur in recs {
            if cur.record_id != id {
                continue;
            }
            let want_v6 = rec.typ == crate::RecordType::AAAA;
            let mut remain = Vec::new();
            for v in split_values(&cur.data_value) {
                if is_v6(&v) == want_v6 && same_ip(&v, &rec.value) {
                    continue;
                }
                remain.push(v);
            }
            if remain.is_empty() {
                return self.delete_record(id).await;
            }
            let ttl = if cur.ttl > 0 { cur.ttl } else { DEFAULT_TTL };
            return self
                .update_record(id, ADDR_TYPE, &join_values(&remain), ttl)
                .await;
        }
        Ok(())
    }
}

/// 拆分逗号分隔的记录值。
fn split_values(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect()
}

/// IPv6 地址含冒号。
fn is_v6(v: &str) -> bool {
    v.contains(':')
}

/// 比较两个 IP，IPv6 先规范化写法再比较。
fn same_ip(a: &str, b: &str) -> bool {
    match (
        a.trim().parse::<std::net::IpAddr>(),
        b.trim().parse::<std::net::IpAddr>(),
    ) {
        (Ok(pa), Ok(pb)) => pa == pb,
        _ => a.trim().eq_ignore_ascii_case(b.trim()),
    }
}

/// 把 IPv4 与 IPv6 值合并成接口需要的逗号分隔字符串，IPv4 在前。
fn join_values(vals: &[String]) -> String {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for v in vals {
        if is_v6(v) {
            v6.push(v.clone());
        } else {
            v4.push(v.clone());
        }
    }
    v4.extend(v6);
    v4.join(",")
}

/// 传输层失败时把 ESA 业务错误码（{Code, Message}）透出为详情。
fn esa_fail(fail: HttpFail, action: &str) -> HttpFail {
    if let HttpFail::Status {
        status,
        body,
        retry_after,
    } = &fail
        && let Ok(v) = serde_json::from_slice::<Value>(body)
        && v.get("Code").map(|c| !c.is_null()).unwrap_or(false)
    {
        let message = format!(
            "阿里云 ESA {action}: {} ({})",
            simple::value_str(&v["Message"]),
            simple::value_str(&v["Code"])
        );
        return HttpFail::Status {
            status: *status,
            body: message.into_bytes().into(),
            retry_after: *retry_after,
        };
    }
    fail
}

crate::impl_provider!(AliEsa, META);
crate::impl_txt!(AliEsa);
crate::impl_deleter!(AliEsa);
