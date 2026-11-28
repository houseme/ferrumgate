//! Amazon Route 53（上游 route53.go）：SigV4 签名（服务 route53，区域固定
//! us-east-1），XML 请求与响应。ID 为 Access Key ID，Secret 为 Secret Access
//! Key；可选 extra `hostedZoneId` 指定托管区域，留空按域名查找。
//!
//! 契约（端点 `https://route53.amazonaws.com`，版本路径 /2013-04-01）：
//!
//! - 全部请求带 X-Amz-Date、X-Amz-Content-Sha256 与 Authorization（SigV4，
//!   签名头 host、x-amz-date、x-amz-content-sha256）；带请求体时
//!   Content-Type: text/xml。
//! - 区域定位：`GET /2013-04-01/hostedzonesbyname?dnsname={zone}.&maxitems=5`，
//!   响应 XML HostedZones>HostedZone 的 Id/Name（Name 带结尾点，Id 带
//!   /hostedzone/ 前缀，使用时剥掉）。
//! - 记录定位：`GET /2013-04-01/hostedzone/{zid}/rrset?name={fqdn}.&type={type}&maxitems=1`，
//!   响应 ResourceRecordSets>ResourceRecordSet（Name 带结尾点；通配符以
//!   `\052` 返回，比较时还原为 `*`）。
//! - 写入：`POST /2013-04-01/hostedzone/{zid}/rrset`，ChangeResourceRecordSets
//!   XML（Action UPSERT/DELETE + ResourceRecordSet），按记录集整体替换。
//! - TTL：>0 时按值发送；未指定时用 300。
//! - TXT（ACME）：值需带引号；add_txt 在现有记录集值后追加新值（UPSERT
//!   整个记录集，TTL 60）；delete_txt 按值（去引号）挑选，全部移除时用
//!   DELETE（必须与现有记录集完全一致），否则 UPSERT 保留值。
//! - 不实现 Deleter（上游注册表未标记删除能力）。

use std::sync::Arc;

use hyper::Method;

use crate::{
    Credentials, Meta, ProviderError, Record, UpsertAction, http::HttpFail, record, sign, txt,
};

pub static FIELDS: [crate::Field; 1] = [crate::Field::new(
    "hostedZoneId",
    "托管区域 ID",
    "可选，如 Z0123456789ABC；留空按域名自动查找",
)];

pub static META: Meta = Meta::new("route53", "Amazon Route 53")
    .labels("Access Key ID", "Secret Access Key")
    .extra(&FIELDS)
    .doc("https://console.aws.amazon.com/iam/home#/security_credentials")
    .acme();

const VERSION: &str = "/2013-04-01";

pub struct Route53 {
    ak: String,
    sk: String,
    zone_id: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

impl Route53 {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://route53.amazonaws.com")
    }

    /// 端点可替换（本地假服务器测试）。
    pub fn with_endpoint(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
        endpoint: &str,
    ) -> Result<Self, ProviderError> {
        crate::require_creds(&META, &creds, true, true)?;
        Ok(Self {
            ak: creds.id.trim().to_owned(),
            sk: creds.secret.trim().to_owned(),
            zone_id: creds
                .extra("hostedZoneId")
                .unwrap_or_default()
                .trim()
                .trim_start_matches("/hostedzone/")
                .to_owned(),
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
        })
    }

    /// 发送一次签名请求并解析 XML；非 2xx 时解析 Error>Code/Message。
    async fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: &str,
    ) -> Result<String, ProviderError> {
        let cq = sign::sigv4::canonical_query(query);
        let mut url = format!(
            "{}{}{}",
            self.endpoint,
            path,
            if cq.is_empty() { "" } else { "?" }
        );
        if !cq.is_empty() {
            url.push_str(&cq);
        }
        let host = self
            .endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or_default()
            .to_owned();
        let now = sign::now_unix();
        let amz_date = sign::amz_date(now);
        let payload_hash = sign::sha256_hex(body.as_bytes());
        let headers = [
            ("host", host.as_str()),
            ("x-amz-content-sha256", payload_hash.as_str()),
            ("x-amz-date", amz_date.as_str()),
        ];
        let auth = sign::sigv4::authorization(
            method.as_str(),
            path,
            &cq,
            &headers,
            body.as_bytes(),
            &self.ak,
            &self.sk,
            "us-east-1",
            "route53",
            &amz_date,
        );
        let mut head: Vec<(&'static str, String)> = vec![
            ("X-Amz-Date", amz_date),
            ("X-Amz-Content-Sha256", payload_hash),
            ("Authorization", auth),
        ];
        if !body.is_empty() {
            head.push(("Content-Type", "text/xml".to_owned()));
        }
        let refs: Vec<(&str, &str)> = head.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let sent = if body.is_empty() {
            None
        } else {
            Some(body.as_bytes().to_vec().into())
        };
        let reply = match self.http.send(method, &url, &refs, sent).await {
            Ok(reply) => reply,
            Err(fail) => return Err(ProviderError::from_http(META.name, r53_fail(fail))),
        };
        Ok(reply.text().into_owned())
    }

    /// 区域定位：extra 指定了 ID 时直接使用，否则按名称查找。
    async fn hosted_zone(&self, zone: &str) -> Result<String, ProviderError> {
        if !self.zone_id.is_empty() {
            return Ok(self.zone_id.clone());
        }
        let query = vec![
            ("dnsname".to_owned(), format!("{zone}.")),
            ("maxitems".to_owned(), "5".to_owned()),
        ];
        let body = self
            .call(
                Method::GET,
                &format!("{VERSION}/hostedzonesbyname"),
                &query,
                "",
            )
            .await?;
        for block in xml_blocks(&body, "HostedZone") {
            let name = xml_first(block, "Name").trim_end_matches('.').to_owned();
            if name.eq_ignore_ascii_case(zone) {
                return Ok(xml_first(block, "Id")
                    .trim_start_matches("/hostedzone/")
                    .to_owned());
            }
        }
        Err(ProviderError::zone_not_found(
            META.name,
            format!("Route 53 账号下未找到域名 {zone}"),
        ))
    }

    /// 读取同名同类型的记录集，不存在时返回 None。
    async fn get_set(
        &self,
        zid: &str,
        fqdn: &str,
        typ: &str,
    ) -> Result<Option<R53Set>, ProviderError> {
        let query = vec![
            ("name".to_owned(), format!("{fqdn}.")),
            ("type".to_owned(), typ.to_owned()),
            ("maxitems".to_owned(), "1".to_owned()),
        ];
        let body = self
            .call(
                Method::GET,
                &format!("{VERSION}/hostedzone/{zid}/rrset"),
                &query,
                "",
            )
            .await?;
        for block in xml_blocks(&body, "ResourceRecordSet") {
            let name = xml_first(block, "Name")
                .trim_end_matches('.')
                .replace("\\052", "*");
            if name.eq_ignore_ascii_case(fqdn) && xml_first(block, "Type") == typ {
                return Ok(Some(R53Set {
                    ttl: xml_first(block, "TTL").parse().unwrap_or(0),
                    values: xml_all(block, "ResourceRecords", "Value"),
                }));
            }
        }
        Ok(None)
    }

    /// 提交一次 UPSERT / DELETE。
    async fn change(
        &self,
        zid: &str,
        action: &str,
        fqdn: &str,
        typ: &str,
        ttl: u32,
        values: &[String],
    ) -> Result<(), ProviderError> {
        let mut b = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\">\
             <ChangeBatch><Changes><Change>",
        );
        b.push_str(&format!("<Action>{action}</Action><ResourceRecordSet>"));
        b.push_str(&format!(
            "<Name>{}</Name><Type>{typ}</Type>",
            xml_escape(&format!("{fqdn}."))
        ));
        b.push_str(&format!("<TTL>{ttl}</TTL><ResourceRecords>"));
        for v in values {
            b.push_str(&format!(
                "<ResourceRecord><Value>{}</Value></ResourceRecord>",
                xml_escape(v)
            ));
        }
        b.push_str("</ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>");
        self.call(
            Method::POST,
            &format!("{VERSION}/hostedzone/{zid}/rrset"),
            &[],
            &b,
        )
        .await
        .map(drop)
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let zid = self.hosted_zone(&rec.zone).await?;
        let fqdn = rec.fqdn();
        let cur = self.get_set(&zid, &fqdn, rec.typ.as_str()).await?;
        let ttl = if rec.ttl == 0 { 300 } else { rec.ttl };
        if let Some(cur) = &cur
            && cur.values.len() == 1
            && cur.values[0] == rec.value
            && (rec.ttl == 0 || cur.ttl == ttl)
        {
            return Ok(UpsertAction::Unchanged);
        }
        self.change(
            &zid,
            "UPSERT",
            &fqdn,
            rec.typ.as_str(),
            ttl,
            std::slice::from_ref(&rec.value),
        )
        .await?;
        Ok(if cur.is_none() {
            UpsertAction::Created
        } else {
            UpsertAction::Updated
        })
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        let zid = self.hosted_zone(zone).await?;
        let fqdn = record::owner_fqdn(zone, sub);
        let cur = self.get_set(&zid, &fqdn, "TXT").await?;
        // 保留已有的验证值，把新值追加在记录集末尾（与上游一致）。
        let mut vals = cur.map(|s| s.values).unwrap_or_default();
        vals.push(format!("\"{value}\""));
        self.change(&zid, "UPSERT", &fqdn, "TXT", 60, &vals).await
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        let zid = self.hosted_zone(zone).await?;
        let fqdn = record::owner_fqdn(zone, sub);
        let cur = self.get_set(&zid, &fqdn, "TXT").await?;
        let Some(cur) = cur else {
            return Ok(());
        };
        let keep: Vec<String> = cur
            .values
            .iter()
            .filter(|v| txt::unquote(v) != value)
            .cloned()
            .collect();
        if keep.len() == cur.values.len() {
            return Ok(());
        }
        if keep.is_empty() {
            // DELETE 必须与现有记录集完全一致。
            return self
                .change(&zid, "DELETE", &fqdn, "TXT", cur.ttl, &cur.values)
                .await;
        }
        self.change(&zid, "UPSERT", &fqdn, "TXT", cur.ttl, &keep)
            .await
    }
}

struct R53Set {
    ttl: u32,
    values: Vec<String>,
}

/// 传输层失败时把 XML 的 Error>Code/Message 透出为详情。
fn r53_fail(fail: HttpFail) -> HttpFail {
    if let HttpFail::Status {
        status,
        body,
        retry_after,
    } = &fail
    {
        let text = String::from_utf8_lossy(body);
        let code = xml_first(&text, "Code");
        if !code.is_empty() {
            let message = format!("Route 53: {code}: {}", xml_first(&text, "Message"));
            return HttpFail::Status {
                status: *status,
                body: message.into_bytes().into(),
                retry_after: *retry_after,
            };
        }
    }
    fail
}

// Route 53 的请求与响应都是小体积的规整 XML，这里用手写的标签定位，不引入
// XML 解析依赖。只处理无属性的标签与字符转义实体。

/// 找出第一个名为 `tag` 的无属性标签的内容（含子标签的原文）。
fn xml_first(body: &str, tag: &str) -> String {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let Some(start) = body.find(&open) else {
        return String::new();
    };
    let rest = &body[start + open.len()..];
    match rest.find(&close) {
        Some(end) => xml_unescape(&rest[..end]),
        None => String::new(),
    }
}

/// 迭代名为 `tag` 的无属性标签块（用于 ResourceRecordSet / HostedZone）。
fn xml_blocks<'a>(body: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(&close) else { break };
        out.push(&after[..end]);
        rest = &after[end + close.len()..];
    }
    out
}

/// 在 `block` 内部找 `wrapper` 标签，再取其中全部 `tag` 的内容。
fn xml_all(block: &str, wrapper: &str, tag: &str) -> Vec<String> {
    let open = format!("<{wrapper}>");
    let close = format!("</{wrapper}>");
    let Some(start) = block.find(&open) else {
        return Vec::new();
    };
    let rest = &block[start + open.len()..];
    let Some(end) = rest.find(&close) else {
        return Vec::new();
    };
    let inner = &rest[..end];
    let t_open = format!("<{tag}>");
    let t_close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = inner;
    while let Some(start) = rest.find(&t_open) {
        let after = &rest[start + t_open.len()..];
        let Some(end) = after.find(&t_close) else {
            break;
        };
        out.push(xml_unescape(&after[..end]));
        rest = &after[end + t_close.len()..];
    }
    out
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
    out
}

fn xml_unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#xA;", "\n")
        .replace("&#xD;", "\r")
        .replace("&#x9;", "\t")
        .replace("&amp;", "&")
}

crate::impl_provider!(Route53, META);
crate::impl_txt!(Route53);
