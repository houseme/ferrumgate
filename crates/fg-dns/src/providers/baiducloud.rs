//! 百度智能云 DNS（云解析 BCD）记录管理（上游 baiducloud.go）：认证方式
//! bce-auth-v1，文档 cloud.baidu.com/doc/BCD/s/4jwvymhs7。
//!
//! 契约（端点 `https://bcd.baidubce.com`，全部动作为 POST JSON，请求头
//! Content-Type: application/json; charset=utf-8 与 Authorization；时间戳
//! 写在认证字符串前缀中，不发送 x-bce-date 头，只签名 host）：
//!
//! - 动作：`/v1/domain/resolve/list`（domain/pageNum/pageNo/pageSize=1000，
//!   两套页码参数都发——部分环境用 pageNum、官方文档写作 pageNo）、
//!   `/v1/domain/resolve/add`（domain/rdType/ttl/rdata/zoneName）、
//!   `/v1/domain/resolve/edit`（recordId/domain/view/rdType/ttl/rdata/
//!   zoneName——只允许改 ttl、rdType、rdata，其余字段需与原记录一致）、
//!   `/v1/domain/resolve/delete`（zoneName/recordId）。成功时返回 200 且无
//!   响应体。
//! - 列表记录字段为小写驼峰：recordId/domain/view/rdtype/ttl/rdata；注意
//!   列表返回 rdtype，增改接口的请求字段为 rdType。
//! - TTL：限制在 60~3600 秒；未指定时新建用 300，更新沿用记录现有值。
//! - 线路：只处理默认线路（view 为空或 DEFAULT），避免误改运营商线路。
//! - TXT：add（TTL 600）新增；list 后按值（去引号）delete。
//! - 删除（DEL）：list 过滤后按值挑选，delete 逐条。
//! - 业务错误：响应体 {code, message}。
//!
//! BCE 签名用官方文档示例（BOS UploadPart）做金标准测试。

use std::sync::Arc;

use hyper::Method;
use serde_json::{Value, json};

use crate::{
    Credentials, Meta, ProviderError, Record, RemoteRecord, UpsertAction, http::HttpFail, sign,
    simple, txt,
};

pub static META: Meta = Meta::new("baiducloud", "百度智能云 DNS")
    .labels("AccessKey ID", "SecretAccessKey")
    .doc("https://console.bce.baidu.com/iam/#/iam/accesslist")
    .acme()
    .delete();

/// 解析 TTL 限制在 60~3600 秒；未指定时默认 300 秒。
const MIN_TTL: u32 = 60;
const MAX_TTL: u32 = 3600;
const DEFAULT_TTL: u32 = 300;
/// 列表接口 pageSize，取 1000，翻页以不足一页作为结束。
const PAGE_SIZE: u32 = 1000;
const MAX_PAGES: u32 = 100;
/// 认证字符串有效期（秒）。
const EXPIRE: i64 = 1800;

pub struct BaiduCloud {
    id: String,
    secret: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

struct BcRecord {
    record_id: i64,
    domain: String,
    view: String,
    rd_type: String,
    ttl: u32,
    rdata: String,
}

impl BaiduCloud {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://bcd.baidubce.com")
    }

    /// 端点可替换（本地假服务器测试）。
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

    /// POST JSON 调用；成功时增改删接口返回 200 且无响应体。
    async fn call(&self, path: &str, body: Value) -> Result<Value, ProviderError> {
        let payload = simple::json_body(&body);
        let host = self
            .endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or_default()
            .to_owned();
        let ts = sign::now_unix();
        let auth = bce_authorization(
            &self.id,
            &self.secret,
            Method::POST.as_str(),
            path,
            &[],
            &[("host", host.as_str())],
            "host",
            ts,
            EXPIRE,
        );
        let headers: Vec<(&'static str, String)> = vec![
            ("Content-Type", "application/json; charset=utf-8".to_owned()),
            ("Authorization", auth),
        ];
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let url = format!("{}{}", self.endpoint, path);
        let reply = match self
            .http
            .send(Method::POST, &url, &refs, Some(payload))
            .await
        {
            Ok(reply) => reply,
            Err(fail) => return Err(ProviderError::from_http(META.name, bc_fail(fail, path))),
        };
        if reply.body.is_empty() {
            return Ok(Value::Null);
        }
        simple::json(META.name, &reply.body)
    }

    /// 分页取出域名下全部解析记录；服务端若忽略页码会重复返回同一页，
    /// 遇到重复即停止。
    async fn list_records(&self, zone: &str) -> Result<Vec<BcRecord>, ProviderError> {
        let mut all = Vec::new();
        let mut prev_first: i64 = 0;
        for page in 1..=MAX_PAGES {
            let v = self
                .call(
                    "/v1/domain/resolve/list",
                    json!({
                        "domain": zone,
                        "pageNum": page,
                        "pageNo": page,
                        "pageSize": PAGE_SIZE,
                    }),
                )
                .await?;
            let list: Vec<BcRecord> = v
                .get("result")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .map(|r| BcRecord {
                            record_id: simple::value_str(&r["recordId"]).parse().unwrap_or(0),
                            domain: simple::value_str(&r["domain"]),
                            view: simple::value_str(&r["view"]),
                            rd_type: simple::value_str(&r["rdtype"]),
                            ttl: simple::value_str(&r["ttl"]).parse().unwrap_or(0),
                            rdata: simple::value_str(&r["rdata"]),
                        })
                        .collect()
                })
                .unwrap_or_default();
            if page > 1
                && let Some(first) = list.first()
                && first.record_id == prev_first
            {
                break;
            }
            let full = (list.len() as u32) < PAGE_SIZE;
            if let Some(first) = list.first() {
                prev_first = first.record_id;
            }
            all.extend(list);
            if full {
                break;
            }
        }
        Ok(all)
    }

    /// 找出主机记录与类型都相同、位于默认线路的记录。
    fn matched<'a>(recs: &'a [BcRecord], rec: &Record) -> Vec<&'a BcRecord> {
        recs.iter()
            .filter(|r| {
                r.domain.eq_ignore_ascii_case(rec.rr())
                    && r.rd_type.eq_ignore_ascii_case(rec.typ.as_str())
                    // 只处理默认线路，避免改动运营商线路等其他线路的记录。
                    && (r.view.is_empty() || r.view.eq_ignore_ascii_case("DEFAULT"))
            })
            .collect()
    }

    fn ttl_clamp(ttl: u32) -> u32 {
        if ttl == 0 {
            return 0;
        }
        ttl.clamp(MIN_TTL, MAX_TTL)
    }

    async fn add_record(
        &self,
        zone: &str,
        host: &str,
        typ: &str,
        value: &str,
        ttl: u32,
    ) -> Result<(), ProviderError> {
        self.call(
            "/v1/domain/resolve/add",
            json!({
                "domain": host,
                "rdType": typ,
                "ttl": ttl,
                "rdata": value,
                "zoneName": zone,
            }),
        )
        .await
        .map(drop)
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let recs = self.list_records(&rec.zone).await?;
        let ttl = Self::ttl_clamp(rec.ttl);
        if let Some(cur) = Self::matched(&recs, rec).first() {
            let same = crate::delete::same_value(rec.typ, &cur.rdata, &rec.value)
                && (ttl == 0 || cur.ttl == ttl);
            if same {
                return Ok(UpsertAction::Unchanged);
            }
            let ttl = if ttl == 0 { cur.ttl } else { ttl };
            // 编辑接口只允许改 ttl、rdType、rdata，其余字段需与原记录一致。
            self.call(
                "/v1/domain/resolve/edit",
                json!({
                    "recordId": cur.record_id,
                    "domain": cur.domain,
                    "view": cur.view,
                    "rdType": rec.typ.as_str(),
                    "ttl": ttl,
                    "rdata": rec.value,
                    "zoneName": rec.zone,
                }),
            )
            .await?;
            return Ok(UpsertAction::Updated);
        }
        let ttl = if ttl == 0 { DEFAULT_TTL } else { ttl };
        self.add_record(&rec.zone, rec.rr(), rec.typ.as_str(), &rec.value, ttl)
            .await?;
        Ok(UpsertAction::Created)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        self.add_record(
            zone,
            crate::record::owner_rr(sub),
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
        let recs = self.list_records(zone).await?;
        let probe = Record {
            zone: zone.to_owned(),
            sub: sub.to_owned(),
            typ: crate::RecordType::TXT,
            ..Record::default()
        };
        for cur in Self::matched(&recs, &probe) {
            if txt::unquote(&cur.rdata) == value {
                return self.delete_record(zone, cur.record_id).await;
            }
        }
        Ok(())
    }

    async fn delete_record(&self, zone: &str, id: i64) -> Result<(), ProviderError> {
        self.call(
            "/v1/domain/resolve/delete",
            json!({"zoneName": zone, "recordId": id}),
        )
        .await
        .map(drop)
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let recs = self.list_records(&rec.zone).await?;
        Ok(Self::matched(&recs, rec)
            .into_iter()
            .map(|r| RemoteRecord {
                id: r.record_id.to_string(),
                scope: String::new(),
                values: vec![r.rdata.clone()],
                ttl: r.ttl,
            })
            .collect())
    }

    pub async fn remove_record(
        &self,
        rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        let id: i64 = remote.id.parse().unwrap_or(0);
        self.delete_record(&rec.zone, id).await
    }
}

/// 传输层失败时把百度云业务错误 {code, message} 透出为详情。
fn bc_fail(fail: HttpFail, path: &str) -> HttpFail {
    if let HttpFail::Status {
        status,
        body,
        retry_after,
    } = &fail
        && let Ok(v) = serde_json::from_slice::<Value>(body)
        && let Some(code) = v.get("code").and_then(|c| c.as_str())
        && !code.is_empty()
    {
        let message = format!(
            "百度智能云 DNS {path}: {} ({code})",
            v.get("message")
                .and_then(|m| m.as_str())
                .unwrap_or_default()
        );
        return HttpFail::Status {
            status: *status,
            body: message.into_bytes().into(),
            retry_after: *retry_after,
        };
    }
    fail
}

/// BCE 规范编码：保留 A-Z a-z 0-9 - . _ ~，其余字节百分号编码（大写十六进制）；
/// `keep_slash` 为 true 时不编码 `/`，用于路径。
fn bce_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            b'/' if keep_slash => out.push('/'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// 生成 bce-auth-v1 认证字符串。`headers` 是参与签名的请求头（名称小写）；
/// `signed_headers` 写入认证字符串，为空表示只签名推荐头。
#[allow(clippy::too_many_arguments)] // 与 BCE 认证字符串的要素一一对应
fn bce_authorization(
    ak: &str,
    sk: &str,
    method: &str,
    path: &str,
    query: &[(String, String)],
    headers: &[(&str, &str)],
    signed_headers: &str,
    unix: i64,
    expire: i64,
) -> String {
    let prefix = format!("bce-auth-v1/{ak}/{}/{}", sign::iso_z(unix), expire);
    // 规范化查询串：忽略 authorization，键值编码后按字典序排序。
    let mut qs: Vec<String> = query
        .iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("authorization"))
        .map(|(k, v)| format!("{}={}", bce_encode(k, false), bce_encode(v, false)))
        .collect();
    qs.sort_unstable();
    // 规范化请求头：名称转小写、值去首尾空白，空值忽略，整串排序。
    let mut hs: Vec<String> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{}:{}", bce_encode(&k, false), bce_encode(&v, false)))
        .collect();
    hs.sort_unstable();
    let path = if path.is_empty() { "/" } else { path };
    let canonical = format!(
        "{method}\n{}\n{}\n{}",
        bce_encode(path, true),
        qs.join("&"),
        hs.join("\n")
    );
    let signing_key = sign::hmac_sha256(sk.as_bytes(), prefix.as_bytes());
    let hex_key = hex::encode(&signing_key);
    let signature = hex::encode(sign::hmac_sha256(hex_key.as_bytes(), canonical.as_bytes()));
    format!("{prefix}/{signed_headers}/{signature}")
}

crate::impl_provider!(BaiduCloud, META);
crate::impl_txt!(BaiduCloud);
crate::impl_deleter!(BaiduCloud);

#[cfg(test)]
mod tests {
    use super::*;

    /// 官方文档中的签名示例（BOS UploadPart，上游 TestBceAuthorizationDocExample
    /// 使用同一向量）：签名头列表为空表示只签名推荐头。
    #[test]
    fn bce_authorization_matches_official_doc_example() {
        let got = bce_authorization(
            &"a".repeat(32),
            &"b".repeat(32),
            "PUT",
            "/v1/test/myfolder/readme.txt",
            &[
                ("partNumber".to_owned(), "9".to_owned()),
                (
                    "uploadId".to_owned(),
                    "a44cc9bab11cbd156984767aad637851".to_owned(),
                ),
            ],
            &[
                ("Host", "bj.bcebos.com"),
                ("Content-Length", "8"),
                ("Content-MD5", "NFzcPqhviddjRNnSOGo4rw=="),
                ("Content-Type", "text/plain"),
                ("x-bce-date", "2015-04-27T08:23:49Z"),
            ],
            "",
            1_430_123_029, // 2015-04-27T08:23:49Z
            1800,
        );
        assert_eq!(
            got,
            format!(
                "bce-auth-v1/{}/2015-04-27T08:23:49Z/1800//{}",
                "a".repeat(32),
                "d74a04362e6a848f5b39b15421cb449427f419c95a480fd6b8cf9fc783e2999e"
            )
        );
    }

    #[test]
    fn bce_encode_percent_encodes_everything_unreserved() {
        assert_eq!(
            bce_encode("NFzcPqhviddjRNnSOGo4rw==", false),
            "NFzcPqhviddjRNnSOGo4rw%3D%3D"
        );
        assert_eq!(bce_encode("text/plain", false), "text%2Fplain");
        assert_eq!(bce_encode("a/b~c", true), "a/b~c");
    }

    #[test]
    fn baidu_cloud_ttl_clamped_to_supported_range() {
        assert_eq!(BaiduCloud::ttl_clamp(0), 0);
        assert_eq!(BaiduCloud::ttl_clamp(5), MIN_TTL);
        assert_eq!(BaiduCloud::ttl_clamp(600), 600);
        assert_eq!(BaiduCloud::ttl_clamp(100_000), MAX_TTL);
    }
}
