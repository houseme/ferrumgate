//! 腾讯云 DNSPod API 3.0（上游 tencentcloud.go）：签名算法 TC3-HMAC-SHA256，
//! 文档 cloud.tencent.com/document/api/1427/56193。
//!
//! 契约（端点 `https://dnspod.tencentcloudapi.com`，全部动作为 POST JSON，
//! 请求头 Content-Type: application/json; charset=utf-8、X-TC-Action、
//! X-TC-Version: 2021-03-23、X-TC-Timestamp、Authorization）：
//!
//! - 动作：`DescribeRecordList`（Domain/Subdomain/RecordType）、
//!   `CreateRecord`（Domain/SubDomain/RecordType/RecordLine/Value[/TTL][/Remark]）、
//!   `ModifyRecord`（同上 + RecordId）、`ModifyRecordRemark`（Domain/Remark/RecordId）、
//!   `DeleteRecord`（Domain/RecordId）。
//! - 无记录时 DescribeRecordList 返回业务错误 ResourceNotFound.NoDataOfRecord，
//!   视为空列表。
//! - 线路（LINE）：RecordLine，空线路对应「默认」。
//! - TTL：>0 时按值发送；未指定时新建不发送，更新发送 600。
//! - 备注（REMARK）：Create/Modify 都带 Remark；只改备注时调 ModifyRecordRemark。
//! - 记录过滤：接口可能按前缀模糊匹配，必须再按 Name（不区分大小写）、
//!   Type、Line 精确过滤，避免误改其他主机头。
//! - TXT：CreateRecord（RecordLine 默认、TTL 600）新增；DescribeRecordList
//!   后按值（去引号）DeleteRecord。
//! - 删除（DEL）：DescribeRecordList 过滤后 DeleteRecord 逐条。
//! - 业务错误：Response.Error → 按代码归类（AuthFailure.* 为认证失败，
//!   ResourceNotFound.* 为未找到，其余无效输入）。

use std::sync::Arc;

use hyper::Method;
use serde_json::{Value, json};

use crate::{
    Credentials, Meta, ProviderError, ProviderErrorKind, Record, RemoteRecord, UpsertAction, msg,
    sign, simple, txt,
};

pub static META: Meta = Meta::new("tencentcloud", "腾讯云 DNSPod (API 3.0)")
    .labels("SecretId", "SecretKey")
    .doc("https://console.cloud.tencent.com/cam/capi")
    .line()
    .remark()
    .acme()
    .delete();

pub struct TencentCloud {
    id: String,
    secret: String,
    http: Arc<crate::http::OutboundHttp>,
    endpoint: String,
}

impl TencentCloud {
    pub fn new(
        creds: Credentials,
        http: Arc<crate::http::OutboundHttp>,
    ) -> Result<Self, ProviderError> {
        Self::with_endpoint(creds, http, "https://dnspod.tencentcloudapi.com")
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

    fn now_unix() -> i64 {
        sign::now_unix()
    }

    fn line_of(rec: &Record) -> String {
        if rec.line.is_empty() {
            "默认".to_owned()
        } else {
            rec.line.clone()
        }
    }

    /// 发送一次 API 调用并解包 Response 信封；业务错误归类后返回。
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
        let ts = Self::now_unix();
        let auth = sign::tc3::authorization(
            &self.id,
            &self.secret,
            "dnspod",
            &host,
            action,
            &payload,
            ts,
        );
        let headers: Vec<(&'static str, String)> = vec![
            ("Content-Type", "application/json; charset=utf-8".to_owned()),
            ("X-TC-Action", action.to_owned()),
            ("X-TC-Version", "2021-03-23".to_owned()),
            ("X-TC-Timestamp", ts.to_string()),
            ("Authorization", auth),
        ];
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let reply = simple::send(
            &self.http,
            META.name,
            Method::POST,
            &self.endpoint,
            &refs,
            Some(payload),
        )
        .await?;
        let env: Value = simple::json(META.name, &reply.body)?;
        let response = env.get("Response").cloned().unwrap_or(Value::Null);
        if let Some(err) = response.get("Error")
            && err.get("Code").is_some()
        {
            let code = simple::value_str(&err["Code"]);
            let message = simple::value_str(&err["Message"]);
            return Err(Self::api_error(action, &code, &message));
        }
        Ok(response)
    }

    /// 业务错误按错误码归类：AuthFailure/UnauthorizedOperation 认证失败，
    /// ResourceNotFound 未找到，Throttling 限速，其余无效输入。
    fn api_error(action: &str, code: &str, message: &str) -> ProviderError {
        let (kind, key) = if code.starts_with("AuthFailure.")
            || code.starts_with("UnauthorizedOperation")
            || code.contains("SignatureFailure")
        {
            (ProviderErrorKind::Auth, msg::AUTH_FAILED)
        } else if code.starts_with("ResourceNotFound") {
            (ProviderErrorKind::NotFound, msg::NOT_FOUND)
        } else if code.starts_with("Throttling") || code.contains("RequestLimitExceeded") {
            (ProviderErrorKind::RateLimited, msg::RATE_LIMITED)
        } else {
            (ProviderErrorKind::InvalidInput, msg::API_ERROR)
        };
        ProviderError::new(META.name, kind, key)
            .with_detail(format!("腾讯云 {action}: {message} ({code})"))
    }

    fn record_of(v: &Value) -> Option<TcRecord> {
        let first = v.get("RecordList")?.as_array()?.first()?;
        Some(TcRecord {
            id: simple::value_str(&first["RecordId"]),
            name: simple::value_str(&first["Name"]),
            typ: simple::value_str(&first["Type"]),
            value: simple::value_str(&first["Value"]),
            line: simple::value_str(&first["Line"]),
            ttl: simple::value_str(&first["TTL"]).parse().unwrap_or(0),
            remark: simple::value_str(&first["Remark"]),
        })
    }

    /// 列出同名同类型记录（ResourceNotFound.NoDataOfRecord 视为空）。
    async fn describe(&self, rec: &Record) -> Result<Option<TcRecord>, ProviderError> {
        let params = json!({
            "Domain": rec.zone,
            "Subdomain": rec.rr(),
            "RecordType": rec.typ.as_str(),
        });
        match self.call("DescribeRecordList", params).await {
            Ok(v) => Ok(Self::record_of(&v)),
            Err(e) if e.kind == ProviderErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn upsert(&self, rec: &Record) -> Result<UpsertAction, ProviderError> {
        let cur = self.describe(rec).await?;
        let line = Self::line_of(rec);
        let mut params = json!({
            "Domain": rec.zone,
            "SubDomain": rec.rr(),
            "RecordType": rec.typ.as_str(),
            "RecordLine": line,
            "Value": rec.value,
        });
        if rec.ttl > 0 {
            params["TTL"] = json!(rec.ttl);
        }
        if !rec.remark.is_empty() {
            params["Remark"] = json!(rec.remark);
        }
        let Some(cur) = cur.filter(|r| {
            r.typ == rec.typ.as_str() && r.line == line && r.name.eq_ignore_ascii_case(rec.rr())
        }) else {
            self.call("CreateRecord", params).await?;
            return Ok(UpsertAction::Created);
        };
        let value_same = cur.value == rec.value && (rec.ttl == 0 || cur.ttl == rec.ttl);
        let remark_same = rec.remark.is_empty() || cur.remark == rec.remark;
        if value_same && remark_same {
            return Ok(UpsertAction::Unchanged);
        }
        let mut action = "ModifyRecord";
        if value_same {
            // 只有备注不同时调用专门的备注接口，不重复提交记录值。
            action = "ModifyRecordRemark";
            params = json!({"Domain": rec.zone, "Remark": rec.remark});
        } else if rec.ttl == 0 {
            // 未指定 TTL 时更新为默认的 600。
            params["TTL"] = json!(600);
        }
        params["RecordId"] = id_value(&cur.id);
        self.call(action, params).await?;
        Ok(UpsertAction::Updated)
    }

    pub async fn add_txt(&self, zone: &str, sub: &str, value: &str) -> Result<(), ProviderError> {
        self.call(
            "CreateRecord",
            json!({
                "Domain": zone,
                "SubDomain": sub,
                "RecordType": "TXT",
                "RecordLine": "默认",
                "Value": value,
                "TTL": txt::TXT_TTL,
            }),
        )
        .await
        .map(drop)
    }

    pub async fn delete_txt(
        &self,
        zone: &str,
        sub: &str,
        value: &str,
    ) -> Result<(), ProviderError> {
        let params = json!({"Domain": zone, "Subdomain": sub, "RecordType": "TXT"});
        let v = match self.call("DescribeRecordList", params).await {
            Ok(v) => v,
            Err(e) if e.kind == ProviderErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let list = v
            .get("RecordList")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for r in &list {
            if txt::unquote(&simple::value_str(&r["Value"])) == value {
                self.call(
                    "DeleteRecord",
                    json!({"Domain": zone, "RecordId": id_value(&simple::value_str(&r["RecordId"]))}),
                )
                .await?;
                return Ok(());
            }
        }
        Ok(())
    }

    pub async fn find_records(&self, rec: &Record) -> Result<Vec<RemoteRecord>, ProviderError> {
        let cur = self.describe(rec).await?;
        let Some(cur) = cur.filter(|r| {
            r.typ == rec.typ.as_str()
                && r.line == Self::line_of(rec)
                && r.name.eq_ignore_ascii_case(rec.rr())
        }) else {
            return Ok(Vec::new());
        };
        Ok(vec![RemoteRecord {
            id: cur.id,
            scope: rec.zone.clone(),
            values: vec![cur.value],
            ttl: cur.ttl,
        }])
    }

    pub async fn remove_record(
        &self,
        rec: &Record,
        remote: &RemoteRecord,
    ) -> Result<(), ProviderError> {
        self.call(
            "DeleteRecord",
            json!({"Domain": rec.zone, "RecordId": id_value(&remote.id)}),
        )
        .await
        .map(drop)
    }
}

/// 腾讯云的 RecordId 是数字；保持数字形态发送，非数字时按字符串。
fn id_value(id: &str) -> Value {
    match id.parse::<u64>() {
        Ok(n) => json!(n),
        Err(_) => json!(id),
    }
}

struct TcRecord {
    id: String,
    name: String,
    typ: String,
    value: String,
    line: String,
    ttl: u32,
    remark: String,
}

crate::impl_provider!(TencentCloud, META);
crate::impl_txt!(TencentCloud);
crate::impl_deleter!(TencentCloud);
