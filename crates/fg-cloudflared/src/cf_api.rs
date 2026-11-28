//! Cloudflare API client (WP-46 §3.2): read / write the remote tunnel
//! config (with the read version for concurrent-modification detection) and
//! query / create DNS records. The outbound HTTP channel is injected
//! (conventions §3.4) — production wires `fg_net::http::OutboundHttp`,
//! tests wire a local fake server — so this crate performs no networking of
//! its own.

use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::model::limits;
use crate::token::TokenInfo;

/// An outbound request the client wants to send. `auth` is the bearer
/// token for the `Authorization` header (the injected channel adds it;
/// production wires `fg_net::http::OutboundHttp`).
#[derive(Clone, Debug)]
pub struct FetchRequest {
    pub method: &'static str,
    pub url: Url,
    /// `Bearer <token>`.
    pub auth: String,
    pub body: Option<Vec<u8>>,
}

/// The outbound response. The injected channel enforces
/// [`limits::CF_RESPONSE_MAX_BYTES`].
#[derive(Clone, Debug)]
pub struct FetchResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The injected outbound HTTP channel (conventions §3.4 `SharedFn`).
pub type FetchFn =
    Arc<dyn Fn(FetchRequest) -> BoxFut<'static, Result<FetchResponse>> + Send + Sync>;

pub type BoxFut<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// The placeholder channel used before the assembler wires `Deps.cf_http`:
/// every call fails with a network error naming the missing dependency.
pub fn unconfigured_fetch() -> FetchFn {
    Arc::new(
        |_: FetchRequest| -> BoxFut<'static, Result<FetchResponse>> {
            Box::pin(async {
                Err(anyhow::anyhow!(
                    "Cloudflare API 出站通道未配置（缺少 Deps.cf_http）"
                ))
            })
        },
    )
}

/// API failure. `Api` carries the first error code plus every
/// `code message` pair joined with `; ` (upstream formatting); `Status` is
/// a non-Cloudflare-envelope HTTP failure; `Network` is transport / timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfError {
    Network(String),
    Status(u16),
    Api { code: i64, message: String },
}

impl CfError {
    fn from_errors(status: u16, errors: Vec<(i64, String)>) -> Self {
        match errors.first() {
            Some((code, _)) => {
                let message = errors
                    .iter()
                    .map(|(code, message)| format!("{code} {message}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                Self::Api {
                    code: *code,
                    message,
                }
            }
            None => Self::Status(status),
        }
    }
}

impl std::fmt::Display for CfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(message) => write!(f, "访问 Cloudflare API 失败: {message}"),
            Self::Status(status) => write!(f, "Cloudflare API 返回 HTTP {status}"),
            Self::Api { message, .. } => write!(f, "Cloudflare: {message}"),
        }
    }
}

impl std::error::Error for CfError {}

/// The tunnel remote configuration (upstream `remoteConfig`). `config` is
/// kept as a raw object so write-backs only replace `ingress` and preserve
/// `warp-routing`, the top-level `originRequest` and everything else.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RemoteConfig {
    #[serde(default)]
    pub tunnel_id: String,
    pub version: u64,
    /// `cloudflare` when the rules are managed remotely; `local` when the
    /// tunnel runs from a local config file (the UI must warn).
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub config: serde_json::Value,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            tunnel_id: String::new(),
            version: 0,
            source: String::new(),
            config: serde_json::json!({}),
        }
    }
}

/// One DNS record (a subset of the Cloudflare fields).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsRecord {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub content: String,
    pub ttl: i64,
    pub proxied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl DnsRecord {
    /// `<type> <content>` for conflict reports.
    pub fn describe(&self) -> String {
        format!("{} {}", self.kind, self.content)
    }
}

/// A hostname's DNS sync outcome (upstream `DNSResult`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsResult {
    pub hostname: String,
    /// `created` | `unchanged` | `conflict` | `failed`.
    pub status: DnsStatus,
    /// The conflicting record (`<type> <content>`), conflicts only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing: Option<String>,
    /// The failure reason, failures only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// DNS sync outcomes (upstream constants).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsStatus {
    Created,
    Unchanged,
    Conflict,
    Failed,
}

/// The Cloudflare API client. Build one per request batch from the owning
/// tunnel's API token; the account / tunnel IDs come from the tunnel token
/// ([`crate::token::parse_token`]).
#[derive(Clone)]
pub struct CfClient {
    /// API endpoint; the default is [`limits::CF_ENDPOINT`] (tests point it
    /// at a local fake server).
    pub endpoint: String,
    pub api_token: String,
    pub http: FetchFn,
}

impl CfClient {
    pub fn new(endpoint: impl Into<String>, api_token: impl Into<String>, http: FetchFn) -> Self {
        Self {
            endpoint: endpoint.into(),
            api_token: api_token.into(),
            http,
        }
    }

    /// The remote config path for a tunnel (upstream `configPath`).
    fn config_url(&self, account: &str, tunnel: &str) -> Result<Url> {
        let mut url = Url::parse(&self.endpoint)?;
        {
            let mut segments = url.path_segments_mut().map_err(|_| {
                anyhow::anyhow!("Cloudflare API 地址不能包含路径段：{}", self.endpoint)
            })?;
            segments.push("accounts").push(account);
            segments.push("cfd_tunnel").push(tunnel);
            segments.push("configurations");
        }
        Ok(url)
    }

    /// One API call: request → envelope → result payload.
    async fn call<Value: serde::de::DeserializeOwned>(
        &self,
        method: &'static str,
        url: Url,
        body: Option<&impl Serialize>,
    ) -> Result<Value, CfError> {
        let body = body
            .map(|value| serde_json::to_vec(value))
            .transpose()
            .map_err(|error| CfError::Network(error.to_string()))?;
        let request = FetchRequest {
            method,
            url,
            auth: format!("Bearer {}", self.api_token),
            body,
        };
        let send = self.http.clone();
        let response = tokio::time::timeout(limits::CF_REQUEST_TIMEOUT, send(request))
            .await
            .map_err(|_| {
                CfError::Network(format!("超过 {} 秒", limits::CF_REQUEST_TIMEOUT.as_secs()))
            })?
            .map_err(|error| CfError::Network(error.to_string()))?;
        #[derive(Deserialize)]
        struct Envelope {
            #[serde(default)]
            success: bool,
            #[serde(default)]
            errors: Vec<CfApiError>,
            #[serde(default)]
            result: Option<serde_json::Value>,
        }
        #[derive(Deserialize)]
        struct CfApiError {
            #[serde(default)]
            code: i64,
            #[serde(default)]
            message: String,
        }
        let envelope: Envelope =
            serde_json::from_slice(&response.body).map_err(|_| CfError::Status(response.status))?;
        if !envelope.success {
            let errors = envelope
                .errors
                .into_iter()
                .map(|error| (error.code, error.message))
                .collect();
            return Err(CfError::from_errors(response.status, errors));
        }
        let result = envelope.result.unwrap_or(serde_json::Value::Null);
        serde_json::from_value(result).map_err(|error| CfError::Network(error.to_string()))
    }

    /// Reads the tunnel's remote configuration.
    pub async fn get_config(&self, account: &str, tunnel: &str) -> Result<RemoteConfig, CfError> {
        let mut config: RemoteConfig = self
            .call(
                "GET",
                self.config_url(account, tunnel)
                    .map_err(|error| CfError::Network(error.to_string()))?,
                None::<&()>,
            )
            .await?;
        if config.config.is_null() {
            config.config = serde_json::json!({});
        }
        Ok(config)
    }

    /// Writes the tunnel's remote configuration (`{"config": …}`, the
    /// upstream wire shape). The concurrent-modification check is done by
    /// the caller: read via [`CfClient::get_config`], compare the versions,
    /// then write back only on a match.
    pub async fn put_config(
        &self,
        account: &str,
        tunnel: &str,
        config: &serde_json::Value,
    ) -> Result<RemoteConfig, CfError> {
        let body = serde_json::json!({ "config": config });
        self.call(
            "PUT",
            self.config_url(account, tunnel)
                .map_err(|error| CfError::Network(error.to_string()))?,
            Some(&body),
        )
        .await
    }

    /// Finds the zone owned by `account` whose name matches `name`
    /// (case-insensitive).
    pub async fn find_zone(&self, account: &str, name: &str) -> Result<Option<String>, CfError> {
        let mut url =
            Url::parse(&self.endpoint).map_err(|error| CfError::Network(error.to_string()))?;
        {
            let mut segments = url.path_segments_mut().map_err(|_| {
                CfError::Network(format!(
                    "Cloudflare API 地址不能包含路径段：{}",
                    self.endpoint
                ))
            })?;
            segments.push("zones");
        }
        url.query_pairs_mut()
            .append_pair("name", name)
            .append_pair("account.id", account);
        #[derive(Deserialize)]
        struct Zone {
            id: String,
            name: String,
        }
        let zones: Vec<Zone> = self.call("GET", url, None::<&()>).await?;
        Ok(zones
            .into_iter()
            .find(|zone| zone.name.eq_ignore_ascii_case(name))
            .map(|zone| zone.id))
    }

    /// Resolves the zone ID for a hostname by trying its suffixes from the
    /// longest down (upstream `zoneFor`). Only zones inside the tunnel's
    /// own account are considered — cross-account hosts must fail here.
    pub async fn zone_for(&self, account: &str, host: &str) -> Result<String, CfError> {
        let host = host.strip_prefix("*.").unwrap_or(host);
        let labels: Vec<&str> = host.split('.').filter(|label| !label.is_empty()).collect();
        for index in 0..labels.len().saturating_sub(1) {
            let name = labels[index..].join(".");
            if let Some(zone) = self.find_zone(account, &name).await? {
                return Ok(zone);
            }
        }
        Err(CfError::Api {
            code: 0,
            message: format!(
                "API 令牌可访问的域名中没有 {host}，请确认域名托管在 Cloudflare 且令牌有该域名的 DNS 编辑权限"
            ),
        })
    }

    /// Lists the DNS records named `name` in `zone`.
    pub async fn find_dns_record(&self, zone: &str, name: &str) -> Result<Vec<DnsRecord>, CfError> {
        let url = self
            .dns_url(zone)?
            .query_pairs_mut()
            .append_pair("name", name)
            .finish()
            .clone();
        self.call("GET", url, None::<&()>).await
    }

    /// Creates a DNS record.
    pub async fn create_dns_record(
        &self,
        zone: &str,
        record: &DnsRecord,
    ) -> Result<DnsRecord, CfError> {
        self.call("POST", self.dns_url(zone)?, Some(record)).await
    }

    /// Creates the proxied CNAME pointing at the tunnel
    /// ([`CfClient::create_cname`]).
    pub async fn create_cname(
        &self,
        zone: &str,
        name: &str,
        target: &str,
        proxied: bool,
    ) -> Result<DnsRecord, CfError> {
        let record = DnsRecord {
            id: String::new(),
            kind: "CNAME".into(),
            name: name.to_owned(),
            content: target.to_owned(),
            ttl: 1,
            proxied,
            comment: Some("FerrumGate cloudflared".into()),
        };
        self.create_dns_record(zone, &record).await
    }

    fn dns_url(&self, zone: &str) -> Result<Url, CfError> {
        let mut url =
            Url::parse(&self.endpoint).map_err(|error| CfError::Network(error.to_string()))?;
        {
            let mut segments = url.path_segments_mut().map_err(|_| {
                CfError::Network(format!(
                    "Cloudflare API 地址不能包含路径段：{}",
                    self.endpoint
                ))
            })?;
            segments.push("zones").push(zone).push("dns_records");
        }
        Ok(url)
    }

    /// Ensures `host` resolves into the tunnel: creates the proxied CNAME
    /// when there is no record, keeps an already-correct proxied CNAME as
    /// unchanged, and reports conflicts without touching them (upstream
    /// `ensureCNAME`).
    pub async fn ensure_cname(&self, account: &str, host: &str, target: &str) -> DnsResult {
        let mut result = DnsResult {
            hostname: host.to_owned(),
            status: DnsStatus::Failed,
            existing: None,
            error: None,
        };
        // 只在隧道所属账号下查找域名，令牌能访问多个账号时不会找到别的账号的同名域名。
        let zone = match self.zone_for(account, host).await {
            Ok(zone) => zone,
            Err(error) => {
                result.error = Some(error.to_string());
                return result;
            }
        };
        let records = match self.find_dns_record(&zone, host).await {
            Ok(records) => records,
            Err(error) => {
                result.error = Some(error.to_string());
                return result;
            }
        };
        for record in &records {
            if !record.name.eq_ignore_ascii_case(host) {
                continue;
            }
            let same_target = record.kind.eq_ignore_ascii_case("CNAME")
                && record
                    .content
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(target);
            if same_target {
                if record.proxied {
                    result.status = DnsStatus::Unchanged;
                    return result;
                }
                // 未开启代理的 CNAME 只解析到隧道域名，流量不会进入隧道，按冲突报告、不擅自修改。
                result.status = DnsStatus::Conflict;
                result.existing = Some(format!("{} (DNS only)", record.describe()));
                return result;
            }
            result.status = DnsStatus::Conflict;
            result.existing = Some(record.describe());
            return result;
        }
        match self.create_cname(&zone, host, target, true).await {
            Ok(_) => {
                result.status = DnsStatus::Created;
            }
            Err(error) => result.error = Some(error.to_string()),
        }
        result
    }

    /// Syncs DNS records for every rule hostname, deduplicated (upstream
    /// `syncDNS`).
    pub async fn sync_dns(
        &self,
        info: &TokenInfo,
        rules: &[crate::ingress::Rule],
    ) -> Vec<DnsResult> {
        let target = info.cname_target();
        let mut seen = std::collections::HashSet::new();
        let mut results = Vec::new();
        for rule in rules {
            if rule.hostname.is_empty() || !seen.insert(rule.hostname.clone()) {
                continue;
            }
            results.push(
                self.ensure_cname(&info.account_tag, &rule.hostname, &target)
                    .await,
            );
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::parse_token;

    fn dummy_client() -> CfClient {
        CfClient::new(
            "https://api.cloudflare.com/client/v4",
            "token",
            Arc::new(|_| Box::pin(async { Err(anyhow::anyhow!("not used")) })),
        )
    }

    #[test]
    fn config_path_uses_account_and_tunnel() {
        let url = dummy_client().config_url("acc", "tid").expect("url builds");
        assert_eq!(
            url.as_str(),
            "https://api.cloudflare.com/client/v4/accounts/acc/cfd_tunnel/tid/configurations"
        );
    }

    #[test]
    fn cf_error_display_carries_codes() {
        let error = CfError::from_errors(
            403,
            vec![
                (10000, "Authentication error".into()),
                (9109, "Unauthorized".into()),
            ],
        );
        assert_eq!(
            error.to_string(),
            "Cloudflare: 10000 Authentication error; 9109 Unauthorized"
        );
        assert!(matches!(error, CfError::Api { code: 10000, .. }));
        assert_eq!(
            CfError::Status(429).to_string(),
            "Cloudflare API 返回 HTTP 429"
        );
    }

    #[test]
    fn remote_config_defaults_empty_config_object() {
        // 远程配置的 config 缺失或为 null 时按空对象处理（新建隧道）。
        let raw = serde_json::json!({"tunnel_id": "tid", "version": 3, "source": "cloudflare"});
        let mut config: RemoteConfig = serde_json::from_value(raw).expect("parses");
        assert_eq!(config.version, 3);
        assert_eq!(config.source, "cloudflare");
        assert!(config.config.is_null(), "缺失的 config 反序列化为 null");
        if config.config.is_null() {
            config.config = serde_json::json!({});
        }
        assert_eq!(config.config, serde_json::json!({}));
    }

    #[test]
    fn dns_record_describe_matches_upstream_conflict_text() {
        let record = DnsRecord {
            kind: "A".into(),
            content: "1.2.3.4".into(),
            ..DnsRecord::default()
        };
        assert_eq!(record.describe(), "A 1.2.3.4");
    }

    #[test]
    fn token_cname_target_from_parsed_token() {
        let info = parse_token("eyJhIjoiYWNjIiwidCI6InRpZCIsInMiOiJzIn0=").expect("parses");
        assert_eq!(info.cname_target(), "tid.cfargotunnel.com");
    }
}
