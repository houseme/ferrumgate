//! WP-41 DNS 提供商适配：DNS 服务商适配层（本批为第一批 9 项），供 DDNS
//! （WP-40）与 ACME DNS-01（WP-32）使用。
//!
//! 契约与上游 `internal/dnsprovider` 对齐：每个提供商实现
//! [`DnsProvider::upsert`]（查询同名记录，值相同则不动，不同则更新，不存在
//! 则创建）；可选实现 [`TxtRecords`]（ACME DNS-01 的 TXT 增删：总是新增、
//! 按值删除）与 [`Deleter`]（删除 DDNS 同步的记录：只删值与最近一次同步
//! 相同的）。每个提供商一个 Cargo feature（`dns-<name>`，无默认 feature；
//! 根包的 default features 列出全部），注册表只包含已启用的 feature。

#![forbid(unsafe_code)]

#[macro_use]
mod macros;

// feature 关闭时注册宏与构造助手暂未被使用（provider 代码由对应 feature 编译）。
#[allow(unused_imports)]
pub(crate) use macros::{impl_deleter, impl_provider, impl_txt, register_provider};

pub mod callback;
pub mod delete;
pub mod http;
pub mod providers;
pub mod record;
pub mod simple;
pub mod split;
pub mod txt;

pub use callback::{CallbackConfig, render, render_json};
pub use delete::{Deleter, RemoteRecord};
pub use record::{Credentials, Record, RecordType};
pub use txt::TxtRecords;

use std::{future::Future, pin::Pin, sync::Arc};

use http::OutboundHttp;

/// 错误与提示的 i18n 消息键（WP-10 消息目录）。
pub mod msg {
    pub const AUTH_FAILED: &str = "dns.provider.authFailed";
    pub const RATE_LIMITED: &str = "dns.provider.rateLimited";
    pub const NOT_FOUND: &str = "dns.provider.notFound";
    pub const ZONE_NOT_FOUND: &str = "dns.provider.zoneNotFound";
    pub const INVALID_INPUT: &str = "dns.provider.invalidInput";
    pub const TRANSPORT: &str = "dns.provider.transport";
    pub const SERVER: &str = "dns.provider.server";
    pub const PARSE: &str = "dns.provider.parse";
    pub const API_ERROR: &str = "dns.provider.apiError";
    pub const CREDS_MISSING: &str = "dns.provider.credentialsMissing";
    pub const UNKNOWN_PROVIDER: &str = "dns.provider.unknown";
    pub const DELETE_VALUE_UNKNOWN: &str = "dns.delete.valueUnknown";
    pub const DELETE_RECORDSET_HAS_OTHERS: &str = "dns.delete.recordSetHasOtherValues";
    pub const DELETE_VALUE_MISMATCH: &str = "dns.delete.valueMismatch";
    pub const CALLBACK_FAILED: &str = "dns.callback.failed";
}

/// 盒装的异步 trait 返回值。本 crate 的 trait 不引入 async-trait 依赖，
/// 方法直接返回盒装 Future；提供商实现固有 `async fn`，用宏包装。
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// 提供商的额外配置项（界面表单元数据，WP-82 渲染）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field {
    pub key: &'static str,
    pub label: &'static str,
    pub placeholder: &'static str,
    pub multiline: bool,
    pub required: bool,
}

impl Field {
    pub const fn new(key: &'static str, label: &'static str, placeholder: &'static str) -> Self {
        Self {
            key,
            label,
            placeholder,
            multiline: false,
            required: false,
        }
    }

    pub const fn multiline(mut self) -> Self {
        self.multiline = true;
        self
    }

    pub const fn required(mut self) -> Self {
        self.required = true;
        self
    }
}

/// 描述一个提供商。`supportsAcme` / `supportsDelete` 等能力标记与 trait
/// 实现的一致性由编译期保证（注册时 `supports_acme = true` 的提供商必须经
/// 要求 `TxtRecords` 边界的构造包装）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Meta {
    pub name: &'static str,
    pub title: &'static str,
    pub id_label: &'static str,
    pub secret_label: &'static str,
    pub extra: &'static [Field],
    pub supports_line: bool,
    pub doc_url: &'static str,
    pub supports_acme: bool,
    pub supports_remark: bool,
    pub supports_delete: bool,
}

impl Meta {
    pub const fn new(name: &'static str, title: &'static str) -> Self {
        Self {
            name,
            title,
            id_label: "",
            secret_label: "",
            extra: &[],
            supports_line: false,
            doc_url: "",
            supports_acme: false,
            supports_remark: false,
            supports_delete: false,
        }
    }

    pub const fn labels(mut self, id_label: &'static str, secret_label: &'static str) -> Self {
        self.id_label = id_label;
        self.secret_label = secret_label;
        self
    }

    pub const fn extra(mut self, extra: &'static [Field]) -> Self {
        self.extra = extra;
        self
    }

    pub const fn doc(mut self, doc_url: &'static str) -> Self {
        self.doc_url = doc_url;
        self
    }

    pub const fn line(mut self) -> Self {
        self.supports_line = true;
        self
    }

    pub const fn acme(mut self) -> Self {
        self.supports_acme = true;
        self
    }

    pub const fn remark(mut self) -> Self {
        self.supports_remark = true;
        self
    }

    pub const fn delete(mut self) -> Self {
        self.supports_delete = true;
        self
    }
}

/// upsert 结果，与上游 ActionUnchanged / ActionUpdated / ActionCreated 对应。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpsertAction {
    Unchanged,
    Updated,
    Created,
}

impl UpsertAction {
    pub fn as_str(self) -> &'static str {
        match self {
            UpsertAction::Unchanged => "unchanged",
            UpsertAction::Updated => "updated",
            UpsertAction::Created => "created",
        }
    }
}

/// 提供商错误分类：认证失败、限速、未找到（记录）、未找到（区域）、无效
/// 输入、传输错误、服务端错误、响应无法解析。认证失败不重试；限速按
/// `retry_after` 退避；未找到在删除时视为成功。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderErrorKind {
    Auth,
    RateLimited,
    NotFound,
    ZoneNotFound,
    InvalidInput,
    Transport,
    Server,
    Parse,
}

impl ProviderErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderErrorKind::Auth => "auth",
            ProviderErrorKind::RateLimited => "rateLimited",
            ProviderErrorKind::NotFound => "notFound",
            ProviderErrorKind::ZoneNotFound => "zoneNotFound",
            ProviderErrorKind::InvalidInput => "invalidInput",
            ProviderErrorKind::Transport => "transport",
            ProviderErrorKind::Server => "server",
            ProviderErrorKind::Parse => "parse",
        }
    }
}

/// 提供商错误。`message_key` 供管理 API 边界翻译；`detail` 是面向日志的
/// 详情（提供商负责在写入前对密钥做 redact）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderError {
    pub kind: ProviderErrorKind,
    pub message_key: &'static str,
    pub provider: &'static str,
    pub retry_after: Option<std::time::Duration>,
    pub detail: String,
}

impl ProviderError {
    pub fn new(provider: &'static str, kind: ProviderErrorKind, message_key: &'static str) -> Self {
        Self {
            kind,
            message_key,
            provider,
            retry_after: None,
            detail: String::new(),
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// 按传输层失败归类（见 [`http::HttpFail`]）。
    pub fn from_http(provider: &'static str, fail: http::HttpFail) -> Self {
        let message_key = match fail.kind() {
            ProviderErrorKind::Auth => msg::AUTH_FAILED,
            ProviderErrorKind::RateLimited => msg::RATE_LIMITED,
            ProviderErrorKind::NotFound | ProviderErrorKind::ZoneNotFound => msg::NOT_FOUND,
            ProviderErrorKind::InvalidInput => msg::INVALID_INPUT,
            ProviderErrorKind::Transport => msg::TRANSPORT,
            ProviderErrorKind::Server => msg::SERVER,
            ProviderErrorKind::Parse => msg::PARSE,
        };
        Self {
            kind: fail.kind(),
            message_key,
            provider,
            retry_after: fail.retry_after(),
            detail: fail.detail(),
        }
    }

    pub fn invalid_input(provider: &'static str, detail: impl Into<String>) -> Self {
        Self::new(
            provider,
            ProviderErrorKind::InvalidInput,
            msg::INVALID_INPUT,
        )
        .with_detail(detail)
    }

    pub fn parse(provider: &'static str, detail: impl Into<String>) -> Self {
        Self::new(provider, ProviderErrorKind::Parse, msg::PARSE).with_detail(detail)
    }

    pub fn not_found(provider: &'static str, detail: impl Into<String>) -> Self {
        Self::new(provider, ProviderErrorKind::NotFound, msg::NOT_FOUND).with_detail(detail)
    }

    pub fn zone_not_found(provider: &'static str, detail: impl Into<String>) -> Self {
        Self::new(
            provider,
            ProviderErrorKind::ZoneNotFound,
            msg::ZONE_NOT_FOUND,
        )
        .with_detail(detail)
    }

    /// 把密钥从错误详情中替换为 `***`；密钥放在查询串里时，原文与 URL 编码
    /// 后的写法都要替换。
    pub fn redact(&mut self, secret: &str) {
        if secret.is_empty() {
            return;
        }
        self.detail = self.detail.replace(secret, "***");
        let escaped = simple::query_escape(secret);
        if escaped != secret {
            self.detail = self.detail.replace(&escaped, "***");
        }
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.provider, self.detail)?;
        if !self.message_key.is_empty() {
            write!(f, " [{}/{}]", self.message_key, self.kind.as_str())?;
        }
        Ok(())
    }
}

impl std::error::Error for ProviderError {}

/// 一个已配置凭据的 DNS 提供商客户端。
pub trait DnsProvider: Send + Sync {
    fn meta(&self) -> &'static Meta;

    /// 新增或更新记录：查询同名同类型记录，值相同则不动，不同则更新，
    /// 不存在则创建。
    fn upsert<'a>(&'a self, rec: &'a Record) -> BoxFut<'a, Result<UpsertAction, ProviderError>>;
}

/// 根据凭据构造提供商客户端的工厂。
pub type Factory =
    fn(Credentials, Arc<OutboundHttp>) -> Result<Box<dyn DnsProvider>, ProviderError>;

/// 注册表：只包含已启用的 feature 对应的提供商，按名称排序。
pub fn registry() -> &'static [(&'static Meta, Factory)] {
    REGISTRY
}

/// 全部已知适配项的名称（含未编译进本构建的，界面据此提示「此构建未包含」）。
pub const ALL_NAMES: &[&str] = &[
    "alidns",
    "aliesa",
    "baiducloud",
    "bunny",
    "callback",
    "cloudflare",
    "cloudns",
    "desec",
    "dnsla",
    "dnspod",
    "dnspodcom",
    "duckdns",
    "dynadot",
    "dyndns2",
    "dynv6",
    "edgeone",
    "eranet",
    "gandi",
    "gcore",
    "godaddy",
    "hipmdnsmgr",
    "huaweicloud",
    "namecheap",
    "namecom",
    "namesilo",
    "nowcn",
    "ns1",
    "ovh",
    "porkbun",
    "rainyun",
    "route53",
    "spaceship",
    "tencentcloud",
    "tnethk",
    "trafficroute",
    "vercel",
];

/// 含未启用提供商的全部名称（WP-41 §3.2）。
pub fn all_names() -> Vec<&'static str> {
    ALL_NAMES.to_vec()
}

/// 按名称构造提供商客户端；名称未注册时返回错误。
pub fn new(
    name: &str,
    creds: Credentials,
    http: Arc<OutboundHttp>,
) -> Result<Box<dyn DnsProvider>, ProviderError> {
    for (meta, factory) in registry() {
        if meta.name == name {
            return factory(creds, http);
        }
    }
    Err(
        ProviderError::new("", ProviderErrorKind::InvalidInput, msg::UNKNOWN_PROVIDER)
            .with_detail(format!("不支持的 DNS 服务商 {name:?}")),
    )
}

/// 校验必填凭据。
// 仅 provider feature 启用时被调用。
#[allow(dead_code)]
pub(crate) fn require_creds(
    meta: &'static Meta,
    creds: &Credentials,
    need_id: bool,
    need_secret: bool,
) -> Result<(), ProviderError> {
    if need_id && creds.id.trim().is_empty() {
        return Err(ProviderError::new(
            meta.name,
            ProviderErrorKind::InvalidInput,
            msg::CREDS_MISSING,
        )
        .with_detail("缺少凭据 ID"));
    }
    if need_secret && creds.secret.trim().is_empty() {
        return Err(ProviderError::new(
            meta.name,
            ProviderErrorKind::InvalidInput,
            msg::CREDS_MISSING,
        )
        .with_detail("缺少凭据 Secret"));
    }
    Ok(())
}

// 仅 provider feature 启用时被调用。
#[allow(dead_code)]
pub(crate) fn box_provider<P: DnsProvider + 'static>(p: P) -> Box<dyn DnsProvider> {
    Box::new(p)
}

/// 注册 `supports_acme = true` 的提供商必须经过这里：构造类型必须实现
/// [`TxtRecords`]（编译期断言，对应上游 SupportsTXT 的注册表能力标记）。
#[allow(dead_code)]
pub(crate) fn box_txt<P: TxtRecords + 'static>(p: P) -> Box<dyn DnsProvider> {
    Box::new(p)
}

type RegistryEntry = (&'static Meta, Factory);

static REGISTRY: &[RegistryEntry] = &[
    #[cfg(feature = "dns-bunny")]
    register_provider!(txt, providers::bunny::META, providers::bunny::Bunny::new),
    #[cfg(feature = "dns-callback")]
    register_provider!(callback::META, callback::Callback::new),
    #[cfg(feature = "dns-cloudflare")]
    register_provider!(
        txt,
        providers::cloudflare::META,
        providers::cloudflare::Cloudflare::new
    ),
    #[cfg(feature = "dns-dnspod")]
    register_provider!(txt, providers::dnspod::META, providers::dnspod::Dnspod::new),
    #[cfg(feature = "dns-dnspodcom")]
    register_provider!(
        txt,
        providers::dnspod::META_COM,
        providers::dnspod::Dnspod::new_com
    ),
    #[cfg(feature = "dns-duckdns")]
    register_provider!(providers::duckdns::META, providers::duckdns::DuckDns::new),
    #[cfg(feature = "dns-dynv6")]
    register_provider!(txt, providers::dynv6::META, providers::dynv6::Dynv6::new),
    #[cfg(feature = "dns-gandi")]
    register_provider!(txt, providers::gandi::META, providers::gandi::Gandi::new),
    #[cfg(feature = "dns-porkbun")]
    register_provider!(
        txt,
        providers::porkbun::META,
        providers::porkbun::Porkbun::new
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_registry_names() -> Vec<&'static str> {
        registry().iter().map(|(meta, _)| meta.name).collect()
    }

    #[test]
    fn registry_matches_enabled_features() {
        let expected: &[&str] = &[
            #[cfg(feature = "dns-bunny")]
            "bunny",
            #[cfg(feature = "dns-callback")]
            "callback",
            #[cfg(feature = "dns-cloudflare")]
            "cloudflare",
            #[cfg(feature = "dns-dnspod")]
            "dnspod",
            #[cfg(feature = "dns-dnspodcom")]
            "dnspodcom",
            #[cfg(feature = "dns-duckdns")]
            "duckdns",
            #[cfg(feature = "dns-dynv6")]
            "dynv6",
            #[cfg(feature = "dns-gandi")]
            "gandi",
            #[cfg(feature = "dns-porkbun")]
            "porkbun",
        ];
        assert_eq!(enabled_registry_names(), expected);
    }

    #[test]
    fn registry_names_sorted_and_known() {
        let names = enabled_registry_names();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "注册表应按名称排序");
        for name in names {
            assert!(ALL_NAMES.contains(&name), "{name} 未登记在 ALL_NAMES");
        }
    }

    #[test]
    fn registry_capability_flags_match_upstream() {
        for (meta, _) in registry() {
            let (acme, del, remark, line) = match meta.name {
                "bunny" => (true, true, false, false),
                "callback" => (false, false, false, false),
                "cloudflare" => (true, true, true, false),
                "dnspod" => (true, true, true, true),
                "dnspodcom" => (true, true, true, false),
                "duckdns" => (false, false, false, false),
                "dynv6" => (true, true, false, false),
                "gandi" => (true, true, false, false),
                "porkbun" => (true, true, false, false),
                other => panic!("未覆盖能力标记的提供商 {other}"),
            };
            assert_eq!(meta.supports_acme, acme, "{} supports_acme", meta.name);
            assert_eq!(meta.supports_delete, del, "{} supports_delete", meta.name);
            assert_eq!(
                meta.supports_remark, remark,
                "{} supports_remark",
                meta.name
            );
            assert_eq!(meta.supports_line, line, "{} supports_line", meta.name);
        }
    }

    #[test]
    fn all_names_contains_full_catalog() {
        assert_eq!(all_names().len(), ALL_NAMES.len());
        for expected in ["cloudflare", "tencentcloud", "dyndns2", "callback"] {
            assert!(ALL_NAMES.contains(&expected), "{expected} 应在全部清单里");
        }
    }

    #[test]
    fn unknown_provider_is_rejected() {
        let http = Arc::new(OutboundHttp::new().expect("client"));
        let err = match new("nope", Credentials::default(), http) {
            Err(e) => e,
            Ok(_) => panic!("unknown provider should be rejected"),
        };
        assert_eq!(err.kind, ProviderErrorKind::InvalidInput);
        assert_eq!(err.message_key, msg::UNKNOWN_PROVIDER);
    }

    #[test]
    fn missing_secret_is_rejected() {
        let http = Arc::new(OutboundHttp::new().expect("client"));
        for name in ["cloudflare", "dnspod", "porkbun"] {
            let err = match new(name, Credentials::default(), http.clone()) {
                Err(e) => e,
                Ok(_) => panic!("{name} should require credentials"),
            };
            assert_eq!(err.kind, ProviderErrorKind::InvalidInput, "{name}");
            assert_eq!(err.message_key, msg::CREDS_MISSING, "{name}");
        }
        // duckdns 只需要 Secret。
        assert!(new("duckdns", Credentials::default(), http.clone()).is_err());
        assert!(
            new(
                "duckdns",
                Credentials {
                    secret: "t".into(),
                    ..Default::default()
                },
                http
            )
            .is_ok()
        );
    }

    #[test]
    fn upsert_action_strings_match_upstream() {
        assert_eq!(UpsertAction::Unchanged.as_str(), "unchanged");
        assert_eq!(UpsertAction::Updated.as_str(), "updated");
        assert_eq!(UpsertAction::Created.as_str(), "created");
    }

    #[test]
    fn provider_error_redacts_secret_and_escaped_form() {
        let mut err = ProviderError::invalid_input("test", "token=abc secret=abc");
        err.redact("abc");
        assert_eq!(err.detail, "token=*** secret=***");
        let mut with_query = ProviderError::invalid_input("test", "failed https://x?token=a+b");
        with_query.redact("a+b");
        assert_eq!(with_query.detail, "failed https://x?token=***");
    }
}
