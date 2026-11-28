use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Component, Path, PathBuf},
    time::Duration,
};

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, de::IgnoredAny};
use url::Url;

use crate::registry::Registry;

pub const DEFAULT_LISTEN: &str = ":16680";
pub const DEFAULT_DENY_STATUS: i32 = 200;
pub const DEFAULT_MAX_LOGIN_FAILURES: u32 = 5;
pub const DEFAULT_LOCK_MINUTES: u64 = 15;
pub const DEFAULT_LOGIN_GLOBAL_LIMIT: u32 = 20;
pub const DEFAULT_CONFIRM_TIMEOUT_SECONDS: u64 = 90;
pub const DEFAULT_LOG_LEVEL: &str = "info";
pub const DEFAULT_LOG_LINES: usize = 2_000;
pub const DEFAULT_LOG_FILE_MB: u64 = 2;
pub const DEFAULT_ACCESS_LOG_DAYS: u32 = 7;
pub const DEFAULT_ACCESS_LOG_MB: u64 = 32;

const DENY_STATUSES: [i32; 7] = [DEFAULT_DENY_STATUS, 403, 404, 410, 500, 502, 503];

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct SettingError {
    pub field: &'static str,
    pub message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub enum Effect {
    Immediate,
    NeedsConfirm,
    NeedsRestart,
    BootOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SettingChange {
    pub field: &'static str,
    pub effect: Effect,
}

macro_rules! setting_effects {
    ($($effect:ident => $($name:literal : $field:ident),+;)+) => {
        pub fn effect_of(field: &str) -> Option<Effect> {
            match field {
                $($($name)|+ => Some(Effect::$effect),)+
                _ => None,
            }
        }

        pub fn effects() -> impl Iterator<Item = (&'static str, Effect)> {
            [$($(($name, Effect::$effect),)+)+].into_iter()
        }

        pub fn changed_with_effect(&self, old: &Self, effect: Effect) -> bool {
            match effect {
                $(Effect::$effect => $(self.$field != old.$field)||+,)+
            }
        }

        /// Classifies differences between normalized settings using persisted JSON field names.
        pub fn changes_from(&self, old: &Self) -> Vec<SettingChange> {
            [$($((self.$field != old.$field, SettingChange {
                field: $name,
                effect: Effect::$effect,
            }),)+)+]
                .into_iter()
                .filter_map(|(changed, change)| changed.then_some(change))
                .collect()
        }
    };
}

/// The persisted `ferrumgate.json` settings. Zero-valued limits request runtime defaults.
/// Contains credentials. Management responses must use a redacted view.
#[derive(Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub listen: String,
    pub https_listen: String,
    #[serde(rename = "forceHTTPS")]
    pub force_https: bool,
    pub safe_path: String,
    pub lan_only: bool,
    pub deny_mode: String,
    pub deny_status: i32,
    pub deny_page: String,
    #[serde(rename = "gatewaySSO")]
    pub gateway_sso: bool,
    pub disable_proxy_headers: bool,
    #[serde(deserialize_with = "null_to_default")]
    pub trusted_proxies: Vec<String>,
    pub max_login_failures: i64,
    pub lock_minutes: i64,
    pub login_global_limit: i64,
    pub confirm_timeout: i64,
    // The startup migration owns this field. New settings never serialize it.
    #[serde(rename = "apiToken", skip_serializing)]
    pub legacy_api_token: String,
    pub language: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ui_language: String,
    pub time_zone: String,
    #[serde(deserialize_with = "null_to_default")]
    pub dns_servers: Vec<String>,
    pub update_proxy: String,
    pub restrict_outbound: bool,
    pub disable_update_check: bool,
    pub log_level: String,
    pub log_lines: i64,
    pub disable_log_persist: bool,
    #[serde(rename = "logFileMB")]
    pub log_file_mb: i64,
    pub access_log_days: i64,
    #[serde(rename = "accessLogMB")]
    pub access_log_mb: i64,
    pub log_dir: String,
    #[serde(deserialize_with = "null_to_default")]
    pub third_login: ThirdLoginSettings,
    #[serde(deserialize_with = "null_to_default")]
    pub disabled_modules: Vec<String>,
    /// WP-39 migration: graceful shutdown deadline in milliseconds
    /// (legacy `server.shutdown_timeout_ms`, default 10 s).
    pub shutdown_timeout_ms: i64,
    /// WP-39 migration: CA bundle for outbound HTTPS connections
    /// (legacy `upstream_ca_file`).
    pub upstream_ca_file: String,
    #[serde(rename = "gcPercent", deserialize_with = "ignore", skip_serializing)]
    _gc_percent: (),
    #[serde(rename = "maxProcs", deserialize_with = "ignore", skip_serializing)]
    _max_procs: (),
}

#[derive(Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct ThirdLoginSettings {
    pub enable: bool,
    pub callback_base: String,
    #[serde(deserialize_with = "null_to_default")]
    pub providers: Vec<IdentityProviderSettings>,
    #[serde(deserialize_with = "null_to_default")]
    pub allowed: Vec<String>,
    pub skip_totp: bool,
}

#[derive(Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityProviderSettings {
    pub key: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub client_id: String,
    pub client_secret: String,
    pub issuer: String,
    pub proxy: String,
}

impl Settings {
    pub fn normalize(&mut self) {
        for value in [
            &mut self.listen,
            &mut self.https_listen,
            &mut self.safe_path,
            &mut self.deny_mode,
            &mut self.time_zone,
            &mut self.update_proxy,
            &mut self.log_level,
            &mut self.log_dir,
            &mut self.third_login.callback_base,
        ] {
            trim(value);
        }
        if self.listen.is_empty() {
            self.listen.push_str(DEFAULT_LISTEN);
        }
        self.safe_path
            .truncate(self.safe_path.trim_end_matches('/').len());
        if !self.safe_path.is_empty() && !self.safe_path.starts_with('/') {
            self.safe_path.insert(0, '/');
        }
        self.deny_mode.make_ascii_lowercase();
        if self.deny_status == 0
            || (self.deny_mode != "custom" && !DENY_STATUSES.contains(&self.deny_status))
        {
            self.deny_status = DEFAULT_DENY_STATUS;
        }
        self.log_level.make_ascii_lowercase();
        let path = Path::new(&self.log_dir);
        if path.is_absolute() {
            // Lexical cleanup keeps normalization independent of filesystem state.
            let mut clean = PathBuf::new();
            for component in path.components() {
                match component {
                    Component::ParentDir => {
                        clean.pop();
                    }
                    Component::CurDir => {}
                    component => clean.push(component.as_os_str()),
                }
            }
            self.log_dir = clean.into_os_string().into_string().expect("UTF-8 path");
        }
        self.language = language_tag(&self.language).to_owned();
        self.ui_language = language_tag(&self.ui_language).to_owned();
        for list in [
            &mut self.trusted_proxies,
            &mut self.dns_servers,
            &mut self.disabled_modules,
            &mut self.third_login.allowed,
        ] {
            list.retain_mut(|value| {
                trim(value);
                !value.is_empty()
            });
        }
        self.third_login
            .callback_base
            .truncate(self.third_login.callback_base.trim_end_matches('/').len());
        self.disabled_modules.sort_unstable();
        self.disabled_modules.dedup();
        self.confirm_timeout = self.confirm_timeout.max(-1);
    }

    /// Validates a normalized candidate without binding sockets or writing files.
    pub fn validate(&self, registry: &Registry) -> Result<(), Vec<SettingError>> {
        let mut errors = Vec::new();
        let mut check = |valid: bool, field, message: &str| {
            if !valid {
                errors.push(SettingError {
                    field,
                    message: message.into(),
                });
            }
        };
        let http = listener_address(&self.listen);
        let https = listener_address(&self.https_listen);
        check(
            http.is_some(),
            "listen",
            "expected :port or an IP socket address",
        );
        check(
            self.https_listen.is_empty() || https.is_some(),
            "httpsListen",
            "expected :port or an IP socket address",
        );
        check(
            https.is_none() || http != https,
            "httpsListen",
            "must differ from listen",
        );
        check(
            !self.force_https || !self.https_listen.is_empty(),
            "forceHTTPS",
            "requires httpsListen",
        );
        check(
            self.safe_path.is_empty() || valid_safe_path(&self.safe_path),
            "safePath",
            "expected at least three path characters outside /api and /assets, without whitespace, ? or #",
        );
        check(
            matches!(
                self.deny_mode.as_str(),
                "" | "notfound" | "blank" | "close" | "drop" | "custom"
            ),
            "denyMode",
            "expected notfound, blank, close, drop, custom or an empty value",
        );
        check(
            DENY_STATUSES.contains(&self.deny_status),
            "denyStatus",
            "expected 200, 403, 404, 410, 500, 502 or 503",
        );
        check(
            self.deny_page.len() <= 64 << 10,
            "denyPage",
            "must be at most 64 KiB",
        );
        check(
            self.trusted_proxies
                .iter()
                .all(|proxy| proxy.parse::<IpNet>().is_ok() || ip_literal(proxy)),
            "trustedProxies",
            "expected IP addresses or CIDR prefixes",
        );
        check(
            (0..=100).contains(&self.max_login_failures),
            "maxLoginFailures",
            "expected 0 through 100",
        );
        check(
            (0..=10080).contains(&self.lock_minutes),
            "lockMinutes",
            "expected 0 through 10080 minutes",
        );
        check(
            self.login_global_limit <= 10_000,
            "loginGlobalLimit",
            "must be at most 10000",
        );
        check(
            self.confirm_timeout <= 0 || (30..=600).contains(&self.confirm_timeout),
            "confirmTimeout",
            "expected 30 through 600 seconds, zero for the default, or a negative value to disable",
        );
        check(
            self.time_zone.is_empty() || jiff_tzdb::get(&self.time_zone).is_some(),
            "timeZone",
            "expected an IANA time zone name",
        );
        check(
            self.dns_servers
                .iter()
                .all(|server| valid_dns_server(server)),
            "dnsServers",
            "expected IP, IP:port, doh@host or an HTTPS URL",
        );
        check(
            self.update_proxy.is_empty() || valid_proxy_url(&self.update_proxy),
            "updateProxy",
            "expected an HTTP, HTTPS, SOCKS5 or SOCKS5H proxy URL",
        );
        check(
            matches!(
                self.log_level.as_str(),
                "" | "debug" | "info" | "warn" | "error"
            ),
            "logLevel",
            "expected debug, info, warn, error or an empty value",
        );
        check(
            self.log_lines <= 20_000,
            "logLines",
            "must be at most 20000",
        );
        check(
            (0..=100).contains(&self.log_file_mb),
            "logFileMB",
            "expected 0 through 100 MiB",
        );
        check(
            (0..=3650).contains(&self.access_log_days),
            "accessLogDays",
            "expected 0 through 3650 days",
        );
        check(
            self.access_log_mb == 0 || (4..=102_400).contains(&self.access_log_mb),
            "accessLogMB",
            "expected 4 through 102400 MiB or zero for the default",
        );
        let path = Path::new(&self.log_dir);
        check(
            self.log_dir.is_empty()
                || (self.log_dir.len() <= 1024
                    && path.is_absolute()
                    && path.parent().is_some()
                    && !self.log_dir.chars().any(char::is_control)),
            "logDir",
            "expected a non-root absolute path of at most 1024 bytes without control characters",
        );

        let third = &self.third_login;
        check(
            !third.enable
                || (!third.callback_base.is_empty()
                    && !third.providers.is_empty()
                    && !third.allowed.is_empty()),
            "thirdLogin",
            "enabling third-party login requires a callback base, a provider and an allowed identity",
        );
        check(
            third.callback_base.is_empty()
                || absolute_url(&third.callback_base).is_some_and(|url| {
                    valid_oauth_endpoint(&url) && url.path() == "/" && url.query().is_none()
                }),
            "thirdLogin.callbackBase",
            "expected an HTTPS or loopback HTTP origin",
        );
        let mut keys = HashSet::new();
        check(
            third.providers.len() <= 16
                && third.providers.iter().all(|provider| {
                    (1..=64).contains(&provider.key.len())
                        && provider
                            .key
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
                        && keys.insert(provider.key.as_str())
                        && !provider.client_id.is_empty()
                        && !provider.client_secret.is_empty()
                        && (provider.proxy.is_empty() || valid_proxy_url(&provider.proxy))
                        && match provider.kind.as_str() {
                            "github" | "google" | "qq" => true,
                            "oidc" => absolute_url(&provider.issuer).is_some_and(|url| {
                                valid_oauth_endpoint(&url) && url.query().is_none()
                            }),
                            _ => false,
                        }
                }),
            "thirdLogin.providers",
            "expected up to 16 distinct providers with a supported type, credentials and valid URLs",
        );
        check(
            third.allowed.iter().all(|entry| {
                allowed_identity(entry).is_some_and(|(key, _)| {
                    !third.enable || third.providers.iter().any(|provider| provider.key == key)
                })
            }),
            "thirdLogin.allowed",
            "expected provider:identity entries",
        );

        if let Err(error) =
            registry.validate_disabled(&self.disabled_modules, !self.https_listen.is_empty())
        {
            errors.push(SettingError {
                field: "disabledModules",
                message: error.to_string(),
            });
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn confirm_timeout(&self) -> Option<Duration> {
        match self.confirm_timeout {
            seconds if seconds < 0 => None,
            0 => Some(Duration::from_secs(DEFAULT_CONFIRM_TIMEOUT_SECONDS)),
            seconds => Some(Duration::from_secs(seconds as u64)),
        }
    }

    setting_effects! {
        NeedsRestart =>
            "listen": listen, "httpsListen": https_listen, "disabledModules": disabled_modules;
        NeedsConfirm =>
            "forceHTTPS": force_https, "safePath": safe_path, "lanOnly": lan_only,
            "denyMode": deny_mode, "denyStatus": deny_status, "denyPage": deny_page,
            "disableProxyHeaders": disable_proxy_headers, "trustedProxies": trusted_proxies;
        Immediate =>
            "gatewaySSO": gateway_sso, "maxLoginFailures": max_login_failures,
            "lockMinutes": lock_minutes, "loginGlobalLimit": login_global_limit,
            "confirmTimeout": confirm_timeout, "language": language, "uiLanguage": ui_language,
            "timeZone": time_zone, "dnsServers": dns_servers, "updateProxy": update_proxy,
            "restrictOutbound": restrict_outbound, "disableUpdateCheck": disable_update_check,
            "logLevel": log_level, "logLines": log_lines, "disableLogPersist": disable_log_persist,
            "logFileMB": log_file_mb, "accessLogDays": access_log_days, "accessLogMB": access_log_mb,
            "logDir": log_dir, "thirdLogin": third_login;
        BootOnly =>
            // WP-39 migrations: the shutdown deadline re-arms with the
            // process; the outbound CA bundle feeds the TLS connectors
            // built at startup.
            "shutdownTimeoutMs": shutdown_timeout_ms, "upstreamCaFile": upstream_ca_file;
        BootOnly => "apiToken": legacy_api_token;
    }
}

pub fn allowed_identity(entry: &str) -> Option<(&str, &str)> {
    let identity = entry
        .split_once(" #")
        .map_or(entry, |(identity, _)| identity);
    let (key, subject) = identity.split_once(':')?;
    let (key, subject) = (key.trim(), subject.trim());
    (!key.is_empty() && !subject.is_empty() && subject != "*").then_some((key, subject))
}

pub fn valid_oauth_endpoint(url: &Url) -> bool {
    let local = match url.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    url.has_host()
        && (url.scheme() == "https" || (url.scheme() == "http" && local))
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

fn listener_address(value: &str) -> Option<SocketAddr> {
    let (_, port) = value.rsplit_once(':')?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if value.starts_with(':') && !value[1..].contains(':') {
        return Some(SocketAddr::new(
            Ipv4Addr::UNSPECIFIED.into(),
            port.parse().ok()?,
        ));
    }
    value.parse().ok()
}

fn valid_safe_path(path: &str) -> bool {
    path.strip_prefix('/')
        .is_some_and(|tail| tail.chars().take(3).count() == 3)
        && path != "/api"
        && !path.starts_with("/api/")
        && !path.starts_with("/assets")
        && !path
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control() || matches!(ch, '?' | '#'))
}

fn ip_literal(value: &str) -> bool {
    let addr = value
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(value);
    addr.parse::<IpAddr>().is_ok()
}

fn absolute_url(raw: &str) -> Option<Url> {
    let (_, authority) = raw.split_once("://")?;
    if authority.is_empty()
        || authority.starts_with('/')
        || raw
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control() || ch == '\\')
    {
        return None;
    }
    Url::parse(raw).ok().filter(Url::has_host)
}

fn valid_proxy_url(raw: &str) -> bool {
    absolute_url(raw)
        .is_some_and(|url| matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h"))
}

fn valid_dns_server(raw: &str) -> bool {
    if raw.parse::<SocketAddr>().is_ok() || ip_literal(raw) {
        return true;
    }
    let Some(prefix) = raw.get(..4) else {
        return false;
    };
    if prefix.eq_ignore_ascii_case("doh@") {
        absolute_url(&format!("https://{}", &raw[4..])).is_some()
    } else {
        absolute_url(raw).is_some_and(|url| url.scheme() == "https")
    }
}

fn trim(value: &mut String) {
    let trimmed = value.trim();
    if value.len() != trimmed.len() {
        *value = trimmed.to_owned();
    }
}

fn language_tag(value: &str) -> &'static str {
    let value = value.trim().split(['.', '@']).next().unwrap_or_default();
    let mut parts = value.split(['-', '_']);
    match parts
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "zh" => {
            if parts.any(|part| {
                ["tw", "hk", "mo", "hant"]
                    .iter()
                    .any(|tag| part.eq_ignore_ascii_case(tag))
            }) {
                "zh-TW"
            } else {
                "zh-CN"
            }
        }
        "pt" => "pt-BR",
        "en" => "en",
        "ja" => "ja",
        "ko" => "ko",
        "es" => "es",
        "fr" => "fr",
        "de" => "de",
        "ru" => "ru",
        _ => "",
    }
}

fn null_to_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn ignore<'de, D: Deserializer<'de>>(deserializer: D) -> Result<(), D::Error> {
    IgnoredAny::deserialize(deserializer).map(|_| ())
}
