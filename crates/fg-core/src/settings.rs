use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, de::IgnoredAny};

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

/// The persisted `ferrumgate.json` settings. Zero-valued limits request runtime defaults.
/// Contains credentials. Management responses must use a redacted view.
#[derive(Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
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
    #[serde(rename = "gcPercent", deserialize_with = "ignore", skip_serializing)]
    _gc_percent: (),
    #[serde(rename = "maxProcs", deserialize_with = "ignore", skip_serializing)]
    _max_procs: (),
}

#[derive(Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
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
