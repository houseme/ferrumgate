//! WP-31 certificate entry model and sources: the `ssl.json` data model,
//! normalization/validation, certificate info parsing, the SNI index and
//! the `CertProvider` surface for the web service and admin HTTPS.
//! This file also carries the module runtime (steps 6/7/9): the
//! [`SslState`] that loads `ssl.json`, the renewal scheduler and the
//! summary/metrics surface. Routes, real WP-32 issuance and deploy
//! wiring follow in later batches.
#![allow(dead_code)]

pub mod index;
pub mod info;
pub(crate) mod legacy;
pub mod model;
pub mod routes;
pub mod provider;
pub mod source;
pub mod validate;

pub(crate) use legacy::Certificates;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Context as _;

use crate::certs::index::CertIndex;
use crate::certs::info::CertInfo;
use crate::certs::model::{Cert, CertSource, FileConfig, Settings};
use crate::certs::provider::{LoadedCert, Provider};
use crate::certs::validate::normalize;

/// `Settings` snapshots are handed out by [`SslState::settings`] and the
/// scheduler, but the serde model does not derive `Clone`. A local
/// manual impl keeps the model file untouched.
impl Clone for Settings {
    fn clone(&self) -> Self {
        Self {
            enable: self.enable,
            renew_before_days: self.renew_before_days,
            short_lived_renew_hours: self.short_lived_renew_hours,
            default_email: self.default_email.clone(),
        }
    }
}

/// The `ssl.json` file name under the config directory.
const SSL_CONFIG_FILE: &str = "ssl.json";

/// Renewal thresholds are day/hour based (§3.3 续期调度).
const DAY: Duration = Duration::from_secs(60 * 60 * 24);
const HOUR: Duration = Duration::from_secs(60 * 60);

/// Upstream `shortLivedLife`: certificates with a total lifetime under
/// ten days renew on the short-lived hourly schedule.
const SHORT_LIVED_LIFE: Duration = Duration::from_secs(10 * 60 * 60 * 24);
/// The ACME profile name that marks an entry short-lived.
const SHORT_LIVED_PROFILE: &str = "shortlived";

const SECONDS_PER_DAY: f64 = 86_400.0;

/// Per-entry failure records: entry key → (latest error text, when it
/// happened). Scheduler backoff reads the timestamp.
type Failures = BTreeMap<String, (String, Instant)>;

/// Reads and normalizes `config_dir/ssl.json`. A missing file is the
/// default config (自动续签开启、没有证书); a file that exists but cannot
/// be read or parsed — or fails normalization — is an error: upstream
/// semantics have the whole module initialization (process start) fail
/// on a broken `ssl.json`.
async fn read_config(config_dir: &Path) -> anyhow::Result<FileConfig> {
    let path = config_dir.join(SSL_CONFIG_FILE);
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(FileConfig::default());
        }
        Err(error) => {
            return Err(anyhow::Error::new(error).context(format!(
                "读取 {} 失败",
                path.display()
            )));
        }
    };
    let mut config: FileConfig = serde_json::from_slice(&bytes)
        .with_context(|| format!("解析 {} 失败", path.display()))?;
    normalize(&mut config)
        .map_err(|error| anyhow::Error::new(error).context(format!("{} 校验失败", path.display())))?;
    Ok(config)
}

/// The shared body of `load`/`reload`: normalized settings, every
/// enabled entry's loaded certificate, and per-entry load failures. A
/// failing entry is recorded and left out of the certificate set; it
/// never blocks the other entries.
async fn collect(
    config_dir: &Path,
) -> anyhow::Result<(Settings, Vec<Arc<LoadedCert>>, Failures)> {
    let config = read_config(config_dir).await?;
    let mut loaded = Vec::new();
    let mut failures = Failures::default();
    for cert in config.certs.iter().filter(|cert| cert.enable) {
        match crate::certs::source::load_entry(cert, config_dir).await {
            Ok(Some(loaded_cert)) => loaded.push(loaded_cert),
            Ok(None) => {}
            Err(error) => {
                failures.insert(cert.key.clone(), (error, Instant::now()));
            }
        }
    }
    Ok((config.settings, loaded, failures))
}

/// The certificate module runtime state: the published SNI index, the
/// current settings, per-entry failure records and a mirror of the
/// loaded set (so summary/metrics classify entries without reaching
/// into the provider).
pub struct SslState {
    provider: Arc<Provider>,
    settings: RwLock<Settings>,
    /// Entry key → (latest error text, when it happened).
    failures: Mutex<Failures>,
    /// Mirror of what is currently published in the provider.
    loaded: Mutex<Vec<Arc<LoadedCert>>>,
}

/// Loads `config_dir/ssl.json` and builds the initial certificate
/// state. A present-but-broken `ssl.json` fails module initialization;
/// a failing single entry only excludes itself from the index.
pub async fn load(config_dir: &Path) -> Result<SslState, anyhow::Error> {
    let (settings, loaded, failures) = collect(config_dir).await?;
    let provider = Provider::empty();
    provider.publish(CertIndex::build(loaded.iter().cloned()));
    Ok(SslState {
        provider: Arc::new(provider),
        settings: RwLock::new(settings),
        failures: Mutex::new(failures),
        loaded: Mutex::new(loaded),
    })
}

impl SslState {
    /// The certificate surface shared with TLS acceptors.
    pub fn provider(&self) -> Arc<Provider> {
        Arc::clone(&self.provider)
    }

    /// Snapshot of the current settings.
    pub fn settings(&self) -> Settings {
        self.settings.read().expect("settings 锁").clone()
    }

    /// Re-runs the load logic against `config_dir` and swaps the results
    /// into the running state: settings, failure records and — the part
    /// TLS acceptors observe — a freshly published provider index with a
    /// bumped version. A broken `ssl.json` leaves the state untouched.
    pub async fn reload(&self, config_dir: &Path) {
        let (settings, loaded, failures) = match collect(config_dir).await {
            Ok(collected) => collected,
            Err(error) => {
                tracing::warn!(%error, "ssl 重载失败，沿用现有证书索引");
                return;
            }
        };
        *self.settings.write().expect("settings 锁") = settings;
        *self.failures.lock().expect("failures 锁") = failures;
        self.publish(loaded);
    }

    /// Replaces the published index (bumping the provider version) and
    /// the summary/metrics mirror, keeping both in step.
    fn publish(&self, loaded: Vec<Arc<LoadedCert>>) {
        self.provider.publish(CertIndex::build(loaded.iter().cloned()));
        *self.loaded.lock().expect("loaded 锁") = loaded;
    }

    /// Classifies the published certificates (§3.3 展示与观测):
    /// expiring within the settings' `renew_before_days` window (kept
    /// disjoint from expired), already expired, and failing entries.
    pub fn summary(&self, settings: &Settings, now: SystemTime) -> CertSummary {
        let loaded = self.loaded.lock().expect("loaded 锁");
        let window = DAY * settings.renew_before_days;
        let mut expiring = 0;
        let mut expired = 0;
        for cert in loaded.iter() {
            let Some(not_after) = cert.not_after else { continue };
            if not_after < now {
                expired += 1;
            } else if not_after
                .duration_since(now)
                .is_ok_and(|remaining| remaining < window)
            {
                expiring += 1;
            }
        }
        let failing = self.failures.lock().expect("failures 锁").len();
        CertSummary {
            expiring,
            expired,
            failing,
        }
    }

    /// Prometheus-style sample pairs (§3.3 展示与观测): per certificate
    /// the whole days remaining (floor, negative once expired) and the
    /// expiry timestamp. Certificates without a known expiry are skipped.
    pub fn metrics(&self, now: SystemTime) -> Vec<(String, f64)> {
        let loaded = self.loaded.lock().expect("loaded 锁");
        let mut samples = Vec::with_capacity(loaded.len() * 2);
        for cert in loaded.iter() {
            let Some(not_after) = cert.not_after else { continue };
            let label = &*cert.entry;
            let remaining = match not_after.duration_since(now) {
                Ok(remaining) => remaining.as_secs_f64(),
                Err(error) => -error.duration().as_secs_f64(),
            };
            samples.push((
                format!("ferrumgate_cert_days_remaining{{cert=\"{label}\"}}"),
                (remaining / SECONDS_PER_DAY).floor(),
            ));
            let expires_at = not_after
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0.0, |since| since.as_secs_f64());
            samples.push((
                format!("ferrumgate_cert_expiry_timestamp_seconds{{cert=\"{label}\"}}"),
                expires_at,
            ));
        }
        samples
    }

    /// One scheduler round: re-read `ssl.json` (settings, entry set,
    /// stored content), check every enabled ACME entry with
    /// [`needs_renewal`], re-read every other source, then republish the
    /// index wholesale (§3.3 证书索引的发布). Entries that failed less
    /// than `backoff` ago keep the previous certificate and failure
    /// record; a failing load keeps the last good certificate in the
    /// index. Failing entries never block the others.
    async fn tick(&self, config_dir: &Path, backoff: Duration) {
        let config = match read_config(config_dir).await {
            Ok(config) => config,
            Err(error) => {
                // ssl.json 读不了/解析不了：维持现状，下一轮再试。
                tracing::warn!(%error, "ssl 调度轮跳过：配置不可用");
                return;
            }
        };
        // 设置随时跟随文件，阈值变化即刻生效。
        let settings = config.settings.clone();
        *self.settings.write().expect("settings 锁") = settings.clone();
        if !settings.enable {
            // 自动续签关闭：不再签发，已有证书照常使用。
            return;
        }
        let now_instant = Instant::now();
        let now = SystemTime::now();
        let previous: HashMap<String, Arc<LoadedCert>> = self
            .loaded
            .lock()
            .expect("loaded 锁")
            .iter()
            .map(|cert| (cert.entry.to_string(), Arc::clone(cert)))
            .collect();
        let outstanding = self.failures.lock().expect("failures 锁").clone();
        let mut loaded = Vec::new();
        let mut failures = Failures::default();
        for cert in config.certs.iter().filter(|cert| cert.enable) {
            // 退避期内跳过：沿用上一份证书与失败记录，interval 后再查。
            if cert.source == CertSource::Acme
                && outstanding
                    .get(&cert.key)
                    .is_some_and(|&(_, at)| now_instant.duration_since(at) < backoff)
            {
                if let Some(kept) = previous.get(&cert.key) {
                    loaded.push(Arc::clone(kept));
                }
                if let Some(recorded) = outstanding.get(&cert.key) {
                    failures.insert(cert.key.clone(), recorded.clone());
                }
                continue;
            }
            match crate::certs::source::load_entry(cert, config_dir).await {
                Ok(Some(loaded_cert)) => {
                    loaded.push(loaded_cert);
                    // TODO(WP-32): needs_renewal 命中后在这里接入真实签发；
                    // 本批次只把原因记入 failures，下一轮按退避重试。
                    if cert.source == CertSource::Acme
                        && let Some(reason) = renewal_reason(cert, &settings, now)
                    {
                        failures.insert(cert.key.clone(), (reason, now_instant));
                    }
                }
                Ok(None) => {
                    // 尚无可加载内容（未签发 / 文件暂缺 / 飞牛已删除）：
                    // 保留上一份证书照常服务；ACME 条目视为待签发。
                    if let Some(kept) = previous.get(&cert.key) {
                        loaded.push(Arc::clone(kept));
                    }
                    if cert.source == CertSource::Acme {
                        // TODO(WP-32): 在这里触发首次签发。
                        failures
                            .insert(cert.key.clone(), ("尚未签发证书".to_string(), now_instant));
                    }
                }
                Err(error) => {
                    // 加载失败：保留上一份好证书，记录最近错误。
                    if let Some(kept) = previous.get(&cert.key) {
                        loaded.push(Arc::clone(kept));
                    }
                    failures.insert(cert.key.clone(), (error, now_instant));
                }
            }
        }
        *self.failures.lock().expect("failures 锁") = failures;
        self.publish(loaded);
    }
}

/// The renewal scheduler (§3.3 续期调度): first pass after `first`, then
/// one round per `interval` (upstream defaults 30 s / 30 min). Issuance
/// itself lands with WP-32; until then rounds only record failures and
/// re-read file-backed sources. Cancellation-safe: a dropped task stops
/// between `tokio::time::sleep` points. Shutdown wiring joins a later
/// batch (不接收关闭句柄).
/// Renewal scheduler: first pass after `first`, then every `interval`;
/// entries that failed wait `backoff`. `current` hands the scheduler the
/// live [`SslState`] each round so a config reload (new generation)
/// keeps being maintained without restarting the task.
pub async fn run_scheduler(
    current: impl Fn() -> Arc<SslState> + Send + Sync + 'static,
    config_dir: PathBuf,
    first: Duration,
    interval: Duration,
    backoff: Duration,
) {
    tokio::time::sleep(first).await;
    loop {
        current().tick(&config_dir, backoff).await;
        tokio::time::sleep(interval).await;
    }
}

/// Certificate collection health at a glance (§3.3 展示与观测).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CertSummary {
    /// Within `renew_before_days` of expiry, not yet expired.
    pub expiring: usize,
    /// Past `not_after`.
    pub expired: usize,
    /// Entries with a recorded load/issuance failure.
    pub failing: usize,
}

/// Renewal decision (upstream `needsRenewal`): an entry without a
/// parsable certificate matching its configured domains/profile needs
/// (re)issuance; short-lived certificates renew within
/// `short_lived_renew_hours`, the rest within `renew_before_days`.
pub fn needs_renewal(cert: &Cert, settings: &Settings, now: SystemTime) -> bool {
    renewal_reason(cert, settings, now).is_some()
}

/// The human-readable reason an entry needs renewal, `None` when it is
/// fine as-is. [`needs_renewal`] is this function's boolean view and
/// must stay in sync with it (the scheduler records the reason text).
fn renewal_reason(cert: &Cert, settings: &Settings, now: SystemTime) -> Option<String> {
    if cert.cert_pem.trim().is_empty() {
        return Some("尚未签发证书".to_string());
    }
    let info = match CertInfo::parse(&cert.cert_pem) {
        Ok(info) => info,
        Err(_) => return Some("证书无法解析".to_string()),
    };
    if certificate_domains(&info) != configured_domains(cert) {
        return Some("证书域名与配置不一致".to_string());
    }
    if cert.issued_profile != configured_profile(cert) {
        return Some("签发时的 profile 与当前配置不一致".to_string());
    }
    let Some(not_after) = info.not_after else {
        return Some("证书没有到期时间".to_string());
    };
    let remaining = not_after.duration_since(now).unwrap_or(Duration::ZERO);
    if is_short_lived(cert, now) {
        let hours = settings.short_lived_renew_hours;
        (remaining < HOUR * hours).then(|| format!("短期证书剩余不足 {hours} 小时"))
    } else {
        let days = settings.renew_before_days;
        (remaining < DAY * days).then(|| format!("剩余不足 {days} 天"))
    }
}

/// Short-lived per upstream `isShortLived`: the entry was issued with
/// the `shortlived` profile, or the certificate's total lifetime is
/// under ten days. `now` is carried for signature symmetry with
/// [`needs_renewal`]; the lifetime check only reads the certificate's
/// own validity.
pub fn is_short_lived(cert: &Cert, _now: SystemTime) -> bool {
    if cert.issued_profile == SHORT_LIVED_PROFILE {
        return true;
    }
    // 无法解析的证书在这里不算短期——needs_renewal 已直接判重签。
    let Ok(info) = CertInfo::parse(&cert.cert_pem) else {
        return false;
    };
    match (info.not_before, info.not_after) {
        (Some(start), Some(end)) => end
            .duration_since(start)
            .is_ok_and(|lifetime| lifetime < SHORT_LIVED_LIFE),
        _ => false,
    }
}

/// The certificate's DNS SAN set, lowercased (order-insensitive).
fn certificate_domains(info: &CertInfo) -> BTreeSet<String> {
    info.dns_names.iter().map(|name| name.to_lowercase()).collect()
}

/// The `acme.domains` set (missing → empty), lowercased.
fn configured_domains(cert: &Cert) -> BTreeSet<String> {
    cert.acme
        .get("domains")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(|name| name.to_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

/// The `acme.profile` string (missing → empty), matching the empty
/// `issued_profile` of entries never issued.
fn configured_profile(cert: &Cert) -> &str {
    cert.acme
        .get("profile")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::provider::CertificateSource as _;

    /// 与 info.rs 测试同一把 rcgen 证书（P-256 自签名，有效期
    /// 2026-01-01..2027-01-01；DNS SAN example.com、*.example.com、
    /// api.example.com，另有 IP SAN）。
    const LEAF_CERT: &str = concat!(
        "-----BEGIN CERTIFICATE-----\n",
        "MIIBuDCCAV6gAwIBAgIUKWPssCtDhk0af/SNCDoOC+yKA0MwCgYIKoZIzj0EAwIw\n",
        "LzEYMBYGA1UEAwwPRmVycnVtZ2F0ZSBUZXN0MRMwEQYDVQQKDApGZXJydW1nYXRl\n",
        "MB4XDTI2MDEwMTAwMDAwMFoXDTI3MDEwMTAwMDAwMFowLzEYMBYGA1UEAwwPRmVy\n",
        "cnVtZ2F0ZSBUZXN0MRMwEQYDVQQKDApGZXJydW1nYXRlMFkwEwYHKoZIzj0CAQYI\n",
        "KoZIzj0DAQcDQgAEZDHpKn6g7Iq0ZWQ4SdgR9VRrlTu4UrPzLb/6odKh4wFA0FO7\n",
        "0eEVoXGUE/vHpyrCmHnvxuF8o0nObqODd3HCB6NYMFYwVAYDVR0RBE0wS4ILZXhh\n",
        "bXBsZS5jb22CDSouZXhhbXBsZS5jb22CD2FwaS5leGFtcGxlLmNvbYcEfwAAAYcQ\n",
        "AAAAAAAAAAAAAAAAAAAAAYcEwKgBCjAKBggqhkjOPQQDAgNIADBFAiB6CQiFvFIN\n",
        "yyavz02N2eggngsf9EuVssIWGDQkTLQZvAIhAIG+MRRcdGdO5+5ROYK5LdkIDHwn\n",
        "MdqKKm63LI10WlT3\n",
        "-----END CERTIFICATE-----\n",
    );

    /// openssl 生成的 5 天有效期自签名证书（P-256，CN=short.example.com，
    /// 无 SAN）——总有效期不足 10 天的短期证书样本。
    const SHORT_LIVED_CERT: &str = concat!(
        "-----BEGIN CERTIFICATE-----\n",
        "MIIBWDCB/6ADAgECAgEBMAoGCCqGSM49BAMCMBwxGjAYBgNVBAMMEXNob3J0LmV4\n",
        "YW1wbGUuY29tMB4XDTI2MTEyNzE2MTI1MVoXDTI2MTIwMjE2MTI1MVowHDEaMBgG\n",
        "A1UEAwwRc2hvcnQuZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n",
        "AARjuDgM5DHT+jgPvxMkHw5yViV/HsjIXsO4oIT4JjY4SbC5uSbjqntUC6oTCXHU\n",
        "Ds27E5eI462Ugyc9rSUatbaNozIwMDAdBgNVHQ4EFgQU1ia72Pa1QE98FmrOZqLb\n",
        "hCKttacwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBxszHspAIN\n",
        "lal1ljxSaXzBnA2szSEsm3QEGuO1ehykcQIhAPlTFU8wCTJFn1s+wMF7aZqDqDlX\n",
        "sx0Qkfko+O5ghxOg\n",
        "-----END CERTIFICATE-----\n",
    );

    fn default_settings() -> Settings {
        Settings {
            enable: true,
            renew_before_days: 30,
            short_lived_renew_hours: 24,
            default_email: String::new(),
        }
    }

    fn acme_cert(cert_pem: &str) -> Cert {
        Cert {
            key: "entry".to_string(),
            remark: "entry".to_string(),
            enable: true,
            source: CertSource::Acme,
            cert_pem: cert_pem.to_string(),
            ..Cert::default()
        }
    }

    /// A LEAF_CERT entry whose domains and profile match the certificate,
    /// i.e. one that only the time thresholds can flag.
    fn matched_cert(issued_profile: &str, acme_profile: Option<&str>) -> Cert {
        let mut cert = acme_cert(LEAF_CERT);
        cert.issued_profile = issued_profile.to_string();
        cert.acme
            .insert("domains".to_string(), serde_json::json!(["example.com", "*.example.com", "api.example.com"]));
        if let Some(profile) = acme_profile {
            cert.acme.insert("profile".to_string(), serde_json::json!(profile));
        }
        cert
    }

    fn expiry_of(cert_pem: &str) -> SystemTime {
        CertInfo::parse(cert_pem)
            .expect("样本证书可解析")
            .not_after
            .expect("样本证书有到期时间")
    }

    #[test]
    fn needs_renewal_reasons() {
        let settings = default_settings();
        let end = expiry_of(LEAF_CERT);

        // 未签发：没有证书内容 → 续签。
        assert!(needs_renewal(&acme_cert(""), &settings, end));
        // 解析失败 → 续签。
        assert!(needs_renewal(&acme_cert("definitely not a pem"), &settings, end));

        // 基线：域名与 profile 一致、剩余 60 天 → 不续签。
        assert!(!needs_renewal(&matched_cert("", None), &settings, end - 60 * DAY));

        // 域名变化 → 续签。
        let mut renamed = matched_cert("", None);
        renamed
            .acme
            .insert("domains".to_string(), serde_json::json!(["example.com"]));
        assert!(needs_renewal(&renamed, &settings, end - 60 * DAY));
        // 集合相等时忽略顺序与大小写 → 不续签。
        let mut recased = matched_cert("", None);
        recased.acme.insert(
            "domains".to_string(),
            serde_json::json!(["*.EXAMPLE.com", "api.EXAMPLE.com", "EXAMPLE.COM"]),
        );
        assert!(!needs_renewal(&recased, &settings, end - 60 * DAY));

        // profile 变化 → 续签；一致 → 不续签。
        assert!(needs_renewal(&matched_cert("default", None), &settings, end - 60 * DAY));
        assert!(!needs_renewal(&matched_cert("default", Some("default")), &settings, end - 60 * DAY));

        // 普通按天：剩余 31 天不续，29 天续；阈值随设置；已过期必续。
        let plain = matched_cert("", None);
        assert!(!needs_renewal(&plain, &settings, end - 31 * DAY));
        assert!(needs_renewal(&plain, &settings, end - 29 * DAY));
        let mut wider = settings.clone();
        wider.renew_before_days = 32;
        assert!(needs_renewal(&plain, &wider, end - 31 * DAY));
        assert!(needs_renewal(&plain, &settings, end + DAY));

        // 短期按小时：总有效期 5 天 < 10 天 → 按小时阈值。
        let short = acme_cert(SHORT_LIVED_CERT);
        let short_end = expiry_of(SHORT_LIVED_CERT);
        assert!(!needs_renewal(&short, &settings, short_end - 30 * HOUR));
        assert!(needs_renewal(&short, &settings, short_end - 2 * HOUR));
        let mut longer = settings.clone();
        longer.short_lived_renew_hours = 48;
        assert!(needs_renewal(&short, &longer, short_end - 30 * HOUR));

        // profile 声明的短期：长证书 + shortlived → 同样按小时阈值。
        let declared = matched_cert("shortlived", Some("shortlived"));
        assert!(!needs_renewal(&declared, &settings, end - 40 * DAY));
        assert!(needs_renewal(&declared, &settings, end - 23 * HOUR));
    }

    #[test]
    fn is_short_lived_by_profile_or_life() {
        let now = SystemTime::now();
        let mut long = acme_cert(LEAF_CERT);
        assert!(!is_short_lived(&long, now), "一年有效期不是短期证书");
        long.issued_profile = "shortlived".to_string();
        assert!(is_short_lived(&long, now), "profile 声明即短期");
        assert!(
            is_short_lived(&acme_cert(SHORT_LIVED_CERT), now),
            "总有效期 5 天不足 10 天"
        );
    }

    #[tokio::test]
    async fn schedule_first_then_interval_then_backoff() {
        let dir = tempfile::tempdir().expect("临时目录");
        std::fs::write(
            dir.path().join("ssl.json"),
            r#"{"settings":{"enable":true},"certs":[{"key":"renew-me","remark":"renew-me","enable":true,"source":"acme"}]}"#,
        )
        .expect("写 ssl.json");
        let state = Arc::new(load(dir.path()).await.expect("初始加载"));
        let mut version = state.provider().subscribe();
        // load 已发布一次（空）索引。
        assert_eq!(*version.borrow_and_update(), 1);
        assert!(
            state.failures.lock().expect("failures 锁").is_empty(),
            "加载阶段 Ok(None) 不记失败"
        );

        tokio::spawn(run_scheduler(
            {
                let state = Arc::clone(&state);
                move || Arc::clone(&state)
            },
            dir.path().to_path_buf(),
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(50),
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;

        let failures = state.failures.lock().expect("failures 锁");
        let (reason, _) = failures
            .get("renew-me")
            .expect("未签发的 ACME 条目应记入 failures");
        assert_eq!(reason, "尚未签发证书");
        drop(failures);
        assert!(
            *version.borrow() >= 2,
            "每个调度轮都重建索引并递增版本（首查至少一轮）"
        );
    }

    #[tokio::test]
    async fn renewal_disabled_keeps_existing_certs() {
        let dir = tempfile::tempdir().expect("临时目录");
        std::fs::write(
            dir.path().join("ssl.json"),
            r#"{"settings":{"enable":false},"certs":[{"key":"parked","remark":"parked","enable":true,"source":"acme"}]}"#,
        )
        .expect("写 ssl.json");
        let state = Arc::new(load(dir.path()).await.expect("初始加载"));
        // 预置一张在服务的证书：关闭续签后它必须原样保留。
        let mut fixture = LoadedCert::fixture(
            vec!["parked.example.com".to_string()],
            Vec::new(),
            Some(SystemTime::now() + 60 * DAY),
        );
        fixture.entry = "parked".into();
        state.publish(vec![Arc::new(fixture)]);
        let mut version = state.provider().subscribe();
        assert_eq!(*version.borrow_and_update(), 2);

        tokio::spawn(run_scheduler(
            {
                let state = Arc::clone(&state);
                move || Arc::clone(&state)
            },
            dir.path().to_path_buf(),
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(50),
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(
            state.failures.lock().expect("failures 锁").is_empty(),
            "关闭续签的调度轮不产生失败记录"
        );
        assert_eq!(*version.borrow(), 2, "调度轮直接跳过，不发布新索引");
        assert!(
            state.provider().has_certificate("parked.example.com"),
            "已有证书照常服务"
        );
    }

    #[test]
    fn metrics_and_selfcheck() {
        let now = SystemTime::now();
        let state = SslState {
            provider: Arc::new(Provider::empty()),
            settings: RwLock::new(default_settings()),
            failures: Mutex::new(Failures::from([(
                "broken".to_string(),
                ("签发失败".to_string(), Instant::now()),
            )])),
            loaded: Mutex::new(Vec::new()),
        };
        let entry = |name: &str, not_after: SystemTime| {
            let mut fixture = LoadedCert::fixture(
                vec![format!("{name}.example.com")],
                Vec::new(),
                Some(not_after),
            );
            fixture.entry = name.into();
            Arc::new(fixture)
        };
        state.publish(vec![
            entry("ok", now + 60 * DAY),
            entry("soon", now + 10 * DAY),
            entry("past", now - DAY),
        ]);

        // 摘要：30 天阈值内即将到期 1 张、已过期 1 张、失败 1 个条目。
        let summary = state.summary(&state.settings(), now);
        assert_eq!(
            summary,
            CertSummary {
                expiring: 1,
                expired: 1,
                failing: 1,
            }
        );

        // 指标：两个键齐全；天数向下取整且可为负。
        let metrics = state.metrics(now);
        let by_name: BTreeMap<&str, f64> = metrics
            .iter()
            .map(|(name, value)| (name.as_str(), *value))
            .collect();
        assert_eq!(
            by_name["ferrumgate_cert_days_remaining{cert=\"ok\"}"],
            60.0
        );
        assert_eq!(
            by_name["ferrumgate_cert_days_remaining{cert=\"soon\"}"],
            10.0
        );
        assert_eq!(
            by_name["ferrumgate_cert_days_remaining{cert=\"past\"}"],
            -1.0
        );
        assert_eq!(
            by_name["ferrumgate_cert_expiry_timestamp_seconds{cert=\"ok\"}"],
            (now + 60 * DAY)
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("unix 时间")
                .as_secs_f64()
        );
        assert_eq!(
            by_name["ferrumgate_cert_expiry_timestamp_seconds{cert=\"past\"}"],
            (now - DAY)
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("unix 时间")
                .as_secs_f64()
        );
    }

    #[tokio::test]
    async fn load_defaults_when_ssl_json_missing() {
        let dir = tempfile::tempdir().expect("临时目录");
        let state = load(dir.path()).await.expect("缺文件按默认配置加载");
        let settings = state.settings();
        assert!(settings.enable);
        assert_eq!(settings.renew_before_days, 30);
        assert_eq!(settings.short_lived_renew_hours, 24);
        assert_eq!(*state.provider().subscribe().borrow(), 1);
        assert!(!state.provider().has_certificate("anything.example.com"));
    }

    #[tokio::test]
    async fn load_fails_when_ssl_json_unparseable() {
        let dir = tempfile::tempdir().expect("临时目录");
        std::fs::write(dir.path().join("ssl.json"), "{ broken").expect("写坏文件");
        assert!(
            load(dir.path()).await.is_err(),
            "读出但解析失败必须让整个模块初始化失败"
        );
    }
}
