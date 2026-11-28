//! Normalization and validation for the DDNS model (WP-40): pure functions
//! over plain data. `normalize` applies the upstream defaults (intervals,
//! timeouts) and canonicalizes user-entered text (lowercased owners,
//! trimmed zones, retired query URLs swapped); `validate` collects every
//! problem instead of stopping at the first. Provider credentials are
//! checked against the compiled provider's [`fg_dns::Meta`] — required
//! `id`/`secret` and required `extra` fields — and the `********` mask
//! submitted by the management UI is resolved against the stored values
//! before validation runs (`merge_credentials`).

use std::collections::BTreeSet;

use crate::ip_source;
use crate::model::{
    Credentials, FileConfig, IpSource, IpSourceKind, Record, RecordType, Task, limits,
};

/// The `********` placeholder the management UI sends for unchanged
/// secrets (fg-admin `SECRET_MASK`).
pub const SECRET_MASK: &str = "********";

/// A collected validation problem: the offending field path and reason.
#[derive(Debug, PartialEq, Eq)]
pub struct Problem {
    pub field: String,
    pub reason: String,
}

impl Problem {
    fn new(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

/// Whether a submitted value means "keep the stored secret".
pub fn is_masked(value: &str) -> bool {
    value.is_empty() || value == SECRET_MASK
}

/// Resolves `********` and empty submissions against the stored
/// credentials (fg-admin `merge` hook semantics): the secret and each
/// `extra` value keep their previous value when the submitted form carries
/// the mask.
pub fn merge_credentials(old: &Credentials, submitted: &mut Credentials) {
    if is_masked(&submitted.secret) {
        submitted.secret = old.secret.clone();
    }
    submitted.secret = submitted.secret.trim().to_owned();
    for (key, value) in &mut submitted.extra {
        if is_masked(value)
            && let Some(previous) = old.extra.get(key.as_str())
        {
            *value = previous.clone();
        }
    }
}

/// Applies defaults and canonicalizes: check period 300 s (floor 30 s),
/// forced sync 3600 s, HTTP timeout 20 s (ceiling 600 s), webhook timeout
/// 10 s (ceiling 60 s), lowercased owner names, trimmed zones, retired IP
/// query URLs replaced (logged), duplicates dropped.
pub fn normalize(mut config: FileConfig) -> FileConfig {
    for task in &mut config.tasks {
        task.key = task.key.trim().to_owned();
        task.name = task.name.trim().to_owned();
        task.group = task.group.trim().to_owned();
        task.provider = task.provider.trim().to_owned();
        task.remark = task.remark.trim().to_owned();
        task.interval = if task.interval == 0 {
            limits::INTERVAL_DEFAULT
        } else {
            task.interval.max(limits::INTERVAL_MIN)
        };
        task.force_interval = if task.force_interval == 0 {
            limits::FORCE_INTERVAL_DEFAULT
        } else {
            task.force_interval
        };
        task.http_timeout = if task.http_timeout == 0 {
            limits::HTTP_TIMEOUT_DEFAULT
        } else {
            task.http_timeout.min(limits::HTTP_TIMEOUT_MAX)
        };
        task.credentials.id = task.credentials.id.trim().to_owned();
        task.credentials.secret = task.credentials.secret.trim().to_owned();
        task.credentials.extra = task
            .credentials
            .extra
            .iter()
            .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
            .filter(|(key, _)| !key.is_empty())
            .collect();
        task.ipv4 = normalize_source(&task.ipv4);
        task.ipv6 = normalize_source(&task.ipv6);
        for record in &mut task.records {
            *record = normalize_record(record);
        }
        normalize_webhook(&mut task.webhook);
    }
    config
}

fn normalize_source(source: &IpSource) -> IpSource {
    let mut source = source.clone();
    source.interface = source.interface.trim().to_owned();
    source.regex = source.regex.trim().to_owned();
    source.command = source.command.trim().to_owned();
    let (urls, _changed) = ip_source::replace_retired_urls(&source.urls);
    source.urls = urls.into_iter().take(limits::URLS_MAX).collect();
    source
}

fn normalize_record(record: &Record) -> Record {
    let mut record = record.clone();
    record.key = record.key.trim().to_owned();
    record.zone = record.zone.trim().trim_end_matches('.').to_owned();
    // Owner names are stored lowercase and sent lowercase (legacy files
    // included); a trailing dot is dropped; the apex is `@`.
    record.sub = crate::remote::normalized_sub(record.sub.trim().trim_end_matches('.'));
    record.value = record.value.trim().to_owned();
    record.line = record.line.trim().to_owned();
    record.remark = record.remark.trim().to_owned();
    record.group = record.group.trim().to_owned();
    record
}

fn normalize_webhook(webhook: &mut crate::model::WebhookConfig) {
    webhook.url = webhook.url.trim().to_owned();
    webhook.method = webhook.method.trim().to_ascii_uppercase();
    webhook.body = webhook.body.clone();
    webhook.proxy = webhook.proxy.trim().to_owned();
    webhook.headers = webhook
        .headers
        .iter()
        .map(|header| header.trim().to_owned())
        .filter(|header| !header.is_empty())
        .take(limits::WEBHOOK_HEADERS_MAX)
        .collect();
    webhook.success_content = webhook
        .success_content
        .iter()
        .map(|needle| needle.trim().to_owned())
        .filter(|needle| !needle.is_empty())
        .collect();
    webhook.timeout = if webhook.timeout == 0 {
        limits::WEBHOOK_TIMEOUT_DEFAULT
    } else {
        webhook.timeout.min(limits::WEBHOOK_TIMEOUT_MAX)
    };
}

/// Validates a normalized config, collecting every problem.
pub fn validate(config: &FileConfig) -> Vec<Problem> {
    let mut problems = Vec::new();
    let mut task_keys = BTreeSet::new();
    for task in &config.tasks {
        let prefix = if task.key.is_empty() {
            format!("tasks.{}", task.name)
        } else {
            format!("tasks.{}", task.key)
        };
        if task.key.is_empty() {
            problems.push(Problem::new("key", "key 不能为空"));
        } else if !task_keys.insert(task.key.as_str()) {
            problems.push(Problem::new("key", format!("重复的 key {}", task.key)));
        }
        if task.name.is_empty() {
            problems.push(Problem::new(format!("{prefix}.name"), "名称不能为空"));
        } else if task.name.chars().count() > limits::NAME_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.name"),
                format!("名称最多 {} 个字符", limits::NAME_MAX_CHARS),
            ));
        }
        if task.group.chars().count() > limits::GROUP_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.group"),
                format!("分组最多 {} 个字符", limits::GROUP_MAX_CHARS),
            ));
        }
        if task.remark.chars().count() > limits::REMARK_FIELD_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.remark"),
                format!("备注最多 {} 个字符", limits::REMARK_FIELD_MAX_CHARS),
            ));
        }
        if task.interval < limits::INTERVAL_MIN {
            problems.push(Problem::new(
                format!("{prefix}.interval"),
                format!("检查周期不能小于 {} 秒", limits::INTERVAL_MIN),
            ));
        }
        validate_provider(&prefix, task, &mut problems);
        validate_source(&prefix, "ipv4", &task.ipv4, &mut problems);
        validate_source(&prefix, "ipv6", &task.ipv6, &mut problems);
        validate_records(&prefix, task, &mut problems);
        validate_webhook(&prefix, &task.webhook, &mut problems);
    }
    problems
}

/// Provider checks: the name must be known (registered or at least a
/// known adapter name of this build); a compiled adapter's required
/// credentials are derived from its `Meta` (`id_label`/`secret_label`
/// non-empty means required, `Field.required` extra fields must be
/// filled), plus the semantic check for the Cloudflare proxy field.
fn validate_provider(prefix: &str, task: &Task, problems: &mut Vec<Problem>) {
    if task.provider.is_empty() {
        problems.push(Problem::new(
            format!("{prefix}.provider"),
            "DNS 服务商不能为空",
        ));
        return;
    }
    let compiled = remote_meta(task.provider.as_str());
    let known = compiled.is_some() || fg_dns::ALL_NAMES.contains(&task.provider.as_str());
    if !known {
        problems.push(Problem::new(
            format!("{prefix}.provider"),
            format!("不支持的 DNS 服务商 {}", task.provider),
        ));
        return;
    }
    let Some(meta) = compiled else {
        // Known adapter name but not compiled into this build: the
        // credentials cannot be checked here, the providers endpoint
        // flags it as unavailable.
        return;
    };
    let creds = &task.credentials;
    if !meta.id_label.is_empty() && creds.id.is_empty() {
        problems.push(Problem::new(
            format!("{prefix}.credentials.id"),
            format!("{} 不能为空", meta.id_label),
        ));
    }
    if !meta.secret_label.is_empty() && creds.secret.is_empty() {
        problems.push(Problem::new(
            format!("{prefix}.credentials.secret"),
            format!("{} 不能为空", meta.secret_label),
        ));
    }
    for field in meta.extra {
        if field.required
            && creds
                .extra
                .get(field.key)
                .is_none_or(|value| value.trim().is_empty())
        {
            problems.push(Problem::new(
                format!("{prefix}.credentials.extra.{}", field.key),
                format!("{} 不能为空", field.label),
            ));
        }
        // Cloudflare proxy state: empty (unmanaged) or a boolean.
        if meta.name == "cloudflare"
            && field.key == "proxied"
            && let Some(value) = creds
                .extra
                .get("proxied")
                .filter(|value| !value.trim().is_empty())
            && !matches!(value.trim().to_ascii_lowercase().as_str(), "true" | "false")
        {
            problems.push(Problem::new(
                format!("{prefix}.credentials.extra.proxied"),
                "代理状态只支持 true / false 或留空".to_owned(),
            ));
        }
    }
}

fn remote_meta(provider: &str) -> Option<&'static fg_dns::Meta> {
    fg_dns::registry()
        .iter()
        .find(|(meta, _)| meta.name == provider)
        .map(|(meta, _)| *meta)
}

fn validate_source(prefix: &str, family: &str, source: &IpSource, problems: &mut Vec<Problem>) {
    let path = format!("{prefix}.{family}");
    if !source.enable {
        return;
    }
    match source.kind {
        IpSourceKind::Url => {
            if source.urls.is_empty() {
                problems.push(Problem::new(format!("{path}.urls"), "查询地址不能为空"));
            }
            if source.urls.len() > limits::URLS_MAX {
                problems.push(Problem::new(
                    format!("{path}.urls"),
                    format!("查询地址最多 {} 个", limits::URLS_MAX),
                ));
            }
        }
        IpSourceKind::NetInterface => {
            if source.interface.is_empty() {
                problems.push(Problem::new(
                    format!("{path}.interface"),
                    "网卡名称不能为空",
                ));
            }
        }
        IpSourceKind::Command => {
            if source.command.is_empty() {
                problems.push(Problem::new(format!("{path}.command"), "命令不能为空"));
            }
        }
    }
    if !source.regex.is_empty()
        && let Err(error) = regex::Regex::new(&source.regex)
    {
        problems.push(Problem::new(
            format!("{path}.regex"),
            format!("正则无效：{error}"),
        ));
    }
}

fn validate_records(prefix: &str, task: &Task, problems: &mut Vec<Problem>) {
    if task.records.len() > limits::RECORDS_MAX {
        problems.push(Problem::new(
            format!("{prefix}.records"),
            format!("每任务最多 {} 条记录", limits::RECORDS_MAX),
        ));
    }
    let mut keys = BTreeSet::new();
    for record in &task.records {
        let path = if record.key.is_empty() {
            format!("{prefix}.records")
        } else {
            format!("{prefix}.records.{}", record.key)
        };
        if record.key.is_empty() {
            problems.push(Problem::new(&path, "记录 key 不能为空"));
        } else if !keys.insert(record.key.as_str()) {
            problems.push(Problem::new(
                &path,
                format!("重复的记录 key {}", record.key),
            ));
        }
        if record.zone.is_empty() {
            problems.push(Problem::new(format!("{path}.zone"), "主域名不能为空"));
        }
        validate_sub(&path, &record.sub, problems);
        if matches!(record.typ, RecordType::A | RecordType::AAAA)
            && record.value.contains('{')
            && !crate::vars::references_stun(&record.value)
            && !record.value.contains("{ipv4Addr}")
            && !record.value.contains("{ipv6Addr}")
        {
            problems.push(Problem::new(
                format!("{path}.value"),
                "地址记录的变量只支持 {{ipv4Addr}} / {{ipv6Addr}} / STUN 变量",
            ));
        }
    }
}

fn validate_sub(path: &str, sub: &str, problems: &mut Vec<Problem>) {
    if sub.len() > 253 {
        problems.push(Problem::new(format!("{path}.sub"), "主机记录过长"));
        return;
    }
    if !sub.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@' | b'*')
    }) {
        problems.push(Problem::new(
            format!("{path}.sub"),
            "主机记录只能包含字母、数字、- _ . @ *",
        ));
    }
}

fn validate_webhook(
    prefix: &str,
    webhook: &crate::model::WebhookConfig,
    problems: &mut Vec<Problem>,
) {
    if !webhook.enable {
        return;
    }
    let path = format!("{prefix}.webhook");
    if !webhook.url.starts_with("http://") && !webhook.url.starts_with("https://") {
        problems.push(Problem::new(
            format!("{path}.url"),
            "URL 需以 http:// 或 https:// 开头",
        ));
    }
    if !["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&webhook.method.as_str()) {
        problems.push(Problem::new(
            format!("{path}.method"),
            "方法只支持 GET / POST / PUT / PATCH / DELETE",
        ));
    }
    for header in &webhook.headers {
        if parse_header(header).is_none() {
            problems.push(Problem::new(
                format!("{path}.headers"),
                format!("请求头需为 \"名称: 值\"：{header}"),
            ));
        }
    }
}

/// Splits a raw `Key: Value` header line (also used by the webhook).
pub fn parse_header(header: &str) -> Option<(String, String)> {
    let (name, value) = header.split_once(':')?;
    let name = name.trim();
    if name.is_empty() || name.contains(char::is_whitespace) {
        return None;
    }
    Some((name.to_owned(), value.trim().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Credentials, IpSource, Settings};

    fn base_task() -> Task {
        Task {
            key: "abc123def456".into(),
            name: "home".into(),
            enable: true,
            provider: "cloudflare".into(),
            credentials: Credentials {
                id: "user@example.com".into(),
                secret: "token".into(),
                ..Credentials::default()
            },
            ipv4: IpSource {
                enable: true,
                urls: vec!["https://api.ipify.org".into()],
                ..IpSource::default()
            },
            records: vec![Record {
                key: "rec000000001".into(),
                enable: true,
                zone: "example.com".into(),
                sub: "Home".into(),
                ..Record::default()
            }],
            ..Task::default()
        }
    }

    #[test]
    fn valid_config_has_no_problems() {
        let config = normalize(FileConfig {
            settings: Settings {
                enable: true,
                ..Settings::default()
            },
            tasks: vec![base_task()],
        });
        assert_eq!(validate(&config), Vec::new(), "{config:?}");
    }

    #[test]
    fn normalize_applies_defaults_and_clamps() {
        let mut task = base_task();
        task.interval = 1;
        task.force_interval = 0;
        task.http_timeout = 100_000;
        task.webhook.enable = true;
        task.webhook.url = " https://example.com/hook ".into();
        task.webhook.method = " post ".into();
        task.webhook.timeout = 0;
        let config = normalize(FileConfig {
            tasks: vec![task],
            ..FileConfig::default()
        });
        let task = &config.tasks[0];
        assert_eq!(task.interval, 30, "below the floor becomes the floor");
        assert_eq!(task.force_interval, 3600);
        assert_eq!(task.http_timeout, 600);
        assert_eq!(task.webhook.url, "https://example.com/hook");
        assert_eq!(task.webhook.method, "POST");
        assert_eq!(task.webhook.timeout, 10);
        // A zero interval normalizes to the default (not the floor).
        let mut task = base_task();
        task.interval = 0;
        let config = normalize(FileConfig {
            tasks: vec![task],
            ..FileConfig::default()
        });
        assert_eq!(config.tasks[0].interval, 300);
    }

    #[test]
    fn normalize_lowercases_sub_and_trims_zone_dot() {
        let mut task = base_task();
        task.records[0].sub = "MiXeD.Case.".into();
        task.records[0].zone = "Example.COM.".into();
        let config = normalize(FileConfig {
            tasks: vec![task],
            ..FileConfig::default()
        });
        assert_eq!(config.tasks[0].records[0].sub, "mixed.case");
        assert_eq!(config.tasks[0].records[0].zone, "Example.COM");
        // The apex keeps its canonical form.
        let mut task = base_task();
        task.records[0].sub = String::new();
        let config = normalize(FileConfig {
            tasks: vec![task],
            ..FileConfig::default()
        });
        assert_eq!(config.tasks[0].records[0].sub, "@");
    }

    #[test]
    fn normalize_replaces_retired_urls() {
        let mut task = base_task();
        task.ipv4.urls = vec!["https://4.ipw.cn".into(), " https://api.ipify.org ".into()];
        let config = normalize(FileConfig {
            tasks: vec![task],
            ..FileConfig::default()
        });
        assert_eq!(
            config.tasks[0].ipv4.urls,
            ["https://api.ipify.org"],
            "the retired ipw.cn address is swapped, trimmed and deduplicated"
        );
    }

    #[test]
    fn validate_reports_provider_problems() {
        let mut task = base_task();
        task.provider = "not-a-provider".into();
        let config = normalize(FileConfig {
            tasks: vec![task],
            ..FileConfig::default()
        });
        let problems = validate(&config);
        assert!(
            problems
                .iter()
                .any(|problem| problem.field.ends_with(".provider")),
            "{problems:?}"
        );

        // A compiled provider requires its credentials per Meta labels.
        let mut task = base_task();
        task.credentials.secret = String::new();
        let config = normalize(FileConfig {
            tasks: vec![task],
            ..FileConfig::default()
        });
        let problems = validate(&config);
        assert!(
            problems
                .iter()
                .any(|problem| problem.field.ends_with("credentials.secret")),
            "{problems:?}"
        );

        // A Cloudflare proxy state must be a boolean (or empty).
        let mut task = base_task();
        task.credentials
            .extra
            .insert("proxied".into(), "maybe".into());
        let config = normalize(FileConfig {
            tasks: vec![task],
            ..FileConfig::default()
        });
        let problems = validate(&config);
        assert!(
            problems
                .iter()
                .any(|problem| problem.field.ends_with("extra.proxied")),
            "{problems:?}"
        );

        // A provider name that is known but not compiled passes
        // (the providers endpoint marks it unavailable).
        let mut task = base_task();
        task.provider = "alidns".into();
        task.credentials.secret = "token".into();
        let config = normalize(FileConfig {
            tasks: vec![task],
            ..FileConfig::default()
        });
        let remaining = validate(&config);
        assert!(
            remaining
                .iter()
                .all(|problem| !problem.field.ends_with(".provider")),
            "{remaining:?}"
        );
    }

    #[test]
    fn validate_reports_source_problems() {
        let mut task = base_task();
        task.ipv4 = IpSource {
            enable: true,
            kind: IpSourceKind::NetInterface,
            interface: " ".into(),
            regex: "(".into(),
            ..IpSource::default()
        };
        task.ipv6 = IpSource {
            enable: true,
            kind: IpSourceKind::Command,
            command: String::new(),
            ..IpSource::default()
        };
        let config = normalize(FileConfig {
            tasks: vec![task],
            ..FileConfig::default()
        });
        let fields: Vec<_> = validate(&config)
            .into_iter()
            .map(|problem| problem.field)
            .collect();
        assert!(
            fields.iter().any(|field| field.ends_with("ipv4.interface")),
            "{fields:?}"
        );
        assert!(
            fields.iter().any(|field| field.ends_with("ipv4.regex")),
            "{fields:?}"
        );
        assert!(
            fields.iter().any(|field| field.ends_with("ipv6.command")),
            "{fields:?}"
        );
        // Disabled sources are not checked.
        let mut task = base_task();
        task.ipv4 = IpSource::default();
        let config = normalize(FileConfig {
            tasks: vec![task],
            ..FileConfig::default()
        });
        let remaining = validate(&config);
        assert!(
            remaining
                .iter()
                .all(|problem| !problem.field.contains(".ipv4.")),
            "{remaining:?}"
        );
    }

    #[test]
    fn validate_reports_record_problems() {
        let mut task = base_task();
        task.records[0].zone = String::new();
        task.records[0].sub = "bad space".into();
        let mut second = task.records[0].clone();
        second.zone = "example.org".into();
        task.records.push(second);
        let config = normalize(FileConfig {
            tasks: vec![task],
            ..FileConfig::default()
        });
        let text = format!("{:?}", validate(&config));
        assert!(text.contains("主域名不能为空"), "{text}");
        assert!(text.contains("重复的记录 key"), "{text}");
        assert!(text.contains("主机记录只能"), "{text}");
    }

    #[test]
    fn validate_reports_webhook_problems() {
        let mut task = base_task();
        task.webhook.enable = true;
        task.webhook.url = "ftp://example.com".into();
        task.webhook.method = "TRACE".into();
        task.webhook.headers = vec!["broken".into()];
        let config = normalize(FileConfig {
            tasks: vec![task],
            ..FileConfig::default()
        });
        let text = format!("{:?}", validate(&config));
        assert!(text.contains("URL 需以"), "{text}");
        assert!(text.contains("方法只支持"), "{text}");
        assert!(text.contains("请求头需为"), "{text}");
        // The interval floor is applied by normalize, never reported.
        let config = normalize(FileConfig {
            tasks: vec![base_task()],
            ..FileConfig::default()
        });
        assert!(validate(&config).is_empty(), "{config:?}");
    }

    #[test]
    fn merge_credentials_fills_mask_and_empty() {
        let old = Credentials {
            id: "id".into(),
            secret: "stored".into(),
            extra: [("proxied".into(), "true".into())].into(),
        };
        // Mask and empty both keep the stored secret.
        let mut submitted = Credentials {
            id: "id".into(),
            secret: SECRET_MASK.into(),
            extra: [("proxied".into(), "false".into())].into(),
        };
        merge_credentials(&old, &mut submitted);
        assert_eq!(submitted.secret, "stored");
        assert_eq!(
            submitted.extra["proxied"], "false",
            "unmasked values are kept"
        );
        let mut submitted = Credentials {
            secret: String::new(),
            ..Credentials::default()
        };
        merge_credentials(&old, &mut submitted);
        assert_eq!(submitted.secret, "stored");
        // An explicitly different value replaces the stored one.
        let mut submitted = Credentials {
            secret: "rotated".into(),
            ..Credentials::default()
        };
        merge_credentials(&old, &mut submitted);
        assert_eq!(submitted.secret, "rotated");
    }

    #[test]
    fn header_parsing_requires_name() {
        assert_eq!(
            parse_header("X-Token: abc"),
            Some(("X-Token".into(), "abc".into()))
        );
        assert_eq!(parse_header(":v"), None);
        assert_eq!(parse_header("no colon"), None);
    }
}
