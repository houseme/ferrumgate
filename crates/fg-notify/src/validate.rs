//! Normalization and validation for the notify model (WP-68): pure
//! functions over plain data. `normalize` applies the upstream defaults
//! (retry counts stay `None`, Bark/ntfy default servers, SMTP port per
//! security mode) and canonicalizes user-entered text; `validate` collects
//! every problem instead of stopping at the first. Channel secrets are
//! masked as `********` in API output; a submission carrying the mask or
//! empty keeps the stored value (`merge_channel`, the fg-admin `merge`
//! hook semantics).

use crate::model::{
    Channel, ChannelConfig, ChannelKind, ChannelProxy, FileConfig, Rule, Settings, SettingsProxy,
    limits,
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

/// The proxy schemes accepted for custom proxy URLs (WP-68 §3.3).
pub const PROXY_SCHEMES: [&str; 4] = ["http", "https", "socks5", "socks5h"];

/// Resolves masked secret fields (and a redacted custom proxy URL) against
/// the stored channel: each secret of the channel's kind keeps its
/// previous value when the submitted form carries the mask or is empty.
pub fn merge_channel(old: &Channel, submitted: &mut Channel) {
    let old_json = serde_json::to_value(&old.config).expect("config serializes");
    let mut new_json = serde_json::to_value(&submitted.config).expect("config serializes");
    if let (Some(old_fields), Some(new_fields)) = (old_json.as_object(), new_json.as_object_mut()) {
        for field in old.secret_fields() {
            if let Some(value) = new_fields.get_mut(*field) {
                let text = value.as_str().unwrap_or_default().to_owned();
                if is_masked(&text)
                    && let Some(previous) = old_fields.get(*field).and_then(|value| value.as_str())
                {
                    *value = serde_json::Value::from(previous);
                }
            }
        }
    }
    submitted.config =
        serde_json::from_value(new_json).expect("masked merge keeps the config shape");
    // A custom proxy URL whose password was redacted for display keeps the
    // stored URL (the redacted form alone cannot dial).
    if let (ChannelProxy::Custom(old_url), ChannelProxy::Custom(submitted_url)) =
        (&old.proxy, &mut submitted.proxy)
        && submitted_url != old_url
        && crate::proxy::redact(old_url) == *submitted_url
    {
        submitted.proxy = ChannelProxy::Custom(old_url.clone());
    }
}

/// Applies defaults and canonicalizes: trimmed text, uppercase webhook
/// method (default POST), default Bark/ntfy servers, default SMTP port per
/// security mode.
pub fn normalize(mut config: FileConfig) -> FileConfig {
    let settings = &mut config.settings;
    settings.language = settings.language.trim().to_owned();
    settings.server_name = settings.server_name.trim().to_owned();
    for channel in &mut config.channels {
        normalize_channel(channel);
    }
    for rule in &mut config.rules {
        normalize_rule(rule);
    }
    config
}

fn normalize_channel(channel: &mut Channel) {
    channel.key = channel.key.trim().to_owned();
    channel.name = channel.name.trim().to_owned();
    channel.group = channel.group.trim().to_owned();
    channel.remark = channel.remark.trim().to_owned();
    let config = &mut channel.config;
    config.url = config.url.trim().to_owned();
    config.method = match config.method.trim() {
        "" => "POST".to_owned(),
        method => method.to_ascii_uppercase(),
    };
    config.headers = config
        .headers
        .iter()
        .map(|header| header.trim().to_owned())
        .filter(|header| !header.is_empty())
        .collect();
    config.body = config.body.trim().to_owned();
    config.token = config.token.trim().to_owned();
    config.chat_id = config.chat_id.trim().to_owned();
    config.device_key = config.device_key.trim().to_owned();
    config.server = config.server.trim().to_owned();
    match channel.kind {
        ChannelKind::Bark if config.server.is_empty() => {
            config.server = limits::BARK_SERVER_DEFAULT.to_owned();
        }
        ChannelKind::Ntfy if config.server.is_empty() => {
            config.server = limits::NTFY_SERVER_DEFAULT.to_owned();
        }
        _ => {}
    }
    config.topic = config.topic.trim().to_owned();
    config.username = config.username.trim().to_owned();
    config.password = config.password.trim().to_owned();
    config.user = config.user.trim().to_owned();
    config.send_key = config.send_key.trim().to_owned();
    config.key = config.key.trim().to_owned();
    config.access_token = config.access_token.trim().to_owned();
    config.secret = config.secret.trim().to_owned();
    config.host = config.host.trim().to_owned();
    config.smtp_user = config.smtp_user.trim().to_owned();
    config.from = config.from.trim().to_owned();
    config.to = config
        .to
        .iter()
        .map(|address| address.trim().to_owned())
        .filter(|address| !address.is_empty())
        .take(limits::EMAIL_RECIPIENTS_MAX)
        .collect();
    if config.port == 0 {
        config.port = config.security.default_port();
    }
}

fn normalize_rule(rule: &mut Rule) {
    rule.key = rule.key.trim().to_owned();
    rule.name = rule.name.trim().to_owned();
    rule.group = rule.group.trim().to_owned();
    rule.remark = rule.remark.trim().to_owned();
    rule.events = rule
        .events
        .iter()
        .map(|event| event.trim().to_owned())
        .filter(|event| !event.is_empty())
        .take(limits::EVENTS_MAX)
        .collect();
    rule.channels = rule
        .channels
        .iter()
        .map(|key| key.trim().to_owned())
        .filter(|key| !key.is_empty())
        .collect();
    rule.template = rule.template.trim().to_owned();
    if let Some(silence) = &mut rule.silence {
        silence.dedup_key = silence.dedup_key.trim().to_owned();
    }
}

/// Validates a normalized config, collecting every problem.
pub fn validate(config: &FileConfig) -> Vec<Problem> {
    let mut problems = Vec::new();
    validate_settings(&config.settings, &mut problems);
    let mut channel_keys = std::collections::BTreeSet::new();
    for channel in &config.channels {
        let prefix = item_prefix("channels", &channel.key, &channel.name);
        if channel.key.is_empty() {
            problems.push(Problem::new(&prefix, "key 不能为空"));
        } else if !channel_keys.insert(channel.key.as_str()) {
            problems.push(Problem::new(&prefix, format!("重复的 key {}", channel.key)));
        }
        if channel.name.is_empty() {
            problems.push(Problem::new(format!("{prefix}.name"), "名称不能为空"));
        } else if channel.name.chars().count() > limits::NAME_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.name"),
                format!("名称最多 {} 个字符", limits::NAME_MAX_CHARS),
            ));
        }
        if channel.group.chars().count() > limits::GROUP_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.group"),
                format!("分组最多 {} 个字符", limits::GROUP_MAX_CHARS),
            ));
        }
        if channel.remark.chars().count() > limits::REMARK_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.remark"),
                format!("备注最多 {} 个字符", limits::REMARK_MAX_CHARS),
            ));
        }
        validate_channel_proxy(&format!("{prefix}.proxy"), &channel.proxy, &mut problems);
        validate_channel_config(&prefix, channel, &mut problems);
    }
    if config.channels.len() > limits::CHANNELS_MAX {
        problems.push(Problem::new(
            "channels",
            format!("最多 {} 个渠道", limits::CHANNELS_MAX),
        ));
    }
    let mut rule_keys = std::collections::BTreeSet::new();
    for rule in &config.rules {
        let prefix = item_prefix("rules", &rule.key, &rule.name);
        if rule.key.is_empty() {
            problems.push(Problem::new(&prefix, "key 不能为空"));
        } else if !rule_keys.insert(rule.key.as_str()) {
            problems.push(Problem::new(&prefix, format!("重复的 key {}", rule.key)));
        }
        if rule.name.is_empty() {
            problems.push(Problem::new(format!("{prefix}.name"), "名称不能为空"));
        } else if rule.name.chars().count() > limits::NAME_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.name"),
                format!("名称最多 {} 个字符", limits::NAME_MAX_CHARS),
            ));
        }
        if rule.group.chars().count() > limits::GROUP_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.group"),
                format!("分组最多 {} 个字符", limits::GROUP_MAX_CHARS),
            ));
        }
        if rule.remark.chars().count() > limits::REMARK_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.remark"),
                format!("备注最多 {} 个字符", limits::REMARK_MAX_CHARS),
            ));
        }
        if rule.template.chars().count() > limits::TEMPLATE_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.template"),
                format!("模板最多 {} 个字符", limits::TEMPLATE_MAX_CHARS),
            ));
        }
        if rule.events.is_empty() {
            problems.push(Problem::new(
                format!("{prefix}.events"),
                "至少需要一个事件类型",
            ));
        }
        if rule.channels.is_empty() {
            problems.push(Problem::new(
                format!("{prefix}.channels"),
                "至少需要一个通知渠道",
            ));
        }
        for key in &rule.channels {
            if !channel_keys.contains(key.as_str()) {
                problems.push(Problem::new(
                    format!("{prefix}.channels"),
                    format!("未知的渠道 key {key}"),
                ));
            }
        }
        if let Some(silence) = &rule.silence {
            if silence.window_minutes == 0 {
                problems.push(Problem::new(
                    format!("{prefix}.silence.windowMinutes"),
                    "静默窗口不能为 0 分钟",
                ));
            } else if silence.window_minutes > limits::SILENCE_WINDOW_MAX {
                problems.push(Problem::new(
                    format!("{prefix}.silence.windowMinutes"),
                    format!("静默窗口最多 {} 分钟", limits::SILENCE_WINDOW_MAX),
                ));
            }
        }
    }
    if config.rules.len() > limits::RULES_MAX {
        problems.push(Problem::new(
            "rules",
            format!("最多 {} 条规则", limits::RULES_MAX),
        ));
    }
    problems
}

fn item_prefix(collection: &str, key: &str, name: &str) -> String {
    if key.is_empty() {
        format!("{collection}.{name}")
    } else {
        format!("{collection}.{key}")
    }
}

fn validate_settings(settings: &Settings, problems: &mut Vec<Problem>) {
    if settings
        .retries
        .is_some_and(|retries| retries > limits::RETRIES_MAX)
    {
        problems.push(Problem::new(
            "settings.retries",
            format!("重试次数最多 {}", limits::RETRIES_MAX),
        ));
    }
    if settings
        .pending_hours
        .is_some_and(|hours| hours > limits::PENDING_HOURS_MAX)
    {
        problems.push(Problem::new(
            "settings.pendingHours",
            format!("补推保留最多 {} 小时", limits::PENDING_HOURS_MAX),
        ));
    }
    validate_settings_proxy("settings.proxy", &settings.proxy, problems);
}

fn validate_settings_proxy(field: &str, proxy: &SettingsProxy, problems: &mut Vec<Problem>) {
    if let SettingsProxy::Custom(url) = proxy {
        check_proxy_url(field, url, problems);
    }
}

fn validate_channel_proxy(field: &str, proxy: &ChannelProxy, problems: &mut Vec<Problem>) {
    if let ChannelProxy::Custom(url) = proxy {
        check_proxy_url(field, url, problems);
    }
}

fn check_proxy_url(field: &str, url: &str, problems: &mut Vec<Problem>) {
    if url.is_empty() {
        problems.push(Problem::new(field, "代理地址不能为空"));
        return;
    }
    let scheme = url
        .split("://")
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !PROXY_SCHEMES.contains(&scheme.as_str()) || !url.contains("://") {
        problems.push(Problem::new(
            field,
            format!(
                "代理地址需以 {} 开头",
                PROXY_SCHEMES
                    .iter()
                    .map(|scheme| format!("{scheme}://"))
                    .collect::<Vec<_>>()
                    .join("、")
            ),
        ));
    }
}

/// Per-kind required fields (WP-68 §3.3 channel table).
fn validate_channel_config(prefix: &str, channel: &Channel, problems: &mut Vec<Problem>) {
    fn required(
        prefix: &str,
        config: &ChannelConfig,
        field: &str,
        label: &str,
        problems: &mut Vec<Problem>,
    ) {
        if is_empty_config_field(config, field) {
            problems.push(Problem::new(
                format!("{prefix}.config.{field}"),
                format!("{label} 不能为空"),
            ));
        }
    }

    fn http_url(
        prefix: &str,
        config: &ChannelConfig,
        field: &str,
        label: &str,
        problems: &mut Vec<Problem>,
    ) {
        let value = config_str(config, field);
        let path = format!("{prefix}.config.{field}");
        if value.is_empty() {
            problems.push(Problem::new(&path, format!("{label} 不能为空")));
        } else if !value.starts_with("http://") && !value.starts_with("https://") {
            problems.push(Problem::new(
                &path,
                format!("{label} 需以 http:// 或 https:// 开头"),
            ));
        }
    }

    let config = &channel.config;
    match channel.kind {
        ChannelKind::Webhook => {
            http_url(prefix, config, "url", "Webhook 地址", problems);
            if !["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&config.method.as_str()) {
                problems.push(Problem::new(
                    format!("{prefix}.config.method"),
                    "方法只支持 GET / POST / PUT / PATCH / DELETE",
                ));
            }
            for header in &config.headers {
                if parse_header(header).is_none() {
                    problems.push(Problem::new(
                        format!("{prefix}.config.headers"),
                        format!("请求头需为 \"名称: 值\"：{header}"),
                    ));
                }
            }
        }
        ChannelKind::Telegram => {
            required(prefix, config, "token", "Bot Token", problems);
            required(prefix, config, "chatId", "Chat ID", problems);
        }
        ChannelKind::Bark => {
            required(prefix, config, "deviceKey", "设备 Key", problems);
            http_url(prefix, config, "server", "Bark 服务器", problems);
        }
        ChannelKind::Ntfy => {
            http_url(prefix, config, "server", "ntfy 服务器", problems);
            required(prefix, config, "topic", "主题", problems);
        }
        ChannelKind::Gotify => {
            http_url(prefix, config, "server", "Gotify 服务器", problems);
            required(prefix, config, "token", "应用 Token", problems);
        }
        ChannelKind::Pushover => {
            required(prefix, config, "token", "应用 Token", problems);
            required(prefix, config, "user", "User Key", problems);
        }
        ChannelKind::Discord | ChannelKind::Slack | ChannelKind::Feishu => {
            http_url(prefix, config, "url", "Webhook 地址", problems)
        }
        ChannelKind::ServerChan => required(prefix, config, "sendKey", "SendKey", problems),
        ChannelKind::PushPlus => required(prefix, config, "token", "Token", problems),
        ChannelKind::WeCom => required(prefix, config, "key", "机器人 Key", problems),
        ChannelKind::DingTalk => required(prefix, config, "accessToken", "Access Token", problems),
        ChannelKind::Email => {
            required(prefix, config, "host", "SMTP 服务器", problems);
            if config.port == 0 {
                problems.push(Problem::new(
                    format!("{prefix}.config.port"),
                    "端口不能为 0",
                ));
            }
            if config.smtp_user.is_empty() && !config.password.is_empty() {
                problems.push(Problem::new(
                    format!("{prefix}.config.smtpUser"),
                    "填写密码时需同时填写用户名",
                ));
            }
            validate_email_address(
                &format!("{prefix}.config.from"),
                "发件人",
                &config.from,
                problems,
            );
            if config.to.is_empty() {
                problems.push(Problem::new(
                    format!("{prefix}.config.to"),
                    "至少需要一个收件人",
                ));
            }
            for address in &config.to {
                validate_email_address(&format!("{prefix}.config.to"), "收件人", address, problems);
            }
            if config.to.len() > limits::EMAIL_RECIPIENTS_MAX {
                problems.push(Problem::new(
                    format!("{prefix}.config.to"),
                    format!("收件人最多 {} 个", limits::EMAIL_RECIPIENTS_MAX),
                ));
            }
        }
    }
}

fn validate_email_address(field: &str, label: &str, address: &str, problems: &mut Vec<Problem>) {
    let (local, domain) = address.rsplit_once('@').unwrap_or(("", address));
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        problems.push(Problem::new(field, format!("{label} 不是有效的邮件地址")));
    }
}

/// Reads a config field as text through its JSON name (camelCase) so the
/// required-field checks stay in one place.
fn config_str(config: &ChannelConfig, field: &str) -> String {
    serde_json::to_value(config)
        .ok()
        .and_then(|value| {
            value
                .get(field)
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

fn is_empty_config_field(config: &ChannelConfig, field: &str) -> bool {
    config_str(config, field).trim().is_empty()
}

/// Splits a raw `Key: Value` header line (webhook channel).
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
    use crate::model::{ChannelProxy, SettingsProxy, SmtpSecurity};

    fn channel(kind: ChannelKind) -> Channel {
        Channel {
            key: format!("chan{}", crate::model::new_key()),
            name: "test".into(),
            enable: true,
            kind,
            ..Channel::default()
        }
    }

    fn config(channels: Vec<Channel>) -> FileConfig {
        normalize(FileConfig {
            channels,
            ..FileConfig::default()
        })
    }

    #[test]
    fn valid_channels_of_every_kind_have_no_problems() {
        let webhook = Channel {
            kind: ChannelKind::Webhook,
            config: ChannelConfig {
                url: "https://example.com/hook".into(),
                method: " post ".into(),
                headers: vec!["X-Token: abc".into()],
                ..ChannelConfig::default()
            },
            ..channel(ChannelKind::Webhook)
        };
        let telegram = Channel {
            kind: ChannelKind::Telegram,
            config: ChannelConfig {
                token: "t".into(),
                chat_id: "1".into(),
                ..ChannelConfig::default()
            },
            ..channel(ChannelKind::Telegram)
        };
        let email = Channel {
            kind: ChannelKind::Email,
            config: ChannelConfig {
                host: "smtp.example.com".into(),
                port: 465,
                security: SmtpSecurity::Ssl,
                smtp_user: "user".into(),
                password: "pass".into(),
                from: "from@example.com".into(),
                to: vec!["to@example.com".into()],
                ..ChannelConfig::default()
            },
            ..channel(ChannelKind::Email)
        };
        let config = config(vec![webhook, telegram, email]);
        assert_eq!(validate(&config), Vec::new(), "{config:?}");
        assert_eq!(config.channels[0].config.method, "POST");
    }

    #[test]
    fn normalize_fills_default_servers_and_smtp_port() {
        let mut bark = channel(ChannelKind::Bark);
        bark.config.device_key = "dev".into();
        let mut email = channel(ChannelKind::Email);
        email.config.host = "smtp.example.com".into();
        email.config.from = "a@b.com".into();
        email.config.to = vec!["c@d.com".into()];
        let config = config(vec![bark, email]);
        assert_eq!(
            config.channels[0].config.server,
            limits::BARK_SERVER_DEFAULT
        );
        assert_eq!(
            config.channels[1].config.port,
            limits::SMTP_PORT_DEFAULT,
            "security none defaults to the submission port"
        );
    }

    #[test]
    fn validate_reports_required_fields_per_kind() {
        let cases: Vec<(ChannelKind, Vec<&str>)> = vec![
            (ChannelKind::Webhook, vec!["url"]),
            (ChannelKind::Telegram, vec!["token", "chatId"]),
            (ChannelKind::Bark, vec!["deviceKey"]),
            (ChannelKind::Ntfy, vec!["topic"]),
            (ChannelKind::Gotify, vec!["token"]),
            (ChannelKind::Pushover, vec!["token", "user"]),
            (ChannelKind::Discord, vec!["url"]),
            (ChannelKind::Slack, vec!["url"]),
            (ChannelKind::ServerChan, vec!["sendKey"]),
            (ChannelKind::PushPlus, vec!["token"]),
            (ChannelKind::WeCom, vec!["key"]),
            (ChannelKind::DingTalk, vec!["accessToken"]),
            (ChannelKind::Feishu, vec!["url"]),
            (ChannelKind::Email, vec!["host", "from", "to"]),
        ];
        for (kind, fields) in cases {
            let config = config(vec![channel(kind)]);
            let problems = validate(&config);
            for field in fields {
                assert!(
                    problems
                        .iter()
                        .any(|problem| problem.field.ends_with(&format!("config.{field}"))),
                    "{kind:?} should report {field}: {problems:?}"
                );
            }
        }
    }

    #[test]
    fn validate_reports_settings_ranges_and_proxy_scheme() {
        let config = normalize(FileConfig {
            settings: Settings {
                retries: Some(limits::RETRIES_MAX + 1),
                pending_hours: Some(limits::PENDING_HOURS_MAX + 1),
                proxy: SettingsProxy::Custom("ftp://gate".into()),
                ..Settings::default()
            },
            ..FileConfig::default()
        });
        let fields: Vec<_> = validate(&config)
            .into_iter()
            .map(|problem| problem.field)
            .collect();
        assert!(
            fields.contains(&"settings.retries".to_owned()),
            "{fields:?}"
        );
        assert!(
            fields.contains(&"settings.pendingHours".to_owned()),
            "{fields:?}"
        );
        assert!(fields.contains(&"settings.proxy".to_owned()), "{fields:?}");
        let custom = normalize(FileConfig {
            settings: Settings {
                proxy: SettingsProxy::Custom("socks5h://gate:1080".into()),
                ..Settings::default()
            },
            ..FileConfig::default()
        });
        assert_eq!(
            validate(&custom),
            Vec::new(),
            "socks5h is an accepted proxy scheme"
        );
    }

    #[test]
    fn validate_reports_rule_problems() {
        let mut chan = channel(ChannelKind::Slack);
        chan.config.url = "https://example.com".into();
        let config = normalize(FileConfig {
            channels: vec![chan],
            rules: vec![Rule {
                key: "rule00000001".into(),
                name: "r".into(),
                enable: true,
                events: vec!["  ".into()],
                min_level: fg_core::events::Level::Warn,
                channels: vec!["ghost".into()],
                silence: Some(crate::model::Silence {
                    window_minutes: 0,
                    ..crate::model::Silence::default()
                }),
                ..Rule::default()
            }],
            ..FileConfig::default()
        });
        // A rule without channels reports the missing channel list.
        let empty = Rule {
            key: "rule00000002".into(),
            name: "e".into(),
            events: vec!["*".into()],
            ..Rule::default()
        };
        let mut config = config;
        config.rules.push(empty);
        let text = format!("{:?}", validate(&config));
        assert!(text.contains("至少需要一个事件类型"), "{text}");
        assert!(text.contains("至少需要一个通知渠道"), "{text}");
        assert!(text.contains("未知的渠道 key ghost"), "{text}");
        assert!(text.contains("静默窗口不能为 0"), "{text}");
    }

    #[test]
    fn merge_channel_keeps_masked_secrets_and_redacted_proxy() {
        let mut old = channel(ChannelKind::Telegram);
        old.config.token = "stored".into();
        old.proxy = ChannelProxy::Custom("http://user:pass@gate:8080".into());
        let mut submitted = channel(ChannelKind::Telegram);
        submitted.config.token = SECRET_MASK.into();
        submitted.proxy = ChannelProxy::Custom("http://user:xxxxx@gate:8080".into());
        merge_channel(&old, &mut submitted);
        assert_eq!(submitted.config.token, "stored");
        assert_eq!(submitted.proxy, old.proxy);
        // An explicit new value replaces the stored one.
        let mut submitted = channel(ChannelKind::Telegram);
        submitted.config.token = "rotated".into();
        submitted.proxy = ChannelProxy::Custom("http://user:new@gate:8080".into());
        merge_channel(&old, &mut submitted);
        assert_eq!(submitted.config.token, "rotated");
        assert_ne!(submitted.proxy, old.proxy);
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
