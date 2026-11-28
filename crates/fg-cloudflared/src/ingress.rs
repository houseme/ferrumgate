//! Ingress rules for token tunnels (WP-46 §3.3, pure functions): service
//! syntax validation, normalization, splitting a remote config into
//! normal rules plus the catch-all, and building the `ingress` array for a
//! write-back. The rules live in Cloudflare's remote config; a running
//! `cloudflared` picks them up without a restart.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

use crate::model::limits;

/// `^http_status:[1-5][0-9]{2}$` (upstream `httpStatusRe`).
static HTTP_STATUS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^http_status:[1-5][0-9]{2}$").expect("static regex"));

/// `^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])$`
/// (upstream `hostnameRe`).
static HOSTNAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])$",
    )
    .expect("static regex")
});

/// The forwarding target of a rule: an origin URL (`http://localhost:8080`,
/// `ssh://localhost:22`, `unix:/run/app.sock`, `hello_world`, `bastion`) or
/// a static status (`http_status:404`). Anything that is not a valid
/// `http_status:` literal deserializes as [`Service::Url`] so the saved
/// value can be reported back by `validate_service`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Service {
    Url(String),
    HttpStatus(u16),
}

impl Service {
    /// The wire form (`http://localhost:8080`, `http_status:404`).
    pub fn to_wire(&self) -> String {
        match self {
            Self::Url(text) => text.clone(),
            Self::HttpStatus(status) => format!("http_status:{status}"),
        }
    }

    /// The status code of an `http_status:` service.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::HttpStatus(status) => Some(*status),
            Self::Url(_) => None,
        }
    }

    /// Parses the wire form; anything that is not a valid `http_status:`
    /// literal becomes a [`Service::Url`].
    pub fn parse(text: &str) -> Self {
        if let Some(code) = text.strip_prefix("http_status:")
            && let Ok(status) = code.parse::<u16>()
            && (100..=599).contains(&status)
            && code.len() == 3
        {
            return Self::HttpStatus(status);
        }
        Self::Url(text.to_owned())
    }
}

impl Serialize for Service {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Url(text) => serializer.serialize_str(text),
            Self::HttpStatus(status) => serializer.serialize_str(&format!("http_status:{status}")),
        }
    }
}

impl<'de> Deserialize<'de> for Service {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Ok(Service::parse(&text))
    }
}

impl Default for Service {
    fn default() -> Self {
        Self::Url(String::new())
    }
}

/// One ingress rule. `origin_request` carries the `originRequest` object
/// as-is (unverified certificates, origin host name, timeouts, …); the UI
/// edits common fields and everything else round-trips untouched.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Rule {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    /// Regex matched against the request path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub service: Service,
    #[serde(
        rename = "originRequest",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub origin_request: Option<serde_json::Value>,
}

impl Rule {
    /// A rule matches everything (no hostname and no path): in the last
    /// position that makes it the catch-all.
    pub fn is_catch_all(&self) -> bool {
        self.hostname.is_empty() && self.path.is_none()
    }
}

/// The default catch-all (upstream `defaultCatchAll`).
pub fn default_catch_all() -> Rule {
    Rule {
        hostname: String::new(),
        path: None,
        service: Service::parse(limits::DEFAULT_CATCH_ALL),
        origin_request: None,
    }
}

/// Strips the trailing lone `/` from HTTP-like service URLs: cloudflared
/// accepts them in the remote config but then rejects the whole file at
/// runtime. Everything else is returned unchanged (upstream
/// `normalizeService`).
pub fn normalize_service(service: &str) -> String {
    let trimmed = service.trim();
    let Ok(url) = Url::parse(trimmed) else {
        return trimmed.to_owned();
    };
    if url.host_str().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return trimmed.to_owned();
    }
    if matches!(url.scheme(), "http" | "https" | "ws" | "wss") {
        return trimmed.trim_end_matches('/').to_owned();
    }
    trimmed.to_owned()
}

/// Validates a service string with the same rules as cloudflared: HTTP-like
/// services must not carry a path, TCP-like services must carry a port
/// (upstream `validateService`).
pub fn validate_service(service: &str) -> Result<(), String> {
    if service == "hello_world" || service == "bastion" || HTTP_STATUS_RE.is_match(service) {
        return Ok(());
    }
    let rest = service
        .strip_prefix("unix+tls:")
        .or_else(|| service.strip_prefix("unix:"));
    if let Some(socket) = rest {
        if socket.is_empty() {
            return Err(format!("服务 {service} 缺少套接字路径"));
        }
        return Ok(());
    }
    let Ok(url) = Url::parse(service) else {
        return Err(format!(
            "服务 {service} 格式不正确，示例：http://localhost:8080、ssh://localhost:22、http_status:404"
        ));
    };
    if url.host_str().is_none() {
        return Err(format!(
            "服务 {service} 格式不正确，示例：http://localhost:8080、ssh://localhost:22、http_status:404"
        ));
    }
    match url.scheme() {
        "http" | "https" | "ws" | "wss" => {
            // The url crate normalizes "http://a" and "http://a/" to the
            // same path "/" (Go keeps them distinct); an explicit trailing
            // slash in the raw text is the only observable path, and both
            // count as "has a path" for cloudflared.
            let has_path = !(url.path().is_empty() || url.path() == "/")
                || (url.path() == "/" && service.ends_with('/'));
            if has_path {
                return Err(format!(
                    "服务 {service} 不能带路径，路由规则只按路径匹配，不改写回源路径"
                ));
            }
            Ok(())
        }
        "tcp" | "ssh" | "rdp" | "smb" => {
            if url.port().is_none() {
                return Err(format!("服务 {service} 需要填写端口"));
            }
            Ok(())
        }
        _ => Err(format!(
            "服务 {service} 的协议不受支持，可用 http、https、tcp、ssh、rdp、smb、unix"
        )),
    }
}

/// Validates a [`Service`] value.
pub fn validate_typed_service(service: &Service) -> Result<(), String> {
    match service {
        Service::HttpStatus(status) if (100..=599).contains(status) => Ok(()),
        Service::HttpStatus(status) => Err(format!("http_status 超出 100～599：{status}")),
        Service::Url(text) => validate_service(text),
    }
}

/// Normalizes and validates the rules (not the catch-all). Every rule needs
/// a hostname or a path — a rule matching everything would shadow the ones
/// after it (upstream `normalizeRules`). Mutates in place like upstream.
pub fn normalize_rules(rules: &mut [Rule]) -> Result<(), String> {
    for (index, rule) in rules.iter_mut().enumerate() {
        let ordinal = index + 1;
        // 主机名去掉末尾的根域点，与 Cloudflare 的记录名写法一致。
        let hostname = rule.hostname.trim();
        let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
        rule.hostname = hostname.to_ascii_lowercase();
        rule.path = rule
            .path
            .as_deref()
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .map(str::to_owned);
        rule.service = Service::parse(&normalize_service(&rule.service.to_wire()));
        if rule.is_catch_all() {
            return Err(format!("第 {ordinal} 条规则需要填写主机名或路径"));
        }
        if !rule.hostname.is_empty() && !HOSTNAME_RE.is_match(&rule.hostname) {
            return Err(format!(
                "第 {ordinal} 条规则的主机名 {} 格式不正确",
                rule.hostname
            ));
        }
        if let Some(path) = &rule.path
            && Regex::new(path).is_err()
        {
            return Err(format!(
                "第 {ordinal} 条规则的路径不是有效的正则表达式: {path}"
            ));
        }
        if rule.service.to_wire().is_empty() {
            return Err(format!("第 {ordinal} 条规则需要填写服务"));
        }
        validate_typed_service(&rule.service)
            .map_err(|error| format!("第 {ordinal} 条规则: {error}"))?;
        // An empty originRequest object normalizes to absent.
        if rule
            .origin_request
            .as_ref()
            .is_some_and(|value| value == &serde_json::json!({}))
        {
            rule.origin_request = None;
        }
    }
    Ok(())
}

/// Splits the remote `config` object into the normal rules and the
/// catch-all (the last rule without hostname and path; the default when
/// there is none). Missing or null `ingress` yields no rules (a fresh
/// tunnel).
pub fn split_ingress(config: &serde_json::Value) -> Result<(Vec<Rule>, Rule), String> {
    let mut catch_all = default_catch_all();
    let Some(raw) = config.get("ingress") else {
        return Ok((Vec::new(), catch_all));
    };
    if raw.is_null() {
        return Ok((Vec::new(), catch_all));
    }
    let mut rules: Vec<Rule> = serde_json::from_value(raw.clone())
        .map_err(|error| format!("无法解析隧道的路由规则: {error}"))?;
    if let Some(last) = rules.last().filter(|rule| rule.is_catch_all()) {
        catch_all = last.clone();
        rules.pop();
    }
    Ok((rules, catch_all))
}

/// Builds the `ingress` array for a remote config write: the rules followed
/// by the catch-all. The catch-all keeps the origin settings of the
/// previous catch-all (the caller passes them in).
pub fn build_ingress(rules: &[Rule], catch_all: &Rule) -> Vec<serde_json::Value> {
    let mut ingress: Vec<serde_json::Value> = rules
        .iter()
        .map(|rule| serde_json::to_value(rule).expect("rule serializes"))
        .collect();
    ingress.push(serde_json::to_value(catch_all).expect("catch-all serializes"));
    ingress
}

/// The ingress editor's response body (upstream `ingressView`). `source`
/// is `cloudflare` when the rules are managed remotely; `local` means the
/// tunnel runs from a local config file and the remote rules do not apply
/// (the UI must warn).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngressView {
    pub tunnel_id: String,
    /// The remote config version; a save carries it back for the
    /// concurrent-modification check.
    pub version: u64,
    pub source: String,
    pub rules: Vec<Rule>,
    pub catch_all: Service,
    /// DNS sync results, present when the save asked for
    /// `syncDns` (upstream `dns`, omitempty).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<crate::cf_api::DnsResult>,
}

/// The save request body (upstream `ingressUpdate`). `rules` must be
/// provided (an empty array clears them) so a save meant only for the
/// catch-all cannot wipe the rules; `force` confirms writing over a
/// locally managed tunnel; `version` must match the value read by the
/// ingress GET.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IngressUpdate {
    #[serde(default)]
    pub version: u64,
    #[serde(default)]
    pub rules: Option<Vec<Rule>>,
    #[serde(default)]
    pub force: bool,
    #[serde(default)]
    pub catch_all: Option<Service>,
    #[serde(default)]
    pub sync_dns: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn service_validation() {
        // HTTP 服务不能带路径；末尾斜杠去掉；http_status 范围。
        let good = [
            "http://localhost:8080",
            "https://192.168.1.2",
            "ssh://localhost:22",
            "tcp://[::1]:3389",
            "rdp://pc:3389",
            "smb://nas:445",
            "unix:/run/app.sock",
            "unix+tls:/run/app.sock",
            "http_status:404",
            "http_status:599",
            "hello_world",
            "bastion",
            "wss://a:1",
        ];
        for service in good {
            assert!(
                validate_service(service).is_ok(),
                "{service} 应通过: {:?}",
                validate_service(service)
            );
        }
        let bad = [
            "localhost:8080",
            "http://localhost:8080/app",
            "http://nas:5000/",
            "ssh://localhost",
            "ftp://a:21",
            "http_status:99",
            "http_status:600",
            "unix:",
            "unix+tls:",
            "nothing",
        ];
        for service in bad {
            assert!(validate_service(service).is_err(), "{service} 应被拒绝");
        }
    }

    #[test]
    fn normalize_service_strips_trailing_slash_only_for_http_like() {
        let cases = [
            (" http://nas:5000/ ", "http://nas:5000"),
            ("https://[::1]:8443/", "https://[::1]:8443"),
            ("http://nas:5000/app/", "http://nas:5000/app/"),
            ("http://nas:5000/?a=1", "http://nas:5000/?a=1"),
            ("ssh://host:22/", "ssh://host:22/"),
            ("http_status:404", "http_status:404"),
        ];
        for (input, want) in cases {
            assert_eq!(normalize_service(input), want, "normalize_service({input})");
        }
    }

    #[test]
    fn ingress_split_rules_and_catch_all() {
        // 最后一条无主机名无路径的为兜底。
        let config = json!({
            "ingress": [
                {"hostname": "a.example.com", "service": "http://localhost:80"},
                {"path": "^/api", "service": "http://localhost:81"},
                {"service": "http_status:503", "originRequest": {"connectTimeout": 10}}
            ],
            "warp-routing": {"enabled": true}
        });
        let (rules, catch_all) = split_ingress(&config).expect("splits");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].hostname, "a.example.com");
        assert_eq!(catch_all.service, Service::HttpStatus(503));
        assert_eq!(
            catch_all.origin_request,
            Some(json!({"connectTimeout": 10})),
            "兜底规则的回源设置保留"
        );
        // 无 ingress 时为空规则 + 默认兜底（新建隧道）。
        let (rules, catch_all) = split_ingress(&json!({})).expect("splits");
        assert!(rules.is_empty());
        assert_eq!(catch_all.service, Service::HttpStatus(404));
        let (rules, catch_all) = split_ingress(&json!({"ingress": null})).expect("splits");
        assert!(rules.is_empty());
        assert_eq!(catch_all.service, Service::HttpStatus(404));
        // ingress 不是规则数组时报错。
        assert!(split_ingress(&json!({"ingress": 5})).is_err());
    }

    #[test]
    fn normalize_rules_lowercase_and_service() {
        let mut rules = vec![
            Rule {
                hostname: " App.Example.com ".into(),
                path: None,
                service: Service::parse(" http://localhost:80 "),
                origin_request: Some(json!({})),
            },
            Rule {
                hostname: "*.example.com".into(),
                path: Some("^/api".into()),
                service: Service::parse("http://localhost:81"),
                origin_request: None,
            },
            Rule {
                hostname: String::new(),
                path: Some("\\.png$".into()),
                service: Service::parse("http_status:404"),
                origin_request: None,
            },
        ];
        normalize_rules(&mut rules).expect("valid");
        assert_eq!(rules[0].hostname, "app.example.com");
        assert_eq!(rules[0].service, Service::Url("http://localhost:80".into()));
        assert_eq!(
            rules[0].origin_request, None,
            "空 originRequest 归一化为缺失"
        );
        // 规范化服务末尾斜杠被去掉。
        let mut rule = vec![Rule {
            hostname: "App.Example.com.".into(),
            path: None,
            service: Service::parse("http://nas:5000/"),
            origin_request: None,
        }];
        normalize_rules(&mut rule).expect("valid");
        assert_eq!(rule[0].hostname, "app.example.com", "末尾根域点被去掉");
        assert_eq!(rule[0].service, Service::Url("http://nas:5000".into()));
    }

    #[test]
    fn normalize_rules_rejects_bad_rules() {
        let bad: Vec<Vec<Rule>> = vec![
            // 无主机名也无路径（会把兜底规则挪到中间）。
            vec![Rule {
                hostname: String::new(),
                path: None,
                service: Service::parse("http://a:1"),
                origin_request: None,
            }],
            // 主机名格式不正确。
            vec![Rule {
                hostname: "bad host".into(),
                path: None,
                service: Service::parse("http://a:1"),
                origin_request: None,
            }],
            vec![Rule {
                hostname: "a.-com".into(),
                path: None,
                service: Service::parse("http://a:1"),
                origin_request: None,
            }],
            // 路径不是正则。
            vec![Rule {
                hostname: "a.example.com".into(),
                path: Some("(".into()),
                service: Service::parse("http://a:1"),
                origin_request: None,
            }],
            // 缺服务。
            vec![Rule {
                hostname: "a.example.com".into(),
                path: None,
                service: Service::Url(String::new()),
                origin_request: None,
            }],
            // 服务格式不正确。
            vec![Rule {
                hostname: "a.example.com".into(),
                path: None,
                service: Service::parse("a:1"),
                origin_request: None,
            }],
        ];
        for (index, rules) in bad.iter().enumerate() {
            let mut rules = rules.clone();
            assert!(
                normalize_rules(&mut rules).is_err(),
                "用例 {index} 应被拒绝"
            );
        }
    }

    #[test]
    fn ingress_keeps_other_remote_config_fields() {
        // originRequest、warp-routing 原样保留：只替换 ingress。
        let config = json!({
            "ingress": [
                {"hostname": "old.example.com", "service": "http://localhost:80",
                 "originRequest": {"noTLSVerify": true}},
                {"service": "http_status:404", "originRequest": {"connectTimeout": 10}}
            ],
            "warp-routing": {"enabled": true}
        });
        let (rules, old_catch_all) = split_ingress(&config).expect("splits");
        let mut new_rules = rules.clone();
        new_rules.push(Rule {
            hostname: "new.example.com".into(),
            path: None,
            service: Service::parse("ssh://localhost:22"),
            origin_request: None,
        });
        // 兜底服务换成 503，但沿用旧兜底的回源设置。
        let catch_all = Rule {
            hostname: String::new(),
            path: None,
            service: Service::parse("http_status:503"),
            origin_request: old_catch_all.origin_request.clone(),
        };
        let ingress = build_ingress(&new_rules, &catch_all);
        // 写回时只替换 ingress，其余字段保留。
        let mut saved = config.clone();
        saved["ingress"] = serde_json::Value::Array(ingress);
        assert_eq!(saved["warp-routing"], json!({"enabled": true}));
        let written = saved["ingress"].as_array().expect("array");
        assert_eq!(written.len(), 3);
        assert_eq!(
            written[0]["originRequest"],
            json!({"noTLSVerify": true}),
            "普通规则的回源设置原样保留"
        );
        assert_eq!(written[2]["service"], "http_status:503");
        assert_eq!(
            written[2]["originRequest"],
            json!({"connectTimeout": 10}),
            "兜底规则的回源设置沿用旧值"
        );
        assert!(written[2].get("hostname").is_none(), "兜底规则不带主机名");
        // 规则的空主机名/路径序列化时省略，与上游 omitempty 一致。
        assert!(written[1].get("hostname").is_some(), "新规则带主机名");
        assert!(written[1].get("path").is_none(), "空路径序列化时省略");
    }

    #[test]
    fn ingress_local_source_shows_warning() {
        // source 为 local 的视图需要界面提示；这里验证解析口径：
        // 远程配置的 source 原样进入视图。
        for (source, is_local) in [("cloudflare", false), ("local", true)] {
            let config = json!({
                "version": 1,
                "source": source,
                "config": {"ingress": [{"service": "http_status:404"}]}
            });
            let view: serde_json::Value = serde_json::from_value(config).expect("view");
            assert_eq!(view["source"], source);
            assert_eq!(view["source"] == "local", is_local);
        }
    }

    #[test]
    fn service_deserialization_is_lenient() {
        assert_eq!(
            serde_json::from_str::<Service>("\"http_status:404\"").expect("parses"),
            Service::HttpStatus(404)
        );
        assert_eq!(
            serde_json::from_str::<Service>("\"http://localhost:8080\"").expect("parses"),
            Service::Url("http://localhost:8080".into())
        );
        // 范围外的 http_status 按普通字符串保留，交由校验报告。
        assert_eq!(
            serde_json::from_str::<Service>("\"http_status:999\"").expect("parses"),
            Service::Url("http_status:999".into())
        );
    }

    #[test]
    fn ingress_round_trips_through_json() {
        let config = json!({
            "ingress": [
                {"hostname": "a.example.com", "path": "^/api", "service": "http://localhost:80",
                 "originRequest": {"noTLSVerify": true, "connectTimeout": {"nested": [1, 2]}}}
            ]
        });
        let (rules, catch_all) = split_ingress(&config).expect("splits");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].path.as_deref(), Some("^/api"));
        assert_eq!(catch_all.service, Service::HttpStatus(404));
        let rebuilt = build_ingress(&rules, &catch_all);
        let (rules2, catch_all2) =
            split_ingress(&json!({"ingress": rebuilt})).expect("splits again");
        assert_eq!(rules, rules2);
        assert_eq!(catch_all, catch_all2);
    }
}
