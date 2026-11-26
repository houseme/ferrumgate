use std::time::Duration;

use fg_core::{
    registry::Registry,
    settings::{
        DEFAULT_ACCESS_LOG_DAYS, DEFAULT_ACCESS_LOG_MB, DEFAULT_CONFIRM_TIMEOUT_SECONDS,
        DEFAULT_LOCK_MINUTES, DEFAULT_LOG_FILE_MB, DEFAULT_LOG_LEVEL, DEFAULT_LOG_LINES,
        DEFAULT_LOGIN_GLOBAL_LIMIT, DEFAULT_MAX_LOGIN_FAILURES, Effect, SettingChange, Settings,
    },
};
use serde_json::{Value, from_str, from_value, json, to_value};

const REGISTRY: Registry = Registry::new(&["portforward", "ssl", "webservice"]);

fn normalized(input: Value) -> Settings {
    let mut settings: Settings = from_value(input).unwrap();
    settings.normalize();
    settings
}

fn rejected(input: Value, field: &str) {
    let errors = normalized(input).validate(&REGISTRY).unwrap_err();
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].field, field);
}

#[test]
fn empty_settings_resolve_structural_defaults_and_preserve_limit_sentinels() {
    let mut settings: Settings = from_str("{}").unwrap();
    settings.normalize();
    assert_eq!(settings.listen, ":16680");
    assert_eq!(settings.deny_status, 200);
    assert!(settings.https_listen.is_empty());
    assert!(settings.log_level.is_empty());
    assert!(!settings.force_https && !settings.lan_only && !settings.gateway_sso);
    assert!(!settings.disable_proxy_headers && !settings.restrict_outbound);
    assert!(!settings.disable_update_check && !settings.disable_log_persist);
    assert!(!settings.third_login.enable && !settings.third_login.skip_totp);

    let wire = to_value(&settings).unwrap();
    for key in [
        "maxLoginFailures",
        "lockMinutes",
        "loginGlobalLimit",
        "confirmTimeout",
        "logLines",
        "logFileMB",
        "accessLogDays",
        "accessLogMB",
    ] {
        assert_eq!(wire[key], 0, "{key}");
    }
    assert_eq!(DEFAULT_MAX_LOGIN_FAILURES, 5);
    assert_eq!(DEFAULT_LOCK_MINUTES, 15);
    assert_eq!(DEFAULT_LOGIN_GLOBAL_LIMIT, 20);
    assert_eq!(DEFAULT_CONFIRM_TIMEOUT_SECONDS, 90);
    assert_eq!(DEFAULT_LOG_LEVEL, "info");
    assert_eq!(DEFAULT_LOG_LINES, 2_000);
    assert_eq!(DEFAULT_LOG_FILE_MB, 2);
    assert_eq!(DEFAULT_ACCESS_LOG_DAYS, 7);
    assert_eq!(DEFAULT_ACCESS_LOG_MB, 32);
}

#[test]
fn accepts_upstream_acronyms_nullable_lists_and_legacy_fields() {
    let settings: Settings = from_str(
        r#"{
        "forceHTTPS": true,
        "gatewaySSO": true,
        "trustedProxies": null,
        "dnsServers": null,
        "disabledModules": null,
        "logFileMB": 12,
        "accessLogMB": 128,
        "apiToken": "legacy-fixture",
        "gcPercent": 75,
        "maxProcs": 2,
        "thirdLogin": {"providers": null, "allowed": null}
    }"#,
    )
    .unwrap();
    assert_eq!(settings.legacy_api_token, "legacy-fixture");
    let wire = to_value(settings).unwrap();
    assert_eq!(wire["forceHTTPS"], true);
    assert_eq!(wire["gatewaySSO"], true);
    assert_eq!(wire["logFileMB"], 12);
    assert_eq!(wire["accessLogMB"], 128);
    for key in ["trustedProxies", "dnsServers", "disabledModules"] {
        assert_eq!(wire[key], json!([]), "{key}");
    }
    assert_eq!(wire["thirdLogin"]["allowed"], json!([]));
    assert_eq!(wire["thirdLogin"]["providers"], json!([]));
    for key in ["apiToken", "gcPercent", "maxProcs"] {
        assert!(wire.get(key).is_none(), "{key}");
    }
}

#[test]
fn unknown_fields_report_the_name_without_the_value() {
    let top = r#"{"logLine":"configuration-value-fixture"}"#;
    let nested = r#"{"thirdLogin":{"providers":[{"clientSecrte":"configuration-value-fixture"}]}}"#;
    for (raw, field) in [(top, "logLine"), (nested, "clientSecrte")] {
        let error = from_str::<Settings>(raw).err().unwrap().to_string();
        assert!(error.contains(&format!("unknown field `{field}`")));
        assert!(!error.contains("configuration-value-fixture"));
    }
}

#[test]
fn duplicate_settings_keys_are_rejected() {
    let error = from_str::<Settings>(r#"{"forceHTTPS":false,"forceHTTPS":true}"#)
        .err()
        .unwrap();
    assert!(error.to_string().contains("duplicate field `forceHTTPS`"));
}

#[test]
fn normalizes_settings_idempotently_without_reordering_network_lists() {
    let mut settings: Settings = from_str(
        r#"{
        "listen": "  ", "httpsListen": " [::1]:9443 ",
        "safePath": "  entrance/// ", "denyMode": " NotFound ", "denyStatus": 418,
        "denyPage": " <p>preserve whitespace</p> ",
        "trustedProxies": [" ::1 ", "  ", " 192.0.2.1 "],
        "dnsServers": [" 1.1.1.1 ", "", " 8.8.8.8 ", "1.1.1.1"],
        "disabledModules": ["webservice", " ", " ssl ", "webservice"],
        "timeZone": " Asia/Shanghai ", "language": " zh_Hant_HK.UTF-8 ",
        "uiLanguage": " PT_pt ", "updateProxy": " http://proxy.test:8000 ",
        "logLevel": " WARN ", "logDir": " relative/logs ", "confirmTimeout": -900,
        "thirdLogin": {
            "callbackBase": " https://login.test/// ", "allowed": ["", " github:123 "],
            "providers": [{"type":"github", "key":"github", "clientSecret":" fixture secret ",
                           "proxy":"http://proxy.test:8001"}]
        }
    }"#,
    )
    .unwrap();
    settings.normalize();
    assert_eq!(settings.listen, ":16680");
    assert_eq!(settings.https_listen, "[::1]:9443");
    assert_eq!(settings.safe_path, "/entrance");
    assert_eq!(settings.deny_mode, "notfound");
    assert_eq!(settings.deny_status, 200);
    assert_eq!(settings.deny_page, " <p>preserve whitespace</p> ");
    assert_eq!(settings.trusted_proxies, ["::1", "192.0.2.1"]);
    assert_eq!(settings.dns_servers, ["1.1.1.1", "8.8.8.8", "1.1.1.1"]);
    assert_eq!(settings.disabled_modules, ["ssl", "webservice"]);
    assert_eq!(settings.time_zone, "Asia/Shanghai");
    assert_eq!(settings.language, "zh-TW");
    assert_eq!(settings.ui_language, "pt-BR");
    assert_eq!(settings.update_proxy, "http://proxy.test:8000");
    assert_eq!(settings.log_level, "warn");
    assert_eq!(settings.log_dir, "relative/logs");
    assert_eq!(settings.confirm_timeout, -1);
    assert_eq!(settings.third_login.callback_base, "https://login.test");
    assert_eq!(settings.third_login.allowed, ["github:123"]);
    assert_eq!(
        settings.third_login.providers[0].client_secret,
        " fixture secret "
    );
    assert_eq!(
        settings.third_login.providers[0].proxy,
        "http://proxy.test:8001"
    );

    let normalized = settings.clone();
    settings.normalize();
    assert!(settings == normalized);
}

#[test]
fn normalizes_absolute_log_paths_and_retains_invalid_custom_status_for_validation() {
    let mut settings: Settings =
        from_str(r#"{"denyMode":" CUSTOM ","denyStatus":418,"language":"C.UTF-8"}"#).unwrap();
    let base = std::env::temp_dir();
    settings.log_dir = base.join("service/../logs/.").display().to_string();
    settings.normalize();
    assert_eq!(settings.log_dir, base.join("logs").display().to_string());
    assert_eq!(settings.deny_mode, "custom");
    assert_eq!(settings.deny_status, 418);
    assert!(settings.language.is_empty());

    settings.deny_status = 0;
    settings.normalize();
    assert_eq!(settings.deny_status, 200);
}

#[test]
fn validates_listener_addresses_and_dependencies() {
    for listen in [":16680", ":0", "127.0.0.1:8080", "[::1]:8080", "[::]:443"] {
        normalized(json!({"listen": listen}))
            .validate(&REGISTRY)
            .unwrap();
    }
    for listen in [
        "localhost:8080",
        "::1:8080",
        "127.0.0.1",
        ":65536",
        ":+80",
        ":",
    ] {
        rejected(json!({"listen": listen}), "listen");
    }
    rejected(json!({"httpsListen": "localhost:8443"}), "httpsListen");
    rejected(
        json!({"listen": ":443", "httpsListen": "0.0.0.0:443"}),
        "httpsListen",
    );
    rejected(json!({"forceHTTPS": true}), "forceHTTPS");
    normalized(json!({"forceHTTPS":true,"httpsListen":"[::1]:443"}))
        .validate(&REGISTRY)
        .unwrap();
    rejected(
        json!({"disabledModules":["not-a-module"]}),
        "disabledModules",
    );
    rejected(json!({"disabledModules":["ssl"]}), "disabledModules");
    rejected(
        json!({"httpsListen":":443","disabledModules":["ssl","webservice"]}),
        "disabledModules",
    );
    normalized(json!({"disabledModules":["ssl","webservice","waf"]}))
        .validate(&REGISTRY)
        .unwrap();
}

#[test]
fn validates_management_access_and_response_settings() {
    for safe_path in [
        "/api",
        "/api/path",
        "/assets-foo",
        "/ab",
        "/秘密",
        "/has space",
        "/foo?x",
        "/foo#x",
        "/foo\nbar",
    ] {
        rejected(json!({"safePath": safe_path}), "safePath");
    }
    rejected(json!({"denyMode":"unknown"}), "denyMode");
    rejected(json!({"denyMode":"custom","denyStatus":418}), "denyStatus");
    rejected(json!({"denyPage":"a".repeat((64 << 10) + 1)}), "denyPage");
    rejected(json!({"trustedProxies":["192.0.2.1/33"]}), "trustedProxies");
    normalized(json!({
        "safePath":"/入口处", "denyMode":"custom", "denyStatus":503,
        "denyPage":"a".repeat(64 << 10), "trustedProxies":["192.0.2.11/24","[::1]","2001:db8::/32"]
    }))
    .validate(&REGISTRY)
    .unwrap();
}

#[test]
fn validates_numeric_limits_and_resolves_confirmation_duration() {
    for (field, invalid, valid) in [
        ("maxLoginFailures", &[-1, 101][..], &[0, 1, 100][..]),
        ("lockMinutes", &[-1, 10_081][..], &[0, 1, 10_080][..]),
        ("loginGlobalLimit", &[10_001][..], &[-7, 0, 10_000][..]),
        ("confirmTimeout", &[29, 601][..], &[-7, 0, 30, 600][..]),
        ("logLines", &[20_001][..], &[-1, 0, 20_000][..]),
        ("logFileMB", &[-1, 101][..], &[0, 1, 100][..]),
        ("accessLogDays", &[-1, 3651][..], &[0, 1, 3650][..]),
        ("accessLogMB", &[-1, 3, 102_401][..], &[0, 4, 102_400][..]),
    ] {
        for value in invalid {
            rejected(json!({(field):value}), field);
        }
        for value in valid {
            normalized(json!({(field):value}))
                .validate(&REGISTRY)
                .unwrap();
        }
    }
    for (value, effective) in [(-20, None), (0, Some(90)), (30, Some(30)), (600, Some(600))] {
        assert_eq!(
            normalized(json!({"confirmTimeout": value})).confirm_timeout(),
            effective.map(Duration::from_secs)
        );
    }
}

#[test]
fn validates_resolvers_proxies_time_zones_and_log_paths() {
    for server in [
        "192.0.2.1:65536",
        "dns.example:53",
        "doh@",
        "doh@/query",
        "https:///example.test",
        "http://example.test/query",
    ] {
        rejected(json!({"dnsServers":[server]}), "dnsServers");
    }
    for proxy in [
        "http:proxy.test",
        "http:///proxy.test",
        "ftp://proxy.test",
        "https://bad host",
    ] {
        rejected(json!({"updateProxy":proxy}), "updateProxy");
    }
    for proxy in [
        "http://proxy.test",
        "https://proxy.test",
        "socks5://proxy.test",
        "socks5h://proxy.test",
    ] {
        normalized(json!({"updateProxy":proxy}))
            .validate(&REGISTRY)
            .unwrap();
    }
    rejected(json!({"timeZone":"Unknown/Fixture"}), "timeZone");
    rejected(json!({"logLevel":"trace"}), "logLevel");
    let base = std::env::temp_dir();
    for dir in [
        "relative/logs".into(),
        base.ancestors().last().unwrap().display().to_string(),
        base.join("control\0character").display().to_string(),
        base.join("a".repeat(1025)).display().to_string(),
    ] {
        rejected(json!({"logDir":dir}), "logDir");
    }
    normalized(json!({
        "timeZone":"Asia/Shanghai", "logLevel":"warn", "logDir":base.join("logs"),
        "dnsServers":["192.0.2.1","192.0.2.1:53","[::1]","[::1]:53","doh@dns.example","https://dns.example/query"]
    })).validate(&REGISTRY).unwrap();
}

#[test]
fn validates_third_login_and_aggregates_only_safe_error_details() {
    rejected(json!({"thirdLogin":{"enable":true}}), "thirdLogin");
    rejected(
        json!({"thirdLogin":{"callbackBase":"https://login.test/path"}}),
        "thirdLogin.callbackBase",
    );
    rejected(
        json!({"thirdLogin":{"allowed":["github:"]}}),
        "thirdLogin.allowed",
    );
    let provider = json!({"type":"oidc","key":"example","clientId":"fixture", "clientSecret":"fixture", "issuer":"https://issuer.test/sso"});
    rejected(
        json!({"thirdLogin":{"providers":[provider.clone(), provider.clone()]}}),
        "thirdLogin.providers",
    );
    normalized(json!({"thirdLogin":{
        "enable":true, "callbackBase":"https://login.test", "providers":[provider],
        "allowed":["example:subject # fixture"],
    }}))
    .validate(&REGISTRY)
    .unwrap();

    let invalid = normalized(json!({
        "updateProxy":"ftp://user:fixture-secret@proxy.test",
        "thirdLogin":{"providers":[{"key":"fixture-secret", "type":"unknown", "clientSecret":"fixture-secret"}]},
        "disabledModules":["fixture-secret"], "logLines":20001,
    }));
    let errors = invalid.validate(&REGISTRY).unwrap_err();
    assert_eq!(
        errors.iter().map(|error| error.field).collect::<Vec<_>>(),
        [
            "updateProxy",
            "logLines",
            "thirdLogin.providers",
            "disabledModules"
        ]
    );
    assert!(!format!("{errors:?}").contains("fixture-secret"));
}

#[test]
fn classifies_settings_changes_using_the_same_field_metadata() {
    let before = normalized(json!({}));
    let after = normalized(json!({
        "listen":":16681", "safePath":"entry/", "trustedProxies":["192.0.2.1"],
        "language":"en-US", "apiToken":"legacy-fixture",
    }));
    let changes = after.changes_from(&before);
    assert_eq!(
        changes,
        [
            SettingChange {
                field: "listen",
                effect: Effect::NeedsRestart
            },
            SettingChange {
                field: "safePath",
                effect: Effect::NeedsConfirm
            },
            SettingChange {
                field: "trustedProxies",
                effect: Effect::NeedsConfirm
            },
            SettingChange {
                field: "language",
                effect: Effect::Immediate
            },
            SettingChange {
                field: "apiToken",
                effect: Effect::BootOnly
            },
        ]
    );
    for change in changes {
        assert_eq!(Settings::effect_of(change.field), Some(change.effect));
    }
    for field in to_value(&after).unwrap().as_object().unwrap().keys() {
        assert!(Settings::effect_of(field).is_some(), "{field}");
    }
    assert_eq!(Settings::effect_of("uiLanguage"), Some(Effect::Immediate));
    assert_eq!(Settings::effect_of("gcPercent"), None);
    assert!(after.changes_from(&after).is_empty());
    let equivalent = normalized(json!({
        "listen":" :16681 ", "safePath":"/entry", "trustedProxies":[" 192.0.2.1 "],
        "language":"en", "apiToken":"legacy-fixture",
    }));
    assert!(equivalent.changes_from(&after).is_empty());
}
