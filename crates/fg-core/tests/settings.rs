use fg_core::settings::{
    DEFAULT_ACCESS_LOG_DAYS, DEFAULT_ACCESS_LOG_MB, DEFAULT_CONFIRM_TIMEOUT_SECONDS,
    DEFAULT_LOCK_MINUTES, DEFAULT_LOG_FILE_MB, DEFAULT_LOG_LEVEL, DEFAULT_LOG_LINES,
    DEFAULT_LOGIN_GLOBAL_LIMIT, DEFAULT_MAX_LOGIN_FAILURES, Settings,
};
use serde_json::{from_str, json, to_value};

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
