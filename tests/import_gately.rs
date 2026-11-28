//! Integration and end-to-end tests for WP-38 (`fgate import gately`).
//! Covers every test case listed in `docs/plan/WP-38-import-gately.md` §6.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use ferrumgate::import_gately::{
    AccountPolicy, FileKind, ImportOptions, MigrateCtx, MigrateModule, REDACTED, Status,
    run_import, run_import_with_built, scan::classify_name_with_built, transform::SettingsMigrator,
};
use serde_json::{Value, json};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gately-config")
}

/// Copies the sanitized fixtures into a temporary source directory so tests can
/// add extra edge-case files without touching the committed fixtures.
fn copy_fixtures_to_temp() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    for entry in fs::read_dir(fixture_dir()).expect("read fixture dir") {
        let entry = entry.expect("entry");
        if entry.path().is_file() {
            fs::copy(entry.path(), dir.path().join(entry.file_name())).expect("copy fixture");
        }
    }
    dir
}

/// Recursively snapshots every file path + exact byte content in a directory.
fn snapshot_dir(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut map = BTreeMap::new();
    fn walk(base: &Path, current: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(current).expect("read_dir") {
            let entry = entry.expect("entry");
            let path = entry.path();
            let rel = path.strip_prefix(base).expect("strip_prefix").to_path_buf();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                out.insert(rel, fs::read(&path).expect("read file"));
            }
        }
    }
    walk(root, root, &mut map);
    map
}

#[test]
fn scan_classifies_files_by_name() {
    let built = |id: &str| matches!(id, "webservice" | "ssl" | "portforward" | "ddns");
    assert_eq!(
        classify_name_with_built("gately", built),
        FileKind::Settings
    );
    assert_eq!(
        classify_name_with_built("account", built),
        FileKind::Account
    );
    assert_eq!(classify_name_with_built("tokens", built), FileKind::Account);
    assert_eq!(
        classify_name_with_built("webservice", built),
        FileKind::ModuleBuilt
    );
    assert_eq!(
        classify_name_with_built("ssl", built),
        FileKind::ModuleBuilt
    );
    assert_eq!(
        classify_name_with_built("portforward", built),
        FileKind::ModuleBuilt
    );
    assert_eq!(
        classify_name_with_built("ddns", built),
        FileKind::ModuleBuilt
    );
    assert_eq!(
        classify_name_with_built("docker", built),
        FileKind::ModuleNotBuilt
    );
    assert_eq!(
        classify_name_with_built("waf", built),
        FileKind::ModuleNotBuilt
    );
    assert_eq!(
        classify_name_with_built("mystery", built),
        FileKind::Unknown
    );
}

#[test]
fn source_dir_is_never_modified() {
    let src = copy_fixtures_to_temp();
    let before = snapshot_dir(src.path());

    let target = tempfile::tempdir().expect("target");
    let mut opts = ImportOptions::new(src.path(), target.path().join("out"));
    opts.dry_run = false;
    let report = run_import(&opts).expect("import succeeds");
    assert!(!report.has_failures());

    let after = snapshot_dir(src.path());
    assert_eq!(
        before, after,
        "source directory must be byte-for-byte identical"
    );
}

#[test]
fn dry_run_writes_nothing() {
    let src = copy_fixtures_to_temp();
    let parent = tempfile::tempdir().expect("parent");
    let target = parent.path().join("new-target");

    let opts = ImportOptions::new(src.path(), &target);
    assert!(opts.dry_run, "dry_run must be true by default");

    let report = run_import(&opts).expect("dry run succeeds");
    assert!(report.summary.dry_run);
    assert!(report.summary.imported >= 4);
    assert!(
        !target.exists(),
        "dry run must not create or touch target directory"
    );
}

#[test]
fn apply_writes_atomically_and_keeps_history() {
    let src = copy_fixtures_to_temp();
    let target = tempfile::tempdir().expect("target");

    // Seed an existing target file so the directory is non-empty.
    let old_webservice = serde_json::to_vec_pretty(&json!({
        "settings": { "enable": false, "responseHeaderTimeoutMs": 30000 },
        "listeners": []
    }))
    .expect("json");
    fs::write(target.path().join("webservice.json"), &old_webservice).expect("seed");

    // Without --force, non-empty target is rejected.
    let mut no_force = ImportOptions::new(src.path(), target.path());
    no_force.dry_run = false;
    no_force.force = false;
    assert!(
        run_import(&no_force).is_err(),
        "non-empty target without --force must fail"
    );

    // With --force, existing file is backed up AND archived in ConfigStore history.
    let mut with_force = ImportOptions::new(src.path(), target.path());
    with_force.dry_run = false;
    with_force.force = true;
    let report = run_import(&with_force).expect("apply with --force succeeds");
    assert!(!report.has_failures());

    // Backup directory created with original webservice.json.
    let backup_dir = PathBuf::from(
        report
            .summary
            .backup_dir
            .as_deref()
            .expect("backup_dir recorded"),
    );
    assert!(backup_dir.is_dir());
    assert_eq!(
        fs::read(backup_dir.join("webservice.json")).expect("read backup"),
        old_webservice
    );

    // ConfigStore history also contains the overwritten previous version.
    let store = fg_config::ConfigStore::open(target.path()).expect("open store");
    let versions = store.versions("webservice").expect("list versions");
    assert_eq!(versions.len(), 1, "previous version must be in history");
    let archived = store
        .read_version("webservice", &versions[0].id)
        .expect("read archived version");
    assert_eq!(archived, old_webservice);

    // Re-running with identical contents reports Unchanged.
    let rerun = run_import(&with_force).expect("second apply succeeds");
    assert_eq!(
        rerun.outcome("webservice").expect("outcome").status,
        Status::Unchanged
    );
}

#[test]
fn settings_field_mapping() {
    let raw: Value = serde_json::from_slice(
        &fs::read(fixture_dir().join("gately.json")).expect("read gately fixture"),
    )
    .expect("parse");

    let out = SettingsMigrator
        .transform_detailed(&raw, &MigrateCtx::default())
        .expect("transform");
    SettingsMigrator.validate(&out.value).expect("valid");

    let obj = out.value.as_object().expect("object");
    assert!(!obj.contains_key("gcPercent"), "gcPercent must be dropped");
    assert!(!obj.contains_key("maxProcs"), "maxProcs must be dropped");
    assert_eq!(obj["listen"], json!(":16680"));
    assert_eq!(obj["httpsListen"], json!(":16443"));
    assert_eq!(obj["safePath"], json!("/panel"));
    assert_eq!(obj["timeZone"], json!("Asia/Shanghai"));
    assert_eq!(obj["disabledModules"], json!(["docker", "waf"]));
    assert!(
        out.warnings
            .iter()
            .any(|w| w.path == "gcPercent" && w.reason_key == "UnsupportedField")
    );
    assert!(
        out.warnings
            .iter()
            .any(|w| w.path == "maxProcs" && w.reason_key == "UnsupportedField")
    );
}

#[test]
fn settings_env_var_hint_in_report() {
    let src = copy_fixtures_to_temp();
    let target = tempfile::tempdir().expect("target");
    let report =
        run_import(&ImportOptions::new(src.path(), target.path().join("out"))).expect("dry run");

    let gately = report.outcome("gately").expect("gately outcome");
    let hint = gately
        .warnings
        .iter()
        .find(|w| w.reason_key == "EnvVarRename")
        .expect("env var rename hint");
    assert!(hint.message.contains("GATELY_*"));
    assert!(hint.message.contains("FERRUMGATE_*"));
}

#[test]
fn disabled_modules_switches_kept_for_unbuilt() {
    let src = copy_fixtures_to_temp();
    let target = tempfile::tempdir().expect("target");
    let out_dir = target.path().join("out");

    let mut opts = ImportOptions::new(src.path(), &out_dir);
    opts.dry_run = false;
    let report = run_import_with_built(&opts, |id| {
        matches!(id, "portforward" | "ssl" | "webservice")
    })
    .expect("import");
    assert!(!report.has_failures());

    let written: Value = serde_json::from_slice(
        &fs::read(out_dir.join("ferrumgate.json")).expect("read ferrumgate.json"),
    )
    .expect("parse");
    assert_eq!(written["disabledModules"], json!(["docker", "waf"]));
}

#[test]
fn module_roundtrip_core_modules() {
    let src = copy_fixtures_to_temp();
    let target = tempfile::tempdir().expect("target");
    let out_dir = target.path().join("out");

    let mut opts = ImportOptions::new(src.path(), &out_dir);
    opts.dry_run = false;
    let report = run_import(&opts).expect("import");
    assert!(!report.has_failures());

    // webservice.json & ssl.json roundtrip identically.
    for name in ["webservice.json", "ssl.json"] {
        let orig: Value =
            serde_json::from_slice(&fs::read(src.path().join(name)).expect("read orig"))
                .expect("parse orig");
        let imported: Value =
            serde_json::from_slice(&fs::read(out_dir.join(name)).expect("read imported"))
                .expect("parse imported");
        assert_eq!(orig, imported, "{name} should round-trip identically");
    }

    // portforward.json maps camelCase keys to FerrumGate's snake_case model and parses cleanly.
    let pf_bytes = fs::read(out_dir.join("portforward.json")).expect("read portforward.json");
    let pf: fg_gateway::l4::portforward::model::FileConfig =
        serde_json::from_slice(&pf_bytes).expect("parse portforward model");
    assert!(pf.settings.enable);
    assert_eq!(pf.settings.default_max_connections, 256);
    assert_eq!(pf.rules.len(), 2);
    assert_eq!(pf.rules[0].key, "ssh-fwd");
    assert_eq!(pf.rules[0].listen_ports, "2222");
    assert_eq!(pf.rules[1].key, "dns-fwd");
    assert_eq!(pf.rules[1].udp_session_timeout, 30);
    assert!(fg_gateway::l4::portforward::validate::validate(&pf).is_empty());
}

#[test]
fn unimplemented_fields_preserved_and_reported() {
    let src = copy_fixtures_to_temp();

    // Add known unimplemented upstream fields to webservice.json and ssl.json.
    let mut ws: Value = serde_json::from_slice(
        &fs::read(src.path().join("webservice.json")).expect("read webservice"),
    )
    .expect("parse");
    ws["listeners"][0]["http3"] = json!(true);
    ws["listeners"][0]["sites"][0]["wafEnabled"] = json!(true);
    ws["listeners"][0]["sites"][0]["locations"] =
        json!([{ "path": "/api", "target": "http://127.0.0.1:9000" }]);
    fs::write(
        src.path().join("webservice.json"),
        serde_json::to_vec_pretty(&ws).expect("ser"),
    )
    .expect("write");

    let mut ssl: Value =
        serde_json::from_slice(&fs::read(src.path().join("ssl.json")).expect("read ssl"))
            .expect("parse");
    ssl["certs"][0]["mapping"] = json!({ "domains": ["example.com"] });
    ssl["certs"][0]["deploys"] =
        json!([{ "key": "d1", "enable": true, "type": "ssh", "host": "10.0.0.2" }]);
    fs::write(
        src.path().join("ssl.json"),
        serde_json::to_vec_pretty(&ssl).expect("ser"),
    )
    .expect("write");

    let target = tempfile::tempdir().expect("target");
    let out_dir = target.path().join("out");
    let mut opts = ImportOptions::new(src.path(), &out_dir);
    opts.dry_run = false;
    let report = run_import(&opts).expect("import");
    assert!(!report.has_failures());

    // Preserved in output JSON.
    let out_ws: Value =
        serde_json::from_slice(&fs::read(out_dir.join("webservice.json")).expect("read"))
            .expect("parse");
    assert_eq!(out_ws["listeners"][0]["http3"], json!(true));
    assert_eq!(
        out_ws["listeners"][0]["sites"][0]["wafEnabled"],
        json!(true)
    );
    assert!(out_ws["listeners"][0]["sites"][0]["locations"].is_array());

    let out_ssl: Value =
        serde_json::from_slice(&fs::read(out_dir.join("ssl.json")).expect("read")).expect("parse");
    assert_eq!(
        out_ssl["certs"][0]["mapping"]["domains"],
        json!(["example.com"])
    );
    assert_eq!(out_ssl["certs"][0]["deploys"][0]["host"], json!("10.0.0.2"));

    // Reported as UnsupportedField warnings.
    let ws_outcome = report.outcome("webservice").expect("ws outcome");
    assert!(
        ws_outcome
            .warnings
            .iter()
            .any(|w| w.path == "listeners[0].http3" && w.reason_key == "UnsupportedField")
    );
    assert!(
        ws_outcome
            .warnings
            .iter()
            .any(|w| w.path == "listeners[0].sites[0].locations"
                && w.reason_key == "UnsupportedField")
    );

    let ssl_outcome = report.outcome("ssl").expect("ssl outcome");
    assert!(
        ssl_outcome
            .warnings
            .iter()
            .any(|w| w.path == "certs[0].mapping.domains" && w.reason_key == "UnsupportedField")
    );
    assert!(
        ssl_outcome
            .warnings
            .iter()
            .any(|w| w.path == "certs[0].deploys[0].host" && w.reason_key == "UnsupportedField")
    );
}

#[test]
fn limit_violation_fails_without_truncation() {
    let src = copy_fixtures_to_temp();

    // Exceed FerrumGate portforward limits: 9 targets (cap 8) and 65 listen ports (cap 64).
    let bad_pf = json!({
        "settings": { "enable": true },
        "rules": [
            {
                "key": "too-many-targets",
                "name": "Overflow Targets",
                "enable": true,
                "protocols": ["tcp"],
                "listenAddress": "127.0.0.1",
                "listenPorts": "9000",
                "targetAddresses": [
                    "10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80",
                    "10.0.0.4:80", "10.0.0.5:80", "10.0.0.6:80",
                    "10.0.0.7:80", "10.0.0.8:80", "10.0.0.9:80"
                ],
                "targetPorts": "80"
            },
            {
                "key": "too-many-ports",
                "name": "Overflow Ports",
                "enable": true,
                "protocols": ["tcp"],
                "listenAddress": "127.0.0.1",
                "listenPorts": "10000-10064",
                "targetAddresses": ["10.0.0.1:80"],
                "targetPorts": "80"
            }
        ]
    });
    fs::write(
        src.path().join("portforward.json"),
        serde_json::to_vec_pretty(&bad_pf).expect("ser"),
    )
    .expect("write");

    let target = tempfile::tempdir().expect("target");
    let out_dir = target.path().join("out");
    let mut opts = ImportOptions::new(src.path(), &out_dir);
    opts.dry_run = false;
    let report = run_import(&opts).expect("run_import returns report with failure status");

    assert!(report.has_failures());
    let pf = report.outcome("portforward").expect("pf outcome");
    assert_eq!(pf.status, Status::Failed);
    assert!(
        pf.errors
            .iter()
            .any(|e| e.contains("too-many-targets") && e.contains("8")),
        "expected target cap error, got {:?}",
        pf.errors
    );
    assert!(
        pf.errors.iter().any(|e| e.contains("too-many-ports")),
        "expected port cap error, got {:?}",
        pf.errors
    );
    assert!(
        !out_dir.join("portforward.json").exists(),
        "failed module must not be truncated or written"
    );
}

#[test]
fn default_value_difference_noted() {
    let src = copy_fixtures_to_temp();

    // Remove explicit `timeoutsConnectSecs` from proxy site so it relies on defaults.
    let mut ws: Value =
        serde_json::from_slice(&fs::read(src.path().join("webservice.json")).expect("read"))
            .expect("parse");
    ws["listeners"][0]["sites"][0]
        .as_object_mut()
        .expect("site obj")
        .remove("timeoutsConnectSecs");
    fs::write(
        src.path().join("webservice.json"),
        serde_json::to_vec_pretty(&ws).expect("ser"),
    )
    .expect("write");

    let target = tempfile::tempdir().expect("target");
    let report =
        run_import(&ImportOptions::new(src.path(), target.path().join("out"))).expect("dry run");

    let ws_outcome = report.outcome("webservice").expect("ws outcome");
    assert!(
        ws_outcome.warnings.iter().any(|w| {
            w.path == "listeners[0].sites[0].timeoutsConnectSecs"
                && w.reason_key == "DefaultValueChanged"
        }),
        "expected DefaultValueChanged warning, got {:?}",
        ws_outcome.warnings
    );

    // When explicitly written (as in committed fixtures), no DefaultValueChanged warning is emitted.
    let clean_src = copy_fixtures_to_temp();
    let clean_report = run_import(&ImportOptions::new(
        clean_src.path(),
        target.path().join("out2"),
    ))
    .expect("dry run");
    assert!(
        !clean_report
            .outcome("webservice")
            .expect("ws")
            .warnings
            .iter()
            .any(|w| w.reason_key == "DefaultValueChanged"),
        "explicit timeout must not trigger default-value-difference warning"
    );
}

#[test]
fn secrets_masked_in_report() {
    let src = copy_fixtures_to_temp();

    // Inject distinct sentinel secrets into gately.json, webservice.json, ssl.json, and account.json.
    let api_token_sentinel = "SENTINEL_API_TOKEN_98765";
    let oauth_secret_sentinel = "SENTINEL_OAUTH_SECRET_54321";
    let auth_secret_sentinel = "SENTINEL_WEBSERVICE_AUTH_SECRET";
    let user_pass_sentinel = "SENTINEL_SITE_PASSWORD_XYZ";
    let session_secret_sentinel = "SENTINEL_SESSION_SECRET_ABC";

    let mut gately: Value =
        serde_json::from_slice(&fs::read(src.path().join("gately.json")).expect("read"))
            .expect("parse");
    gately["apiToken"] = json!(api_token_sentinel);
    gately["thirdLogin"] = json!({
        "enable": false,
        "callbackBase": "https://panel.example.com",
        "providers": [{
            "key": "gh",
            "name": "GitHub",
            "type": "github",
            "clientId": "public-client-id",
            "clientSecret": oauth_secret_sentinel,
            "issuer": "",
            "proxy": ""
        }],
        "allowed": ["gh:alice"],
        "skipTotp": false
    });
    fs::write(
        src.path().join("gately.json"),
        serde_json::to_vec_pretty(&gately).expect("ser"),
    )
    .expect("write");

    let mut ws: Value =
        serde_json::from_slice(&fs::read(src.path().join("webservice.json")).expect("read"))
            .expect("parse");
    ws["settings"]["authSecret"] = json!(auth_secret_sentinel);
    ws["listeners"][0]["sites"][0]["users"] = json!([format!("alice:{user_pass_sentinel}")]);
    fs::write(
        src.path().join("webservice.json"),
        serde_json::to_vec_pretty(&ws).expect("ser"),
    )
    .expect("write");

    fs::write(
        src.path().join("account.json"),
        serde_json::to_vec_pretty(&json!({
            "username": "admin",
            "passwordHash": "$2b$10$SENTINEL_BCRYPT_HASH_VALUE",
            "sessionSecret": session_secret_sentinel,
            "tokenTTLHours": 24
        }))
        .expect("ser"),
    )
    .expect("write");

    let target = tempfile::tempdir().expect("target");
    let mut opts = ImportOptions::new(src.path(), target.path().join("out"));
    opts.accounts = AccountPolicy::Import;
    let report = run_import(&opts).expect("dry run");

    let ssl_outcome = report.outcome("ssl").expect("ssl outcome");
    let key_pem_change = ssl_outcome
        .changed_fields
        .iter()
        .find(|c| c.path == "certs[0].keyPem")
        .expect("keyPem recorded in changed_fields");
    assert_eq!(key_pem_change.to, REDACTED);

    let report_json = report.to_json_pretty().expect("json report");
    let report_human = report.format_human(&opts.target_dir);

    for rendered in [&report_json, &report_human] {
        for forbidden in [
            "PRIVATE KEY",
            "MIGHAgEA",
            api_token_sentinel,
            oauth_secret_sentinel,
            auth_secret_sentinel,
            user_pass_sentinel,
            session_secret_sentinel,
            "SENTINEL_BCRYPT_HASH_VALUE",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "report leaked secret material '{forbidden}'"
            );
        }
    }
}

#[test]
fn accounts_skipped_by_default() {
    let src = copy_fixtures_to_temp();
    fs::write(
        src.path().join("account.json"),
        r#"{"username":"admin","passwordHash":"$2b$10$dummy","sessionSecret":"abc"}"#,
    )
    .expect("write account");
    fs::write(src.path().join("tokens.json"), r#"{"tokens":[]}"#).expect("write tokens");

    let target = tempfile::tempdir().expect("target");
    let out_dir = target.path().join("out");
    let mut opts = ImportOptions::new(src.path(), &out_dir);
    opts.dry_run = false;
    assert_eq!(opts.accounts, AccountPolicy::Skip);

    let report = run_import(&opts).expect("import");
    assert!(!report.has_failures());
    assert_eq!(
        report.outcome("account").expect("account").status,
        Status::Skipped
    );
    assert_eq!(
        report.outcome("tokens").expect("tokens").status,
        Status::Skipped
    );
    assert!(!out_dir.join("account.json").exists());
    assert!(!out_dir.join("tokens.json").exists());
}

#[test]
fn accounts_import_only_into_fresh_target() {
    let src = copy_fixtures_to_temp();
    fs::write(
        src.path().join("account.json"),
        r#"{"username":"admin","passwordHash":"$2b$10$dummy","sessionSecret":"source-session-secret"}"#,
    )
    .expect("write account");
    fs::write(src.path().join("tokens.json"), r#"{"tokens":[]}"#).expect("write tokens");

    // 1) Fresh target succeeds and emits sessionSecret preservation warning.
    let fresh_parent = tempfile::tempdir().expect("fresh");
    let fresh_target = fresh_parent.path().join("fresh");
    let mut fresh_opts = ImportOptions::new(src.path(), &fresh_target);
    fresh_opts.dry_run = false;
    fresh_opts.accounts = AccountPolicy::Import;
    let fresh_report = run_import(&fresh_opts).expect("fresh import");
    assert!(!fresh_report.has_failures());
    let acct = fresh_report.outcome("account").expect("account");
    assert_eq!(acct.status, Status::Imported);
    assert!(
        acct.warnings
            .iter()
            .any(|w| w.reason_key == "SessionSecretPreserved"),
        "expected SessionSecretPreserved warning"
    );
    assert!(fresh_target.join("account.json").exists());
    assert!(fresh_target.join("tokens.json").exists());

    // 2) Target that ALREADY has account.json must refuse account import even with --force.
    let existing_account_bytes =
        br#"{"username":"existing-admin","passwordHash":"$2b$10$keep","sessionSecret":"keep"}"#;
    let existing = tempfile::tempdir().expect("existing");
    fs::write(existing.path().join("account.json"), existing_account_bytes).expect("seed account");

    let mut reject_opts = ImportOptions::new(src.path(), existing.path());
    reject_opts.dry_run = false;
    reject_opts.force = true;
    reject_opts.accounts = AccountPolicy::Import;
    let reject_report = run_import(&reject_opts).expect("import returns failed account outcome");
    assert!(reject_report.has_failures());
    assert_eq!(
        reject_report.outcome("account").expect("account").status,
        Status::Failed
    );
    assert_eq!(
        fs::read(existing.path().join("account.json")).expect("read existing account"),
        existing_account_bytes,
        "existing account.json must not be overwritten"
    );
}

#[test]
fn unbuilt_module_reported_not_imported() {
    let src = copy_fixtures_to_temp();
    fs::write(src.path().join("docker.json"), r#"{"enable":true}"#).expect("write docker");
    fs::write(src.path().join("waf.json"), r#"{"enable":true}"#).expect("write waf");

    let target = tempfile::tempdir().expect("target");
    let out_dir = target.path().join("out");
    let mut opts = ImportOptions::new(src.path(), &out_dir);
    opts.dry_run = false;
    let report = run_import_with_built(&opts, |id| {
        matches!(id, "portforward" | "ssl" | "webservice")
    })
    .expect("import");

    assert!(!report.has_failures());
    for unbuilt in ["docker", "waf"] {
        let outcome = report.outcome(unbuilt).expect("unbuilt outcome");
        assert_eq!(outcome.status, Status::NotBuilt);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.reason_key == "ModuleNotBuilt")
        );
        assert!(
            !out_dir.join(format!("{unbuilt}.json")).exists(),
            "unbuilt module {unbuilt} must not be written"
        );
    }
}

#[test]
fn unknown_json_files_listed() {
    let src = copy_fixtures_to_temp();
    fs::write(src.path().join("custom-plugin.json"), r#"{"foo":"bar"}"#).expect("write unknown");

    let target = tempfile::tempdir().expect("target");
    let out_dir = target.path().join("out");
    let mut opts = ImportOptions::new(src.path(), &out_dir);
    opts.dry_run = false;
    let report = run_import(&opts).expect("import");

    let unknown = report.outcome("custom-plugin").expect("unknown listed");
    assert_eq!(unknown.status, Status::Skipped);
    assert!(
        unknown
            .warnings
            .iter()
            .any(|w| w.reason_key == "UnknownFile")
    );
    assert!(!out_dir.join("custom-plugin.json").exists());
}

#[test]
fn newer_source_version_hint() {
    let src = copy_fixtures_to_temp();
    let mut ws: Value =
        serde_json::from_slice(&fs::read(src.path().join("webservice.json")).expect("read"))
            .expect("parse");
    ws["listeners"][0]["sites"][0]["quantumRouting2027"] = json!("enabled");
    fs::write(
        src.path().join("webservice.json"),
        serde_json::to_vec_pretty(&ws).expect("ser"),
    )
    .expect("write");

    let target = tempfile::tempdir().expect("target");
    let out_dir = target.path().join("out");
    let mut opts = ImportOptions::new(src.path(), &out_dir);
    opts.dry_run = false;
    let report = run_import(&opts).expect("import");

    assert!(!report.has_failures());
    let ws_outcome = report.outcome("webservice").expect("ws outcome");
    assert!(
        ws_outcome
            .warnings
            .iter()
            .any(|w| w.reason_key == "NewerSourceVersion"),
        "expected NewerSourceVersion warning, got {:?}",
        ws_outcome.warnings
    );

    // Unknown field from newer version is preserved in output JSON.
    let written: Value =
        serde_json::from_slice(&fs::read(out_dir.join("webservice.json")).expect("read"))
            .expect("parse");
    assert_eq!(
        written["listeners"][0]["sites"][0]["quantumRouting2027"],
        json!("enabled")
    );
}

#[tokio::test]
async fn full_config_dir_import_then_check() {
    let src = copy_fixtures_to_temp();
    let target = tempfile::tempdir().expect("target");
    let out_dir = target.path().join("imported");

    let mut opts = ImportOptions::new(src.path(), &out_dir);
    opts.dry_run = false;
    let report = run_import(&opts).expect("import succeeds");
    assert!(!report.has_failures(), "unexpected failures: {report:#?}");
    assert_eq!(report.summary.imported, 4);

    // Run FerrumGate's `fgate check` validation over the imported directory.
    fg_gateway::check_config(&out_dir)
        .await
        .expect("fgate check must pass on imported config directory");
}
