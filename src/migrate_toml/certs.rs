//! WP-39 step 3: the certificate mapping — legacy `[[certificates]]` and
//! `[acme]` into `ssl.json` (spec: docs/plan/WP-39-migrate-toml.md §3.3).
#![allow(dead_code)]

use super::report::{DroppedField, FieldMap, MigrateReport};
use fg_gateway::certs::model::{Cert, CertSource};
use fg_gateway::legacy_config::RawConfig;

fn map(from: &str, report: &mut MigrateReport, to: &str) {
    report.mapped.push(FieldMap {
        from: from.to_owned(),
        to: to.to_owned(),
    });
}

fn drop_field(report: &mut MigrateReport, field: &str, reason: &str, hint: &str) {
    report.dropped.push(DroppedField {
        field: field.to_owned(),
        reason_key: reason.to_owned(),
        hint_key: hint.to_owned(),
    });
}

fn file_entry(host: &str, cert_file: &str, key_file: &str) -> Cert {
    Cert {
        remark: host.to_owned(),
        enable: true,
        source: CertSource::File,
        cert_file: cert_file.to_owned(),
        key_file: key_file.to_owned(),
        ..Cert::default()
    }
}

/// The ACME entry: ssl.json keeps ACME parameters as a JSON map until
/// WP-32 gives them their typed shape; legacy names map to the upstream
/// camelCase keys. RawAcme fields are private — serde is the shared view.
fn acme_entry(config: &RawConfig, report: &mut MigrateReport) -> Result<Cert, String> {
    let acme = serde_json::to_value(config.acme.as_ref().expect("acme section exists"))
        .map_err(|_| "acme 段无法读取".to_owned())?;
    let mut params = serde_json::Map::new();
    params.insert("domains".into(), acme["domains"].clone());
    params.insert("email".into(), acme["email"].clone());
    match acme.get("directory").and_then(|d| d.as_str()) {
        Some(url) => {
            params.insert("ca".into(), serde_json::json!("custom"));
            params.insert("directoryUrl".into(), serde_json::json!(url));
        }
        None => {
            params.insert("ca".into(), serde_json::json!("letsencrypt"));
        }
    }
    if let Some(profile) = acme.get("profile").and_then(|p| p.as_str()) {
        params.insert("profile".into(), serde_json::json!(profile));
    }
    if let Some(eab) = acme.get("eab") {
        if let Some(kid) = eab.get("key_id").and_then(|k| k.as_str()) {
            params.insert("eabKid".into(), serde_json::json!(kid));
        }
        drop_field(
            report,
            "acme.eab.hmac_key_file",
            "EAB HMAC 以文件路径保存",
            "迁移后把 HMAC 值直接填入 ssl.json 的 eabHmac",
        );
    }
    if let Some(dns01) = acme.get("dns01") {
        params.insert("challenge".into(), serde_json::json!("dns"));
        params.insert("provider".into(), serde_json::json!("cloudflare"));
        params.insert("credentials".into(), dns01.clone());
    }
    if let Some(port) = acme.get("challenge_listen").and_then(|p| p.as_str()) {
        params.insert("httpPort".into(), serde_json::json!(port));
    }
    if let Some(hours) = acme.get("renew_before_hours").and_then(|h| h.as_u64()) {
        map(
            "acme.renew_before_hours",
            report,
            "settings.renewBeforeDays（向上取整到天）",
        );
        params.insert(
            "renewBeforeDays".into(),
            serde_json::json!((hours / 24).max(1)),
        );
    }
    drop_field(
        report,
        "acme.accept_terms",
        "新模型始终接受服务条款",
        "无需操作",
    );
    drop_field(
        report,
        "acme.state_dir",
        "新模型的 ACME 状态保存在 ssl.json 内",
        "无需操作；旧状态目录可归档",
    );
    let mut cert = Cert {
        enable: true,
        source: CertSource::Acme,
        acme: params,
        ..Cert::default()
    };
    cert.key = "acme".to_owned();
    cert.remark = acme["domains"]
        .as_array()
        .and_then(|domains| domains.first())
        .and_then(|first| first.as_str())
        .unwrap_or("acme")
        .to_owned();
    Ok(cert)
}

/// Converts the certificate section: file certificates keep their paths,
/// the ACME section becomes one entry.
pub fn convert(
    config: &RawConfig,
    report: &mut MigrateReport,
) -> Result<fg_gateway::certs::model::FileConfig, String> {
    let mut file = fg_gateway::certs::model::FileConfig::default();
    for entry in &config.certificates {
        // CertificateFiles fields are private; serde is the shared view.
        let Ok(value) = serde_json::to_value(entry) else {
            return Err("certificate 条目无法读取".to_owned());
        };
        let host = value
            .get("host")
            .and_then(|h| h.as_str())
            .unwrap_or_default();
        let cert_file = value
            .get("cert_file")
            .and_then(|c| c.as_str())
            .unwrap_or_default();
        let key_file = value
            .get("key_file")
            .and_then(|k| k.as_str())
            .unwrap_or_default();
        map("certificates[]", report, "ssl.certs[] source=file");
        file.certs.push(file_entry(host, cert_file, key_file));
    }
    let acme_view = match &config.acme {
        Some(acme) => serde_json::to_value(acme).ok(),
        None => None,
    };
    if let Some(acme_value) = acme_view {
        map("[acme]", report, "ssl.certs[] source=acme");
        let entry = acme_entry(config, report)?;
        file.settings.default_email = acme_value["email"].as_str().unwrap_or_default().to_owned();
        file.certs.push(entry);
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(toml_text: &str) -> RawConfig {
        toml::from_str::<RawConfig>(toml_text).expect("fixture parses")
    }

    const FIXTURE: &str = include_str!("../../tests/fixtures/toml/certs.toml");

    #[test]
    fn certificates_become_file_source_entries() {
        let mut report = MigrateReport::default();
        let file = convert(&config(FIXTURE), &mut report).expect("converts");
        let entry = file
            .certs
            .iter()
            .find(|cert| cert.source == CertSource::File)
            .expect("file entry");
        assert_eq!(entry.remark, "home.example.com");
        assert_eq!(entry.cert_file, "/etc/ssl/home.pem");
        assert_eq!(entry.key_file, "/etc/ssl/home.key");
        assert!(entry.enable);
    }

    #[test]
    fn acme_maps_to_custom_directory_and_days() {
        let mut report = MigrateReport::default();
        let file = convert(&config(FIXTURE), &mut report).expect("converts");
        let entry = file
            .certs
            .iter()
            .find(|cert| cert.source == CertSource::Acme)
            .expect("acme entry");
        assert_eq!(entry.acme["ca"], "custom");
        assert_eq!(entry.acme["directoryUrl"], "https://acme.example/dir");
        assert_eq!(entry.acme["profile"], "shortlived");
        assert_eq!(entry.acme["renewBeforeDays"], 2); // integer division 50/24 = 2
        assert!(file.settings.default_email.contains("@"));
        assert!(report.dropped.iter().any(|d| d.field == "acme.accept_terms"));
        assert!(report.dropped.iter().any(|d| d.field == "acme.state_dir"));
    }

    #[test]
    fn dns01_maps_to_challenge_and_provider() {
        let mut report = MigrateReport::default();
        let file = convert(&config(FIXTURE), &mut report).expect("converts");
        let entry = file
            .certs
            .iter()
            .find(|cert| cert.source == CertSource::Acme)
            .expect("acme entry");
        assert_eq!(entry.acme["challenge"], "dns");
        assert_eq!(entry.acme["provider"], "cloudflare");
        assert!(entry.acme.get("credentials").is_some());
    }
}
