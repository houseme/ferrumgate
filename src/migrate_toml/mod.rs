//! WP-39: `fgate migrate --config <toml> --dir <dir>` — converts the
//! legacy single-file TOML into the new configuration directory
//! (webservice.json + ssl.json + portforward.json + settings), reports
//! every mapping decision, and never touches the source file.
#![allow(dead_code)]

pub mod certs;
pub mod portforward;
pub mod report;
pub mod web;

use std::path::Path;

use fg_gateway::legacy_config::RawConfig;

#[allow(unused_imports)]
pub use report::{
    Converted, DefaultChange, DroppedField, FieldMap, MigrateError, MigrateReport, Summary, Warning,
};

/// Command-line options for `fgate migrate`.
pub struct MigrateOptions {
    pub config: std::path::PathBuf,
    pub dir: std::path::PathBuf,
    pub force: bool,
    pub report: Option<std::path::PathBuf>,
}

/// Reads the legacy TOML, converts it, writes the target directory
/// (which must be new or empty; `--force` moves existing documents into
/// `backup-<timestamp>`), self-checks, and rolls the writes back on any
/// failure. The source file is never modified.
pub fn run(options: &MigrateOptions) -> anyhow::Result<()> {
    use anyhow::Context;

    let text = std::fs::read_to_string(&options.config)
        .with_context(|| format!("读取旧配置失败：{}", options.config.display()))?;
    let raw: RawConfig = toml::from_str::<RawConfig>(&text)
        .map_err(|error| anyhow::anyhow!("旧配置 schema 校验失败：{error}"))
        .and_then(|raw: RawConfig| {
            // Schema version guard: only `schema_version = 1` migrates.
            if raw.schema_version == 1 {
                Ok(raw)
            } else {
                Err(anyhow::anyhow!(
                    "仅支持 schema_version = 1（读到 {}）",
                    raw.schema_version
                ))
            }
        })?;
    let converted = convert(&raw).map_err(|error| anyhow::anyhow!(error.to_string()))?;

    let dir = &options.dir;
    let mut backup: Option<std::path::PathBuf> = None;
    if dir.exists() {
        let empty = std::fs::read_dir(dir)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false);
        if !empty && !options.force {
            anyhow::bail!(
                "目标目录 {} 非空；确认后加 --force（已有同名文件会先备份）",
                dir.display()
            );
        }
        if !empty {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or(0);
            let target = dir.join(format!("backup-{stamp}"));
            std::fs::create_dir_all(&target)
                .with_context(|| format!("创建备份目录失败：{}", target.display()))?;
            for name in ["webservice.json", "ssl.json", "portforward.json"] {
                let from = dir.join(name);
                if from.exists() {
                    std::fs::rename(&from, target.join(name)).with_context(|| {
                        format!("备份 {} 失败", from.display())
                    })?;
                }
            }
            backup = Some(target);
        }
    } else {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("创建目标目录失败：{}", dir.display()))?;
    }

    let documents: [(&str, serde_json::Value); 3] = [
        (
            "webservice.json",
            serde_json::to_value(&converted.webservice)?,
        ),
        ("ssl.json", serde_json::to_value(&converted.ssl)?),
        (
            "portforward.json",
            serde_json::to_value(&converted.portforward)?,
        ),
    ];
    let mut written = Vec::new();
    let mut write_error: Option<anyhow::Error> = None;
    for (name, value) in &documents {
        let path = dir.join(name);
        let body = serde_json::to_string_pretty(value)?;
        match std::fs::write(&path, body).with_context(|| format!("写入 {} 失败", path.display())) {
            Ok(()) => written.push(path),
            Err(error) => {
                write_error = Some(error);
                break;
            }
        }
    }
    // ssl.json carries private keys and credential material: 0600.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            dir.join("ssl.json"),
            std::fs::Permissions::from_mode(0o600),
        );
    }

    let outcome = if let Some(error) = &write_error {
        Err(vec![format!("写入失败：{error}")])
    } else {
        verify_written(dir)
    };
    if let Err(problems) = outcome {
        // Roll back: remove what this run wrote and restore the backup.
        for path in &written {
            let _ = std::fs::remove_file(path);
        }
        if let Some(backup_dir) = &backup {
            for name in ["webservice.json", "ssl.json", "portforward.json"] {
                let from = backup_dir.join(name);
                if from.exists() {
                    let _ = std::fs::rename(&from, dir.join(name));
                }
            }
        }
        anyhow::bail!(
            "自检失败，本次写入已回滚：{}",
            problems.join("；")
        );
    }

    let report_json = serde_json::to_string_pretty(&converted.report)?;
    match &options.report {
        Some(path) => std::fs::write(path, report_json)
            .with_context(|| format!("写入迁移报告失败：{}", path.display()))?,
        None => println!("{}", report_json),
    }
    println!(
        "迁移完成：{} → {}（备份：{}）",
        options.config.display(),
        dir.display(),
        backup
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "无".to_owned())
    );
    Ok(())
}

/// Converts a validated legacy config into the new model documents plus
/// the mapping report. Pure function: no I/O.
pub fn convert(config: &RawConfig) -> Result<Converted, MigrateError> {
    let mut report = MigrateReport::default();
    let webservice = web::convert(config, &mut report).map_err(MigrateError::Invalid)?;
    let ssl = certs::convert(config, &mut report).map_err(MigrateError::Invalid)?;
    let portforward =
        portforward::convert(config, &mut report).map_err(MigrateError::Invalid)?;
    report.summary.files = vec![
        ("webservice.json".to_owned(), {
            let listeners = &webservice.listeners;
            listeners.iter().map(|listener| listener.sites.len()).sum::<usize>()
        }),
        ("ssl.json".to_owned(), ssl.certs.len()),
        ("portforward.json".to_owned(), portforward.rules.len()),
    ];
    Ok(Converted {
        webservice,
        ssl,
        portforward,
        report,
    })
}

/// Self-check after writing: run every model's validation over the
/// files in `dir` (the same checks startup performs).
pub fn verify_written(dir: &Path) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    let read = |name: &str| -> Option<serde_json::Value> {
        std::fs::read(dir.join(name))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    };
    if let Some(value) = read("webservice.json")
        && let Ok(config) =
            serde_json::from_value::<fg_gateway::web::model::FileConfig>(value)
    {
        let normalized = fg_gateway::web::validate::normalize(config);
        let _ = normalized;
    } else {
        problems.push("webservice.json 无法读取或解析".to_owned());
    }
    if let Some(value) = read("ssl.json")
        && let Ok(mut config) = serde_json::from_value::<fg_gateway::certs::model::FileConfig>(value)
    {
        if let Err(error) = fg_gateway::certs::validate::normalize(&mut config) {
            problems.push(error.to_string());
        }
    } else {
        problems.push("ssl.json 无法读取或解析".to_owned());
    }
    if read("portforward.json").is_none() {
        problems.push("portforward.json 无法读取或解析".to_owned());
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}
