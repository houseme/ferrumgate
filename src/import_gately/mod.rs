//! WP-38: `fgate import gately` — imports a Gately configuration directory into
//! FerrumGate with dry-run reporting, atomic writes, history/backup support,
//! secret redaction, and round-trip preservation of unimplemented fields.

pub mod report;
pub mod scan;
pub mod transform;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use serde_json::Value;

pub use report::{
    AccountPolicy, FieldChange, ImportOptions, ModuleOutcome, REDACTED, Report, Status, Summary,
    Warning,
};
pub use scan::{FileKind, MAX_FILE_BYTES, ScannedFile, classify_name, scan_source_dir};
pub use transform::{MigrateCtx, MigrateModule, TransformOutput, UPSTREAM_BASELINE};

struct PlannedWrite {
    /// Config store name without `.json` (e.g. `"ferrumgate"`, `"webservice"`, `"ssl"`).
    config_name: String,
    /// Pretty-printed JSON bytes ending with `\n`.
    bytes: Vec<u8>,
    /// Index into `report.outcomes` so write errors can mark the outcome failed.
    outcome_index: usize,
}

/// Runs the Gately configuration directory import according to `options`.
///
/// - Never modifies `options.source_dir`.
/// - When `options.dry_run` is true (default CLI mode without `--apply`),
///   `options.target_dir` is not created or modified.
/// - When `options.dry_run` is false, requires `options.target_dir` to be
///   new/empty unless `options.force` is true (in which case overwritten files
///   are backed up to `backup-<timestamp>` AND archived via `ConfigStore`
///   history before atomic replacement).
pub fn run_import(options: &ImportOptions) -> Result<Report> {
    run_import_with_built(options, fg_core::features::built)
}

/// Internal testable entry point accepting a custom `is_built` predicate.
pub fn run_import_with_built(
    options: &ImportOptions,
    is_built: impl Fn(&str) -> bool,
) -> Result<Report> {
    let scanned = scan::scan_source_dir_with_built(&options.source_dir, &is_built)?;

    // Safety guard: never allow source_dir and target_dir to resolve to the same directory.
    if options.target_dir.exists() {
        let src_canon = options
            .source_dir
            .canonicalize()
            .with_context(|| format!("cannot resolve {}", options.source_dir.display()))?;
        let dst_canon = options
            .target_dir
            .canonicalize()
            .with_context(|| format!("cannot resolve {}", options.target_dir.display()))?;
        ensure!(
            src_canon != dst_canon,
            "target directory must differ from source directory (source directory is read-only)"
        );
    }

    // Validate target directory preconditions before writing.
    let target_non_empty = if options.target_dir.exists() {
        let meta = fs::metadata(&options.target_dir)
            .with_context(|| format!("cannot inspect {}", options.target_dir.display()))?;
        ensure!(
            meta.is_dir(),
            "target path {} exists and is not a directory",
            options.target_dir.display()
        );
        fs::read_dir(&options.target_dir)
            .with_context(|| format!("cannot list {}", options.target_dir.display()))?
            .next()
            .is_some()
    } else {
        false
    };

    if !options.dry_run && target_non_empty && !options.force {
        bail!(
            "target directory {} is not empty; pass --force to back up existing files and overwrite",
            options.target_dir.display()
        );
    }

    let built_modules: Vec<&'static str> = fg_core::features::CATALOG_IDS
        .iter()
        .copied()
        .filter(|id| is_built(id))
        .collect();
    let ctx = MigrateCtx { built_modules };
    let target_has_account = options.target_dir.join("account.json").exists();

    let mut report = Report::default();
    let mut planned_writes: Vec<PlannedWrite> = Vec::new();

    for file in &scanned {
        match file.kind {
            FileKind::Settings => {
                if !included_by_filter(&options.include, &file.id, Some("ferrumgate")) {
                    let mut outcome = ModuleOutcome::new(&file.id, Status::Skipped);
                    outcome.warnings.push(Warning::new(
                        file.file_name.clone(),
                        "ExcludedByFilter",
                        "import.gately.excluded_by_include",
                        "Skipped because it was not listed in --include.",
                    ));
                    report.outcomes.push(outcome);
                    continue;
                }
                process_migrator(
                    file,
                    "ferrumgate",
                    &transform::SettingsMigrator,
                    &ctx,
                    &options.target_dir,
                    &mut report.outcomes,
                    &mut planned_writes,
                );
            }
            FileKind::Account => {
                process_account_file(
                    file,
                    options,
                    target_has_account,
                    &mut report.outcomes,
                    &mut planned_writes,
                );
            }
            FileKind::ModuleBuilt => {
                if !included_by_filter(&options.include, &file.id, None) {
                    let mut outcome = ModuleOutcome::new(&file.id, Status::Skipped);
                    outcome.warnings.push(Warning::new(
                        file.file_name.clone(),
                        "ExcludedByFilter",
                        "import.gately.excluded_by_include",
                        "Skipped because it was not listed in --include.",
                    ));
                    report.outcomes.push(outcome);
                    continue;
                }
                let Some(migrator) = transform::migrator_for_module(&file.id) else {
                    let mut outcome = ModuleOutcome::new(&file.id, Status::NotBuilt);
                    outcome.warnings.push(Warning::new(
                        file.file_name.clone(),
                        "ModuleNotBuilt",
                        "import.gately.module_not_built_keep_source",
                        format!("No migrator available for module '{}'.", file.id),
                    ));
                    report.outcomes.push(outcome);
                    continue;
                };
                process_migrator(
                    file,
                    &file.id,
                    migrator.as_ref(),
                    &ctx,
                    &options.target_dir,
                    &mut report.outcomes,
                    &mut planned_writes,
                );
            }
            FileKind::ModuleNotBuilt => {
                let mut outcome = ModuleOutcome::new(&file.id, Status::NotBuilt);
                outcome.warnings.push(Warning::new(
                    file.file_name.clone(),
                    "ModuleNotBuilt",
                    "import.gately.module_not_built_keep_source",
                    format!(
                        "Module '{}' is not included in this build or not yet implemented; not imported. Keep the source directory if you plan to switch to a full build.",
                        file.id
                    ),
                ));
                report.outcomes.push(outcome);
            }
            FileKind::Unknown => {
                let mut outcome = ModuleOutcome::new(&file.id, Status::Skipped);
                outcome.warnings.push(Warning::new(
                    file.file_name.clone(),
                    "UnknownFile",
                    "import.gately.unknown_json_skipped",
                    format!("Unrecognized JSON file '{}' was skipped.", file.file_name),
                ));
                report.outcomes.push(outcome);
            }
        }
    }

    let mut backup_dir_str: Option<String> = None;

    if !options.dry_run && !planned_writes.is_empty() {
        // When --force overwrites existing files in a non-empty target directory,
        // copy the existing same-named files into `backup-<timestamp>` first,
        // keeping the originals in place so `ConfigStore::write_raw` also
        // snapshots them into `history/<name>/`.
        if target_non_empty && options.force {
            backup_dir_str = backup_overwritten_files(&options.target_dir, &planned_writes)?;
        }

        let store = fg_config::ConfigStore::open(&options.target_dir).with_context(|| {
            format!("open target config store {}", options.target_dir.display())
        })?;
        store.enable_history(fg_config::DEFAULT_HISTORY_KEEP, &[]);

        for write in &planned_writes {
            match store.write_raw(&write.config_name, &write.bytes) {
                Ok(saved) => {
                    if !saved.changed {
                        report.outcomes[write.outcome_index].status = Status::Unchanged;
                    }
                }
                Err(err) => {
                    let outcome = &mut report.outcomes[write.outcome_index];
                    outcome.status = Status::Failed;
                    outcome
                        .errors
                        .push(format!("failed writing {}: {err:#}", write.config_name));
                }
            }
        }
    }

    report.recompute_summary(options.dry_run, backup_dir_str);

    if let Some(report_path) = &options.report_file {
        let json = report.to_json_pretty()?;
        fs::write(report_path, json)
            .with_context(|| format!("failed writing report to {}", report_path.display()))?;
    }

    Ok(report)
}

fn included_by_filter(include: &[String], id: &str, alias: Option<&str>) -> bool {
    if include.is_empty() {
        return true;
    }
    include.iter().any(|item| {
        let item = item.trim();
        item == id || alias.is_some_and(|a| item == a) || (id == "gately" && item == "settings")
    })
}

fn process_migrator(
    file: &ScannedFile,
    target_config_name: &str,
    migrator: &dyn MigrateModule,
    ctx: &MigrateCtx,
    target_dir: &Path,
    outcomes: &mut Vec<ModuleOutcome>,
    planned_writes: &mut Vec<PlannedWrite>,
) {
    let raw_bytes = match scan::read_file_limited(&file.path) {
        Ok(bytes) => bytes,
        Err(err) => {
            let mut outcome = ModuleOutcome::new(&file.id, Status::Failed);
            outcome.errors.push(format!("{err:#}"));
            outcomes.push(outcome);
            return;
        }
    };

    let raw_json: Value = match serde_json::from_slice(&raw_bytes) {
        Ok(value) => value,
        Err(err) => {
            let mut outcome = ModuleOutcome::new(&file.id, Status::Failed);
            outcome.errors.push(format!(
                "invalid JSON in {} at line {}, column {}: {err}",
                file.file_name,
                err.line(),
                err.column()
            ));
            outcomes.push(outcome);
            return;
        }
    };

    let transformed = match migrator.transform_detailed(&raw_json, ctx) {
        Ok(output) => output,
        Err(warnings) => {
            let mut outcome = ModuleOutcome::new(&file.id, Status::Failed);
            for w in &warnings {
                if !w.message.is_empty() {
                    outcome.errors.push(w.message.clone());
                }
            }
            outcome.warnings = warnings;
            outcomes.push(outcome);
            return;
        }
    };

    let mut outcome = ModuleOutcome::new(&file.id, Status::Imported);
    outcome.warnings = transformed.warnings;
    outcome.changed_fields = transformed.changed_fields;

    if transformed.newer_version_detected {
        outcome.warnings.push(Warning::new(
            "$",
            "NewerSourceVersion",
            "import.gately.newer_source_version",
            format!(
                "Source {} contains fields unknown to baseline {}; it may come from a newer Gately version. Unrecognized fields were preserved.",
                file.file_name, UPSTREAM_BASELINE
            ),
        ));
    }

    if let Err(errors) = migrator.validate(&transformed.value) {
        outcome.status = Status::Failed;
        outcome.errors = errors;
        outcomes.push(outcome);
        return;
    }

    // Compare against existing target file (if any).
    let existing = read_existing_json(&target_dir.join(format!("{target_config_name}.json")));
    if let Some(existing_val) = &existing
        && *existing_val == transformed.value
    {
        outcome.status = Status::Unchanged;
        outcomes.push(outcome);
        return;
    }

    // Record secret-safe diff of target changes (avoid duplicating paths already
    // recorded by the transformer such as removed Go tuning keys).
    let mut diff_changes = Vec::new();
    report::diff_json_changes(
        "",
        existing.as_ref(),
        Some(&transformed.value),
        &mut diff_changes,
    );
    for change in diff_changes {
        if !outcome
            .changed_fields
            .iter()
            .any(|existing_change| existing_change.path == change.path)
        {
            outcome.changed_fields.push(change);
        }
    }

    let mut bytes = match serde_json::to_vec_pretty(&transformed.value) {
        Ok(bytes) => bytes,
        Err(err) => {
            outcome.status = Status::Failed;
            outcome
                .errors
                .push(format!("failed serializing {target_config_name}: {err}"));
            outcomes.push(outcome);
            return;
        }
    };
    bytes.push(b'\n');

    let outcome_index = outcomes.len();
    outcomes.push(outcome);
    planned_writes.push(PlannedWrite {
        config_name: target_config_name.to_owned(),
        bytes,
        outcome_index,
    });
}

fn process_account_file(
    file: &ScannedFile,
    options: &ImportOptions,
    target_has_account: bool,
    outcomes: &mut Vec<ModuleOutcome>,
    planned_writes: &mut Vec<PlannedWrite>,
) {
    if options.accounts == AccountPolicy::Skip {
        let mut outcome = ModuleOutcome::new(&file.id, Status::Skipped);
        outcome.warnings.push(Warning::new(
            file.file_name.clone(),
            "AccountsSkipped",
            "import.gately.accounts_skipped_default",
            format!(
                "'{}' was skipped by default (--accounts skip); the target instance will initialize its own administrator credentials on first start.",
                file.file_name
            ),
        ));
        outcomes.push(outcome);
        return;
    }

    if target_has_account {
        let mut outcome = ModuleOutcome::new(&file.id, Status::Failed);
        outcome.errors.push(format!(
            "refusing to import '{}': target directory already contains account.json (account import is only allowed into a fresh target without an existing account)",
            file.file_name
        ));
        outcomes.push(outcome);
        return;
    }

    let raw_bytes = match scan::read_file_limited(&file.path) {
        Ok(bytes) => bytes,
        Err(err) => {
            let mut outcome = ModuleOutcome::new(&file.id, Status::Failed);
            outcome.errors.push(format!("{err:#}"));
            outcomes.push(outcome);
            return;
        }
    };

    let parsed: Value = match serde_json::from_slice::<Value>(&raw_bytes) {
        Ok(val) if val.is_object() => val,
        Ok(_) => {
            let mut outcome = ModuleOutcome::new(&file.id, Status::Failed);
            outcome
                .errors
                .push(format!("{} root must be a JSON object", file.file_name));
            outcomes.push(outcome);
            return;
        }
        Err(err) => {
            let mut outcome = ModuleOutcome::new(&file.id, Status::Failed);
            outcome.errors.push(format!(
                "invalid JSON in {} at line {}, column {}: {err}",
                file.file_name,
                err.line(),
                err.column()
            ));
            outcomes.push(outcome);
            return;
        }
    };

    let mut outcome = ModuleOutcome::new(&file.id, Status::Imported);
    report::diff_json_changes("", None, Some(&parsed), &mut outcome.changed_fields);

    if file.id == "account"
        && parsed
            .get("sessionSecret")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
    {
        outcome.warnings.push(Warning::new(
            "sessionSecret",
            "SessionSecretPreserved",
            "import.gately.session_secret_preserved",
            "Imported account.json preserves sessionSecret; existing Gately browser sessions will remain valid unless credentials or sessions are rotated.",
        ));
    }

    let mut bytes = match serde_json::to_vec_pretty(&parsed) {
        Ok(b) => b,
        Err(err) => {
            outcome.status = Status::Failed;
            outcome
                .errors
                .push(format!("failed serializing {}: {err}", file.file_name));
            outcomes.push(outcome);
            return;
        }
    };
    bytes.push(b'\n');

    let outcome_index = outcomes.len();
    outcomes.push(outcome);
    planned_writes.push(PlannedWrite {
        config_name: file.id.clone(),
        bytes,
        outcome_index,
    });
}

fn read_existing_json(path: &Path) -> Option<Value> {
    let bytes = scan::read_file_limited(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn backup_overwritten_files(
    target_dir: &Path,
    planned_writes: &[PlannedWrite],
) -> Result<Option<String>> {
    let existing: Vec<(String, PathBuf)> = planned_writes
        .iter()
        .filter_map(|write| {
            let file_name = format!("{}.json", write.config_name);
            let path = target_dir.join(&file_name);
            path.is_file().then_some((file_name, path))
        })
        .collect();

    if existing.is_empty() {
        return Ok(None);
    }

    let stamp = time::OffsetDateTime::now_utc();
    let base_name = format!(
        "backup-{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        stamp.year(),
        u8::from(stamp.month()),
        stamp.day(),
        stamp.hour(),
        stamp.minute(),
        stamp.second(),
    );
    let mut backup_dir = target_dir.join(&base_name);
    let mut suffix = 1u32;
    while backup_dir.exists() {
        backup_dir = target_dir.join(format!("{base_name}-{suffix}"));
        suffix += 1;
    }

    fs::create_dir_all(&backup_dir)
        .with_context(|| format!("create backup directory {}", backup_dir.display()))?;

    for (file_name, src_path) in existing {
        let dst_path = backup_dir.join(&file_name);
        fs::copy(&src_path, &dst_path)
            .with_context(|| format!("back up {} to {}", src_path.display(), dst_path.display()))?;
    }

    Ok(Some(backup_dir.display().to_string()))
}
