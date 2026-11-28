//! WP-38 report types, option structs, and secret-safe value summarization.

use std::fmt::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Placeholder used in reports wherever a secret, private key, password, or
/// token would otherwise appear.
pub const REDACTED: &str = "********";

/// Policy for handling `account.json` and `tokens.json` from the source Gately
/// configuration directory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "camelCase")]
pub enum AccountPolicy {
    /// Do not import `account.json` or `tokens.json` (default).
    #[default]
    Skip,
    /// Copy `account.json` and `tokens.json` only into a fresh target directory
    /// that does not already contain an `account.json`.
    Import,
}

/// Options controlling `fgate import gately`.
#[derive(Clone, Debug)]
pub struct ImportOptions {
    /// Read-only source Gately configuration directory.
    pub source_dir: PathBuf,
    /// Destination FerrumGate configuration directory.
    pub target_dir: PathBuf,
    /// When true, only inspect and produce a report without touching `target_dir`.
    pub dry_run: bool,
    /// Allow applying into a non-empty `target_dir` (existing same-named files
    /// are backed up into `backup-<timestamp>` before atomic replacement).
    pub force: bool,
    /// If non-empty, only import the listed module/config IDs.
    pub include: Vec<String>,
    /// Handling of `account.json` and `tokens.json`.
    pub accounts: AccountPolicy,
    /// Optional path to write the structured JSON report.
    pub report_file: Option<PathBuf>,
}

impl ImportOptions {
    /// Creates default dry-run options (`AccountPolicy::Skip`, `force = false`).
    pub fn new(source_dir: impl Into<PathBuf>, target_dir: impl Into<PathBuf>) -> Self {
        Self {
            source_dir: source_dir.into(),
            target_dir: target_dir.into(),
            dry_run: true,
            force: false,
            include: Vec::new(),
            accounts: AccountPolicy::Skip,
            report_file: None,
        }
    }
}

/// Per-file outcome status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    Imported,
    Unchanged,
    Skipped,
    NotBuilt,
    Failed,
    UnsupportedVersion,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Imported => "imported",
            Self::Unchanged => "unchanged",
            Self::Skipped => "skipped",
            Self::NotBuilt => "notBuilt",
            Self::Failed => "failed",
            Self::UnsupportedVersion => "unsupportedVersion",
        }
    }
}

/// One field-level change recorded in the report (always secret-redacted).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldChange {
    pub path: String,
    pub from: String,
    pub to: String,
}

/// A non-fatal warning or hint emitted during import.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Warning {
    pub path: String,
    pub reason_key: String,
    pub hint_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
}

impl Warning {
    pub fn new(
        path: impl Into<String>,
        reason_key: impl Into<String>,
        hint_key: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            reason_key: reason_key.into(),
            hint_key: hint_key.into(),
            message: message.into(),
        }
    }
}

/// Import result for one discovered source file / module.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleOutcome {
    pub id: String,
    pub status: Status,
    pub changed_fields: Vec<FieldChange>,
    pub warnings: Vec<Warning>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

impl ModuleOutcome {
    pub fn new(id: impl Into<String>, status: Status) -> Self {
        Self {
            id: id.into(),
            status,
            changed_fields: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }
}

/// Aggregate counts across all outcomes in a [`Report`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub dry_run: bool,
    pub imported: usize,
    pub unchanged: usize,
    pub skipped: usize,
    pub not_built: usize,
    pub failed: usize,
    pub unsupported_version: usize,
    pub warnings: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_dir: Option<String>,
}

/// Complete import report returned by [`crate::import_gately::run_import`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub source_version: Option<String>,
    pub outcomes: Vec<ModuleOutcome>,
    pub summary: Summary,
}

impl Report {
    /// Recomputes aggregate counters from `self.outcomes`.
    pub fn recompute_summary(&mut self, dry_run: bool, backup_dir: Option<String>) {
        let mut summary = Summary {
            dry_run,
            backup_dir,
            ..Summary::default()
        };
        for outcome in &self.outcomes {
            match outcome.status {
                Status::Imported => summary.imported += 1,
                Status::Unchanged => summary.unchanged += 1,
                Status::Skipped => summary.skipped += 1,
                Status::NotBuilt => summary.not_built += 1,
                Status::Failed => summary.failed += 1,
                Status::UnsupportedVersion => summary.unsupported_version += 1,
            }
            summary.warnings += outcome.warnings.len();
        }
        self.summary = summary;
    }

    /// Returns true if any module failed or had an unsupported version.
    pub fn has_failures(&self) -> bool {
        self.summary.failed > 0 || self.summary.unsupported_version > 0
    }

    /// Finds an outcome by its ID.
    pub fn outcome(&self, id: &str) -> Option<&ModuleOutcome> {
        self.outcomes.iter().find(|outcome| outcome.id == id)
    }

    /// Renders the report as pretty-printed JSON.
    pub fn to_json_pretty(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Renders a human-readable summary suitable for stdout.
    pub fn format_human(&self, target_dir: &std::path::Path) -> String {
        let mut out = String::new();
        let mode = if self.summary.dry_run {
            "DRY-RUN (no files written; pass --apply to write)"
        } else {
            "APPLIED"
        };
        let _ = writeln!(out, "Gately import report [{mode}]");
        if let Some(version) = &self.source_version {
            let _ = writeln!(out, "Source version: {version}");
        }
        if let Some(backup) = &self.summary.backup_dir {
            let _ = writeln!(out, "Backup directory: {backup}");
        }
        let _ = writeln!(
            out,
            "Summary: {} imported, {} unchanged, {} skipped, {} notBuilt, {} failed, {} warnings",
            self.summary.imported,
            self.summary.unchanged,
            self.summary.skipped,
            self.summary.not_built,
            self.summary.failed + self.summary.unsupported_version,
            self.summary.warnings
        );
        for outcome in &self.outcomes {
            let _ = writeln!(out, "\n- {} [{}]", outcome.id, outcome.status.as_str());
            for change in &outcome.changed_fields {
                let _ = writeln!(
                    out,
                    "    change {}: {} -> {}",
                    change.path, change.from, change.to
                );
            }
            for warning in &outcome.warnings {
                if warning.message.is_empty() {
                    let _ = writeln!(
                        out,
                        "    warn {} ({}): {}",
                        warning.path, warning.reason_key, warning.hint_key
                    );
                } else {
                    let _ = writeln!(
                        out,
                        "    warn {} ({}): {}",
                        warning.path, warning.reason_key, warning.message
                    );
                }
            }
            for error in &outcome.errors {
                let _ = writeln!(out, "    error: {error}");
            }
        }
        if !self.summary.dry_run && !self.has_failures() {
            let _ = writeln!(
                out,
                "\nNext step: validate the target directory before starting:\n  fgate check --config {}",
                target_dir.display()
            );
        }
        out
    }
}

/// Returns true if a JSON field path refers to a secret, private key, password,
/// credential, or token whose value must never be shown in reports.
pub fn is_secret_path(path: &str) -> bool {
    for raw_segment in path.split('.') {
        let base = raw_segment.split('[').next().unwrap_or(raw_segment);
        let normalized: String = base
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .map(|ch| ch.to_ascii_lowercase())
            .collect();
        if normalized.is_empty() {
            continue;
        }
        // Site-level `users` entries contain `username:password` / bcrypt hashes.
        if normalized == "users" && path.contains("sites[") {
            return true;
        }
        // Account token hash field (`tokens[i].hash`).
        if normalized == "hash" && (path.contains("tokens[") || path == "hash") {
            return true;
        }
        if matches!(
            normalized.as_str(),
            "keypem"
                | "privatekey"
                | "privkey"
                | "sshkey"
                | "sshprivatekey"
                | "tlskey"
                | "apikey"
                | "accesskey"
                | "accesskeysecret"
                | "secretkey"
                | "eabhmackey"
                | "eabhmac"
                | "password"
                | "passwd"
                | "passphrase"
                | "passwordhash"
                | "totpsecret"
                | "sessionsecret"
                | "authsecret"
                | "clientsecret"
                | "apitoken"
                | "token"
                | "dnstoken"
                | "webhooksecret"
                | "signingkey"
        ) || normalized.contains("secret")
            || normalized.contains("password")
            || normalized.contains("passwd")
            || normalized.contains("passphrase")
            || normalized.contains("privatekey")
            || normalized.contains("privkey")
            || normalized.contains("keypem")
            || normalized.contains("apikey")
            || normalized.contains("apitoken")
            || normalized.contains("dnstoken")
            || normalized.contains("totp")
            || normalized.contains("credential")
            || (normalized.ends_with("token") && normalized != "tokenttlhours")
        {
            return true;
        }
    }
    false
}

/// Returns true if a string value itself looks like raw private key or password
/// hash material (defense-in-depth redaction).
fn looks_like_secret_value(text: &str) -> bool {
    text.contains("PRIVATE KEY-----")
        || text.starts_with("$2a$")
        || text.starts_with("$2b$")
        || text.starts_with("$2y$")
        || text.starts_with("gtl_")
}

/// Produces a compact, secret-safe summary of a JSON value at `path`.
pub fn summarize_value(path: &str, value: &Value) -> String {
    if is_secret_path(path) {
        return match value {
            Value::Null => "null".to_owned(),
            Value::String(s) if s.is_empty() => "\"\"".to_owned(),
            _ => REDACTED.to_owned(),
        };
    }
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => {
            if looks_like_secret_value(s) {
                return REDACTED.to_owned();
            }
            if s.chars().count() > 80 {
                let truncated: String = s.chars().take(77).collect();
                format!("\"{truncated}...\"")
            } else {
                format!("\"{s}\"")
            }
        }
        Value::Array(items) => {
            if items.is_empty() {
                "[]".to_owned()
            } else {
                format!("[{} item(s)]", items.len())
            }
        }
        Value::Object(map) => {
            if map.is_empty() {
                "{}".to_owned()
            } else {
                format!("{{{} key(s)}}", map.len())
            }
        }
    }
}

/// Computes secret-safe leaf-level [`FieldChange`] records between `old` and
/// `new`. Recurses into objects and arrays so secrets nested inside entries
/// (such as `certs[0].keyPem` or `thirdLogin.providers[0].clientSecret`) are
/// reported by path with value `********`.
pub fn diff_json_changes(
    prefix: &str,
    old: Option<&Value>,
    new: Option<&Value>,
    out: &mut Vec<FieldChange>,
) {
    match (old, new) {
        (Some(a), Some(b)) if a == b => {}
        (Some(Value::Object(a)), Some(Value::Object(b))) => {
            let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
            keys.sort_unstable();
            keys.dedup();
            for key in keys {
                let path = join_field(prefix, key);
                diff_json_changes(&path, a.get(key), b.get(key), out);
            }
        }
        (None, Some(Value::Object(b))) => {
            let mut keys: Vec<&String> = b.keys().collect();
            keys.sort_unstable();
            for key in keys {
                let path = join_field(prefix, key);
                diff_json_changes(&path, None, b.get(key), out);
            }
        }
        (Some(Value::Object(a)), None) => {
            let mut keys: Vec<&String> = a.keys().collect();
            keys.sort_unstable();
            for key in keys {
                let path = join_field(prefix, key);
                diff_json_changes(&path, a.get(key), None, out);
            }
        }
        (Some(Value::Array(a)), Some(Value::Array(b))) => {
            let max_len = a.len().max(b.len());
            for idx in 0..max_len {
                let path = format!("{prefix}[{idx}]");
                diff_json_changes(&path, a.get(idx), b.get(idx), out);
            }
        }
        (None, Some(Value::Array(b))) => {
            if b.is_empty() {
                out.push(FieldChange {
                    path: prefix.to_owned(),
                    from: "<absent>".to_owned(),
                    to: "[]".to_owned(),
                });
            } else {
                for (idx, item) in b.iter().enumerate() {
                    let path = format!("{prefix}[{idx}]");
                    diff_json_changes(&path, None, Some(item), out);
                }
            }
        }
        (Some(Value::Array(a)), None) => {
            if a.is_empty() {
                out.push(FieldChange {
                    path: prefix.to_owned(),
                    from: "[]".to_owned(),
                    to: "<removed>".to_owned(),
                });
            } else {
                for (idx, item) in a.iter().enumerate() {
                    let path = format!("{prefix}[{idx}]");
                    diff_json_changes(&path, Some(item), None, out);
                }
            }
        }
        (old_val, new_val) => {
            let from = old_val
                .map(|v| summarize_value(prefix, v))
                .unwrap_or_else(|| "<absent>".to_owned());
            let to = new_val
                .map(|v| summarize_value(prefix, v))
                .unwrap_or_else(|| "<removed>".to_owned());
            out.push(FieldChange {
                path: prefix.to_owned(),
                from,
                to,
            });
        }
    }
}

fn join_field(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_owned()
    } else {
        format!("{prefix}.{key}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn secret_paths_and_values_are_redacted() {
        for path in [
            "certs[0].keyPem",
            "accounts.default.keyPem",
            "apiToken",
            "thirdLogin.providers[0].clientSecret",
            "settings.authSecret",
            "settings.authUsers[0].password",
            "settings.authUsers[0].totpSecret",
            "listeners[0].sites[0].users[0]",
            "sessionSecret",
            "passwordHash",
            "tokens[0].hash",
        ] {
            assert!(is_secret_path(path), "expected {path} to be secret");
            assert_eq!(
                summarize_value(path, &json!("super-secret-value")),
                REDACTED
            );
        }

        for safe_path in [
            "listen",
            "certs[0].key",
            "certs[0].acme.keyType",
            "tokenTTLHours",
            "listeners[0].port",
        ] {
            assert!(
                !is_secret_path(safe_path),
                "expected {safe_path} to be non-secret"
            );
        }

        // Defense-in-depth: raw PEM private keys are redacted even on unexpected paths.
        assert_eq!(
            summarize_value(
                "customField",
                &json!("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----")
            ),
            REDACTED
        );
    }

    #[test]
    fn diff_masks_nested_secrets() {
        let mut changes = Vec::new();
        let doc = json!({
            "certs": [{
                "key": "c1",
                "keyPem": "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----"
            }]
        });
        diff_json_changes("", None, Some(&doc), &mut changes);
        let key_pem = changes
            .iter()
            .find(|c| c.path == "certs[0].keyPem")
            .expect("keyPem change present");
        assert_eq!(key_pem.to, REDACTED);
        assert!(!key_pem.to.contains("SECRET"));
    }
}
