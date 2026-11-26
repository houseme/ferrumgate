//! Declarative configuration: on every start, copy the first-level
//! `<name>.json` files of a directory over the configuration store.
//!
//! Everything is validated before anything is written: a rejected file
//! leaves earlier valid files untouched instead of re-applying half the
//! directory on each start. This tightens the upstream behavior (which
//! writes until it hits the error) and keeps semantics otherwise identical.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, ensure};

use crate::ConfigStore;

/// Credentials and tokens are managed only through login sessions.
const FORBIDDEN: [&str; 2] = ["account", "tokens"];

#[derive(Debug)]
pub struct ApplyReport {
    pub applied: usize,
    pub skipped: usize,
    pub names: Vec<String>,
}

/// Applies `dir` into `store`. Any invalid file is an error the caller uses
/// to refuse startup; files already applied by an earlier, valid run stay.
pub fn apply_config_dir(store: &ConfigStore, dir: &Path) -> Result<ApplyReport> {
    fg_core::fsperm::protect(dir);
    let candidates = collect(dir)?;
    let mut staged = Vec::new();
    for (name, path) in candidates {
        let bytes =
            fs::read(&path).with_context(|| format!("read declarative file {}", path.display()))?;
        let checked = staged.len() + 1;
        serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|error| {
            anyhow!(
                "declarative file {name}.json is not valid JSON after {checked} candidate file(s) \
                 were checked: {error}"
            )
        })?;
        let mut bytes = bytes;
        if !bytes.ends_with(b"\n") {
            // Match the store's write format so unchanged files are not
            // rewritten on every start over a missing final newline.
            bytes.push(b'\n');
        }
        staged.push((name, bytes));
    }
    let mut report = ApplyReport {
        applied: 0,
        skipped: 0,
        names: Vec::new(),
    };
    for (name, bytes) in staged {
        if store.load_raw(&name)?.as_deref() == Some(bytes.as_slice()) {
            report.skipped += 1;
            continue;
        }
        store.write_raw(&name, &bytes)?;
        report.applied += 1;
        report.names.push(name);
    }
    Ok(report)
}

/// Lists the applicable files, sorted by configuration name so runs are
/// deterministic regardless of directory order.
fn collect(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let entries = fs::read_dir(dir)
        .with_context(|| format!("read declarative directory {}", dir.display()))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("list {}", dir.display()))?;
        let path = entry.path();
        if !entry.metadata().is_ok_and(|metadata| metadata.is_file()) {
            continue;
        }
        let Some(file) = path.file_name().and_then(|file| file.to_str()) else {
            continue;
        };
        if file.starts_with('.') {
            continue;
        }
        let Some(name) = file.strip_suffix(".json") else {
            continue;
        };
        crate::validate_name(name)
            .map_err(|_| anyhow!("declarative file {file} is not a valid configuration name"))?;
        ensure!(
            !FORBIDDEN.contains(&name),
            "declarative file {file} must not manage the account or API tokens"
        );
        files.push((name.to_owned(), path));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}
