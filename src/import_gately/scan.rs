//! Source Gately configuration directory scanner and file classifier (WP-38).
//!
//! Reads only top-level `*.json` files without ever modifying the source
//! directory, enforcing the 64 MiB single-file read limit from WP-00.

use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};

/// Single-file read cap (matches `fg_config::MAX_BYTES` = 64 MiB).
pub const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;

/// Classification of a top-level `*.json` file in a Gately configuration directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    /// Global settings (`gately.json` -> `ferrumgate.json`).
    Settings,
    /// Administrator account or API token store (`account.json`, `tokens.json`).
    Account,
    /// Known catalog module that is compiled into this binary.
    ModuleBuilt,
    /// Known catalog module that is not compiled into this binary (or not yet implemented).
    ModuleNotBuilt,
    /// Any other top-level `*.json` file not recognized by FerrumGate.
    Unknown,
}

/// One top-level `*.json` file discovered in the source directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScannedFile {
    /// Stem without the `.json` suffix (e.g., `"gately"`, `"webservice"`, `"account"`).
    pub id: String,
    /// Original file name (e.g., `"gately.json"`).
    pub file_name: String,
    /// Full read-only path inside the source directory.
    pub path: PathBuf,
    /// File size in bytes.
    pub size: u64,
    /// How this file is handled during import.
    pub kind: FileKind,
}

/// Classifies a configuration stem (filename without `.json`) using the
/// current binary's compiled module feature flags.
pub fn classify_name(stem: &str) -> FileKind {
    classify_name_with_built(stem, fg_core::features::built)
}

/// Classifies a configuration stem using a caller-supplied `is_built` predicate
/// (useful for unit testing custom build feature sets).
pub fn classify_name_with_built(stem: &str, is_built: impl Fn(&str) -> bool) -> FileKind {
    match stem {
        "gately" => FileKind::Settings,
        "account" | "tokens" => FileKind::Account,
        other if fg_core::features::CATALOG_IDS.contains(&other) => {
            if is_built(other) {
                FileKind::ModuleBuilt
            } else {
                FileKind::ModuleNotBuilt
            }
        }
        _ => FileKind::Unknown,
    }
}

/// Validates a configuration store name (`^[a-z0-9][a-z0-9_-]*$`, <= 64 bytes),
/// matching `fg_config`'s naming rules.
pub fn is_valid_config_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    name.len() <= 64
        && bytes.next().is_some_and(is_alnum)
        && bytes.all(|b| is_alnum(b) || matches!(b, b'_' | b'-'))
}

/// Scans the top-level `*.json` files of `source_dir` in read-only mode.
///
/// Rejects missing, unreadable, or non-directory paths, and requires at least
/// one recognizable configuration file (`gately.json` or `<module-id>.json`).
pub fn scan_source_dir(source_dir: &Path) -> Result<Vec<ScannedFile>> {
    scan_source_dir_with_built(source_dir, fg_core::features::built)
}

/// Like [`scan_source_dir`], but accepts a custom `is_built` predicate.
pub fn scan_source_dir_with_built(
    source_dir: &Path,
    is_built: impl Fn(&str) -> bool,
) -> Result<Vec<ScannedFile>> {
    let meta = fs::metadata(source_dir)
        .with_context(|| format!("cannot read source directory {}", source_dir.display()))?;
    ensure!(
        meta.is_dir(),
        "source path {} is not a directory",
        source_dir.display()
    );

    let entries = fs::read_dir(source_dir)
        .with_context(|| format!("cannot list source directory {}", source_dir.display()))?;

    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "failed reading entry in source directory {}",
                source_dir.display()
            )
        })?;
        let path = entry.path();
        let entry_meta =
            fs::metadata(&path).with_context(|| format!("cannot inspect {}", path.display()))?;
        if !entry_meta.is_file() {
            continue;
        }
        let Ok(file_name) = entry.file_name().into_string() else {
            continue;
        };
        let Some(stem) = file_name.strip_suffix(".json") else {
            continue;
        };
        let kind = classify_name_with_built(stem, &is_built);
        files.push(ScannedFile {
            id: stem.to_owned(),
            file_name,
            path,
            size: entry_meta.len(),
            kind,
        });
    }

    let has_recognizable = files.iter().any(|file| {
        matches!(
            file.kind,
            FileKind::Settings | FileKind::ModuleBuilt | FileKind::ModuleNotBuilt
        )
    });
    ensure!(
        has_recognizable,
        "source directory {} contains no recognizable Gately config files (expected gately.json or <module-id>.json)",
        source_dir.display()
    );

    files.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
    Ok(files)
}

fn sort_key(file: &ScannedFile) -> (u8, usize, &str) {
    match file.kind {
        FileKind::Settings => (0, 0, file.id.as_str()),
        FileKind::Account => (1, usize::from(file.id != "account"), file.id.as_str()),
        FileKind::ModuleBuilt => (2, catalog_index(&file.id), file.id.as_str()),
        FileKind::ModuleNotBuilt => (3, catalog_index(&file.id), file.id.as_str()),
        FileKind::Unknown => (4, usize::MAX, file.id.as_str()),
    }
}

fn catalog_index(id: &str) -> usize {
    fg_core::features::CATALOG_IDS
        .iter()
        .position(|&candidate| candidate == id)
        .unwrap_or(usize::MAX)
}

/// Reads a single file in read-only mode, enforcing the 64 MiB limit.
pub fn read_file_limited(path: &Path) -> Result<Vec<u8>> {
    let file =
        File::open(path).with_context(|| format!("cannot open {} for reading", path.display()))?;
    let meta = file
        .metadata()
        .with_context(|| format!("cannot stat {}", path.display()))?;
    ensure!(meta.is_file(), "{} is not a regular file", path.display());
    ensure!(
        meta.len() <= MAX_FILE_BYTES as u64,
        "{} exceeds 64 MiB limit ({} bytes)",
        path.display(),
        meta.len()
    );
    let mut bytes = Vec::with_capacity(meta.len().min(1024 * 1024) as usize);
    file.take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed reading {}", path.display()))?;
    ensure!(
        bytes.len() <= MAX_FILE_BYTES,
        "{} exceeds 64 MiB limit",
        path.display()
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            classify_name_with_built("custom-extra", built),
            FileKind::Unknown
        );
        assert_eq!(classify_name_with_built("random", built), FileKind::Unknown);
    }

    #[test]
    fn scan_rejects_empty_or_unrecognizable_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(scan_source_dir(dir.path()).is_err());

        fs::write(dir.path().join("unrelated.json"), "{}").expect("write");
        assert!(scan_source_dir(dir.path()).is_err());

        fs::write(dir.path().join("gately.json"), "{}").expect("write");
        let files = scan_source_dir(dir.path()).expect("scan");
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].id, "gately");
        assert_eq!(files[0].kind, FileKind::Settings);
        assert_eq!(files[1].id, "unrelated");
        assert_eq!(files[1].kind, FileKind::Unknown);
    }
}
