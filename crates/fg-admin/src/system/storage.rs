//! Storage usage: sizes of the configuration directory grouped by purpose.
//! Symlinks are never followed; the log directory, when outside the
//! configuration directory, is reported separately.

use std::{
    fs,
    path::{Path, PathBuf},
};

use axum::{Json, http::Method};
use schemars::JsonSchema;
use serde::Serialize;

use crate::{ApiRouter, RouteModels};

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    pub key: &'static str,
    pub bytes: u64,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StorageUsage {
    pub total_bytes: u64,
    pub categories: Vec<Usage>,
    /// The log directory when it lives outside the configuration directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_dir: Option<Usage>,
}

/// Directory names mapped to stable usage keys.
const CATEGORIES: [(&str, &str); 12] = [
    ("history", "history"),
    ("logs", "logs"),
    ("visitors", "visitors"),
    ("guard", "guard"),
    ("notify", "notify"),
    ("bin", "bin"),
    ("compose", "compose"),
    ("iplists", "iplists"),
    ("geoip", "geoip"),
    ("filebrowser", "filebrowser"),
    ("backup", "backup"),
    ("certs", "certs"),
];

pub(super) fn mount(router: ApiRouter) -> ApiRouter {
    router.modeled_route(
        Method::GET,
        "/api/system/storage",
        "Get storage usage by category",
        RouteModels::default().response::<StorageUsage>(),
        move || async move { Json(usage(&PathBuf::from("."), None)) },
    )
}

/// Walks `dir` without following symlinks; `dir_size` is the test entry.
pub fn usage(dir: &Path, log_dir: Option<&Path>) -> StorageUsage {
    let mut categories: Vec<Usage> = Vec::new();
    let mut remainder = 0u64;
    for (name, key) in CATEGORIES {
        let path = dir.join(name);
        // symlink_metadata does not follow links: a symlinked category
        // directory is skipped entirely.
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.is_dir() {
            continue;
        }
        let bytes = dir_size(&path);
        if bytes > 0 {
            categories.push(Usage { key, bytes });
        }
    }
    // Everything else at the top level (configuration files and unknown
    // directories).
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.filter_map(|entry| entry.ok()) {
            let path = entry.path();
            let known = CATEGORIES
                .iter()
                .any(|(name, _)| path.file_name().is_some_and(|n| n == *name));
            if known {
                continue;
            }
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            // Symlinks contribute their own metadata length only.
            if file_type.is_symlink() {
                remainder += entry_len(&path);
            } else if file_type.is_dir() {
                remainder += dir_size(&path);
            } else {
                remainder += entry_len(&path);
            }
        }
    }
    if remainder > 0 {
        categories.push(Usage {
            key: "other",
            bytes: remainder,
        });
    }
    let total = categories.iter().map(|usage| usage.bytes).sum();
    let log_dir = log_dir.filter(|path| !dir.starts_with(path) && !path.starts_with(dir));
    StorageUsage {
        total_bytes: total,
        categories,
        log_dir: log_dir.map(|path| Usage {
            key: "logs",
            bytes: dir_size(path),
        }),
    }
}

/// Recursively sizes a directory without following symlinks.
pub fn dir_size(dir: &Path) -> u64 {
    let mut total = 0u64;
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    for entry in entries.filter_map(|entry| entry.ok()) {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            total += dir_size(&path);
        } else {
            total += entry_len(&path);
        }
    }
    total
}

fn entry_len(path: &Path) -> u64 {
    path.metadata().map(|meta| meta.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_categorizes_and_skips_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("history")).unwrap();
        std::fs::write(dir.path().join("history/v1.json"), "x".repeat(100)).unwrap();
        std::fs::create_dir(dir.path().join("logs")).unwrap();
        std::fs::write(dir.path().join("logs/app.log"), "y".repeat(50)).unwrap();
        std::fs::write(dir.path().join("ddns.json"), "z".repeat(20)).unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("web.log"), "w".repeat(70)).unwrap();

        let report = usage(dir.path(), Some(outside.path()));
        assert_eq!(report.total_bytes, 100 + 50 + 20);
        let find = |key: &str| {
            report
                .categories
                .iter()
                .find(|usage| usage.key == key)
                .map(|usage| usage.bytes)
        };
        assert_eq!(find("history"), Some(100));
        assert_eq!(find("logs"), Some(50));
        assert_eq!(find("other"), Some(20));
        assert_eq!(report.log_dir.as_ref().map(|usage| usage.bytes), Some(70));

        // A symlinked subdirectory is never followed.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside.path(), dir.path().join("visitors")).unwrap();
            let report = usage(dir.path(), None);
            assert!(
                !report
                    .categories
                    .iter()
                    .any(|usage| usage.key == "visitors"),
                "symlink directories stay out of the total"
            );
        }
    }
}
