//! Shared helpers for the fg-cron integration tests.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Builds the small Rust fixture executable (conventions §4: no shell
/// scripts) with rustc and returns its path; one build per test process.
pub fn fixture() -> PathBuf {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE.get_or_init(build).clone()
}

fn build() -> PathBuf {
    let source = include_str!("../fixtures/fixture.rs");
    let id = std::process::id();
    let source_path = std::env::temp_dir().join(format!("fg-cron-fixture-{id}.rs"));
    let out_path = std::env::temp_dir().join(format!("fg-cron-fixture-{id}"));
    std::fs::write(&source_path, source).expect("write fixture source");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let status = Command::new(rustc)
        .args(["--edition", "2021"])
        .arg("-o")
        .arg(&out_path)
        .arg(&source_path)
        .status()
        .expect("run rustc");
    assert!(status.success(), "compiling the fixture failed");
    let _ = std::fs::remove_file(&source_path);
    out_path
}

/// Quotes a path for use inside a `sh -c` command string.
pub fn sh_quote(path: &Path) -> String {
    format!("'{}'", path.display())
}
