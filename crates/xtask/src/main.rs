//! Repository maintenance tasks: `xtask i18n-extract` and `xtask i18n-check`.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

pub mod i18n;

fn main() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("workspace root")?
        .parent()
        .context("workspace root")?
        .to_path_buf();
    let mut arguments = std::env::args().skip(1);
    let task = arguments.next().context("a task name is required")?;
    let locales = root.join("crates/fg-i18n/locales");
    let sources: Vec<PathBuf> = ["crates", "src"].iter().map(|dir| root.join(dir)).collect();
    match task.as_str() {
        "i18n-extract" => {
            let prune = arguments.next().as_deref() == Some("--prune");
            let keys = i18n::extract_literals(&sources)?;
            let written = i18n::sync_catalogs(&locales, &keys, prune)?;
            println!(
                "i18n-extract: {} keys, {} locale files updated",
                keys.len(),
                written
            );
            Ok(())
        }
        "i18n-check" => {
            let keys = i18n::extract_literals(&sources)?;
            let violations = i18n::check_catalogs(&locales, &keys)?;
            for violation in &violations {
                println!("{violation:?}");
            }
            if violations.is_empty() {
                println!("i18n-check: {} keys consistent", keys.len());
                Ok(())
            } else {
                bail!("i18n-check found {} violations", violations.len());
            }
        }
        other => bail!("unknown task {other}"),
    }
}
