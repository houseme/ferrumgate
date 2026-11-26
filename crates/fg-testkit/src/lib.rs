#![forbid(unsafe_code)]

use std::{io, path::Path};

/// Owns a disposable parent and exposes a fresh path for the configuration store.
pub struct TempConfigDir(tempfile::TempDir);

impl TempConfigDir {
    pub fn new() -> io::Result<Self> {
        tempfile::tempdir().map(Self)
    }

    pub fn parent(&self) -> &Path {
        self.0.path()
    }

    pub fn path(&self) -> std::path::PathBuf {
        self.parent().join("config")
    }
}
