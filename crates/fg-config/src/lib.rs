#![forbid(unsafe_code)]

use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, anyhow, ensure};
use fg_core::fsperm;
use serde::{Serialize, de::DeserializeOwned};
use tempfile::TempPath;

pub mod apply;
pub mod confirm;
mod diff;
mod history;
pub mod rollback;

pub use diff::{DiffLine, Op, diff};
use history::History;
pub use history::{DEFAULT_HISTORY_KEEP, Version, VersionId};

const MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Loaded<T> {
    Found(T),
    Missing,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Saved {
    pub changed: bool,
}

/// A synchronous store shared by the modules using one configuration directory.
pub struct ConfigStore {
    dir: PathBuf,
    lock: Mutex<History>,
}

impl ConfigStore {
    pub fn open(dir: &Path) -> Result<Arc<Self>> {
        let dir = std::path::absolute(dir).context("resolve configuration directory")?;
        fsperm::mkdir_all(&dir, 0o700).context("create or secure configuration directory")?;
        let dir = dir
            .canonicalize()
            .context("resolve configuration directory")?;
        fsperm::protect(&dir);
        Ok(Arc::new(Self {
            dir,
            lock: Mutex::new(History::default()),
        }))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn data_dir(&self, name: &str) -> Result<PathBuf> {
        validate_name(name)?;
        Ok(self.dir.join(name))
    }

    pub fn load<T: DeserializeOwned>(&self, name: &str) -> Result<Loaded<T>> {
        let Some(bytes) = self.load_raw(name)? else {
            return Ok(Loaded::Missing);
        };
        serde_json::from_slice(&bytes)
            .map(Loaded::Found)
            .map_err(|error| {
                anyhow!(
                    "parse configuration {name} at line {}, column {}",
                    error.line(),
                    error.column()
                )
            })
    }

    pub fn load_raw(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path(name)?;
        let _lock = self.lock.lock().expect("config store lock poisoned");
        open_config(&path)
            .and_then(|file| file.map(|file| read_limited(file, MAX_BYTES)).transpose())
            .with_context(|| format!("read configuration {name} (limit 64 MiB)"))
    }

    pub fn save<T: Serialize>(&self, name: &str, value: &T) -> Result<Saved> {
        validate_name(name)?;
        let mut bytes = serde_json::to_vec_pretty(value)
            .map_err(|_| anyhow!("serialize configuration {name}"))?;
        bytes.push(b'\n');
        self.write_raw(name, &bytes)
    }

    pub fn write_raw(&self, name: &str, bytes: &[u8]) -> Result<Saved> {
        let path = self.path(name)?;
        check_size(name, bytes.len())?;
        let mut history = self.lock.lock().expect("config store lock poisoned");
        self.write_locked(name, &path, bytes, &mut history)
    }

    /// Replaces the exact configuration read by a migration without archiving its old contents.
    pub fn replace_unversioned(
        &self,
        name: &str,
        expected: &[u8],
        replacement: &[u8],
    ) -> Result<bool> {
        let path = self.path(name)?;
        check_size(name, replacement.len())?;
        let _lock = self.lock.lock().expect("config store lock poisoned");
        let Some(mut file) = open_config(&path)? else {
            return Ok(false);
        };
        if file.metadata()?.len() != expected.len() as u64 || !same_contents(&mut file, expected)? {
            return Ok(false);
        }
        drop(file);
        self.write_locked(name, &path, replacement, &mut History::default())?;
        Ok(true)
    }

    fn write_locked(
        &self,
        name: &str,
        path: &Path,
        bytes: &[u8],
        history: &mut History,
    ) -> Result<Saved> {
        let mut previous =
            open_config(path).with_context(|| format!("open configuration {name}"))?;
        if let Some(file) = &mut previous
            && file.metadata()?.len() == bytes.len() as u64
            && same_contents(file, bytes)
                .with_context(|| format!("compare configuration {name}"))?
        {
            return Ok(Saved { changed: false });
        }
        let temp = stage(&self.dir, name, |file| file.write_all(bytes))
            .with_context(|| format!("stage configuration {name}"))?;
        let snapshot = self.snapshot(name, history, previous)?;
        if let Err(error) = temp.persist(path) {
            history::discard_snapshot(snapshot.as_deref());
            return Err(error.error).with_context(|| format!("replace configuration {name}"));
        }
        sync_directory(&self.dir)
            .with_context(|| format!("sync directory after replacing configuration {name}"))?;
        history
            .prune(snapshot.as_deref())
            .with_context(|| format!("configuration {name} replaced; prune history"))?;
        Ok(Saved { changed: true })
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        let path = self.path(name)?;
        let mut history = self.lock.lock().expect("config store lock poisoned");
        let snapshot = if history.records(name) {
            let previous =
                open_config(&path).with_context(|| format!("open configuration {name}"))?;
            self.snapshot(name, &mut history, previous)?
        } else {
            None
        };
        if let Err(error) = fs::remove_file(path) {
            history::discard_snapshot(snapshot.as_deref());
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(());
            }
            return Err(error).with_context(|| format!("remove configuration {name}"));
        }
        sync_directory(&self.dir)
            .with_context(|| format!("sync directory after removing configuration {name}"))?;
        history
            .prune(snapshot.as_deref())
            .with_context(|| format!("configuration {name} removed; prune history"))
    }

    pub fn tighten(&self) -> usize {
        let _lock = self.lock.lock().expect("config store lock poisoned");
        fsperm::tighten(&self.dir)
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        validate_name(name)?;
        Ok(self.dir.join(format!("{name}.json")))
    }
}

fn validate_name(name: &str) -> Result<()> {
    let mut bytes = name.bytes();
    let alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    ensure!(
        name.len() <= 64
            && bytes.next().is_some_and(alphanumeric)
            && bytes.all(|byte| alphanumeric(byte) || matches!(byte, b'_' | b'-')),
        "invalid configuration name"
    );
    Ok(())
}

fn check_size(name: &str, len: usize) -> Result<()> {
    ensure!(len <= MAX_BYTES, "configuration {name} exceeds 64 MiB");
    Ok(())
}

fn open_config(path: &Path) -> io::Result<Option<File>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        // A FIFO must not block a configuration read.
        options.custom_flags(libc::O_NONBLOCK);
    }
    match fs::metadata(path).and_then(|metadata| {
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a regular file",
            ));
        }
        options.open(path)
    }) {
        Ok(file) if file.metadata()?.is_file() => Ok(Some(file)),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a regular file",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn same_contents(file: &mut File, mut expected: &[u8]) -> io::Result<bool> {
    let mut file = BufReader::new(file);
    loop {
        let chunk = file.fill_buf()?;
        if chunk.is_empty() {
            return Ok(expected.is_empty());
        }
        let Some(rest) = expected.strip_prefix(chunk) else {
            return Ok(false);
        };
        expected = rest;
        let len = chunk.len();
        file.consume(len);
    }
}

fn read_limited(file: File, max: usize) -> io::Result<Vec<u8>> {
    if file.metadata()?.len() > max as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds size limit",
        ));
    }
    let mut bytes = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds size limit",
        ));
    }
    Ok(bytes)
}

fn stage(
    dir: &Path,
    name: &str,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<TempPath> {
    let mut temp = tempfile::Builder::new()
        .prefix(&format!(".{name}."))
        .suffix(".tmp")
        .tempfile_in(dir)
        .map_err(|error| io::Error::from(error.kind()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // Some filesystems ignore the mode passed when creating the file.
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    write(temp.as_file_mut())?;
    temp.as_file().sync_all()?;
    Ok(temp.into_temp_path())
}

fn sync_directory(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_rejects_traversal_and_uppercase() {
        for invalid in [
            "",
            "../x",
            "a/b",
            "a\\b",
            "Abc",
            "-name",
            "_name",
            &"a".repeat(65),
        ] {
            assert!(validate_name(invalid).is_err(), "accepted {invalid:?}");
        }
        for valid in ["a", "3", "web_service-1", &"a".repeat(64)] {
            assert!(validate_name(valid).is_ok(), "rejected {valid:?}");
        }
    }

    #[test]
    fn failed_atomic_replace_leaves_existing_target_and_cleans_temp_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let blocked = dir.path().join("webservice.json");
        fs::create_dir(&blocked)?;
        fs::write(blocked.join("existing"), "keep")?;
        let candidate = stage(dir.path(), "webservice", |file| {
            file.write_all(b"candidate")
        })?;
        drop(candidate.persist(&blocked).unwrap_err());
        assert_eq!(fs::read(blocked.join("existing"))?, b"keep");
        assert_eq!(fs::read_dir(dir.path())?.count(), 1);
        Ok(())
    }
}
