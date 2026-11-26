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
    lock: Mutex<()>,
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
            lock: Mutex::new(()),
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
        let Some(file) =
            open_config(&path).with_context(|| format!("open configuration {name}"))?
        else {
            return Ok(None);
        };
        let metadata = file
            .metadata()
            .with_context(|| format!("stat configuration {name}"))?;
        ensure!(
            metadata.len() <= MAX_BYTES as u64,
            "configuration {name} exceeds 64 MiB"
        );
        let mut bytes = Vec::new();
        file.take(MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read configuration {name}"))?;
        check_size(name, bytes.len())?;
        Ok(Some(bytes))
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
        let _lock = self.lock.lock().expect("config store lock poisoned");
        if let Some(file) =
            open_config(&path).with_context(|| format!("open configuration {name}"))?
            && same_contents(file, bytes)
                .with_context(|| format!("compare configuration {name}"))?
        {
            return Ok(Saved { changed: false });
        }
        replace(&self.dir, &path, name, bytes)
            .with_context(|| format!("write configuration {name}"))?;
        sync_directory(&self.dir)
            .with_context(|| format!("sync directory after replacing configuration {name}"))?;
        Ok(Saved { changed: true })
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        let path = self.path(name)?;
        let _lock = self.lock.lock().expect("config store lock poisoned");
        match fs::remove_file(path) {
            Ok(()) => sync_directory(&self.dir)
                .with_context(|| format!("sync directory after removing configuration {name}")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| format!("remove configuration {name}")),
        }
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

fn same_contents(file: File, mut expected: &[u8]) -> io::Result<bool> {
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

fn replace(dir: &Path, path: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
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
    temp.as_file_mut().write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.into_temp_path()
        .persist(path)
        .map_err(|error| error.error)
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
        assert!(replace(dir.path(), &blocked, "webservice", b"candidate").is_err());
        assert_eq!(fs::read(blocked.join("existing"))?, b"keep");
        assert_eq!(fs::read_dir(dir.path())?.count(), 1);
        Ok(())
    }
}
