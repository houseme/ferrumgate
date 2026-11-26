use std::{
    collections::HashSet,
    fmt,
    fs::{self, File},
    io::{self, Read, Seek},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use time::{
    Duration, OffsetDateTime, PrimitiveDateTime, format_description::BorrowedFormatItem,
    macros::format_description,
};

use crate::{
    ConfigStore, MAX_BYTES, open_config, read_limited, stage, sync_directory, validate_name,
};

pub const DEFAULT_HISTORY_KEEP: usize = 30;
const SKIP: &[&str] = &[
    "account",
    "tokens",
    "migrations",
    "update-check",
    "login-ips",
    "gateway-origins",
    "onboarding",
];
const VERSION_FORMAT: &[BorrowedFormatItem<'_>] =
    format_description!("[year][month][day]T[hour][minute][second].[subsecond digits:9]Z");

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct VersionId(String);

impl VersionId {
    fn timestamp(&self) -> Result<OffsetDateTime> {
        Ok(PrimitiveDateTime::parse(&self.0, VERSION_FORMAT)?.assume_utc())
    }

    fn filename(&self) -> String {
        format!("{}.json", self.0)
    }
}

impl FromStr for VersionId {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let bytes = value.as_bytes();
        ensure!(
            bytes.len() == 26
                && bytes[8] == b'T'
                && bytes[15] == b'.'
                && bytes[25] == b'Z'
                && bytes[..8].iter().all(u8::is_ascii_digit)
                && bytes[9..15].iter().all(u8::is_ascii_digit)
                && bytes[16..25].iter().all(u8::is_ascii_digit),
            "invalid history version ID"
        );
        let id = Self(value.to_owned());
        id.timestamp().context("invalid history version ID")?;
        Ok(id)
    }
}

impl TryFrom<String> for VersionId {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        value.parse()
    }
}

impl fmt::Display for VersionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug)]
pub struct Version {
    pub id: VersionId,
    pub time: OffsetDateTime,
    pub size: u64,
}

#[derive(Default)]
pub(super) struct History {
    keep: usize,
    skip: HashSet<String>,
    last: Option<OffsetDateTime>,
}

impl History {
    pub fn records(&self, name: &str) -> bool {
        self.keep > 0 && !SKIP.contains(&name) && !self.skip.contains(name)
    }

    pub fn prune(&self, snapshot: Option<&Path>) -> Result<()> {
        let Some(dir) = snapshot.and_then(Path::parent) else {
            return Ok(());
        };
        let ids = version_ids(dir)?;
        let excess = ids.len().saturating_sub(self.keep);
        if excess > 0 {
            for id in &ids[..excess] {
                fs::remove_file(dir.join(id.filename())).context("prune history version")?;
            }
            sync_directory(dir).context("sync history directory after pruning")?;
        }
        Ok(())
    }
}

impl ConfigStore {
    pub fn enable_history(&self, keep: usize, skip: &[&str]) {
        let mut history = self.lock.lock().expect("config store lock poisoned");
        history.keep = keep;
        history.skip = skip.iter().map(|&name| name.to_owned()).collect();
    }

    pub fn history_names(&self) -> Result<Vec<String>> {
        let _history = self.lock.lock().expect("config store lock poisoned");
        let mut names = self.history_dirs()?;
        // Keep empty directories out of the public history listing.
        let mut populated = Vec::new();
        for name in names.drain(..) {
            if !version_ids(&self.version_dir(&name))?.is_empty() {
                populated.push(name);
            }
        }
        Ok(populated)
    }

    pub fn versions(&self, name: &str) -> Result<Vec<Version>> {
        validate_name(name)?;
        if SKIP.contains(&name) {
            return Ok(Vec::new());
        }
        let _history = self.lock.lock().expect("config store lock poisoned");
        if !check_dir(&self.dir.join("history"))? {
            return Ok(Vec::new());
        }
        let dir = self.version_dir(name);
        version_ids(&dir)?
            .into_iter()
            .rev()
            .map(|id| {
                let size = fs::symlink_metadata(dir.join(id.filename()))?.len();
                Ok(Version {
                    time: id.timestamp()?,
                    id,
                    size,
                })
            })
            .collect()
    }

    pub fn read_version(&self, name: &str, id: &VersionId) -> Result<Vec<u8>> {
        let _history = self.lock.lock().expect("config store lock poisoned");
        self.read_version_locked(name, id)
    }

    pub fn restore_version(&self, name: &str, id: &VersionId) -> Result<()> {
        let mut history = self.lock.lock().expect("config store lock poisoned");
        self.restore_locked(name, id, &mut history)
    }

    pub(super) fn restore_locked(
        &self,
        name: &str,
        id: &VersionId,
        history: &mut History,
    ) -> Result<()> {
        let bytes = self.read_version_locked(name, id)?;
        self.write_locked(name, &self.path(name)?, &bytes, history)?;
        Ok(())
    }

    pub(super) fn newest_version(&self) -> Result<Option<(String, VersionId)>> {
        let mut latest: Option<(String, VersionId)> = None;
        for name in self.history_dirs()? {
            if let Some(id) = version_ids(&self.version_dir(&name))?.pop()
                && latest.as_ref().is_none_or(|(_, old)| id > *old)
            {
                latest = Some((name, id));
            }
        }
        Ok(latest)
    }

    pub(super) fn snapshot(
        &self,
        name: &str,
        history: &mut History,
        previous: Option<File>,
    ) -> Result<Option<PathBuf>> {
        let Some(mut previous) = previous.filter(|_| history.records(name)) else {
            return Ok(None);
        };
        ensure!(
            previous.metadata()?.len() <= MAX_BYTES as u64,
            "configuration history exceeds 64 MiB"
        );
        let dir = self.version_dir(name);
        create_history_dir(&self.dir.join("history"))?;
        create_history_dir(&dir)?;
        previous.rewind()?;
        let mut temp = stage(&dir, name, |file| {
            let bytes = io::copy(&mut previous.take(MAX_BYTES as u64 + 1), file)?;
            if bytes > MAX_BYTES as u64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "file exceeds size limit",
                ));
            }
            Ok(())
        })
        .context("stage configuration history")?;
        let now = OffsetDateTime::now_utc();
        let mut time = history
            .last
            .map_or(now, |last| now.max(last + Duration::NANOSECOND));
        loop {
            let id = VersionId(time.format(VERSION_FORMAT)?);
            let path = dir.join(id.filename());
            match temp.persist_noclobber(&path) {
                Ok(()) => {
                    sync_directory(&dir).context("sync configuration history")?;
                    history.last = Some(time);
                    return Ok(Some(path));
                }
                Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                    temp = error.path;
                    time += Duration::NANOSECOND;
                }
                Err(error) => return Err(error.error).context("publish configuration history"),
            }
        }
    }

    fn version_dir(&self, name: &str) -> PathBuf {
        self.dir.join("history").join(name)
    }

    fn history_dirs(&self) -> Result<Vec<String>> {
        let dir = self.dir.join("history");
        if !check_dir(&dir)? {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(dir).context("list configuration history")? {
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && let Ok(name) = entry.file_name().into_string()
                && validate_history_name(&name).is_ok()
            {
                names.push(name);
            }
        }
        names.sort_unstable();
        Ok(names)
    }

    fn read_version_locked(&self, name: &str, id: &VersionId) -> Result<Vec<u8>> {
        validate_history_name(name)?;
        let dir = self.version_dir(name);
        ensure!(
            check_dir(&self.dir.join("history"))? && check_dir(&dir)?,
            "history version not found"
        );
        let path = dir.join(id.filename());
        let metadata = fs::symlink_metadata(&path).context("open history version")?;
        ensure!(metadata.is_file(), "expected a regular history file");
        let file = open_config(&path)?.context("history version not found")?;
        read_limited(file, MAX_BYTES).context("read history version (limit 64 MiB)")
    }
}

fn validate_history_name(name: &str) -> Result<()> {
    validate_name(name)?;
    ensure!(
        !SKIP.contains(&name),
        "history is unavailable for this configuration"
    );
    Ok(())
}

fn version_ids(dir: &Path) -> Result<Vec<VersionId>> {
    if !check_dir(dir)? {
        return Ok(Vec::new());
    }
    let mut versions = Vec::new();
    for entry in fs::read_dir(dir).context("list history versions")? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && let Some(id) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_suffix(".json"))
            && let Ok(id) = id.parse::<VersionId>()
        {
            versions.push(id);
        }
    }
    versions.sort_unstable();
    Ok(versions)
}

fn check_dir(dir: &Path) -> Result<bool> {
    match fs::symlink_metadata(dir) {
        Ok(metadata) => {
            ensure!(metadata.is_dir(), "expected a regular history directory");
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("inspect history directory"),
    }
}

fn create_history_dir(dir: &Path) -> Result<()> {
    if !check_dir(dir)? {
        fg_core::fsperm::mkdir_all(dir, 0o700).context("create history directory")?;
        sync_directory(dir.parent().expect("history directory parent"))
            .context("sync new history directory's parent")?;
    }
    Ok(())
}

pub(super) fn discard_snapshot(path: Option<&Path>) {
    if let Some(path) = path
        && fs::remove_file(path).is_ok()
    {
        let _ = sync_directory(path.parent().expect("history snapshot parent"));
    }
}
