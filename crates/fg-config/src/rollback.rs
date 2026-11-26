//! Filesystem handoff between an offline CLI and the running process.

use std::{
    fs,
    io::{self, Write},
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    ConfigStore, VersionId, open_config, read_limited, stage, sync_directory, validate_name,
};

const REQUEST: &str = "rollback-request.state";
const MAX_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RollbackRequest {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub config: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<VersionId>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub last: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pending: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

enum Target<'a> {
    Version(&'a str, &'a VersionId),
    Last,
    Pending,
}

impl RollbackRequest {
    fn target(&self) -> Result<Target<'_>> {
        match (
            self.last,
            self.pending,
            self.config.as_str(),
            self.version.as_ref(),
        ) {
            (true, false, "", None) => Ok(Target::Last),
            (false, true, "", None) => Ok(Target::Pending),
            (false, false, name, Some(id)) => {
                validate_name(name)?;
                Ok(Target::Version(name, id))
            }
            _ => bail!("invalid rollback request target"),
        }
    }
}

pub fn write_request(dir: &Path, request: &RollbackRequest) -> Result<()> {
    request.target()?;
    let bytes = serde_json::to_vec(request).context("serialize rollback request")?;
    ensure!(bytes.len() <= MAX_BYTES, "rollback request exceeds 4 KiB");
    let temp = stage(dir, "rollback-request", |file| file.write_all(&bytes))
        .context("stage rollback request")?;
    match temp.persist_noclobber(dir.join(REQUEST)) {
        Ok(()) => sync_directory(dir).context("sync rollback request directory"),
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            bail!("a rollback request is already pending")
        }
        Err(error) => Err(error.error).context("publish rollback request"),
    }
}

pub fn request_pending(dir: &Path) -> bool {
    fs::symlink_metadata(dir.join(REQUEST)).is_ok_and(|metadata| metadata.is_file())
}

pub fn take_request(dir: &Path) -> Result<Option<RollbackRequest>> {
    let pending = dir.join(REQUEST);
    match fs::symlink_metadata(&pending) {
        Ok(metadata) => ensure!(
            metadata.is_file(),
            "expected a regular rollback request file"
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect rollback request"),
    }
    let claimed = tempfile::Builder::new()
        .prefix(".rollback-claim.")
        .suffix(".tmp")
        .tempfile_in(dir)
        .context("reserve rollback request claim")?
        .into_temp_path();
    match fs::rename(&pending, &claimed) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("claim rollback request"),
    }
    let file = open_config(&claimed)?.context("claimed rollback request disappeared")?;
    let bytes = read_limited(file, MAX_BYTES).context("read rollback request (limit 4 KiB)")?;
    claimed.close().context("remove claimed rollback request")?;
    sync_directory(dir).context("sync claimed rollback request directory")?;
    let request: RollbackRequest = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid rollback request JSON"))?;
    request.target()?;
    Ok(Some(request))
}

pub fn apply_offline(store: &ConfigStore, request: RollbackRequest) -> Result<String> {
    let target = request.target()?;
    let mut history = store.lock.lock().expect("config store lock poisoned");
    let latest;
    let (name, id) = match target {
        Target::Version(name, id) => (name, id),
        Target::Last => {
            latest = store
                .newest_version()?
                .context("no configuration history")?;
            (latest.0.as_str(), &latest.1)
        }
        Target::Pending => {
            bail!("pending confirmation rollback requires the confirmation workflow")
        }
    };
    store.restore_locked(name, id, &mut history)?;
    Ok(format!("restored configuration {name} to version {id}"))
}
