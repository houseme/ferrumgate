use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeployTarget {
    pub directory: PathBuf,
    #[serde(default = "default_chain")]
    fullchain_name: String,
    #[serde(default = "default_key")]
    key_name: String,
}

fn default_chain() -> String {
    "fullchain.pem".into()
}

fn default_key() -> String {
    "privkey.pem".into()
}

impl DeployTarget {
    pub async fn compile(mut self, config_dir: &Path, state_dir: &Path) -> Result<Self> {
        ensure!(cfg!(unix), "local ACME deployment requires Unix");
        ensure!(
            file_name(&self.fullchain_name)
                && file_name(&self.key_name)
                && self.fullchain_name != self.key_name,
            "ACME deployment requires distinct simple certificate and key filenames"
        );
        ensure!(
            !self.directory.as_os_str().is_empty(),
            "ACME deployment directory is required"
        );
        let directory = config_dir.join(&self.directory);
        let metadata = tokio::fs::symlink_metadata(&directory)
            .await
            .context("inspect ACME deployment directory")?;
        ensure!(metadata.is_dir(), "ACME deployment needs a real directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode() & 0o022 == 0,
                "ACME deployment directory must not be writable by group or others"
            );
        }
        self.directory = tokio::fs::canonicalize(directory)
            .await
            .context("resolve ACME deployment directory")?;
        ensure!(
            !self.directory.starts_with(state_dir) && !state_dir.starts_with(&self.directory),
            "ACME deployment and state directories must be separate"
        );
        Ok(self)
    }
}

fn file_name(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(unix)]
pub(crate) struct Materials {
    chain: String,
    key: String,
}

#[cfg(unix)]
impl Materials {
    pub fn from_bundle(bundle: &[u8]) -> Result<Self> {
        let sections =
            pem::parse_many(bundle).map_err(|_| anyhow::anyhow!("parse ACME deployment PEM"))?;
        let mut chain = String::new();
        let mut key = None;
        for section in sections {
            match section.tag() {
                "CERTIFICATE" => chain.push_str(&pem::encode(&section)),
                "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" => {
                    ensure!(
                        key.is_none(),
                        "ACME deployment PEM has more than one private key"
                    );
                    key = Some(pem::encode(&section));
                }
                _ => {}
            }
        }
        ensure!(
            !chain.is_empty(),
            "ACME deployment PEM has no certificate chain"
        );
        Ok(Self {
            chain,
            key: key.context("ACME deployment PEM has no private key")?,
        })
    }
}

#[cfg(unix)]
impl DeployTarget {
    pub fn deploy(&self, material: &Materials, state_dir: &Path) -> Result<bool> {
        use std::{
            fs::{self, File, OpenOptions},
            io::ErrorKind,
            os::unix::{
                ffi::OsStrExt,
                fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink},
            },
        };

        const STORE: &str = ".fgate-acme";
        const MARKER: &[u8] = b"ferrumgate acme generation 1\n";
        let store = self.directory.join(STORE);
        match fs::DirBuilder::new().mode(0o700).create(&store) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("create deployment storage"),
        }
        let metadata = fs::symlink_metadata(&store)?;
        ensure!(
            metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0,
            "deployment storage is not a private directory"
        );
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(store.join("lock"))?;
        ensure!(
            lock.metadata()?.is_file(),
            "deployment lock must be a regular file"
        );
        lock.try_lock().context("deployment directory is in use")?;
        let owner_file = store.join("owner");
        let owner = state_dir.as_os_str().as_bytes();
        match fs::symlink_metadata(&owner_file) {
            Err(error) if error.kind() == ErrorKind::NotFound => write(&owner_file, owner, 0o600)?,
            Err(error) => return Err(error).context("inspect deployment owner"),
            Ok(_) => ensure!(
                file_matches(&owner_file, owner, 0o600),
                "deployment directory belongs to another ACME state directory"
            ),
        }

        let current = self.directory.join("current");
        let old = match fs::read_link(&current) {
            Ok(path) => {
                let mut parts = path.components();
                ensure!(
                    parts.next() == Some(std::path::Component::Normal(STORE.as_ref()))
                        && parts.next().is_some_and(|part| match part {
                            std::path::Component::Normal(name) =>
                                generation_name(&name.to_string_lossy()),
                            _ => false,
                        })
                        && parts.next().is_none(),
                    "refusing to replace a non-managed current link"
                );
                Some(self.directory.join(path))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("refusing to replace non-link current path"),
        };
        if let Some(old) = &old {
            let owned = fs::symlink_metadata(old).is_ok_and(|info| info.is_dir());
            ensure!(
                owned || !old.exists(),
                "current generation is not a directory"
            );
            if owned {
                ensure!(
                    file_matches(&old.join(".fgate-generation"), MARKER, 0o600),
                    "current generation is not managed by FerrumGate"
                );
            }
            if owned
                && file_matches(
                    &old.join(&self.fullchain_name),
                    material.chain.as_bytes(),
                    0o644,
                )
                && file_matches(&old.join(&self.key_name), material.key.as_bytes(), 0o600)
            {
                return Ok(false);
            }
        }

        let staging = tempfile::Builder::new()
            .prefix("generation-")
            .tempdir_in(&store)?;
        write(
            &staging.path().join(&self.fullchain_name),
            material.chain.as_bytes(),
            0o644,
        )?;
        write(
            &staging.path().join(&self.key_name),
            material.key.as_bytes(),
            0o600,
        )?;
        write(&staging.path().join(".fgate-generation"), MARKER, 0o600)?;
        File::open(staging.path())?.sync_all()?;
        let name = staging.path().file_name().context("generation name")?;
        let pointer = tempfile::tempdir_in(&store)?;
        let next = pointer.path().join("current");
        symlink(Path::new(STORE).join(name), &next)?;
        File::open(pointer.path())?.sync_all()?;
        File::open(&store)?.sync_all()?;
        fs::rename(&next, &current).context("publish certificate generation")?;
        let generation = staging.keep();
        File::open(&self.directory)?.sync_all()?;
        prune(&store, &generation, old.as_deref());
        Ok(true)
    }
}

#[cfg(unix)]
fn generation_name(name: &str) -> bool {
    name.strip_prefix("generation-")
        .is_some_and(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_alphanumeric()))
}

#[cfg(unix)]
fn file_matches(path: &Path, expected: &[u8], mode: u32) -> bool {
    use std::{
        fs::OpenOptions,
        io::Read,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };
    let result = (|| -> std::io::Result<bool> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let info = file.metadata()?;
        if !info.is_file()
            || info.len() != expected.len() as u64
            || info.permissions().mode() & 0o777 != mode
        {
            return Ok(false);
        }
        let mut bytes = Vec::with_capacity(expected.len());
        file.take(expected.len() as u64 + 1)
            .read_to_end(&mut bytes)?;
        Ok(bytes == expected)
    })();
    result.unwrap_or(false)
}

#[cfg(unix)]
fn write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::{
        fs::{OpenOptions, Permissions},
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(path)?;
    file.write_all(bytes)?;
    file.set_permissions(Permissions::from_mode(mode))?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn prune(store: &Path, current: &Path, previous: Option<&Path>) {
    let Ok(entries) = std::fs::read_dir(store) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path != current
            && previous != Some(path.as_path())
            && generation_name(&entry.file_name().to_string_lossy())
            && entry.file_type().is_ok_and(|kind| kind.is_dir())
            && file_matches(
                &path.join(".fgate-generation"),
                b"ferrumgate acme generation 1\n",
                0o600,
            )
            && let Err(error) = std::fs::remove_dir_all(path)
        {
            tracing::warn!(kind = ?error.kind(), "could not remove an old ACME deployment generation");
        }
    }
}
