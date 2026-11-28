//! Probing (`--version`) and atomic same-directory binary installation with
//! `<name>.old` backup retention.

use std::{
    fs::{self, File},
    io::{ErrorKind, Read, Write},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail, ensure};

use super::download::MAX_UPGRADE_BINARY;
use crate::update::version::parse_version;

/// Timeout for probing a candidate binary with `--version`.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

const MAX_PROBE_OUTPUT_BYTES: u64 = 64 << 10;

/// Executes `path --version` with a bounded timeout to verify that the binary
/// is runnable on this host/architecture and reports a version string.
pub async fn probe_binary(path: &Path) -> Result<String> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || probe_binary_sync(&path))
        .await
        .context("join probe_binary task")?
}

/// Atomically installs `bin` at `exe`:
/// 1. Writes `bin` to a same-directory temp file (`.fgate-upgrade-*`) with
///    executable permissions and calls `sync_all`.
/// 2. Closes the write descriptor (avoiding Linux `ETXTBSY`) and probes the
///    temp binary via `--version`.
/// 3. Backs up the existing `exe` to `<name>.old` via hard link (falling back
///    to file copy when hard links are unsupported).
/// 4. Atomically renames the temp file over `exe` and syncs the directory.
///
/// Any failure cleans up the temporary file automatically without modifying `exe`.
pub async fn install_binary(exe: &Path, bin: &[u8]) -> Result<String> {
    let exe = exe.to_path_buf();
    let bin = bin.to_vec();
    tokio::task::spawn_blocking(move || install_binary_sync(&exe, &bin))
        .await
        .context("join install_binary task")?
}

pub(crate) fn probe_binary_sync(path: &Path) -> Result<String> {
    let mut child = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to execute candidate binary {}", path.display()))?;

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let stdout_handle = thread::spawn(move || read_pipe_limited(stdout_pipe));
    let stderr_handle = thread::spawn(move || read_pipe_limited(stderr_pipe));

    let deadline = Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_handle.join();
                    let _ = stderr_handle.join();
                    bail!("candidate binary --version probe timed out");
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(err).context("wait for candidate binary --version probe");
            }
        }
    };

    let stdout = stdout_handle.join().unwrap_or_default();
    let stderr = stderr_handle.join().unwrap_or_default();

    if !status.success() {
        let err_msg = String::from_utf8_lossy(&stderr).trim().to_owned();
        if err_msg.is_empty() {
            bail!("candidate binary --version exited with {status}");
        }
        bail!("candidate binary --version exited with {status}: {err_msg}");
    }

    let out = String::from_utf8_lossy(&stdout);
    let first_line = out
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| anyhow!("candidate binary --version produced no output"))?;

    // Extract version token when formatted as `<program> <version>`.
    if let Some(token) = first_line
        .split_whitespace()
        .rev()
        .find(|tok| parse_version(tok).is_some())
    {
        Ok(token.to_owned())
    } else {
        Ok(first_line.to_owned())
    }
}

fn read_pipe_limited<R: Read>(pipe: Option<R>) -> Vec<u8> {
    let Some(pipe) = pipe else {
        return Vec::new();
    };
    let mut buf = Vec::new();
    let _ = pipe.take(MAX_PROBE_OUTPUT_BYTES).read_to_end(&mut buf);
    buf
}

fn install_binary_sync(exe: &Path, bin: &[u8]) -> Result<String> {
    ensure!(!bin.is_empty(), "upgrade binary is empty");
    ensure!(
        bin.len() as u64 <= MAX_UPGRADE_BINARY,
        "upgrade binary exceeds {} bytes",
        MAX_UPGRADE_BINARY
    );

    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("executable path has no parent directory"))?;
    let file_name = exe
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("executable path has no valid file name"))?;

    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(exe)
            .map(|meta| meta.permissions().mode() | 0o111)
            .unwrap_or(0o755)
    };

    let mut temp = tempfile::Builder::new()
        .prefix(".fgate-upgrade-")
        .tempfile_in(dir)
        .with_context(|| format!("create temporary upgrade file in {}", dir.display()))?;

    if let Err(err) = temp.as_file_mut().write_all(bin) {
        if err.kind() == ErrorKind::StorageFull {
            bail!(
                "insufficient disk space in {} (need at least {} bytes)",
                dir.display(),
                bin.len()
            );
        }
        return Err(err).context("write candidate binary to temporary file");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(mode))
            .context("set executable permissions on candidate binary")?;
    }

    temp.as_file()
        .sync_all()
        .context("sync candidate binary to disk")?;

    // Close the write file descriptor before probing to prevent ETXTBSY on Linux.
    let temp_path = temp.into_temp_path();
    let probed_version = probe_binary_sync(&temp_path)?;

    if exe.exists() {
        let old_path = dir.join(format!("{file_name}.old"));
        if let Err(err) = fs::remove_file(&old_path)
            && err.kind() != ErrorKind::NotFound
        {
            return Err(err)
                .with_context(|| format!("remove previous backup {}", old_path.display()));
        }
        if fs::hard_link(exe, &old_path).is_err() {
            fs::copy(exe, &old_path).with_context(|| {
                format!(
                    "backup existing binary {} to {}",
                    exe.display(),
                    old_path.display()
                )
            })?;
        }
    }

    temp_path
        .persist(exe)
        .map_err(|err| err.error)
        .with_context(|| format!("atomically replace {}", exe.display()))?;

    #[cfg(unix)]
    if let Ok(parent_dir) = File::open(dir) {
        let _ = parent_dir.sync_all();
    }

    Ok(probed_version)
}
