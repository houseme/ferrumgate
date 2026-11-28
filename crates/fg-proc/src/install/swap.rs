//! 原子替换、旧版本保留与回滚、卸载、残留清理（WP-43 §3.3）。
//!
//! `bin/` 布局：安装的文件直接放在 `bin/` 下（多个程序共享）；被替换
//! 下来的版本保存在 `bin/.versions/<程序>/<版本>/`；当前安装的元数据
//! （版本、时间、文件名）记录在 `bin/.versions/<程序>/current.json`；
//! 下载与卸载的暂存目录在 `bin/.staging/` 下。全部操作先移走旧文件、
//! 再移入新文件，中途失败尽量还原——两个 rename 之间崩溃会让程序暂时
//! 不存在，残留清理与「从 .versions 恢复」要覆盖这种情况。

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use super::InstallError;

/// 保留的旧版本数：最多 3 个（上游 `MaxBackups`）。
pub const KEEP_BACKUPS: usize = 3;
const VERSIONS: &str = ".versions";
const STAGING: &str = ".staging";
const CURRENT_META: &str = "current.json";
const BACKUP_META: &str = "meta.json";

/// 当前安装的记录。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installed {
    pub version: String,
    /// `bin/` 下的文件名（不是路径）。
    pub files: Vec<String>,
    pub at: SystemTime,
}

/// 一个旧版本（备份）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backup {
    pub version: String,
    pub at: SystemTime,
}

/// 元数据文件的磁盘格式；时间一律 UTC 的 RFC 3339（约定 §3.5）。
#[derive(Serialize, Deserialize)]
struct MetaJson {
    version: String,
    at: String,
    files: Vec<String>,
}

impl MetaJson {
    fn now(version: impl Into<String>, files: Vec<String>) -> Self {
        let at: time::OffsetDateTime = SystemTime::now().into();
        Self {
            version: version.into(),
            at: at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            files,
        }
    }

    fn at(&self) -> SystemTime {
        time::OffsetDateTime::parse(&self.at, &time::format_description::well_known::Rfc3339)
            .map(SystemTime::from)
            .unwrap_or(UNIX_EPOCH)
    }
}

fn write_json(path: &Path, value: &MetaJson) -> Result<(), InstallError> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|_| InstallError::Io("序列化元数据失败".into()))?;
    std::fs::write(path, bytes)
        .and_then(|()| set_owner_only(path))
        .map_err(|error| InstallError::Io(format!("写元数据失败：{error}")))
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_owner_only(_: &Path) -> std::io::Result<()> {
    Ok(())
}

fn read_json(path: &Path) -> Option<MetaJson> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn versions_dir(bin_dir: &Path, program: &str) -> PathBuf {
    bin_dir.join(VERSIONS).join(program)
}

pub fn staging_root(bin_dir: &Path) -> PathBuf {
    bin_dir.join(STAGING)
}

/// 版本目录名要安全：只保留常见版本字符，其余换成 `_`。
fn safe_dir_name(version: &str) -> String {
    let mut name: String = version
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if name == ".." || name == "." {
        name = "_".to_owned();
    }
    name
}

fn now_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// 新的暂存目录（进程内唯一）。
pub fn new_staging_dir(bin_dir: &Path) -> Result<PathBuf, InstallError> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = staging_root(bin_dir).join(format!(
        "{}-{}-{}",
        std::process::id(),
        now_unix_nanos(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir)
        .map_err(|error| InstallError::Io(format!("创建暂存目录失败：{error}")))?;
    Ok(dir)
}

/// 残留清理：进程被强制结束时可能留下暂存目录（下载解压、替换同版本
/// 时移走的旧文件、卸载时移走的文件）；在没有任何操作进行时全部删除。
pub fn clean_stale_staging(bin_dir: &Path) {
    let root = staging_root(bin_dir);
    let Ok(entries) = std::fs::read_dir(&root) else {
        return;
    };
    for entry in entries.flatten() {
        if let Err(error) = std::fs::remove_dir_all(entry.path()) {
            tracing::warn!(dir = %entry.path().display(), %error, "删除残留暂存目录失败");
        }
    }
}

/// 当前安装记录；`files` 已展开为 `bin/` 下的路径。
pub fn read_current(bin_dir: &Path, program: &str) -> Option<Installed> {
    let meta: MetaJson = read_json(&versions_dir(bin_dir, program).join(CURRENT_META))?;
    let at = meta.at();
    Some(Installed {
        version: meta.version,
        files: meta.files,
        at,
    })
}

pub fn write_current(
    bin_dir: &Path,
    program: &str,
    installed: &Installed,
) -> Result<(), InstallError> {
    let dir = versions_dir(bin_dir, program);
    std::fs::create_dir_all(&dir)
        .map_err(|error| InstallError::Io(format!("创建旧版本目录失败：{error}")))?;
    let meta = MetaJson {
        version: installed.version.clone(),
        at: {
            let at: time::OffsetDateTime = installed.at.into();
            at.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        },
        files: installed.files.clone(),
    };
    write_json(&dir.join(CURRENT_META), &meta)
}

/// 旧版本列表，最新的在前。
pub fn list_backups(bin_dir: &Path, program: &str) -> Vec<Backup> {
    let dir = versions_dir(bin_dir, program);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut backups: Vec<Backup> = entries
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let meta = read_json(&entry.path().join(BACKUP_META));
            let at = meta.as_ref().map(|meta| meta.at()).unwrap_or_else(|| {
                entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(UNIX_EPOCH)
            });
            let version = meta.map(|meta| meta.version).unwrap_or(name.clone());
            Backup { version, at }
        })
        .collect();
    backups.sort_by(|a, b| b.at.cmp(&a.at).then_with(|| b.version.cmp(&a.version)));
    backups
}

/// 只保留最新的 `keep` 个旧版本，超出时删除最旧的。
pub fn prune_backups(bin_dir: &Path, program: &str, keep: usize) {
    for backup in list_backups(bin_dir, program).into_iter().skip(keep) {
        let dir = versions_dir(bin_dir, program).join(safe_dir_name(&backup.version));
        if let Err(error) = std::fs::remove_dir_all(&dir) {
            tracing::warn!(
                program,
                version = %backup.version,
                %error,
                "删除最旧的旧版本失败"
            );
        }
    }
}

/// 一条「已发生的移动」，失败时按逆序还原。
struct Moved(PathBuf, PathBuf);

impl Moved {
    fn revert(&self) {
        let _ = std::fs::rename(&self.0, &self.1);
    }
}

fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::rename(from, to)
}

/// 把暂存目录里 `files` 列出的文件装入 `bin/`：先移走旧文件（存为旧版
/// 本），再移入新文件；中途失败尽量还原。装入后写当前版本元数据。
pub fn swap_in(
    staged: &Path,
    files: &[&str],
    bin_dir: &Path,
    program: &str,
    version: &str,
    previous: Option<&Installed>,
) -> Result<(), InstallError> {
    let versions = versions_dir(bin_dir, program);
    let old_version = previous
        .map(|p| p.version.clone())
        .unwrap_or_else(|| "previous".to_owned());
    let backup = versions.join(safe_dir_name(&old_version));
    // 同版本重装：先清掉旧的同名备份。
    let _ = std::fs::remove_dir_all(&backup);
    if let Err(error) = std::fs::create_dir_all(&backup) {
        return Err(InstallError::Io(format!("创建旧版本目录失败：{error}")));
    }
    let mut moved_old: Vec<Moved> = Vec::new();
    let mut moved_new: Vec<Moved> = Vec::new();
    let mut old_files: Vec<String> = Vec::new();
    let result = (|| -> Result<(), InstallError> {
        for name in files {
            let src = bin_dir.join(name);
            if src.is_file() {
                let dst = backup.join(name);
                move_file(&src, &dst)
                    .map_err(|error| InstallError::Io(format!("移走旧文件失败：{error}")))?;
                moved_old.push(Moved(dst, src));
                old_files.push((*name).to_owned());
            }
        }
        for name in files {
            let src = staged.join(name);
            if !src.is_file() {
                return Err(InstallError::Extract(format!("暂存目录缺少 {name}")));
            }
            let dst = bin_dir.join(name);
            move_file(&src, &dst)
                .map_err(|error| InstallError::Io(format!("移入新文件失败：{error}")))?;
            moved_new.push(Moved(dst.clone(), src));
            set_exec_mode(&dst);
        }
        if old_files.is_empty() {
            // 首次安装没有旧文件：不留下空的备份目录。
            let _ = std::fs::remove_dir_all(&backup);
        } else {
            write_json(
                &backup.join(BACKUP_META),
                &MetaJson::now(old_version, old_files),
            )?;
        }
        write_current(
            bin_dir,
            program,
            &Installed {
                version: version.to_owned(),
                files: files.iter().map(|name| (*name).to_owned()).collect(),
                at: SystemTime::now(),
            },
        )
    })();
    if let Err(error) = result {
        // 尽量还原：新文件退回暂存目录，旧文件退回 bin/。
        for move_ in moved_new.iter().rev() {
            move_.revert();
        }
        for move_ in moved_old.iter().rev() {
            move_.revert();
        }
        let _ = std::fs::remove_dir_all(&backup);
        return Err(error);
    }
    Ok(())
}

/// 回滚：把指定的旧版本换回 `bin/`；当前版本同样保留（存为新备份），
/// 之后还能再切回来。
pub fn rollback(bin_dir: &Path, program: &str, version: &str) -> Result<Installed, InstallError> {
    let current = read_current(bin_dir, program)
        .ok_or_else(|| InstallError::Resolve("尚未安装，无法回滚".into()))?;
    if version_eq(&current.version, version) {
        return Err(InstallError::Resolve(format!(
            "该版本（{version}）已是当前版本"
        )));
    }
    let versions = versions_dir(bin_dir, program);
    let backup = versions.join(safe_dir_name(version));
    if !backup.is_dir() {
        return Err(InstallError::Resolve(format!("没有这个旧版本：{version}")));
    }
    let current_backup = versions.join(safe_dir_name(&current.version));
    let _ = std::fs::remove_dir_all(&current_backup);
    if let Err(error) = std::fs::create_dir_all(&current_backup) {
        return Err(InstallError::Io(format!("创建旧版本目录失败：{error}")));
    }
    let mut moved_old: Vec<Moved> = Vec::new();
    let mut moved_new: Vec<Moved> = Vec::new();
    let result = (|| -> Result<(), InstallError> {
        for name in &current.files {
            let src = bin_dir.join(name);
            if src.is_file() {
                let dst = current_backup.join(name);
                move_file(&src, &dst)
                    .map_err(|error| InstallError::Io(format!("移走当前文件失败：{error}")))?;
                moved_old.push(Moved(dst, src));
            }
        }
        for name in &current.files {
            let src = backup.join(name);
            if !src.is_file() {
                return Err(InstallError::Extract(format!("旧版本目录缺少 {name}")));
            }
            let dst = bin_dir.join(name);
            move_file(&src, &dst)
                .map_err(|error| InstallError::Io(format!("移入旧版本失败：{error}")))?;
            moved_new.push(Moved(dst.clone(), src));
            set_exec_mode(&dst);
        }
        write_json(
            &current_backup.join(BACKUP_META),
            &MetaJson::now(current.version.clone(), current.files.clone()),
        )?;
        write_current(
            bin_dir,
            program,
            &Installed {
                version: version.to_owned(),
                files: current.files.clone(),
                at: SystemTime::now(),
            },
        )
    })();
    if let Err(error) = result {
        for move_ in moved_new.iter().rev() {
            move_.revert();
        }
        for move_ in moved_old.iter().rev() {
            move_.revert();
        }
        let _ = std::fs::remove_dir_all(&current_backup);
        return Err(error);
    }
    // 旧版本目录已经空了，清掉；当前版本成为新备份，之后还能再切回。
    let _ = std::fs::remove_dir_all(&backup);
    Ok(Installed {
        version: version.to_owned(),
        files: current.files.clone(),
        at: SystemTime::now(),
    })
}

/// 卸载：删除 `bin/` 下安装的程序与全部旧版本（先移入暂存目录再删除）。
/// 模块配置保留。
pub fn remove_installed(
    bin_dir: &Path,
    program: &str,
    files: &[String],
) -> Result<(), InstallError> {
    let staging = new_staging_dir(bin_dir)?;
    let versions = versions_dir(bin_dir, program);
    let result = (|| -> Result<(), InstallError> {
        for name in files {
            let src = bin_dir.join(name);
            if src.exists() {
                move_file(&src, &staging.join(name))
                    .map_err(|error| InstallError::Io(format!("移走程序文件失败：{error}")))?;
            }
        }
        if versions.exists() {
            std::fs::rename(&versions, staging.join(VERSIONS))
                .map_err(|error| InstallError::Io(format!("移走旧版本失败：{error}")))?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        // 尽量还原。
        for name in files {
            let _ = std::fs::rename(staging.join(name), bin_dir.join(name));
        }
        let _ = std::fs::rename(staging.join(VERSIONS), &versions);
        let _ = std::fs::remove_dir_all(&staging);
        return Err(error);
    }
    let _ = std::fs::remove_dir_all(&staging);
    Ok(())
}

#[cfg(unix)]
fn set_exec_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
}

#[cfg(not(unix))]
fn set_exec_mode(_: &Path) {}

/// 版本文本比较口径：去掉前缀 `v`、忽略大小写。
pub fn normalize_version(version: &str) -> String {
    let trimmed = version.trim();
    let trimmed = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    trimmed.to_ascii_lowercase()
}

/// 版本相等（忽略前缀 `v` 与大小写）。
pub fn version_eq(a: &str, b: &str) -> bool {
    normalize_version(a) == normalize_version(b)
}

/// `candidate` 是否比 `current` 新：按 `.` 分段，数字段按数值比较，
/// 其它按字典序；比较前先做 [`normalize_version`]。
pub fn version_newer(candidate: &str, current: &str) -> bool {
    let candidate = normalize_version(candidate);
    let current = normalize_version(current);
    let mut a = candidate.split('.');
    let mut b = current.split('.');
    loop {
        match (a.next(), b.next()) {
            (None, None) => return false,
            (None, Some(_)) => return false,
            (Some(_), None) => return true,
            (Some(sa), Some(sb)) => {
                let order = match (sa.parse::<u64>(), sb.parse::<u64>()) {
                    (Ok(na), Ok(nb)) => na.cmp(&nb),
                    _ => sa.cmp(sb),
                };
                if order != std::cmp::Ordering::Equal {
                    return order == std::cmp::Ordering::Greater;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compare_ignores_v_prefix_and_case() {
        assert!(version_eq("V1.2.3", "v1.2.3"));
        assert!(version_eq("1.2.3", "v1.2.3"));
        assert!(version_eq("1.2.3-Beta", "1.2.3-BETA"));
        assert!(!version_eq("1.2.3", "1.2.4"));
        assert!(version_newer("v1.10.0", "1.9.9"), "数值段按数值比较");
        assert!(version_newer("2.0", "1.99.99"));
        assert!(!version_newer("v1.9.9", "1.10.0"));
        assert!(!version_newer("1.2.3", "V1.2.3"));
        assert!(version_newer("1.3", "1.2.9"), "段数多且更大时算更新");
    }
}
