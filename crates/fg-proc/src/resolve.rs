//! 查找托管程序的可执行文件（WP-43 §3.3）：模块设置中填写的路径 → 配置
//! 目录下的 `bin/` → `PATH`，返回绝对路径。`bin/` 排在 `PATH` 之前：界面
//! 中在线安装、更新或回滚的程序都在 `bin/` 下，应当优先生效。子进程可能
//! 在别的工作目录启动（如 File Browser），相对路径会找不到，因此一律返回
//! 绝对路径。

use std::path::{Path, PathBuf};

/// 程序可执行文件的来源。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedFrom {
    /// 模块设置中填写的路径。
    Configured,
    /// 配置目录下的 `bin/`（在线安装、更新与回滚的位置）。
    BinDir,
    /// 系统的 `PATH`。
    Path,
}

/// 按顺序查找 `name`：`configured`（模块设置）→ `bin_dir/<name>` → `PATH`。
/// 填写的路径不存在时继续按后面的来源查找（此时在线安装的版本会生效，
/// 与上游「填写路径后安装不生效」的提示口径一致，由界面提示）。
pub fn resolve(
    configured: Option<&Path>,
    bin_dir: &Path,
    name: &str,
) -> Option<(ResolvedFrom, PathBuf)> {
    if let Some(path) = configured.filter(|p| !p.as_os_str().is_empty()) {
        if is_executable_file(path) {
            return Some((ResolvedFrom::Configured, absolutize(path)));
        }
        tracing::debug!(
            configured = %path.display(),
            "模块设置中的程序路径不存在，继续按 bin/ 与 PATH 查找"
        );
    }
    let in_bin = bin_dir.join(executable_name(name));
    if is_executable_file(&in_bin) {
        return Some((ResolvedFrom::BinDir, absolutize(&in_bin)));
    }
    resolve_with_path(name, &std::env::var("PATH").unwrap_or_default())
        .map(|path| (ResolvedFrom::Path, path))
}

/// `PATH` 查找的纯逻辑（测试注入路径用）。
pub fn resolve_with_path(name: &str, path_var: &str) -> Option<PathBuf> {
    let want = executable_name(name);
    for dir in path_var.split(':').filter(|d| !d.is_empty()) {
        let candidate = Path::new(dir).join(&want);
        if is_executable_file(&candidate) {
            return Some(absolutize(&candidate));
        }
    }
    None
}

/// Windows 上补 `.exe` 后缀；其它平台原样。
fn executable_name(name: &str) -> String {
    #[cfg(windows)]
    if !name.to_ascii_lowercase().ends_with(".exe") {
        return format!("{name}.exe");
    }
    name.to_owned()
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// 绝对化：优先解析符号链接，失败时退回纯文本绝对化。
pub(crate) fn absolutize(path: &Path) -> PathBuf {
    path.canonicalize()
        .or_else(|_| std::path::absolute(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exec(path: &Path) {
        std::fs::write(path, "#!/bin/sh\n").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
    }

    #[test]
    fn resolve_prefers_configured_then_bin_then_path() {
        let base = tempfile::tempdir().expect("tempdir");
        let bin_dir = base.path().join("bin");
        let path_dir = base.path().join("pathdir");
        std::fs::create_dir_all(&bin_dir).expect("mkdir");
        std::fs::create_dir_all(&path_dir).expect("mkdir");
        make_exec(&bin_dir.join("prog"));
        make_exec(&path_dir.join("prog"));

        // 只有 PATH 里有时来自 PATH。
        let (from, found) = resolve_with_path("prog", &path_dir.display().to_string())
            .map(|p| (ResolvedFrom::Path, p))
            .expect("found in path");
        assert_eq!(from, ResolvedFrom::Path);
        assert_eq!(found, absolutize(&path_dir.join("prog")));

        // bin/ 出现后优先于 PATH。
        let (from, found) = resolve(None, &bin_dir, "prog").expect("found in bin dir");
        assert_eq!(from, ResolvedFrom::BinDir);
        assert_eq!(found, absolutize(&bin_dir.join("prog")));

        // 填写的路径优先于 bin/；填写的路径不存在时落到 bin/。
        let configured = base.path().join("custom").join("prog");
        std::fs::create_dir_all(configured.parent().expect("parent")).expect("mkdir");
        make_exec(&configured);
        let (from, found) = resolve(Some(&configured), &bin_dir, "prog").expect("configured");
        assert_eq!(from, ResolvedFrom::Configured);
        assert_eq!(found, absolutize(&configured));
        let (from, _) = resolve(Some(&base.path().join("missing")), &bin_dir, "prog")
            .expect("falls back to bin");
        assert_eq!(from, ResolvedFrom::BinDir);
    }

    #[test]
    fn resolve_returns_absolute_path() {
        let base = tempfile::tempdir().expect("tempdir");
        let bin_dir = base.path().join("bin");
        std::fs::create_dir_all(&bin_dir).expect("mkdir");
        make_exec(&bin_dir.join("prog"));
        let (_, found) = resolve(None, &bin_dir, "prog").expect("found");
        assert!(found.is_absolute(), "relative: {found:?}");
        assert_eq!(found.file_name().and_then(|n| n.to_str()), Some("prog"));

        // 相对路径的填写项也要返回绝对路径（直接走绝对化，不改进程工作目录）。
        let (from, found) =
            resolve(Some(&base.path().join("missing-prog")), &bin_dir, "prog").expect("found");
        assert_eq!(from, ResolvedFrom::BinDir);
        assert!(found.is_absolute(), "relative: {found:?}");
        assert!(absolutize(Path::new("relative/prog")).is_absolute());
    }
}
