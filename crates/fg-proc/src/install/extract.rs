//! 解包（WP-43 §3.3）：`tar.gz` / `zip` / 裸二进制。安全限制（下载并
//! 运行外部二进制是高风险操作，这里是一道独立防线）：
//!
//! - 拒绝路径穿越的条目名（`..`、绝对路径）；
//! - 拒绝符号链接与硬链接条目（zip 的加密条目一并拒绝）；
//! - 限制条目数与解压后总大小，按实际写出的字节计数，不信任声明值；
//! - 只取出 `ProgramSpec::files` 列出的文件（按文件名匹配，归档内的
//!   目录层级不管）。

use std::{
    io::Read,
    path::{Component, Path, PathBuf},
};

use super::{ArchiveKind, InstallError};

/// 解包限制；默认值见 [`Limits::default`]。
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// 最多接受的条目数（含不取出的目录与其它文件）。
    pub max_entries: usize,
    /// 解压后总字节数上限。
    pub max_total_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 2000,
            max_total_bytes: 512 << 20,
        }
    }
}

/// 解出 `wanted` 列出的文件到 `out`（文件名平铺），返回取出的路径（顺序
/// 与 `wanted` 一致）。归档里必须包含全部 `wanted` 文件，否则失败。
pub fn extract(
    archive: &Path,
    kind: ArchiveKind,
    wanted: &[&str],
    out: &Path,
    limits: &Limits,
) -> Result<Vec<PathBuf>, InstallError> {
    std::fs::create_dir_all(out)
        .map_err(|error| InstallError::Extract(format!("创建解包目录失败：{error}")))?;
    let paths = match kind {
        ArchiveKind::TarGz => extract_tar_gz(archive, wanted, out, limits)?,
        ArchiveKind::Zip => extract_zip(archive, wanted, out, limits)?,
        ArchiveKind::Raw => extract_raw(archive, wanted, out)?,
    };
    ensure_all_wanted(&paths, wanted, out)
}

fn is_safe_name(name: &Path) -> bool {
    if name.as_os_str().is_empty() {
        return false;
    }
    name.components()
        .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn check_entry(name: &Path) -> Result<(), InstallError> {
    if !is_safe_name(name) {
        return Err(InstallError::Extract(format!(
            "归档条目名不安全：{}",
            name.display()
        )));
    }
    Ok(())
}

/// 写一个条目并按实际写出的字节计数：声明的尺寸可以撒谎，计数器不会。
fn write_entry<R: Read>(
    entry: R,
    target: &Path,
    remaining: u64,
    total: &mut u64,
) -> Result<(), InstallError> {
    let mut file = std::fs::File::create(target)
        .map_err(|error| InstallError::Extract(format!("写文件失败：{error}")))?;
    let mut limited = entry.take(remaining.saturating_add(1));
    let copied = std::io::copy(&mut limited, &mut file)
        .map_err(|error| InstallError::Extract(format!("解压失败：{error}")))?;
    if copied > remaining {
        return Err(size_limit_error());
    }
    *total += copied;
    Ok(())
}

/// 未选中的条目也计入总大小，避免解压炸弹绕过限制。
fn drain_entry<R: Read>(entry: R, total: &mut u64, limits: &Limits) -> Result<(), InstallError> {
    let mut sink = std::io::sink();
    let mut limited = entry.take(limits.max_total_bytes.saturating_sub(*total) + 1);
    let copied = std::io::copy(&mut limited, &mut sink)
        .map_err(|error| InstallError::Extract(format!("读取条目失败：{error}")))?;
    if copied + *total > limits.max_total_bytes {
        return Err(size_limit_error());
    }
    *total += copied;
    Ok(())
}

#[cfg(unix)]
fn set_exec_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
}

#[cfg(not(unix))]
fn set_exec_mode(_: &Path) {}

fn entry_limit_error(limits: &Limits) -> InstallError {
    InstallError::Extract(format!("归档条目数超过 {} 上限", limits.max_entries))
}

fn size_limit_error() -> InstallError {
    InstallError::Extract("解压后总大小超过上限".into())
}

fn extract_tar_gz(
    archive: &Path,
    wanted: &[&str],
    out: &Path,
    limits: &Limits,
) -> Result<Vec<PathBuf>, InstallError> {
    let file = std::fs::File::open(archive)
        .map_err(|error| InstallError::Extract(format!("打开归档失败：{error}")))?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut tar = tar::Archive::new(gz);
    let mut count = 0usize;
    let mut total = 0u64;
    let mut extracted: Vec<(String, PathBuf)> = Vec::new();
    let entries = tar
        .entries()
        .map_err(|error| InstallError::Extract(format!("读取归档失败：{error}")))?;
    for entry in entries {
        let mut entry =
            entry.map_err(|error| InstallError::Extract(format!("读取条目失败：{error}")))?;
        count += 1;
        if count > limits.max_entries {
            return Err(entry_limit_error(limits));
        }
        let name = entry
            .path()
            .map_err(|error| InstallError::Extract(error.to_string()))?;
        check_entry(&name)?;
        let name = name
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| InstallError::Extract("归档条目没有文件名".into()))?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            return Err(InstallError::Extract(format!("归档包含链接条目：{name}")));
        }
        if !entry_type.is_file() {
            // 目录等结构性条目：只校验名字，不落盘。
            continue;
        }
        if !wanted.contains(&name.as_str()) {
            drain_entry(&mut entry, &mut total, limits)?;
            continue;
        }
        let target = out.join(&name);
        write_entry(
            &mut entry,
            &target,
            limits.max_total_bytes.saturating_sub(total),
            &mut total,
        )?;
        set_exec_mode(&target);
        extracted.push((name, target));
    }
    Ok(extracted.into_iter().map(|(_, path)| path).collect())
}

fn extract_zip(
    archive: &Path,
    wanted: &[&str],
    out: &Path,
    limits: &Limits,
) -> Result<Vec<PathBuf>, InstallError> {
    let file = std::fs::File::open(archive)
        .map_err(|error| InstallError::Extract(format!("打开归档失败：{error}")))?;
    let mut zip = zip::ZipArchive::new(file)
        .map_err(|error| InstallError::Extract(format!("读取归档失败：{error}")))?;
    if zip.len() > limits.max_entries {
        return Err(entry_limit_error(limits));
    }
    let mut count = 0usize;
    let mut total = 0u64;
    let mut extracted: Vec<(String, PathBuf)> = Vec::new();
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|error| InstallError::Extract(format!("读取条目失败：{error}")))?;
        count += 1;
        if count > limits.max_entries {
            return Err(entry_limit_error(limits));
        }
        let raw = entry
            .name()
            .map_err(|error| InstallError::Extract(format!("读取条目名失败：{error}")))?;
        check_entry(Path::new(&*raw))?;
        let name = raw
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or_default()
            .to_owned();
        if entry.encrypted() {
            return Err(InstallError::Extract(format!("归档包含加密条目：{name}")));
        }
        if entry.is_symlink() {
            return Err(InstallError::Extract(format!("归档包含链接条目：{name}")));
        }
        if entry.is_dir() {
            continue;
        }
        if !wanted.contains(&name.as_str()) {
            drain_entry(&mut entry, &mut total, limits)?;
            continue;
        }
        let target = out.join(&name);
        write_entry(
            &mut entry,
            &target,
            limits.max_total_bytes.saturating_sub(total),
            &mut total,
        )?;
        set_exec_mode(&target);
        extracted.push((name, target));
    }
    Ok(extracted.into_iter().map(|(_, path)| path).collect())
}

/// 裸二进制：下载的产物就是主程序本体，复制改名后安装。
fn extract_raw(archive: &Path, wanted: &[&str], out: &Path) -> Result<Vec<PathBuf>, InstallError> {
    let main = wanted
        .first()
        .ok_or_else(|| InstallError::Extract("程序规格没有列出任何文件".into()))?;
    let target = out.join(main);
    std::fs::copy(archive, &target)
        .map_err(|error| InstallError::Extract(format!("复制裸二进制失败：{error}")))?;
    set_exec_mode(&target);
    Ok(vec![target])
}

fn ensure_all_wanted(
    paths: &[PathBuf],
    wanted: &[&str],
    out: &Path,
) -> Result<Vec<PathBuf>, InstallError> {
    let mut ordered = Vec::with_capacity(wanted.len());
    for want in wanted {
        let found = paths
            .iter()
            .find(|path| path.file_name().and_then(|name| name.to_str()) == Some(*want));
        let Some(path) = found else {
            return Err(InstallError::Extract(format!("归档缺少需要的文件：{want}")));
        };
        ordered.push(path.clone());
    }
    let _ = out;
    Ok(ordered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// 构造一个 tar.gz（测试夹具：字节在内存里拼装，不经 shell）。
    fn tar_gz(entries: Vec<(String, Vec<u8>)>) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, name, data.as_slice())
                .expect("append tar entry");
        }
        let tar_bytes = builder.into_inner().expect("finish tar");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&tar_bytes).expect("gzip");
        encoder.finish().expect("gzip finish")
    }

    /// 手工拼一个 POSIX ustar 头（tar 库自己拒绝 `..` 与绝对路径，恶意
    /// 归档的条目头只能逐字节构造）。
    fn ustar_header(name: &str, size: usize) -> [u8; 512] {
        let mut header = [0u8; 512];
        let name_bytes = &name.as_bytes()[..name.len().min(100)];
        header[0..name_bytes.len()].copy_from_slice(name_bytes);
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        let size_octal = format!("{size:011o}\u{0}");
        header[124..136].copy_from_slice(size_octal.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        let checksum_text = format!("{checksum:06o}\u{0} ");
        header[148..156].copy_from_slice(checksum_text.as_bytes());
        header
    }

    /// 构造一个带恶意条目名的 tar.gz。
    fn tar_gz_with_hostile_name(hostile_name: &str, data: &[u8]) -> Vec<u8> {
        let mut tar_data = Vec::new();
        tar_data.extend_from_slice(&ustar_header(hostile_name, data.len()));
        tar_data.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        tar_data.extend(std::iter::repeat_n(0u8, pad));
        // tar 结束标记：两个全零块。
        tar_data.extend_from_slice(&[0u8; 1024]);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&tar_data).expect("gzip");
        encoder.finish().expect("gzip finish")
    }

    /// 构造一个 zip。
    fn zip_bytes(entries: Vec<(String, Vec<u8>)>) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, data) in entries {
            writer
                .start_file(name, zip::write::SimpleFileOptions::default())
                .expect("start zip entry");
            writer.write_all(&data).expect("zip entry data");
        }
        writer.finish().expect("finish zip").into_inner()
    }

    fn write_archive(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("write archive");
        path
    }

    #[test]
    fn extract_rejects_traversal_and_links() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("out");
        let limits = Limits::default();
        // tar：路径穿越。
        let archive = write_archive(
            dir.path(),
            "evil.tar.gz",
            &tar_gz_with_hostile_name("../evil.txt", b"payload"),
        );
        let error = extract(&archive, ArchiveKind::TarGz, &["x"], &out, &limits)
            .expect_err("traversal entries are rejected");
        assert!(matches!(error, InstallError::Extract(_)));
        assert!(!dir.path().join("evil.txt").exists(), "穿越条目未落盘");
        assert!(
            !dir.path()
                .parent()
                .expect("parent")
                .join("evil.txt")
                .exists()
        );

        // tar：绝对路径。
        let archive = write_archive(
            dir.path(),
            "abs.tar.gz",
            &tar_gz_with_hostile_name("/etc/evil", b"payload"),
        );
        let error = extract(&archive, ArchiveKind::TarGz, &["x"], &out, &limits)
            .expect_err("absolute entries are rejected");
        assert!(matches!(error, InstallError::Extract(_)));

        // tar：符号链接条目。
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_link(&mut header, "evil-link", "/etc/passwd")
            .expect("append link");
        let archive = write_archive(
            dir.path(),
            "link.tar.gz",
            &builder.into_inner().expect("finish tar"),
        );
        let error = extract(&archive, ArchiveKind::TarGz, &["x"], &out, &limits)
            .expect_err("symlink entries are rejected");
        assert!(matches!(error, InstallError::Extract(_)));

        // zip：路径穿越。
        let archive = write_archive(
            dir.path(),
            "evil.zip",
            &zip_bytes(vec![("../evil.txt".to_owned(), b"payload".to_vec())]),
        );
        let error = extract(&archive, ArchiveKind::Zip, &["x"], &out, &limits)
            .expect_err("zip traversal entries are rejected");
        assert!(matches!(error, InstallError::Extract(_)));
        assert!(!dir.path().join("evil.txt").exists());
    }

    #[test]
    fn extract_rejects_zip_symlink_named_as_requested_binary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("out");
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .add_symlink(
                "bin/prog",
                "another-file",
                zip::write::SimpleFileOptions::default(),
            )
            .expect("write zip symlink");
        let bytes = writer.finish().expect("finish zip").into_inner();
        let archive = write_archive(dir.path(), "link.zip", &bytes);

        let error = extract(
            &archive,
            ArchiveKind::Zip,
            &["prog"],
            &out,
            &Limits::default(),
        )
        .expect_err("zip symlink is rejected");
        assert!(matches!(error, InstallError::Extract(message) if message.contains("链接条目")));
        assert!(!out.join("prog").exists());
    }

    #[test]
    fn extract_size_and_entry_limits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("out");
        let tiny = Limits {
            max_entries: 100,
            max_total_bytes: 8,
        };
        // 条目总大小超限（未选中的条目也计入）。
        let archive = write_archive(
            dir.path(),
            "big.tar.gz",
            &tar_gz(vec![
                ("prog".to_owned(), vec![b'8'; 8]),
                ("other".to_owned(), b"zzzz".to_vec()),
            ]),
        );
        let error = extract(&archive, ArchiveKind::TarGz, &["prog"], &out, &tiny)
            .expect_err("total size above limit fails");
        assert!(matches!(error, InstallError::Extract(_)));

        // 条目数超限。
        let entries: Vec<(String, Vec<u8>)> =
            (0..50).map(|i| (format!("f{i}"), vec![b'x'])).collect();
        let archive = write_archive(dir.path(), "many.tar.gz", &tar_gz(entries));
        let error = extract(
            &archive,
            ArchiveKind::TarGz,
            &["prog"],
            &out,
            &Limits {
                max_entries: 10,
                max_total_bytes: 1 << 20,
            },
        )
        .expect_err("entry count above limit fails");
        assert!(matches!(error, InstallError::Extract(_)));

        // zip 同样受限。
        let archive = write_archive(
            dir.path(),
            "big.zip",
            &zip_bytes(vec![
                ("prog".to_owned(), vec![b'8'; 8]),
                ("other".to_owned(), b"zzzz".to_vec()),
            ]),
        );
        let error = extract(&archive, ArchiveKind::Zip, &["prog"], &out, &tiny)
            .expect_err("zip total size above limit fails");
        assert!(matches!(error, InstallError::Extract(_)));
    }

    #[test]
    fn extract_picks_wanted_files_and_rejects_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("out");
        let archive = write_archive(
            dir.path(),
            "pkg.tar.gz",
            &tar_gz(vec![
                ("pkg-1.0.0/prog".to_owned(), b"#!bin".to_vec()),
                ("pkg-1.0.0/companion.txt".to_owned(), b"data".to_vec()),
                ("pkg-1.0.0/README".to_owned(), b"readme".to_vec()),
            ]),
        );
        let paths = extract(
            &archive,
            ArchiveKind::TarGz,
            &["prog", "companion.txt"],
            &out,
            &Limits::default(),
        )
        .expect("wanted files extracted");
        assert_eq!(
            paths,
            vec![out.join("prog"), out.join("companion.txt")],
            "按文件名平铺取出"
        );
        assert_eq!(std::fs::read(out.join("prog")).expect("prog"), b"#!bin");
        assert!(!out.join("README").exists(), "未列出的文件不落盘");

        // 缺少需要的文件时报错。
        let error = extract(
            &archive,
            ArchiveKind::TarGz,
            &["prog", "missing.dll"],
            &dir.path().join("out2"),
            &Limits::default(),
        )
        .expect_err("missing wanted file fails");
        assert!(matches!(error, InstallError::Extract(_)));
    }
}
