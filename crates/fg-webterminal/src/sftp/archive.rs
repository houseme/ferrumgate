//! Pure-Rust archive compression, decompression, and preview (WP-61 §3.3):
//! Supports `.zip` and `.tar.gz` / `.tgz` without relying on remote shell tools.
//!
//! Security guarantees:
//! - Entries containing `..`, absolute roots, or backslashes traversing parents
//!   reject the entire archive extraction (zip-slip / tar-slip protection).
//! - Symbolic links and hard links are skipped during extraction.
//! - File permissions preserve only `rwx` bits (`mode & 0o777`), stripping
//!   setuid/setgid/sticky bits.
//! - Total extracted entry count and total uncompressed byte size are capped.
//! - Preview lists at most [`limits::ARCHIVE_PREVIEW_MAX_ENTRIES`] (10,000) entries.

use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::model::limits;

/// Default maximum total uncompressed bytes allowed during archive extraction (512 MiB).
pub const DEFAULT_MAX_EXTRACT_BYTES: u64 = 512 * 1024 * 1024;
/// Default maximum number of entries allowed during archive extraction.
pub const DEFAULT_MAX_EXTRACT_ENTRIES: usize = 50_000;

/// Supported archive formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveFormat {
    Zip,
    #[serde(alias = "tar.gz", alias = "tgz")]
    TarGz,
}

impl ArchiveFormat {
    /// Detects the archive format from a filename extension.
    pub fn from_path(path: &str) -> Option<Self> {
        let lower = path.to_ascii_lowercase();
        if lower.ends_with(".zip") {
            Some(Self::Zip)
        } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
            Some(Self::TarGz)
        } else {
            None
        }
    }
}

/// Errors produced during archive validation, preview, compression, or extraction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArchiveError {
    UnsupportedFormat(String),
    PathTraversal(String),
    LimitExceeded(String),
    Corrupt(String),
}

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedFormat(s) => write!(f, "不支持的归档格式：{s}"),
            Self::PathTraversal(p) => write!(f, "归档包含非法路径（禁止目录穿越）：{p}"),
            Self::LimitExceeded(msg) => write!(f, "归档超出安全限制：{msg}"),
            Self::Corrupt(msg) => write!(f, "归档解析失败：{msg}"),
        }
    }
}

impl std::error::Error for ArchiveError {}

/// Limits applied during extraction.
#[derive(Clone, Copy, Debug)]
pub struct ExtractLimits {
    pub max_bytes: u64,
    pub max_entries: usize,
}

impl Default for ExtractLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_EXTRACT_BYTES,
            max_entries: DEFAULT_MAX_EXTRACT_ENTRIES,
        }
    }
}

/// One entry in an archive preview.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchivePreviewEntry {
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub mode: u32,
}

/// Result of previewing an archive (capped at 10,000 entries).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchivePreview {
    pub format: ArchiveFormat,
    pub entries: Vec<ArchivePreviewEntry>,
    pub truncated: bool,
    pub total: usize,
}

/// A validated, safe extracted entry ready to be written to local or remote storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractedEntry {
    /// Safe relative path with forward slashes (no leading `/`, no `..`).
    pub rel_path: String,
    pub is_dir: bool,
    /// Only `rwx` permission bits (`0..=0o777`).
    pub mode: u32,
    pub data: Vec<u8>,
}

/// Input item for archive compression.
#[derive(Clone, Debug)]
pub struct CompressInput {
    /// Relative path inside the archive.
    pub rel_path: String,
    pub is_dir: bool,
    pub mode: u32,
    pub data: Vec<u8>,
}

/// Sanitizes an archive entry's mode to keep ONLY the `rwx` bits (`0o777`),
/// stripping setuid (`0o4000`), setgid (`0o2000`), sticky (`0o1000`), and
/// file-type upper bits.
pub fn sanitize_rwx_mode(raw_mode: u32, is_dir: bool) -> u32 {
    let rwx = raw_mode & 0o777;
    if rwx == 0 {
        if is_dir { 0o755 } else { 0o644 }
    } else {
        rwx
    }
}

/// Validates and normalizes an archive member path.
/// Rejects any entry containing `..`, absolute roots, Windows drive prefixes,
/// or NUL bytes.
pub fn validate_entry_path(raw: &str) -> Result<String, ArchiveError> {
    if raw.contains('\0') {
        return Err(ArchiveError::PathTraversal(raw.to_owned()));
    }
    // Reject Windows-style backslash traversal as well.
    let unified = raw.replace('\\', "/");
    if unified.starts_with('/') {
        return Err(ArchiveError::PathTraversal(raw.to_owned()));
    }
    let mut parts: Vec<String> = Vec::new();
    for comp in Path::new(&unified).components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_string_lossy();
                if s.is_empty() {
                    continue;
                }
                parts.push(s.into_owned());
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ArchiveError::PathTraversal(raw.to_owned()));
            }
        }
    }
    if parts.is_empty() {
        return Err(ArchiveError::PathTraversal(raw.to_owned()));
    }
    Ok(parts.join("/"))
}

/// Previews the contents of a `.zip` or `.tar.gz` archive (at most 10,000 entries).
pub fn preview_archive(
    format: ArchiveFormat,
    bytes: &[u8],
) -> Result<ArchivePreview, ArchiveError> {
    match format {
        ArchiveFormat::Zip => preview_zip(bytes),
        ArchiveFormat::TarGz => preview_targz(bytes),
    }
}

fn preview_zip(bytes: &[u8]) -> Result<ArchivePreview, ArchiveError> {
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
    let total = archive.len();
    let cap = limits::ARCHIVE_PREVIEW_MAX_ENTRIES;
    let take = total.min(cap);
    let mut entries = Vec::with_capacity(take);
    for i in 0..take {
        let file = archive
            .by_index(i)
            .map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
        let unix_mode = file.unix_mode().unwrap_or(0);
        let is_symlink = file.is_symlink() || is_zip_symlink(unix_mode);
        let is_dir = file.is_dir();
        entries.push(ArchivePreviewEntry {
            path: file.name().to_owned(),
            is_dir,
            is_symlink,
            size: file.size(),
            mode: sanitize_rwx_mode(unix_mode, is_dir),
        });
    }
    Ok(ArchivePreview {
        format: ArchiveFormat::Zip,
        entries,
        truncated: total > cap,
        total,
    })
}

fn preview_targz(bytes: &[u8]) -> Result<ArchivePreview, ArchiveError> {
    let gz = GzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(gz);
    let cap = limits::ARCHIVE_PREVIEW_MAX_ENTRIES;
    let mut entries = Vec::new();
    let mut total = 0usize;
    let mut truncated = false;

    for entry_res in archive
        .entries()
        .map_err(|e| ArchiveError::Corrupt(e.to_string()))?
    {
        let entry = entry_res.map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
        total += 1;
        if entries.len() < cap {
            let path = entry
                .path()
                .map_err(|e| ArchiveError::Corrupt(e.to_string()))?
                .to_string_lossy()
                .into_owned();
            let entry_type = entry.header().entry_type();
            let is_dir = entry_type.is_dir();
            let is_symlink = entry_type.is_symlink() || entry_type.is_hard_link();
            let raw_mode = entry.header().mode().unwrap_or(0);
            let size = entry.header().size().unwrap_or(0);
            entries.push(ArchivePreviewEntry {
                path,
                is_dir,
                is_symlink,
                size,
                mode: sanitize_rwx_mode(raw_mode, is_dir),
            });
        } else {
            truncated = true;
        }
    }

    Ok(ArchivePreview {
        format: ArchiveFormat::TarGz,
        entries,
        truncated,
        total,
    })
}

/// Extracts and validates every safe entry from a `.zip` or `.tar.gz` archive.
///
/// - Any entry with `..` or an absolute path causes the whole extraction to fail
///   with [`ArchiveError::PathTraversal`].
/// - Symlinks and hardlinks are skipped.
/// - Permissions keep only `rwx` bits (`0o777`).
/// - Entry count and cumulative uncompressed byte size are checked against `limits`.
pub fn extract_archive(
    format: ArchiveFormat,
    bytes: &[u8],
    extract_limits: ExtractLimits,
) -> Result<Vec<ExtractedEntry>, ArchiveError> {
    match format {
        ArchiveFormat::Zip => extract_zip(bytes, extract_limits),
        ArchiveFormat::TarGz => extract_targz(bytes, extract_limits),
    }
}

fn is_zip_symlink(unix_mode: u32) -> bool {
    (unix_mode & 0o170000) == 0o120000
}

fn extract_zip(
    bytes: &[u8],
    extract_limits: ExtractLimits,
) -> Result<Vec<ExtractedEntry>, ArchiveError> {
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).map_err(|e| ArchiveError::Corrupt(e.to_string()))?;

    let mut out = Vec::new();
    let mut total_bytes: u64 = 0;

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
        let raw_name = file.name().to_owned();
        // Always validate path BEFORE skipping anything so traversal entries
        // are rejected unconditionally.
        if raw_name == "." || raw_name == "./" {
            continue;
        }
        let rel_path = validate_entry_path(&raw_name)?;

        let unix_mode = file.unix_mode().unwrap_or(0);
        if file.is_symlink() || is_zip_symlink(unix_mode) {
            continue;
        }

        if out.len() >= extract_limits.max_entries {
            return Err(ArchiveError::LimitExceeded(format!(
                "条目数超过上限 {}",
                extract_limits.max_entries
            )));
        }

        let is_dir = file.is_dir();
        let mode = sanitize_rwx_mode(unix_mode, is_dir);

        if is_dir {
            out.push(ExtractedEntry {
                rel_path,
                is_dir: true,
                mode,
                data: Vec::new(),
            });
            continue;
        }

        let remaining = extract_limits.max_bytes.saturating_sub(total_bytes);
        let mut data = Vec::new();
        let mut limited = file.by_ref().take(remaining.saturating_add(1));
        limited
            .read_to_end(&mut data)
            .map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
        if data.len() as u64 > remaining {
            return Err(ArchiveError::LimitExceeded(format!(
                "解压总大小超过上限 {} 字节",
                extract_limits.max_bytes
            )));
        }
        total_bytes = total_bytes.saturating_add(data.len() as u64);

        out.push(ExtractedEntry {
            rel_path,
            is_dir: false,
            mode,
            data,
        });
    }

    Ok(out)
}

fn extract_targz(
    bytes: &[u8],
    extract_limits: ExtractLimits,
) -> Result<Vec<ExtractedEntry>, ArchiveError> {
    let gz = GzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(gz);

    let mut out = Vec::new();
    let mut total_bytes: u64 = 0;

    for entry_res in archive
        .entries()
        .map_err(|e| ArchiveError::Corrupt(e.to_string()))?
    {
        let mut entry = entry_res.map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
        let raw_name = entry
            .path()
            .map_err(|e| ArchiveError::Corrupt(e.to_string()))?
            .to_string_lossy()
            .into_owned();
        if raw_name == "." || raw_name == "./" {
            continue;
        }
        let rel_path = validate_entry_path(&raw_name)?;

        let entry_type = entry.header().entry_type();
        // Skip symlinks and hardlinks (WP-61 §3.3).
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            continue;
        }
        // Also skip device/fifo/pax special entries cleanly.
        if !entry_type.is_file() && !entry_type.is_dir() {
            continue;
        }

        if out.len() >= extract_limits.max_entries {
            return Err(ArchiveError::LimitExceeded(format!(
                "条目数超过上限 {}",
                extract_limits.max_entries
            )));
        }

        let is_dir = entry_type.is_dir();
        let raw_mode = entry.header().mode().unwrap_or(0);
        let mode = sanitize_rwx_mode(raw_mode, is_dir);

        if is_dir {
            out.push(ExtractedEntry {
                rel_path,
                is_dir: true,
                mode,
                data: Vec::new(),
            });
            continue;
        }

        let remaining = extract_limits.max_bytes.saturating_sub(total_bytes);
        let mut data = Vec::new();
        let mut limited = entry.by_ref().take(remaining.saturating_add(1));
        limited
            .read_to_end(&mut data)
            .map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
        if data.len() as u64 > remaining {
            return Err(ArchiveError::LimitExceeded(format!(
                "解压总大小超过上限 {} 字节",
                extract_limits.max_bytes
            )));
        }
        total_bytes = total_bytes.saturating_add(data.len() as u64);

        out.push(ExtractedEntry {
            rel_path,
            is_dir: false,
            mode,
            data,
        });
    }

    Ok(out)
}

/// Compresses items into a `.zip` or `.tar.gz` byte buffer.
pub fn compress_entries(
    format: ArchiveFormat,
    items: &[CompressInput],
) -> Result<Vec<u8>, ArchiveError> {
    match format {
        ArchiveFormat::Zip => compress_zip(items),
        ArchiveFormat::TarGz => compress_targz(items),
    }
}

fn compress_zip(items: &[CompressInput]) -> Result<Vec<u8>, ArchiveError> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cursor);
        for item in items {
            let rel = validate_entry_path(&item.rel_path)?;
            let mode = sanitize_rwx_mode(item.mode, item.is_dir);
            let opts = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .unix_permissions(mode);
            if item.is_dir {
                let dir_name = format!("{rel}/");
                writer
                    .add_directory(dir_name, opts)
                    .map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
            } else {
                writer
                    .start_file(rel, opts)
                    .map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
                writer
                    .write_all(&item.data)
                    .map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
            }
        }
        writer
            .finish()
            .map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
    }
    Ok(cursor.into_inner())
}

fn compress_targz(items: &[CompressInput]) -> Result<Vec<u8>, ArchiveError> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for item in items {
        let rel = validate_entry_path(&item.rel_path)?;
        let mode = sanitize_rwx_mode(item.mode, item.is_dir);
        let mut header = tar::Header::new_gnu();
        header.set_mode(mode);
        if item.is_dir {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, PathBuf::from(&rel), std::io::empty())
                .map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
        } else {
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(item.data.len() as u64);
            header.set_cksum();
            builder
                .append_data(&mut header, PathBuf::from(&rel), Cursor::new(&item.data))
                .map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
        }
    }
    let encoder = builder
        .into_inner()
        .map_err(|e| ArchiveError::Corrupt(e.to_string()))?;
    encoder
        .finish()
        .map_err(|e| ArchiveError::Corrupt(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_zip_with_raw_entry(name: &str, mode: u32, data: &[u8]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let opts = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored)
                .unix_permissions(mode);
            writer.start_file(name, opts).unwrap();
            writer.write_all(data).unwrap();
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    #[test]
    fn archive_rejects_parent_dir_entries() {
        let evil_zip = make_zip_with_raw_entry("../etc/passwd", 0o644, b"root:x:0:0");
        let err = extract_archive(ArchiveFormat::Zip, &evil_zip, ExtractLimits::default())
            .expect_err("zip-slip must fail");
        assert!(matches!(err, ArchiveError::PathTraversal(_)));

        let evil_nested = make_zip_with_raw_entry("a/b/../../evil.txt", 0o644, b"x");
        assert!(matches!(
            extract_archive(ArchiveFormat::Zip, &evil_nested, ExtractLimits::default()),
            Err(ArchiveError::PathTraversal(_))
        ));

        // Tar.gz with .. path (construct raw header bypassing builder check)
        let mut tar_buf = Vec::new();
        {
            let mut header = tar::Header::new_gnu();
            header.set_size(3);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            // Write raw path bytes directly into header name field
            let raw_bytes = header.as_mut_bytes();
            let bad = b"../evil.txt";
            raw_bytes[..bad.len()].copy_from_slice(bad);
            header.set_cksum();
            tar_buf.extend_from_slice(header.as_bytes());
            let mut block = [0u8; 512];
            block[..3].copy_from_slice(b"abc");
            tar_buf.extend_from_slice(&block);
            tar_buf.extend_from_slice(&[0u8; 1024]);
        }
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&tar_buf).unwrap();
        let evil_tgz = enc.finish().unwrap();
        assert!(matches!(
            extract_archive(ArchiveFormat::TarGz, &evil_tgz, ExtractLimits::default()),
            Err(ArchiveError::PathTraversal(_))
        ));
    }

    #[test]
    fn archive_skips_symlink_and_hardlink() {
        // 1. Zip symlink + regular file
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let sym_opts = SimpleFileOptions::default().unix_permissions(0o777);
            writer
                .add_symlink("link_to_etc", "/etc/passwd", sym_opts)
                .unwrap();
            let reg_opts = SimpleFileOptions::default().unix_permissions(0o644);
            writer.start_file("safe.txt", reg_opts).unwrap();
            writer.write_all(b"hello").unwrap();
            writer.finish().unwrap();
        }
        let extracted = extract_archive(
            ArchiveFormat::Zip,
            &cursor.into_inner(),
            ExtractLimits::default(),
        )
        .expect("extract zip");
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].rel_path, "safe.txt");

        // 2. Tar.gz symlink + hardlink + regular file
        let enc = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(enc);
        let mut sym = tar::Header::new_gnu();
        sym.set_entry_type(tar::EntryType::Symlink);
        sym.set_size(0);
        sym.set_mode(0o777);
        builder.append_link(&mut sym, "sym", "/etc/passwd").unwrap();

        let mut hard = tar::Header::new_gnu();
        hard.set_entry_type(tar::EntryType::Link);
        hard.set_size(0);
        hard.set_mode(0o644);
        builder.append_link(&mut hard, "hard", "ok.txt").unwrap();

        let mut reg = tar::Header::new_gnu();
        reg.set_entry_type(tar::EntryType::Regular);
        reg.set_size(2);
        reg.set_mode(0o640);
        reg.set_cksum();
        builder
            .append_data(&mut reg, "ok.txt", Cursor::new(b"ok"))
            .unwrap();
        let tgz = builder.into_inner().unwrap().finish().unwrap();

        let extracted =
            extract_archive(ArchiveFormat::TarGz, &tgz, ExtractLimits::default()).expect("extract");
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].rel_path, "ok.txt");
    }

    #[test]
    fn archive_keeps_only_rwx_bits() {
        // Setuid (0o4000) + setgid (0o2000) + sticky (0o1000) + rwxr-xr-x (0o755)
        let zip_bytes = make_zip_with_raw_entry("tool.sh", 0o107755, b"#!/bin/sh");
        let extracted =
            extract_archive(ArchiveFormat::Zip, &zip_bytes, ExtractLimits::default()).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].mode, 0o755);
        assert_eq!(extracted[0].mode & !0o777, 0);

        // Same for tar.gz
        let enc = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(enc);
        let mut hdr = tar::Header::new_gnu();
        hdr.set_entry_type(tar::EntryType::Regular);
        hdr.set_mode(0o6750);
        hdr.set_size(1);
        hdr.set_cksum();
        builder
            .append_data(&mut hdr, "suid.bin", Cursor::new(b"x"))
            .unwrap();
        let tgz = builder.into_inner().unwrap().finish().unwrap();
        let extracted =
            extract_archive(ArchiveFormat::TarGz, &tgz, ExtractLimits::default()).unwrap();
        assert_eq!(extracted[0].mode, 0o750);
    }

    #[test]
    fn archive_preview_cap_10000() {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            for i in 0..10_005 {
                writer.start_file(format!("f{i}.txt"), opts).unwrap();
            }
            writer.finish().unwrap();
        }
        let preview = preview_archive(ArchiveFormat::Zip, &cursor.into_inner()).unwrap();
        assert_eq!(preview.entries.len(), limits::ARCHIVE_PREVIEW_MAX_ENTRIES);
        assert_eq!(preview.total, 10_005);
        assert!(preview.truncated);
    }

    #[test]
    fn archive_roundtrip_zip_and_targz() {
        let inputs = vec![
            CompressInput {
                rel_path: "dir".into(),
                is_dir: true,
                mode: 0o755,
                data: Vec::new(),
            },
            CompressInput {
                rel_path: "dir/hello.txt".into(),
                is_dir: false,
                mode: 0o644,
                data: b"hello world".to_vec(),
            },
        ];
        for fmt in [ArchiveFormat::Zip, ArchiveFormat::TarGz] {
            let bytes = compress_entries(fmt, &inputs).unwrap();
            let extracted = extract_archive(fmt, &bytes, ExtractLimits::default()).unwrap();
            assert_eq!(extracted.len(), 2);
            assert!(extracted[0].is_dir);
            assert_eq!(extracted[1].rel_path, "dir/hello.txt");
            assert_eq!(extracted[1].data, b"hello world");
            assert_eq!(extracted[1].mode, 0o644);
        }
    }
}
