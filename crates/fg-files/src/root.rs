//! Confined directory access built on `cap_std::fs::Dir` and `fg_core::fsperm`
//! (WP-63).
//!
//! Enforces three non-negotiable security invariants:
//! 1. Protected configuration directories (and anything inside them) can never
//!    be opened as a share root.
//! 2. When a parent directory containing a protected configuration directory is
//!    shared, the protected directory is hidden from listings and inaccessible.
//! 3. Symlinks pointing outside the share root (or into a protected directory)
//!    are never followed for read, write, list, mkdir, remove, rename, copy, or
//!    move; symlinks pointing inside the share root continue to work.

use std::{
    fmt, io,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use cap_std::{
    ambient_authority,
    fs::{Dir, File, Metadata, OpenOptions},
};
use fg_core::fsperm;

const MAX_SYMLINK_HOPS: usize = 40;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirError {
    NotFound,
    Forbidden,
    NotADirectory,
    AlreadyExists,
    TooManySymlinks,
    Protected,
    CrossMount,
    ReadOnly,
    InvalidPath,
    Io(String),
}

impl fmt::Display for DirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "path not found"),
            Self::Forbidden => write!(f, "access outside root is forbidden"),
            Self::NotADirectory => write!(f, "not a directory"),
            Self::AlreadyExists => write!(f, "target already exists"),
            Self::TooManySymlinks => write!(f, "too many levels of symbolic links"),
            Self::Protected => write!(f, "path is inside a protected configuration directory"),
            Self::CrossMount => write!(f, "operation across different mounts is not allowed"),
            Self::ReadOnly => write!(f, "target is read-only"),
            Self::InvalidPath => write!(f, "invalid relative path"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl std::error::Error for DirError {}

impl From<io::Error> for DirError {
    fn from(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::NotFound => Self::NotFound,
            io::ErrorKind::AlreadyExists => Self::AlreadyExists,
            io::ErrorKind::PermissionDenied => Self::Forbidden,
            io::ErrorKind::NotADirectory => Self::NotADirectory,
            _ => Self::Io(err.to_string()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExposableError {
    NotAbsolute,
    Protected(PathBuf),
}

impl fmt::Display for ExposableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsolute => write!(f, "directory path must be absolute"),
            Self::Protected(_) => {
                write!(
                    f,
                    "directory cannot be or lie inside a protected configuration directory"
                )
            }
        }
    }
}

impl std::error::Error for ExposableError {}

/// Checks whether `path` is allowed to be configured as a user share root.
///
/// Rejects non-absolute paths and any path equal to or inside a protected
/// configuration directory (`fg_core::fsperm::check_exposable`). A parent
/// directory that *contains* a protected directory is allowed; the protected
/// subtree is hidden at access time.
pub fn is_exposable(path: &Path) -> Result<(), ExposableError> {
    if !path.is_absolute() {
        return Err(ExposableError::NotAbsolute);
    }
    if let Some(protected) = fsperm::inside(path) {
        return Err(ExposableError::Protected(protected));
    }
    fsperm::check_exposable(path).map_err(|_| ExposableError::Protected(path.to_path_buf()))
}

/// Opens `path` as a `cap_std::fs::Dir` after verifying it is exposable and
/// canonicalizing it (re-checking against protected directories after symlink
/// resolution).
pub fn open_root(path: &Path) -> Result<Dir, DirError> {
    let (dir, _) = open_root_with_canonical(path)?;
    Ok(dir)
}

fn open_root_with_canonical(path: &Path) -> Result<(Dir, PathBuf), DirError> {
    if !path.is_absolute() {
        return Err(DirError::InvalidPath);
    }
    if is_exposable(path).is_err() {
        return Err(DirError::Protected);
    }
    let meta = std::fs::metadata(path).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => DirError::NotFound,
        io::ErrorKind::PermissionDenied => DirError::Forbidden,
        _ => DirError::Io(e.to_string()),
    })?;
    if !meta.is_dir() {
        return Err(DirError::NotADirectory);
    }
    let canonical = std::fs::canonicalize(path).map_err(DirError::from)?;
    if is_exposable(&canonical).is_err() {
        return Err(DirError::Protected);
    }
    let dir = Dir::open_ambient_dir(&canonical, ambient_authority()).map_err(DirError::from)?;
    Ok((dir, canonical))
}

/// Resolves `rel` segment-by-segment inside `root`, refusing any symlink that
/// points outside `root` (or exceeds `MAX_SYMLINK_HOPS`).
///
/// Returns a clean relative `PathBuf` (empty for root itself) with all
/// intermediate symlinks expanded inside `root`.
pub fn resolve(root: &Dir, rel: &str) -> Result<PathBuf, DirError> {
    resolve_inner(root, None, rel, true)
}

/// Entry metadata returned by [`ConfinedRoot::list_dir`] and [`MultiRoot::list_dir`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryInfo {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<SystemTime>,
}

/// A confined share root backed by a `cap_std::fs::Dir` handle and its
/// canonical host path (used solely for protected-directory hiding and
/// normalizing intra-root absolute symlinks).
#[derive(Clone)]
pub struct ConfinedRoot {
    dir: Arc<Dir>,
    canonical_root: PathBuf,
}

impl fmt::Debug for ConfinedRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfinedRoot")
            .field("canonical_root", &self.canonical_root)
            .finish()
    }
}

impl ConfinedRoot {
    /// Opens a confined share root, refusing protected configuration directories.
    pub fn open(path: &Path) -> Result<Self, DirError> {
        let (dir, canonical_root) = open_root_with_canonical(path)?;
        Ok(Self {
            dir: Arc::new(dir),
            canonical_root,
        })
    }

    pub fn dir(&self) -> &Dir {
        &self.dir
    }

    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

    /// Returns `true` if `rel` (a clean relative path under this root) refers
    /// to or lies inside a protected configuration directory.
    pub fn is_hidden_rel(&self, rel: &Path) -> bool {
        if rel.as_os_str().is_empty() {
            return fsperm::inside(&self.canonical_root).is_some();
        }
        let candidate = self.canonical_root.join(rel);
        fsperm::inside(&candidate).is_some()
    }

    /// Resolves an existing path inside the root, following intra-root symlinks
    /// and rejecting escaping symlinks or protected directories.
    pub fn resolve_existing(&self, rel: &str) -> Result<PathBuf, DirError> {
        let resolved = resolve_inner(&self.dir, Some(&self.canonical_root), rel, true)?;
        if self.is_hidden_rel(&resolved) {
            return Err(DirError::NotFound);
        }
        Ok(resolved)
    }

    /// Resolves a target path that may not yet exist (e.g. for `PUT`, `MKCOL`,
    /// `COPY`/`MOVE` destination).
    ///
    /// All existing parent segments must resolve inside the root (following
    /// intra-root symlinks, rejecting escapes). If the final leaf already
    /// exists and is a symlink, it is also checked: escaping symlinks are
    /// rejected with `DirError::Forbidden`, and protected paths with
    /// `DirError::Protected`.
    pub fn resolve_target(&self, rel: &str) -> Result<PathBuf, DirError> {
        let segments = parse_rel_segments(rel)?;
        if segments.is_empty() {
            return Ok(PathBuf::new());
        }
        let parent_rel = segments[..segments.len() - 1].join("/");
        let leaf = &segments[segments.len() - 1];
        let parent_resolved = if parent_rel.is_empty() {
            PathBuf::new()
        } else {
            let p = resolve_inner(&self.dir, Some(&self.canonical_root), &parent_rel, true)?;
            if self.is_hidden_rel(&p) {
                return Err(DirError::Protected);
            }
            p
        };
        let candidate = if parent_resolved.as_os_str().is_empty() {
            PathBuf::from(leaf)
        } else {
            parent_resolved.join(leaf)
        };
        if self.is_hidden_rel(&candidate) {
            return Err(DirError::Protected);
        }
        // If leaf exists and is a symlink, resolve it to ensure it cannot escape
        // or point into a protected directory.
        if let Ok(meta) = self.dir.symlink_metadata(&candidate)
            && meta.file_type().is_symlink()
        {
            let full_str = candidate.to_string_lossy();
            let resolved = resolve_inner(&self.dir, Some(&self.canonical_root), &full_str, false)?;
            if self.is_hidden_rel(&resolved) {
                return Err(DirError::Protected);
            }
            return Ok(resolved);
        }
        Ok(candidate)
    }

    /// Returns metadata for an existing entry inside the root.
    pub fn stat(&self, rel: &str) -> Result<EntryInfo, DirError> {
        let resolved = self.resolve_existing(rel)?;
        let meta = if resolved.as_os_str().is_empty() {
            self.dir.dir_metadata().map_err(DirError::from)?
        } else {
            self.dir.metadata(&resolved).map_err(DirError::from)?
        };
        let name = resolved
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(entry_from_meta(name, &meta))
    }

    /// Opens an existing regular file for reading.
    pub fn open_read(&self, rel: &str) -> Result<(File, Metadata), DirError> {
        let resolved = self.resolve_existing(rel)?;
        if resolved.as_os_str().is_empty() {
            return Err(DirError::Forbidden);
        }
        let mut opts = OpenOptions::new();
        opts.read(true);
        let file = self
            .dir
            .open_with(&resolved, &opts)
            .map_err(DirError::from)?;
        let meta = file.metadata().map_err(DirError::from)?;
        if meta.is_dir() {
            return Err(DirError::Forbidden);
        }
        Ok((file, meta))
    }

    /// Opens or creates a file for writing (truncating any existing file).
    /// Returns `(file, existed_before)`.
    pub fn open_write(&self, rel: &str) -> Result<(File, bool), DirError> {
        let resolved = self.resolve_target(rel)?;
        if resolved.as_os_str().is_empty() {
            return Err(DirError::Forbidden);
        }
        let existed = self.dir.try_exists(&resolved).unwrap_or(false);
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        let file = self
            .dir
            .open_with(&resolved, &opts)
            .map_err(DirError::from)?;
        Ok((file, existed))
    }

    /// Creates a new directory at `rel`.
    pub fn create_dir(&self, rel: &str) -> Result<(), DirError> {
        let resolved = self.resolve_target(rel)?;
        if resolved.as_os_str().is_empty() {
            return Err(DirError::AlreadyExists);
        }
        self.dir.create_dir(&resolved).map_err(DirError::from)
    }

    /// Lists entries of a directory at `rel`, omitting any protected
    /// configuration directory and any symlink pointing outside the root.
    pub fn list_dir(&self, rel: &str) -> Result<Vec<EntryInfo>, DirError> {
        let resolved = self.resolve_existing(rel)?;
        let iter = if resolved.as_os_str().is_empty() {
            self.dir.entries().map_err(DirError::from)?
        } else {
            let meta = self.dir.metadata(&resolved).map_err(DirError::from)?;
            if !meta.is_dir() {
                return Err(DirError::NotADirectory);
            }
            self.dir.read_dir(&resolved).map_err(DirError::from)?
        };
        let mut out = Vec::new();
        for item in iter {
            let Ok(entry) = item else {
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let child_rel = if resolved.as_os_str().is_empty() {
                PathBuf::from(&name)
            } else {
                resolved.join(&name)
            };
            if self.is_hidden_rel(&child_rel) {
                continue;
            }
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                // Only expose symlinks that resolve inside the root and outside protected dirs.
                let child_str = child_rel.to_string_lossy();
                let Ok(target_rel) =
                    resolve_inner(&self.dir, Some(&self.canonical_root), &child_str, true)
                else {
                    continue;
                };
                if self.is_hidden_rel(&target_rel) {
                    continue;
                }
                let Ok(meta) = (if target_rel.as_os_str().is_empty() {
                    self.dir.dir_metadata()
                } else {
                    self.dir.metadata(&target_rel)
                }) else {
                    continue;
                };
                out.push(entry_from_meta(name, &meta));
            } else if let Ok(meta) = entry.metadata() {
                out.push(entry_from_meta(name, &meta));
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Removes a file or directory (recursively) inside the root.
    /// Refuses escaping symlinks and protected directories.
    pub fn remove_entry(&self, rel: &str) -> Result<(), DirError> {
        let segments = parse_rel_segments(rel)?;
        if segments.is_empty() {
            return Err(DirError::Forbidden);
        }
        // Resolve the entry; escaping symlinks fail with Forbidden before removal.
        let resolved = self.resolve_existing(rel)?;
        if resolved.as_os_str().is_empty() {
            return Err(DirError::Forbidden);
        }
        // Also check parent + leaf directly in case `rel` itself was an intra-root symlink.
        let parent_rel = segments[..segments.len() - 1].join("/");
        let leaf = &segments[segments.len() - 1];
        let direct = if parent_rel.is_empty() {
            PathBuf::from(leaf)
        } else {
            self.resolve_existing(&parent_rel)?.join(leaf)
        };
        if self.is_hidden_rel(&direct) {
            return Err(DirError::NotFound);
        }
        let lmeta = self.dir.symlink_metadata(&direct).map_err(DirError::from)?;
        if lmeta.file_type().is_symlink() || lmeta.is_file() {
            self.dir.remove_file(&direct).map_err(DirError::from)
        } else if lmeta.is_dir() {
            self.remove_dir_safe(&direct)
        } else {
            Err(DirError::Forbidden)
        }
    }

    fn remove_dir_safe(&self, dir_rel: &Path) -> Result<(), DirError> {
        let entries = self.dir.read_dir(dir_rel).map_err(DirError::from)?;
        for entry in entries {
            let entry = entry.map_err(DirError::from)?;
            let child = dir_rel.join(entry.file_name());
            if self.is_hidden_rel(&child) {
                return Err(DirError::Protected);
            }
            let ft = entry.file_type().map_err(DirError::from)?;
            if ft.is_dir() {
                self.remove_dir_safe(&child)?;
            } else {
                self.dir.remove_file(&child).map_err(DirError::from)?;
            }
        }
        self.dir.remove_dir(dir_rel).map_err(DirError::from)
    }

    /// Renames/moves an entry within the same root.
    /// Rejects symlinks pointing outside the root and protected directories.
    pub fn rename(&self, src_rel: &str, dst_rel: &str, overwrite: bool) -> Result<bool, DirError> {
        let src_segments = parse_rel_segments(src_rel)?;
        let dst_segments = parse_rel_segments(dst_rel)?;
        if src_segments.is_empty() || dst_segments.is_empty() {
            return Err(DirError::Forbidden);
        }
        // Validate source does not escape root (even if source itself is a symlink).
        let _ = self.resolve_existing(src_rel)?;
        let src_parent = src_segments[..src_segments.len() - 1].join("/");
        let src_leaf = &src_segments[src_segments.len() - 1];
        let src_direct = if src_parent.is_empty() {
            PathBuf::from(src_leaf)
        } else {
            self.resolve_existing(&src_parent)?.join(src_leaf)
        };
        if self.is_hidden_rel(&src_direct) {
            return Err(DirError::NotFound);
        }

        let dst = self.resolve_target(dst_rel)?;
        if dst.as_os_str().is_empty() {
            return Err(DirError::Forbidden);
        }
        if let Some(parent) = dst.parent()
            && !parent.as_os_str().is_empty()
            && !self.dir.try_exists(parent).unwrap_or(false)
        {
            return Err(DirError::NotFound);
        }

        let existed = self.dir.try_exists(&dst).unwrap_or(false);
        if existed {
            if !overwrite {
                return Err(DirError::AlreadyExists);
            }
            // Remove existing destination safely if it's a directory or different type.
            let dst_str = dst.to_string_lossy();
            self.remove_entry(&dst_str)?;
        }

        self.dir
            .rename(&src_direct, &self.dir, &dst)
            .map_err(DirError::from)?;
        Ok(existed)
    }

    /// Copies a file or directory recursively from `self` at `src_rel` to
    /// `dst_root` at `dst_rel`.
    pub fn copy_to(
        &self,
        src_rel: &str,
        dst_root: &ConfinedRoot,
        dst_rel: &str,
        overwrite: bool,
        recursive: bool,
    ) -> Result<bool, DirError> {
        let src = self.resolve_existing(src_rel)?;
        let dst = dst_root.resolve_target(dst_rel)?;
        if dst.as_os_str().is_empty() {
            return Err(DirError::Forbidden);
        }
        if let Some(parent) = dst.parent()
            && !parent.as_os_str().is_empty()
            && !dst_root.dir.try_exists(parent).unwrap_or(false)
        {
            return Err(DirError::NotFound);
        }

        let existed = dst_root.dir.try_exists(&dst).unwrap_or(false);
        if existed {
            if !overwrite {
                return Err(DirError::AlreadyExists);
            }
            let dst_str = dst.to_string_lossy();
            dst_root.remove_entry(&dst_str)?;
        }

        let src_meta = if src.as_os_str().is_empty() {
            self.dir.dir_metadata().map_err(DirError::from)?
        } else {
            self.dir.metadata(&src).map_err(DirError::from)?
        };
        if src_meta.is_dir() {
            dst_root.dir.create_dir(&dst).map_err(DirError::from)?;
            if recursive {
                self.copy_dir_contents(&src, dst_root, &dst)?;
            }
        } else {
            let mut reader = self.dir.open(&src).map_err(DirError::from)?;
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            let mut writer = dst_root
                .dir
                .open_with(&dst, &opts)
                .map_err(DirError::from)?;
            io::copy(&mut reader, &mut writer).map_err(DirError::from)?;
        }
        Ok(existed)
    }

    fn copy_dir_contents(
        &self,
        src_dir: &Path,
        dst_root: &ConfinedRoot,
        dst_dir: &Path,
    ) -> Result<(), DirError> {
        let entries = if src_dir.as_os_str().is_empty() {
            self.dir.entries().map_err(DirError::from)?
        } else {
            self.dir.read_dir(src_dir).map_err(DirError::from)?
        };
        for item in entries {
            let entry = item.map_err(DirError::from)?;
            let name = entry.file_name();
            let src_child = if src_dir.as_os_str().is_empty() {
                PathBuf::from(&name)
            } else {
                src_dir.join(&name)
            };
            if self.is_hidden_rel(&src_child) {
                continue;
            }
            let dst_child = dst_dir.join(&name);
            let src_child_str = src_child.to_string_lossy();
            let Ok(resolved_src) =
                resolve_inner(&self.dir, Some(&self.canonical_root), &src_child_str, true)
            else {
                // Skip escaping symlinks when recursively copying a directory.
                continue;
            };
            if self.is_hidden_rel(&resolved_src) {
                continue;
            }
            let meta = if resolved_src.as_os_str().is_empty() {
                self.dir.dir_metadata().map_err(DirError::from)?
            } else {
                self.dir.metadata(&resolved_src).map_err(DirError::from)?
            };
            if meta.is_dir() {
                dst_root
                    .dir
                    .create_dir(&dst_child)
                    .map_err(DirError::from)?;
                self.copy_dir_contents(&resolved_src, dst_root, &dst_child)?;
            } else if meta.is_file() {
                let mut reader = self.dir.open(&resolved_src).map_err(DirError::from)?;
                let mut opts = OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                let mut writer = dst_root
                    .dir
                    .open_with(&dst_child, &opts)
                    .map_err(DirError::from)?;
                io::copy(&mut reader, &mut writer).map_err(DirError::from)?;
            }
        }
        Ok(())
    }
}

/// One named mount inside a [`MultiRoot`].
#[derive(Clone, Debug)]
pub struct MountedRoot {
    pub name: String,
    pub root: ConfinedRoot,
    pub read_only: bool,
}

/// Virtual root abstraction supporting both single-directory and multi-mount
/// users (reusable by WebDAV, FTP, SMB, and storage).
#[derive(Clone, Debug)]
pub enum MultiRoot {
    Single { root: ConfinedRoot, read_only: bool },
    Mounts { mounts: Vec<MountedRoot> },
}

/// Result of routing a virtual path through a [`MultiRoot`].
pub enum ResolvedMount<'a> {
    /// Virtual read-only root listing all mounts.
    VirtualRoot,
    /// A real path inside a confined root.
    InMount {
        mount_name: Option<&'a str>,
        root: &'a ConfinedRoot,
        rel: String,
        read_only: bool,
    },
}

impl MultiRoot {
    /// Opens a single-root view.
    pub fn open_single(path: &Path, read_only: bool) -> Result<Self, DirError> {
        let root = ConfinedRoot::open(path)?;
        Ok(Self::Single { root, read_only })
    }

    /// Opens a multi-mount view. Any mount pointing inside a protected
    /// configuration directory is skipped with a warning (WP-63 §3.3).
    pub fn open_mounts(specs: &[(String, PathBuf, bool)]) -> Result<Self, DirError> {
        let mut mounts = Vec::with_capacity(specs.len());
        for (name, path, read_only) in specs {
            match ConfinedRoot::open(path) {
                Ok(root) => mounts.push(MountedRoot {
                    name: name.clone(),
                    root,
                    read_only: *read_only,
                }),
                Err(DirError::Protected) => {
                    tracing::warn!(
                        mount = %name,
                        path = %path.display(),
                        "skipping mount inside protected configuration directory"
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        mount = %name,
                        path = %path.display(),
                        error = %err,
                        "skipping inaccessible mount"
                    );
                }
            }
        }
        Ok(Self::Mounts { mounts })
    }

    /// Routes a virtual path (e.g. `/`, `/docs/a.txt`) to either the virtual
    /// root or a concrete mount + relative path.
    pub fn locate<'a>(&'a self, virtual_path: &str) -> Result<ResolvedMount<'a>, DirError> {
        let segments = parse_rel_segments(virtual_path)?;
        match self {
            Self::Single { root, read_only } => Ok(ResolvedMount::InMount {
                mount_name: None,
                root,
                rel: segments.join("/"),
                read_only: *read_only,
            }),
            Self::Mounts { mounts } => {
                if segments.is_empty() {
                    return Ok(ResolvedMount::VirtualRoot);
                }
                let mount_name = &segments[0];
                let Some(mount) = mounts.iter().find(|m| m.name == *mount_name) else {
                    return Err(DirError::NotFound);
                };
                Ok(ResolvedMount::InMount {
                    mount_name: Some(&mount.name),
                    root: &mount.root,
                    rel: segments[1..].join("/"),
                    read_only: mount.read_only,
                })
            }
        }
    }

    /// Lists entries at `virtual_path`.
    pub fn list_dir(&self, virtual_path: &str) -> Result<Vec<EntryInfo>, DirError> {
        match self.locate(virtual_path)? {
            ResolvedMount::VirtualRoot => {
                let Self::Mounts { mounts } = self else {
                    unreachable!();
                };
                Ok(mounts
                    .iter()
                    .map(|m| EntryInfo {
                        name: m.name.clone(),
                        is_dir: true,
                        size: 0,
                        modified: m
                            .root
                            .dir()
                            .dir_metadata()
                            .ok()
                            .and_then(|meta| meta.modified().ok())
                            .map(cap_time_to_system),
                    })
                    .collect())
            }
            ResolvedMount::InMount { root, rel, .. } => root.list_dir(&rel),
        }
    }

    /// Returns metadata for `virtual_path`.
    pub fn stat(&self, virtual_path: &str) -> Result<EntryInfo, DirError> {
        match self.locate(virtual_path)? {
            ResolvedMount::VirtualRoot => Ok(EntryInfo {
                name: String::new(),
                is_dir: true,
                size: 0,
                modified: None,
            }),
            ResolvedMount::InMount {
                mount_name,
                root,
                rel,
                ..
            } => {
                let mut info = root.stat(&rel)?;
                if rel.is_empty()
                    && let Some(name) = mount_name
                {
                    info.name = name.to_string();
                }
                Ok(info)
            }
        }
    }

    /// Moves an entry within the same mount. Cross-mount moves and writes to
    /// the virtual root are rejected (`DirError::CrossMount` / `DirError::ReadOnly`).
    pub fn move_entry(
        &self,
        src_virtual: &str,
        dst_virtual: &str,
        overwrite: bool,
    ) -> Result<bool, DirError> {
        let src = self.locate(src_virtual)?;
        let dst = self.locate(dst_virtual)?;
        match (src, dst) {
            (
                ResolvedMount::InMount {
                    mount_name: src_mount,
                    root: src_root,
                    rel: src_rel,
                    read_only: src_ro,
                },
                ResolvedMount::InMount {
                    mount_name: dst_mount,
                    rel: dst_rel,
                    read_only: dst_ro,
                    ..
                },
            ) => {
                if src_mount != dst_mount {
                    return Err(DirError::CrossMount);
                }
                if src_ro || dst_ro {
                    return Err(DirError::ReadOnly);
                }
                if src_rel.is_empty() || dst_rel.is_empty() {
                    return Err(DirError::Forbidden);
                }
                src_root.rename(&src_rel, &dst_rel, overwrite)
            }
            (ResolvedMount::VirtualRoot, _) | (_, ResolvedMount::VirtualRoot) => {
                Err(DirError::ReadOnly)
            }
        }
    }

    /// Copies an entry (supports both same-mount and cross-mount copy if the
    /// destination mount is writable).
    pub fn copy_entry(
        &self,
        src_virtual: &str,
        dst_virtual: &str,
        overwrite: bool,
        recursive: bool,
    ) -> Result<bool, DirError> {
        let src = self.locate(src_virtual)?;
        let dst = self.locate(dst_virtual)?;
        match (src, dst) {
            (
                ResolvedMount::InMount {
                    root: src_root,
                    rel: src_rel,
                    ..
                },
                ResolvedMount::InMount {
                    root: dst_root,
                    rel: dst_rel,
                    read_only: dst_ro,
                    ..
                },
            ) => {
                if dst_ro {
                    return Err(DirError::ReadOnly);
                }
                if dst_rel.is_empty() {
                    return Err(DirError::Forbidden);
                }
                src_root.copy_to(&src_rel, dst_root, &dst_rel, overwrite, recursive)
            }
            (_, ResolvedMount::VirtualRoot) => Err(DirError::ReadOnly),
            (ResolvedMount::VirtualRoot, _) => Err(DirError::Forbidden),
        }
    }
}

fn entry_from_meta(name: String, meta: &Metadata) -> EntryInfo {
    EntryInfo {
        name,
        is_dir: meta.is_dir(),
        size: if meta.is_dir() { 0 } else { meta.len() },
        modified: meta.modified().ok().map(cap_time_to_system),
    }
}

fn cap_time_to_system(ts: cap_std::time::SystemTime) -> SystemTime {
    ts.into_std()
}

fn parse_rel_segments(rel: &str) -> Result<Vec<String>, DirError> {
    if rel.contains('\0') || rel.contains('\\') {
        return Err(DirError::InvalidPath);
    }
    let mut out = Vec::new();
    for seg in rel.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err(DirError::Forbidden);
        }
        out.push(seg.to_string());
    }
    Ok(out)
}

/// Segment-by-segment symlink resolver confined to `root`.
///
/// If `must_exist` is `true`, missing segments return `DirError::NotFound`.
/// If `must_exist` is `false`, a missing final target is returned cleanly as
/// long as it does not escape `root`.
fn resolve_inner(
    root: &Dir,
    canonical_root: Option<&Path>,
    rel: &str,
    must_exist: bool,
) -> Result<PathBuf, DirError> {
    let initial = parse_rel_segments(rel)?;
    let mut pending: Vec<String> = initial.into_iter().rev().collect();
    let mut resolved: Vec<String> = Vec::new();
    let mut hops: usize = 0;

    while let Some(seg) = pending.pop() {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            if resolved.pop().is_none() {
                return Err(DirError::Forbidden);
            }
            continue;
        }

        let mut candidate = PathBuf::new();
        for part in &resolved {
            candidate.push(part);
        }
        candidate.push(&seg);

        match root.symlink_metadata(&candidate) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    hops += 1;
                    if hops > MAX_SYMLINK_HOPS {
                        return Err(DirError::TooManySymlinks);
                    }
                    let target = read_link_target(root, canonical_root, &candidate)?;
                    let target_segs = expand_symlink_target(&target, &resolved, canonical_root)?;
                    // Reset resolved to root and push target segments followed by remaining pending.
                    // Because `pending` is a stack (LIFO), push target segments in reverse order.
                    resolved.clear();
                    for part in target_segs.into_iter().rev() {
                        pending.push(part);
                    }
                } else {
                    if !pending.is_empty() && !meta.is_dir() {
                        return Err(DirError::NotADirectory);
                    }
                    resolved.push(seg);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                if !must_exist && pending.is_empty() {
                    resolved.push(seg);
                } else {
                    return Err(DirError::NotFound);
                }
            }
            Err(err) => return Err(DirError::from(err)),
        }
    }

    let mut path = PathBuf::new();
    for part in resolved {
        path.push(part);
    }
    Ok(path)
}

fn read_link_target(
    root: &Dir,
    canonical_root: Option<&Path>,
    candidate: &Path,
) -> Result<PathBuf, DirError> {
    match root.read_link_contents(candidate) {
        Ok(target) => Ok(target),
        Err(err) => {
            // `cap_std::fs::Dir::read_link_contents` rejects absolute symlink targets.
            // When we know `canonical_root`, read the raw link target so we can allow
            // absolute symlinks pointing *inside* the root while still rejecting any
            // symlink pointing outside the root.
            if let Some(root_path) = canonical_root
                && let Ok(target) = std::fs::read_link(root_path.join(candidate))
            {
                return Ok(target);
            }
            match err.kind() {
                io::ErrorKind::NotFound => Err(DirError::NotFound),
                _ => Err(DirError::Forbidden),
            }
        }
    }
}

/// Resolves a symlink target relative to `parent_segments` (or against
/// `canonical_root` if absolute), ensuring it never escapes above the root.
fn expand_symlink_target(
    target: &Path,
    parent_segments: &[String],
    canonical_root: Option<&Path>,
) -> Result<Vec<String>, DirError> {
    if target.is_absolute() {
        let Some(root_path) = canonical_root else {
            return Err(DirError::Forbidden);
        };
        let normalized_target = normalize_lexical(target);
        let stripped = strip_prefix_platform(&normalized_target, root_path)
            .or_else(|| {
                let resolved_target = canonicalize_existing_ancestor(&normalized_target);
                strip_prefix_platform(&resolved_target, root_path)
            })
            .ok_or(DirError::Forbidden)?;
        let mut parts = Vec::new();
        for comp in stripped.components() {
            match comp {
                Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
                Component::CurDir => {}
                Component::ParentDir => {
                    if parts.pop().is_none() {
                        return Err(DirError::Forbidden);
                    }
                }
                _ => return Err(DirError::Forbidden),
            }
        }
        return Ok(parts);
    }

    let mut stack: Vec<String> = parent_segments.to_vec();
    for comp in target.components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(s) => stack.push(s.to_string_lossy().into_owned()),
            Component::ParentDir => {
                if stack.pop().is_none() {
                    return Err(DirError::Forbidden);
                }
            }
            _ => return Err(DirError::Forbidden),
        }
    }
    Ok(stack)
}

fn canonicalize_existing_ancestor(path: &Path) -> PathBuf {
    for ancestor in path.ancestors() {
        if let Ok(canon) = std::fs::canonicalize(ancestor)
            && let Ok(suffix) = path.strip_prefix(ancestor)
        {
            return normalize_lexical(&canon.join(suffix));
        }
    }
    normalize_lexical(path)
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            other => normalized.push(other),
        }
    }
    normalized
}

fn strip_prefix_platform(path: &Path, prefix: &Path) -> Option<PathBuf> {
    if let Ok(rest) = path.strip_prefix(prefix) {
        return Some(rest.to_path_buf());
    }
    #[cfg(any(target_os = "macos", windows))]
    {
        let p_low = path.to_string_lossy().to_lowercase();
        let pre_low = prefix.to_string_lossy().to_lowercase();
        if p_low == pre_low {
            return Some(PathBuf::new());
        }
        let sep = if pre_low.ends_with(std::path::MAIN_SEPARATOR) {
            pre_low
        } else {
            format!("{pre_low}{}", std::path::MAIN_SEPARATOR)
        };
        if p_low.starts_with(&sep) {
            let suffix = &path.to_string_lossy()[sep.len()..];
            return Some(PathBuf::from(suffix));
        }
    }
    let _ = path;
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_rejects_config_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg_dir = tmp.path().join("cfg");
        let sub_dir = cfg_dir.join("sub");
        std::fs::create_dir_all(&sub_dir).unwrap();
        fsperm::protect(&cfg_dir);

        assert!(is_exposable(&cfg_dir).is_err());
        assert!(is_exposable(&sub_dir).is_err());
        assert_eq!(open_root(&cfg_dir).unwrap_err(), DirError::Protected);
        assert_eq!(open_root(&sub_dir).unwrap_err(), DirError::Protected);
        assert!(is_exposable(tmp.path()).is_ok());
        assert!(open_root(tmp.path()).is_ok());
    }
}
