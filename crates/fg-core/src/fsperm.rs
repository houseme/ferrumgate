use std::{
    fs, io,
    path::{Component, Path, PathBuf},
    sync::{Arc, RwLock, Weak},
};

use anyhow::{Result, ensure};

struct Directories {
    protected: Vec<PathBuf>,
    published: Vec<Weak<Path>>,
}

static DIRECTORIES: RwLock<Directories> = RwLock::new(Directories {
    protected: Vec::new(),
    published: Vec::new(),
});

/// Create the directory and set its permissions, including when it already exists.
pub fn mkdir_all(dir: &Path, mode: u32) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        builder.mode(mode).create(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        builder.create(dir)
    }
}

/// Tighten modes on a private configuration tree. Skip links and unreadable entries.
#[cfg(unix)]
pub fn tighten(root: &Path) -> usize {
    use std::os::unix::fs::PermissionsExt;

    let mut changed = 0;
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        let mode = metadata.permissions().mode() & 0o7777;
        let target = if metadata.is_dir() && mode & 0o077 != 0 {
            Some(0o700)
        } else if metadata.is_file() && mode != 0o600 {
            Some(0o600)
        } else {
            None
        };
        if let Some(target) = target
            && fs::set_permissions(&path, fs::Permissions::from_mode(target)).is_ok()
        {
            changed += 1;
        }
        if metadata.is_dir()
            && let Ok(entries) = fs::read_dir(path)
        {
            pending.extend(entries.filter_map(|entry| entry.ok().map(|entry| entry.path())));
        }
    }
    changed
}

#[cfg(not(unix))]
pub fn tighten(_: &Path) -> usize {
    0
}

/// Register a protected directory for the lifetime of the process.
pub fn protect(dir: &Path) {
    if !dir.as_os_str().is_empty()
        && let Ok(absolute) = std::path::absolute(dir)
    {
        let dir = normalize(&absolute);
        let mut registry = DIRECTORIES.write().expect("directory registry poisoned");
        let protected = &mut registry.protected;
        if !protected.contains(&dir) {
            protected.push(dir);
        }
    }
}

/// Registers an already canonicalized static root for the lifetime of its route generation.
pub fn publish_static_root(root: &Path) -> Result<Arc<Path>> {
    let mut registry = DIRECTORIES.write().expect("directory registry poisoned");
    ensure!(
        !registry.protected.iter().any(|path| overlap(path, root)),
        "path overlaps a protected configuration directory"
    );
    registry.published.retain(|path| path.strong_count() != 0);
    let root = Arc::<Path>::from(root);
    registry.published.push(Arc::downgrade(&root));
    Ok(root)
}

pub fn check_log_directory(path: &Path) -> Result<()> {
    let registry = DIRECTORIES.read().expect("directory registry poisoned");
    check_unpublished(&registry, path)
}

/// Prevents a log directory and a live static root from being activated over the same files.
pub fn protect_log_directory(path: &Path) -> Result<()> {
    let mut registry = DIRECTORIES.write().expect("directory registry poisoned");
    check_unpublished(&registry, path)?;
    let path = normalize(path);
    if !registry.protected.contains(&path) {
        registry.protected.push(path);
    }
    Ok(())
}

fn check_unpublished(registry: &Directories, path: &Path) -> Result<()> {
    ensure!(
        !registry
            .published
            .iter()
            .filter_map(Weak::upgrade)
            .any(|root| overlap(&root, path)),
        "log directory overlaps a published static root"
    );
    Ok(())
}

pub fn protected(path: &Path) -> Option<PathBuf> {
    find(path, |dir, path| within(dir, path) || within(path, dir))
}

pub fn inside(path: &Path) -> Option<PathBuf> {
    find(path, within)
}

pub fn contains(path: &Path) -> Option<PathBuf> {
    find(path, |dir, path| within(path, dir) && !within(dir, path))
}

pub fn check_exposable(path: &Path) -> Result<()> {
    ensure!(
        inside(path).is_none(),
        "path is inside a protected configuration directory"
    );
    Ok(())
}

pub fn check_whole_dir(path: &Path) -> Result<()> {
    ensure!(
        protected(path).is_none(),
        "path overlaps a protected configuration directory"
    );
    Ok(())
}

pub fn overlap(a: &Path, b: &Path) -> bool {
    match (std::path::absolute(a), std::path::absolute(b)) {
        (Ok(a), Ok(b)) => within(&a, &b) || within(&b, &a),
        _ => false,
    }
}

fn find(path: &Path, matches: impl Fn(&Path, &Path) -> bool) -> Option<PathBuf> {
    let path = std::path::absolute(path).ok()?;
    let dirs = DIRECTORIES
        .read()
        .expect("directory registry poisoned")
        .protected
        .clone();
    dirs.into_iter().find(|dir| matches(dir, &path))
}

fn within(parent: &Path, child: &Path) -> bool {
    lexical_within(&normalize(parent), &normalize(child))
        || lexical_within(&resolve(parent), &resolve(child))
        || same_on_path(parent, child)
}

fn lexical_within(parent: &Path, child: &Path) -> bool {
    #[cfg(any(target_os = "macos", windows))]
    let (parent, child) = (
        PathBuf::from(parent.to_string_lossy().to_lowercase()),
        PathBuf::from(child.to_string_lossy().to_lowercase()),
    );
    child.starts_with(parent)
}

fn normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for part in path.components() {
        match part {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            part => normalized.push(part),
        }
    }
    normalized
}

fn resolve(path: &Path) -> PathBuf {
    for ancestor in path.ancestors() {
        if let Ok(root) = ancestor.canonicalize() {
            let suffix = path
                .strip_prefix(ancestor)
                .expect("path comes from its ancestors");
            return normalize(&root.join(suffix));
        }
    }
    normalize(path)
}

#[cfg(unix)]
fn same_on_path(parent: &Path, child: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let Ok(parent) = fs::metadata(parent) else {
        return false;
    };
    child.ancestors().any(|ancestor| {
        fs::metadata(ancestor)
            .is_ok_and(|child| (parent.dev(), parent.ino()) == (child.dev(), child.ino()))
    })
}

#[cfg(not(unix))]
fn same_on_path(_: &Path, _: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_paths_distinguish_parents_and_descendants() -> Result<()> {
        let base = tempfile::tempdir()?;
        let dir = base.path().join("private");
        mkdir_all(&dir, 0o700)?;
        protect(&dir);
        protect(&dir);
        let child = dir.join("missing");
        let sibling = base.path().join("private-old");
        assert_eq!(inside(&dir), Some(dir.clone()));
        assert_eq!(inside(&child), Some(dir.clone()));
        assert_eq!(protected(base.path()), Some(dir.clone()));
        assert_eq!(contains(base.path()), Some(dir.clone()));
        assert_eq!(contains(&dir), None);
        assert_eq!(inside(base.path()), None);
        assert_eq!(protected(&sibling), None);
        assert!(overlap(&dir, &sibling.join("../private")));
        assert!(check_exposable(&child).is_err());
        assert!(check_exposable(base.path()).is_ok());
        assert!(check_whole_dir(base.path()).is_err());
        assert!(check_whole_dir(&sibling).is_ok());
        assert_eq!(
            DIRECTORIES
                .read()
                .unwrap()
                .protected
                .iter()
                .filter(|entry| **entry == dir)
                .count(),
            1
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn overlap_resolves_directory_links_and_missing_descendants() -> Result<()> {
        let base = tempfile::tempdir()?;
        let dir = base.path().join("config");
        let alias = base.path().join("alias");
        let sibling = base.path().join("other");
        mkdir_all(&dir, 0o700)?;
        mkdir_all(&sibling, 0o700)?;
        std::os::unix::fs::symlink(&dir, &alias)?;
        protect(&dir);
        assert!(overlap(&alias, &dir));
        assert_eq!(inside(&alias.join("not/created")), Some(dir));
        assert_eq!(inside(&sibling), None);
        Ok(())
    }

    #[cfg(any(target_os = "macos", windows))]
    #[test]
    fn overlap_handles_case_insensitive_paths() -> Result<()> {
        let base = tempfile::tempdir()?;
        let dir = base.path().join("ConfigData");
        mkdir_all(&dir, 0o700)?;
        assert!(overlap(&dir, &base.path().join("configdata/missing")));
        Ok(())
    }
}
