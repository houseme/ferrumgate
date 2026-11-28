//! The rotating log-file reader (WP-52 §3.3 "文件轮转"): a poll-based
//! tail that starts at the end of an existing file, follows appends, and
//! survives both rotation styles —
//!
//! - rename (`mv auth.log auth.log.1`, new file appears at the path):
//!   the old handle is drained to EOF so nothing written before the
//!   rename is lost, then the path is reopened and read from its start
//!   (the fresh file only ever contains new lines; the already-read part
//!   of the old file is never replayed);
//! - truncate (copytruncate logrotate, or delete + recreate): when the
//!   file shrinks below the current position (same inode) or the path
//!   disappears and reappears, reading restarts at 0.
//!
//! Polling keeps this portable and trivially testable; the readers run
//! in their own task ([`super::file_source`]) with a 1-second interval,
//! matching the upstream poll fallback rather than the inotify fast
//! path.

use std::{
    fs,
    io::{self, Read, Seek},
    path::{Path, PathBuf},
};

/// FerrumGate protection: partial lines are capped; an unbounded line
/// cannot grow the buffer past this.
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// FerrumGate protection: bytes read per poll; leftovers are picked up
/// on the next tick.
pub const MAX_READ_BYTES: u64 = 8 << 20;

/// One followed file.
pub struct Tail {
    path: PathBuf,
    file: Option<std::fs::File>,
    /// Byte offset of already-consumed content (complete lines only).
    position: u64,
    /// Whether we ever attached to a file: the first attach seeks to the
    /// end (a newly configured jail must not replay history); every
    /// later (re)open reads from the start.
    attached: bool,
    partial: Vec<u8>,
}

impl Tail {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            file: None,
            position: 0,
            attached: false,
            partial: Vec::new(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads everything newly appended and returns the complete lines.
    /// Rotation is detected per poll; `Ok(vec![])` means nothing new.
    pub fn poll(&mut self) -> io::Result<Vec<String>> {
        let mut drained: Vec<String> = Vec::new();
        let metadata = fs::metadata(&self.path);
        match (&self.file, metadata) {
            (None, Ok(metadata)) => {
                let mut file = fs::File::open(&self.path)?;
                if self.attached {
                    // The path reappeared after a rename/delete: read the
                    // new file from its start.
                    self.position = 0;
                } else {
                    // First attach: start at the end, no history replay.
                    self.position = metadata.len();
                    self.attached = true;
                }
                file.seek(io::SeekFrom::Start(self.position))?;
                self.file = Some(file);
            }
            (Some(_), Ok(metadata)) => {
                let rotated = rotated_away(self.file.as_ref().expect("checked"), &metadata);
                if rotated {
                    drained = self.drain_old()?;
                    let mut file = fs::File::open(&self.path)?;
                    self.position = 0;
                    file.seek(io::SeekFrom::Start(0))?;
                    self.file = Some(file);
                } else if metadata.len() < self.position {
                    // Same inode but truncated (copytruncate): restart at
                    // 0; content read before the truncation is not
                    // repeated.
                    let mut file = self.file.take().expect("checked");
                    file.seek(io::SeekFrom::Start(0))?;
                    self.position = 0;
                    self.file = Some(file);
                }
            }
            (Some(_), Err(_)) => {
                // The path is gone (mid-rotation): finish the old file so
                // lines written up to the rename are not lost, then wait
                // for the new one.
                drained = self.drain_old()?;
                self.file = None;
                self.position = 0;
                return Ok(drained);
            }
            (None, Err(_)) => {}
        }
        let mut lines = self.read_appended()?;
        // The drained tail of the old file precedes the new file's lines.
        lines.splice(0..0, drained);
        Ok(lines)
    }

    /// Reads to the end of the old handle (rotation drain); the read is
    /// bounded like every poll, and anything beyond the budget is left
    /// unread with the handle closed (documented cap behavior).
    fn drain_old(&mut self) -> io::Result<Vec<String>> {
        let file = self.file.as_mut().expect("drain needs a file");
        file.seek(io::SeekFrom::Start(self.position))?;
        let mut bytes = Vec::new();
        file.take(MAX_READ_BYTES).read_to_end(&mut bytes)?;
        self.position += bytes.len() as u64;
        Ok(split_lines_from(&mut self.partial, &bytes))
    }

    /// Reads the appended bytes of the open file and returns complete
    /// lines.
    fn read_appended(&mut self) -> io::Result<Vec<String>> {
        let Some(file) = self.file.as_mut() else {
            return Ok(Vec::new());
        };
        file.seek(io::SeekFrom::Start(self.position))?;
        let budget = MAX_READ_BYTES;
        let mut bytes = Vec::new();
        file.take(budget).read_to_end(&mut bytes)?;
        self.position += bytes.len() as u64;
        Ok(split_lines_from(&mut self.partial, &bytes))
    }
}

/// Rotation detection: the path's inode no longer matches the open file.
#[cfg(unix)]
fn rotated_away(file: &std::fs::File, metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    match file.metadata() {
        Ok(opened) => opened.ino() != metadata.ino() || opened.dev() != metadata.dev(),
        Err(_) => true,
    }
}

#[cfg(not(unix))]
fn rotated_away(_file: &std::fs::File, metadata: &fs::Metadata) -> bool {
    // Without inode metadata, shrinkage is the only rotation signal.
    metadata.len() == 0
}

/// Splits complete lines (keeping the trailing partial in `partial`);
/// oversize lines are truncated to [`MAX_LINE_BYTES`].
fn split_lines_from(partial: &mut Vec<u8>, bytes: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'\n' {
            continue;
        }
        partial.extend_from_slice(&bytes[start..index]);
        let mut line = std::mem::take(partial);
        line.truncate(MAX_LINE_BYTES);
        lines.push(
            String::from_utf8_lossy(&line)
                .trim_end_matches('\r')
                .to_owned(),
        );
        start = index + 1;
    }
    if partial.len() < MAX_LINE_BYTES {
        partial.extend_from_slice(&bytes[start..]);
    }
    lines
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn temp_log(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, "").expect("create");
        path
    }

    #[test]
    fn tail_follows_appends_without_history() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = temp_log(dir.path(), "app.log");
        fs::write(&path, "old-1\nold-2\n").expect("seed");
        let mut tail = Tail::new(&path);
        assert!(tail.poll().expect("poll").is_empty(), "no history replay");
        fs::write(&path, "old-1\nold-2\nnew-1\n").expect("append");
        let lines = tail.poll().expect("poll");
        assert_eq!(lines, ["new-1"]);
    }

    #[test]
    fn file_follows_rename_rotation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = temp_log(dir.path(), "auth.log");
        fs::write(&path, "before-a\nbefore-b\n").expect("seed");
        let mut tail = Tail::new(&path);
        assert!(tail.poll().expect("first attach").is_empty());

        // Rotate: rename the old file away, a fresh file appears.
        fs::rename(&path, dir.path().join("auth.log.1")).expect("rename");
        fs::write(&path, "after-1\n").expect("new file");
        let lines = tail.poll().expect("poll after rename");
        assert_eq!(lines, ["after-1"], "the new file is read from its start");
        assert!(!lines.iter().any(|line| line.contains("before")));

        // Lines appended to the followed file right before the rename
        // are drained from the open handle, not lost, and the fresh file
        // is read from its start.
        fs::write(&path, "after-1\nlate\n").expect("append before rename");
        fs::rename(&path, dir.path().join("auth.log.1")).expect("rotate");
        fs::write(&path, "after-2\n").expect("new file");
        let lines = tail.poll().expect("poll");
        assert!(
            lines.contains(&"late".to_owned()),
            "the drained old file contributes its tail, got {lines:?}"
        );
        assert!(lines.contains(&"after-2".to_owned()));
        assert!(!lines.iter().any(|line| line.contains("before")));
    }

    #[test]
    fn file_follows_truncation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = temp_log(dir.path(), "copy.log");
        fs::write(&path, "a\nb\nc\n").expect("seed");
        let mut tail = Tail::new(&path);
        assert!(tail.poll().expect("attach").is_empty());
        // copytruncate: same file, shorter.
        fs::write(&path, "d\n").expect("truncate + write");
        let lines = tail.poll().expect("poll");
        assert_eq!(lines, ["d"], "post-truncation content only, no re-read");
        // Delete + recreate reads the fresh file from its start.
        fs::remove_file(&path).expect("remove");
        let lines = tail.poll().expect("poll while missing");
        assert!(lines.is_empty());
        fs::write(&path, "e\n").expect("recreate");
        let lines = tail.poll().expect("poll");
        assert_eq!(lines, ["e"]);
    }

    #[test]
    fn tail_keeps_partial_lines_and_caps_length() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = temp_log(dir.path(), "partial.log");
        let mut tail = Tail::new(&path);
        assert!(tail.poll().expect("attach").is_empty());
        fs::write(&path, "half").expect("no newline yet");
        assert!(
            tail.poll().expect("poll").is_empty(),
            "partial stays buffered"
        );
        fs::write(&path, "half line\nnext").expect("complete it");
        let lines = tail.poll().expect("poll");
        assert_eq!(lines, ["half line"]);
        // A single line beyond the cap is truncated, not unbounded.
        let oversized = "y".repeat(MAX_LINE_BYTES * 2);
        fs::write(&path, format!("{oversized}\n")).expect("oversized");
        let lines = tail.poll().expect("poll");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].len(), MAX_LINE_BYTES);
    }
}
