use std::{
    collections::BTreeMap,
    fs::{self, FileTimes},
    io::{self, Read},
    path::{Path, PathBuf},
    time::SystemTime,
};

use anyhow::{Result, ensure};
use flate2::{Compression, Crc, GzBuilder};
use serde::Deserialize;
use time::{
    Duration, OffsetDateTime, PrimitiveDateTime, format_description::BorrowedFormatItem,
    macros::format_description,
};

use super::{
    Filter, Module,
    persist::{DiskView, open_regular, private_file},
    query::scan_forward_lines,
};

pub(super) const MAX_RAW: u64 = 16 << 20;
pub(super) const MAX_ARCHIVES: usize = 128;
const STAMP: &[BorrowedFormatItem<'_>] =
    format_description!("[year][month][day]T[hour][minute][second]Z");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveOptions {
    pub keep_days: u32,
    pub keep_bytes: u64,
}

impl Default for ArchiveOptions {
    fn default() -> Self {
        Self {
            keep_days: 7,
            keep_bytes: 32 << 20,
        }
    }
}

impl ArchiveOptions {
    pub(super) fn prepare(self, dir: &Path) -> Result<Self> {
        ensure!(
            (1..=3650).contains(&self.keep_days),
            "Web archive keep days must be in 1..=3650"
        );
        ensure!(
            self.keep_bytes >= 4 << 20,
            "Web archive budget must be at least 4 MiB"
        );
        #[cfg(unix)]
        let keep_bytes = {
            let partition = rustix::fs::statvfs(dir)?;
            let limit = partition.f_blocks.saturating_mul(partition.f_frsize) / 20;
            ensure!(
                limit >= 4 << 20,
                "Web archive partition budget is below 4 MiB"
            );
            self.keep_bytes.min(limit)
        };
        #[cfg(not(unix))]
        let keep_bytes = {
            let _ = dir;
            self.keep_bytes
        };
        Ok(Self { keep_bytes, ..self })
    }

    pub(super) fn file_limit(self) -> u64 {
        (self.keep_bytes / 4).clamp(1 << 20, MAX_RAW)
    }
}

pub(super) fn cleanup_temporaries(dir: &Path) -> io::Result<()> {
    for item in fs::read_dir(dir)? {
        let item = item?;
        if item.file_type()?.is_file()
            && item
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".fg-log-archive.") && name.ends_with(".tmp"))
        {
            remove(&item.path())?;
        }
    }
    Ok(())
}

#[derive(Default)]
pub(super) struct Archive {
    pub plain: Option<PathBuf>,
    pub gzip: Option<PathBuf>,
}

impl Archive {
    pub fn paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.plain.iter().chain(&self.gzip)
    }

    pub fn preferred(&self) -> (&Path, bool) {
        if let Some(path) = &self.gzip {
            (path, true)
        } else {
            (self.plain.as_deref().expect("listed archive"), false)
        }
    }
}

pub(super) fn list(dir: &Path) -> io::Result<Vec<Archive>> {
    // Imported archives have a timestamp and optional short tie breaker. Our 20-digit
    // suffix is the stream sequence, which keeps ordering stable after a clock adjustment.
    let mut entries = BTreeMap::<(Option<u64>, OffsetDateTime, u64), Archive>::new();
    for item in fs::read_dir(dir)? {
        let item = item?;
        if !item.file_type()?.is_file() {
            continue;
        }
        let name = item.file_name();
        let Some(name) = name
            .to_str()
            .and_then(|name| name.strip_prefix("webservice."))
        else {
            continue;
        };
        let (plain, gzip) = if let Some(stem) = name.strip_suffix(".log.gz") {
            (stem, true)
        } else if let Some(stem) = name.strip_suffix(".log") {
            (stem, false)
        } else {
            continue;
        };
        let (stamp, suffix) = plain.split_once('-').unwrap_or((plain, "0"));
        if stamp.len() != 16
            || suffix.is_empty()
            || !suffix.bytes().all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        let Ok(time) = PrimitiveDateTime::parse(stamp, STAMP) else {
            continue;
        };
        let Ok(number) = suffix.parse::<u64>() else {
            continue;
        };
        let entry = entries
            .entry((
                (suffix.len() == 20).then_some(number),
                time.assume_utc(),
                number,
            ))
            .or_default();
        if gzip {
            entry.gzip = Some(item.path());
        } else {
            entry.plain = Some(item.path());
        }
    }
    Ok(entries.into_values().collect())
}

pub(super) fn rotate(dir: &Path, path: &Path, started: OffsetDateTime, seq: u64) -> io::Result<()> {
    let stamp = started.format(STAMP).map_err(io::Error::other)?;
    let path_for = |seq| dir.join(format!("webservice.{stamp}-{seq:020}.log"));
    let mut sequence = seq;
    loop {
        let target = path_for(sequence);
        let gzip = target.with_extension("log.gz");
        if missing(&target)? && missing(&gzip)? {
            return fs::rename(path, target);
        }
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("archive name sequence exhausted"))?;
    }
}

fn missing(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

pub(super) fn maintain(view: &DiskView) -> io::Result<()> {
    let (generation, archives) = {
        let files = view.files.lock().expect("log file mutex poisoned");
        (files[Module::Web as usize].generation, list(&view.dir)?)
    };
    let mut failed = None;
    for entry in archives {
        let Some(plain) = entry.plain else { continue };
        let result = if entry.gzip.is_some() {
            let files = view.files.lock().expect("log file mutex poisoned");
            if files[Module::Web as usize].generation != generation {
                return Ok(());
            }
            remove_copied_plain(&view.dir, &plain)
        } else {
            compress(view, generation, &plain)
        };
        if let Err(error) = result {
            failed.get_or_insert(error);
        }
    }
    let files = view.files.lock().expect("log file mutex poisoned");
    if files[Module::Web as usize].generation == generation
        && let Some(options) = view.limits.load().archive
    {
        prune(&view.dir, options, OffsetDateTime::now_utc())?;
    }
    failed.map_or(Ok(()), Err)
}

fn compress(view: &DiskView, generation: u64, path: &Path) -> io::Result<()> {
    let Some(mut source) = open_regular(path, false)? else {
        return Ok(());
    };
    let metadata = source.metadata()?;
    if metadata.len() > MAX_RAW {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Web log archive exceeds uncompressed limit",
        ));
    }
    let modified = metadata.modified()?;
    let mut minimum = i64::MAX;
    let mut maximum = i64::MIN;
    #[derive(Deserialize)]
    struct Timestamp {
        #[serde(with = "time::serde::rfc3339")]
        time: OffsetDateTime,
    }
    scan_forward_lines(source.try_clone()?, metadata.len(), |line| {
        if let Ok(entry) = serde_json::from_slice::<Timestamp>(line) {
            let time = entry.time.unix_timestamp();
            minimum = minimum.min(time);
            maximum = maximum.max(time);
        }
        Ok(true)
    })?;
    std::io::Seek::rewind(&mut source)?;
    let mut file = tempfile::Builder::new()
        .prefix(".fg-log-archive.")
        .suffix(".tmp")
        .tempfile_in(&view.dir)
        .map_err(|error| io::Error::from(error.kind()))?;
    private_file(file.as_file())?;
    let mut gzip = GzBuilder::new();
    if minimum <= maximum {
        // A gzip FEXTRA subfield with two inclusive UTC seconds and a checksum.
        let mut bounds = [0; 24];
        bounds[..4].copy_from_slice(b"FG\x14\0");
        bounds[4..12].copy_from_slice(&minimum.to_le_bytes());
        bounds[12..20].copy_from_slice(&maximum.to_le_bytes());
        let mut crc = Crc::new();
        crc.update(&bounds[4..20]);
        bounds[20..24].copy_from_slice(&crc.sum().to_le_bytes());
        gzip = gzip.extra(bounds);
    }
    let mut encoder = gzip.write(file.as_file_mut(), Compression::fast());
    if io::copy(&mut source.take(MAX_RAW + 1), &mut encoder)? > MAX_RAW {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Web log archive exceeds uncompressed limit",
        ));
    }
    encoder.finish()?;
    file.as_file()
        .set_times(FileTimes::new().set_modified(modified))?;
    file.as_file().sync_all()?;
    let files = view.files.lock().expect("log file mutex poisoned");
    if files[Module::Web as usize].generation == generation && !missing(path)? {
        file.into_temp_path()
            .persist(path.with_extension("log.gz"))
            .map_err(|error| error.error)?;
        remove_copied_plain(&view.dir, path)?;
    }
    Ok(())
}

pub(super) fn outside_time_range(extra: Option<&[u8]>, filter: &Filter) -> bool {
    let Some([b'F', b'G', 20, 0, bounds @ ..]) = extra else {
        return false;
    };
    let Ok(bounds) = <&[u8; 20]>::try_from(bounds) else {
        return false;
    };
    let mut crc = Crc::new();
    crc.update(&bounds[..16]);
    if bounds[16..] != crc.sum().to_le_bytes() {
        return false;
    }
    let minimum = i64::from_le_bytes(bounds[..8].try_into().expect("eight-byte timestamp"));
    let maximum = i64::from_le_bytes(bounds[8..16].try_into().expect("eight-byte timestamp"));
    minimum <= maximum
        && (filter
            .from
            .is_some_and(|from| maximum < from.unix_timestamp())
            || filter.to.is_some_and(|to| minimum > to.unix_timestamp()))
}

fn remove_copied_plain(dir: &Path, path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    remove(path)
}

pub(super) fn prune(dir: &Path, options: ArchiveOptions, now: OffsetDateTime) -> io::Result<()> {
    let cutoff: SystemTime = (now - Duration::days(i64::from(options.keep_days))).into();
    let active = directory_entry_bytes(&dir.join("webservice.log"))?;
    let mut used = active;
    let mut eligible = Vec::new();
    let legacy = dir.join("webservice.log.1");
    let mut archives = list(dir)?;
    if !missing(&legacy)? {
        archives.insert(
            0,
            Archive {
                plain: Some(legacy),
                gzip: None,
            },
        );
    }
    for archive in archives {
        let (preferred, _) = archive.preferred();
        let modified = fs::metadata(preferred)?.modified()?;
        let mut bytes = 0u64;
        for path in archive.paths() {
            bytes = bytes.saturating_add(directory_entry_bytes(path)?);
        }
        if modified < cutoff {
            for path in archive.paths() {
                remove(path)?;
            }
        } else {
            used = used.saturating_add(bytes);
            eligible.push((archive, bytes));
        }
    }
    let mut remaining = eligible.len();
    for (archive, bytes) in eligible {
        if remaining <= MAX_ARCHIVES && used <= options.keep_bytes {
            break;
        }
        for path in archive.paths() {
            remove(path)?;
        }
        used = used.saturating_sub(bytes);
        remaining -= 1;
    }
    Ok(())
}

fn directory_entry_bytes(path: &Path) -> io::Result<u64> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => Ok(meta.len()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a regular log file",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error),
    }
}

pub(super) fn remove(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Buffer, persist::Disk};

    #[test]
    fn retention_expires_old_files_then_prunes_oldest_to_budget() -> Result<()> {
        let root = tempfile::tempdir()?;
        let now = OffsetDateTime::now_utc();
        let mut paths = Vec::new();
        for index in 1..=3 {
            let path = root
                .path()
                .join(format!("webservice.20261125T000000Z-{index:020}.log"));
            let file = fs::File::create(&path)?;
            file.set_len(2 << 20)?;
            if index == 3 {
                file.set_times(FileTimes::new().set_modified((now - Duration::days(9)).into()))?;
            }
            paths.push(path);
        }
        let active = fs::File::create(root.path().join("webservice.log"))?;
        active.set_len(1 << 20)?;
        prune(
            root.path(),
            ArchiveOptions {
                keep_days: 7,
                keep_bytes: 4 << 20,
            },
            now,
        )?;
        assert!(!paths[0].exists());
        assert!(paths[1].exists());
        assert!(!paths[2].exists());
        Ok(())
    }

    #[test]
    fn stale_compressor_cannot_publish_after_the_stream_was_cleared() -> Result<()> {
        let root = tempfile::tempdir()?;
        let raw = root.path().join("webservice.20261125T000000Z.log");
        fs::write(&raw, b"new file")?;
        let disk = Disk::open(
            root.path().to_owned(),
            MAX_RAW,
            1,
            None,
            &mut std::array::from_fn(|_| Buffer::default()),
        )?;
        disk.view.files.lock().unwrap()[Module::Web as usize].generation = 1;
        compress(&disk.view, 0, &raw)?;
        assert!(raw.exists());
        assert!(!raw.with_extension("log.gz").exists());
        Ok(())
    }

    #[test]
    fn query_skips_disjoint_gzip_without_reading_its_body() -> Result<()> {
        use crate::query::LogFile;
        use flate2::read::GzDecoder;

        let root = tempfile::tempdir()?;
        let raw = root.path().join("webservice.20261126T000000Z.log");
        fs::write(
            &raw,
            concat!(
                "{\"seq\":1,\"level\":\"info\",\"time\":\"2026-11-26T00:00:00.900Z\",\"message\":\"later\"}\n",
                "{\"seq\":2,\"level\":\"info\",\"time\":\"2026-11-25T00:00:00Z\",\"message\":\"earlier\"}\n",
            ),
        )?;
        let disk = Disk::open(
            root.path().to_owned(),
            MAX_RAW,
            1,
            None,
            &mut std::array::from_fn(|_| Buffer::default()),
        )?;
        compress(&disk.view, 0, &raw)?;
        let path = raw.with_extension("log.gz");
        let header = GzDecoder::new(fs::File::open(&path)?);
        let extra = header.header().unwrap().extra().unwrap();
        let earlier = OffsetDateTime::parse(
            "2026-11-25T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )?;
        let upper = OffsetDateTime::parse(
            "2026-11-26T00:00:00.950Z",
            &time::format_description::well_known::Rfc3339,
        )?;
        let mut filter = Filter::default();
        filter.from = Some(earlier);
        filter.to = Some(upper);
        assert!(!outside_time_range(Some(extra), &filter));
        filter.from = Some(upper);
        assert!(!outside_time_range(Some(extra), &filter));
        filter.from = Some(upper + Duration::seconds(1));
        filter.to = None;
        assert!(outside_time_range(Some(extra), &filter));
        let mut invalid_extra = extra.to_vec();
        invalid_extra[4] ^= 1;
        assert!(!outside_time_range(Some(&invalid_extra), &filter));
        assert!(!outside_time_range(None, &filter));
        drop(header);

        let mut corrupt = fs::read(&path)?;
        let footer = corrupt.len() - 8;
        corrupt[footer] ^= 1;
        fs::write(&path, corrupt)?;
        let read = LogFile::open(&path, true)?.unwrap();
        assert!(read.visit::<true>(Some(&filter), &mut |_| panic!("archive was not skipped"))?);
        let read = LogFile::open(&path, true)?.unwrap();
        assert!(read.visit::<true>(None, &mut |_| Ok(true)).is_err());
        Ok(())
    }
}
