use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwap;
use time::OffsetDateTime;

use super::{
    Buffer, MAX_JSON_LINE, MAX_RING_BYTES, MAX_SOURCES, MODULES, Module, Record,
    archive::{self, ArchiveOptions},
    query::{LogFile, scan_forward},
};

pub(super) struct Disk {
    pub view: Arc<DiskView>,
    streams: [Stream; MODULES.len()],
    encoded: Vec<u8>,
    maintenance_pending: bool,
}

/// Coordinates file snapshots with rotation without involving publishers.
pub(super) struct DiskView {
    pub dir: PathBuf,
    pub files: Mutex<[Clear; MODULES.len()]>,
    pub limits: ArcSwap<DiskLimits>,
    _lock: File,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct DiskLimits {
    pub file_bytes: u64,
    pub archive: Option<ArchiveOptions>,
}

#[derive(Clone, Copy, Default)]
pub(super) struct Clear {
    pub through: u64,
    pub generation: u64,
}

impl DiskView {
    pub fn configure(&self, file_bytes: u64, archive: Option<ArchiveOptions>) -> Result<()> {
        let archive = archive
            .map(|options| options.prepare(&self.dir))
            .transpose()?;
        let next = DiskLimits {
            file_bytes,
            archive,
        };
        let _files = self.files.lock().expect("log file mutex poisoned");
        let old = self.limits.load();
        if **old != next {
            if archive != old.archive
                && let Some(options) = archive
            {
                archive::prune(&self.dir, options, OffsetDateTime::now_utc())?;
            }
            self.limits.store(Arc::new(next));
        }
        Ok(())
    }

    pub fn clear_files(&self, module: Module) -> io::Result<()> {
        for suffix in ["log", "log.1", "sources"] {
            archive::remove(&self.dir.join(format!("{}.{suffix}", module.stem())))?;
        }
        if module == Module::Web {
            for entry in archive::list(&self.dir)? {
                for path in entry.paths() {
                    archive::remove(path)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct Stream {
    file: Option<OpenLog>,
    sources: BTreeSet<String>,
    changed_sources: bool,
    generation: u64,
}

struct OpenLog {
    writer: BufWriter<File>,
    size: u64,
    needs_delimiter: bool,
    started: Option<OffsetDateTime>,
}

impl Disk {
    pub fn open(
        dir: PathBuf,
        limit: u64,
        lines: usize,
        archive: Option<ArchiveOptions>,
        buffers: &mut [Buffer; MODULES.len()],
    ) -> Result<Self> {
        ensure!(dir.is_absolute(), "log directory must be absolute");
        ensure_dir(&dir).context("prepare runtime log directory")?;
        let dir = dir
            .canonicalize()
            .context("resolve runtime log directory")?;
        fg_core::fsperm::protect_log_directory(&dir)?;
        let lock = open_regular(&dir.join(".ferrumgate-log.lock"), true)?
            .context("open runtime log lock")?;
        lock.try_lock().context("runtime log directory is in use")?;
        let archive = archive.map(|options| options.prepare(&dir)).transpose()?;
        if let Some(options) = archive {
            archive::cleanup_temporaries(&dir)?;
            archive::prune(&dir, options, OffsetDateTime::now_utc())?;
        }
        let mut disk = Self {
            view: Arc::new(DiskView {
                dir,
                files: Mutex::new([Clear::default(); MODULES.len()]),
                limits: ArcSwap::from_pointee(DiskLimits {
                    file_bytes: limit,
                    archive,
                }),
                _lock: lock,
            }),
            streams: std::array::from_fn(|_| Stream::default()),
            encoded: Vec::with_capacity(1024),
            maintenance_pending: archive.is_some(),
        };
        for module in MODULES {
            let buffer = &mut buffers[module as usize];
            if module == Module::Web && archive.is_some() {
                restore_archived(&disk.view.dir, lines, buffer)?;
            } else {
                for suffix in ["log.1", "log"] {
                    restore(
                        &disk.view.dir.join(format!("{}.{suffix}", module.stem())),
                        lines,
                        buffer,
                    )
                    .with_context(|| format!("restore {} runtime log", module.stem()))?;
                }
            }

            if let Some(file) = open_regular(
                &disk.view.dir.join(format!("{}.sources", module.stem())),
                false,
            )? {
                private_file(&file)?;
                let mut bytes = Vec::new();
                file.take((MAX_SOURCES * 512 + 1) as u64)
                    .read_to_end(&mut bytes)?;
                if bytes.len() <= MAX_SOURCES * 512
                    && let Ok(sources) = serde_json::from_slice::<Vec<String>>(&bytes)
                {
                    for source in sources
                        .into_iter()
                        .filter(|source| !source.is_empty() && source.len() <= 256)
                    {
                        if buffer.sources.len() >= MAX_SOURCES {
                            break;
                        }
                        buffer.sources.insert(source);
                    }
                }
            }
            disk.streams[module as usize]
                .sources
                .clone_from(&buffer.sources);
        }
        Ok(disk)
    }

    pub fn write(&mut self, batch: &[Record]) -> io::Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let files = self.view.files.lock().expect("log file mutex poisoned");
        let limits = self.view.limits.load();
        for (stream, clear) in self.streams.iter_mut().zip(files.iter()) {
            if stream.generation != clear.generation {
                *stream = Stream {
                    generation: clear.generation,
                    ..Stream::default()
                };
            }
        }
        for Record(module, entry) in batch {
            if entry.seq <= files[*module as usize].through {
                continue;
            }
            let archive = limits.archive.filter(|_| *module == Module::Web);
            let limit = archive.map_or(limits.file_bytes, ArchiveOptions::file_limit);

            self.encoded.clear();
            serde_json::to_writer(&mut self.encoded, entry.as_ref())?;
            self.encoded.push(b'\n');
            if self.encoded.len() > MAX_JSON_LINE || self.encoded.len() as u64 > limit {
                continue;
            }
            let stream = &mut self.streams[*module as usize];
            if stream.file.is_none() {
                stream.file = Some(open_log(
                    &self.view.dir.join(format!("{}.log", module.stem())),
                    archive.is_some(),
                )?);
            }
            let record_len = self.encoded.len() as u64;
            let file = stream.file.as_mut().expect("log file opened");
            let new_day = archive.is_some()
                && file
                    .started
                    .is_some_and(|started| started.date() != entry.time.date());
            if (file.size != 0 && new_day)
                || file
                    .size
                    .saturating_add(record_len + u64::from(file.needs_delimiter))
                    > limit
            {
                let mut previous = stream.file.take().expect("log file opened");
                previous.writer.flush()?;
                let started = previous.started.unwrap_or(entry.time);
                drop(previous);
                let path = self.view.dir.join(format!("{}.log", module.stem()));
                if archive.is_some() {
                    archive::rotate(&self.view.dir, &path, started, entry.seq)?;
                    self.maintenance_pending = true;
                } else {
                    fs::rename(
                        &path,
                        self.view.dir.join(format!("{}.log.1", module.stem())),
                    )?;
                }
                stream.file = Some(open_log(&path, archive.is_some())?);
            }
            let file = stream.file.as_mut().expect("log file opened");
            if file.needs_delimiter {
                file.writer.write_all(b"\n")?;
                file.size += 1;
                file.needs_delimiter = false;
            }
            file.writer.write_all(&self.encoded)?;
            file.size += record_len;
            file.started.get_or_insert(entry.time);
            if stream.sources.len() < MAX_SOURCES
                && !entry.source.is_empty()
                && !stream.sources.contains(&entry.source)
            {
                stream.sources.insert(entry.source.clone());
                stream.changed_sources = true;
            }
        }
        for module in MODULES {
            let stream = &mut self.streams[module as usize];
            if let Some(file) = &mut stream.file {
                file.writer.flush()?;
            }
            if stream.changed_sources {
                let mut temporary = tempfile::Builder::new()
                    .prefix(".log-sources.")
                    .tempfile_in(&self.view.dir)
                    .map_err(|error| io::Error::from(error.kind()))?;
                private_file(temporary.as_file())?;
                serde_json::to_writer(temporary.as_file_mut(), &stream.sources)?;
                temporary
                    .into_temp_path()
                    .persist(self.view.dir.join(format!("{}.sources", module.stem())))
                    .map_err(|err| err.error)?;
                stream.changed_sources = false;
            }
        }
        Ok(())
    }
    pub fn maintain_archives(&mut self) -> io::Result<()> {
        if std::mem::take(&mut self.maintenance_pending)
            && self.view.limits.load().archive.is_some()
        {
            let result = archive::maintain(&self.view);
            self.maintenance_pending = result.is_err();
            result
        } else {
            Ok(())
        }
    }
}

fn restore_archived(dir: &Path, limit: usize, buffer: &mut Buffer) -> io::Result<()> {
    let mut recent = Vec::new();
    let mut bytes = 0;
    let mut visit = |entry: super::Entry| {
        if recent
            .last()
            .is_some_and(|previous: &super::Entry| entry.seq >= previous.seq)
        {
            return Ok(true);
        }
        let size = entry.bytes();
        if recent.len() == limit || bytes + size > MAX_RING_BYTES {
            return Ok(false);
        }
        bytes += size;
        recent.push(entry);
        Ok(true)
    };
    let archives = archive::list(dir)?;
    let current = dir.join("webservice.log");
    let previous = dir.join("webservice.log.1");
    let files = std::iter::once((current.as_path(), false))
        .chain(archives.iter().rev().map(archive::Archive::preferred))
        .chain(std::iter::once((previous.as_path(), false)));
    for (path, gzip) in files {
        if let Some(file) = LogFile::open(path, gzip)? {
            private_file(&file.file)?;
            if !file.visit::<true>(None, &mut visit)? {
                break;
            }
        }
    }
    for entry in recent.into_iter().rev() {
        let size = entry.bytes();
        buffer.add(Arc::new(entry), size, limit);
    }
    Ok(())
}

fn restore(path: &Path, lines: usize, buffer: &mut Buffer) -> io::Result<()> {
    let Some(file) = open_regular(path, false)? else {
        return Ok(());
    };
    private_file(&file)?;
    let size = file.metadata()?.len();
    scan_forward(file, size, |entry| {
        if entry.seq > buffer.latest {
            let bytes = entry.bytes();
            buffer.add(Arc::new(entry), bytes, lines);
        }
        Ok(true)
    })?;
    Ok(())
}

fn open_log(path: &Path, archiving: bool) -> io::Result<OpenLog> {
    let mut file = open_regular(path, true)?.ok_or(io::ErrorKind::NotFound)?;
    let size = file.metadata()?.len();
    let mut started = None;
    if archiving && size > 0 {
        scan_forward(file.try_clone()?, size, |entry| {
            started = Some(entry.time);
            Ok(false)
        })?;
        if started.is_none() {
            started = Some(file.metadata()?.modified()?.into());
        }
    }
    let mut last = *b"\n";

    if size != 0 {
        file.seek(SeekFrom::End(-1))?;
        file.read_exact(&mut last)?;
    }
    Ok(OpenLog {
        writer: BufWriter::with_capacity(32 << 10, file),
        size,
        needs_delimiter: last != *b"\n",
        started,
    })
}

pub(super) fn open_regular(path: &Path, append: bool) -> io::Result<Option<File>> {
    match fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_file() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a regular log file",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if !append {
                return Ok(None);
            }
        }
        Err(error) => return Err(error),
    }
    let mut options = OpenOptions::new();
    options.read(true).append(append).create(append);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a regular log file",
        ));
    }
    if append {
        private_file(&file)?;
    }
    Ok(Some(file))
}

fn ensure_dir(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a regular log directory",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
                builder.mode(0o700).create(path)?;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            }
            #[cfg(not(unix))]
            builder.create(path)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn private_file(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}
