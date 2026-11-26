use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, ensure};

use super::{Buffer, MAX_JSON_LINE, MAX_SOURCES, MODULES, Record, query::scan_forward};

pub(super) struct Disk {
    pub view: Arc<DiskView>,
    limit: u64,
    streams: [Stream; MODULES.len()],
    _lock: File,
    encoded: Vec<u8>,
}

/// Coordinates file snapshots with rotation without involving publishers.
pub(super) struct DiskView {
    pub dir: PathBuf,
    pub files: Mutex<()>,
}

#[derive(Default)]
struct Stream {
    file: Option<OpenLog>,
    sources: BTreeSet<String>,
    changed_sources: bool,
}

struct OpenLog {
    writer: BufWriter<File>,
    size: u64,
    needs_delimiter: bool,
}

impl Disk {
    pub fn open(
        dir: PathBuf,
        limit: u64,
        lines: usize,
        buffers: &mut [Buffer; MODULES.len()],
    ) -> Result<Self> {
        ensure!(dir.is_absolute(), "log directory must be absolute");
        ensure_dir(&dir).context("prepare runtime log directory")?;
        let lock = open_regular(&dir.join(".ferrumgate-log.lock"), true)?
            .context("open runtime log lock")?;
        lock.try_lock().context("runtime log directory is in use")?;
        let mut disk = Self {
            view: Arc::new(DiskView {
                dir,
                files: Mutex::new(()),
            }),
            limit,
            _lock: lock,
            streams: std::array::from_fn(|_| Stream::default()),
            encoded: Vec::with_capacity(1024),
        };
        for module in MODULES {
            let buffer = &mut buffers[module as usize];
            for suffix in ["log.1", "log"] {
                restore(
                    &disk.view.dir.join(format!("{}.{suffix}", module.stem())),
                    lines,
                    buffer,
                )
                .with_context(|| format!("restore {} runtime log", module.stem()))?;
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
        let _files = self.view.files.lock().expect("log file mutex poisoned");
        for Record(module, entry) in batch {
            self.encoded.clear();
            serde_json::to_writer(&mut self.encoded, entry.as_ref())?;
            self.encoded.push(b'\n');
            if self.encoded.len() > MAX_JSON_LINE || self.encoded.len() as u64 > self.limit {
                continue;
            }
            let stream = &mut self.streams[*module as usize];
            if stream.file.is_none() {
                stream.file = Some(open_log(
                    &self.view.dir.join(format!("{}.log", module.stem())),
                )?);
            }
            let record_len = self.encoded.len() as u64;
            let file = stream.file.as_mut().expect("log file opened");
            if file
                .size
                .saturating_add(record_len + u64::from(file.needs_delimiter))
                > self.limit
            {
                let mut previous = stream.file.take().expect("log file opened");
                previous.writer.flush()?;
                drop(previous);
                let path = self.view.dir.join(format!("{}.log", module.stem()));
                fs::rename(
                    &path,
                    self.view.dir.join(format!("{}.log.1", module.stem())),
                )?;
                stream.file = Some(open_log(&path)?);
            }
            let file = stream.file.as_mut().expect("log file opened");
            if file.needs_delimiter {
                file.writer.write_all(b"\n")?;
                file.size += 1;
                file.needs_delimiter = false;
            }
            file.writer.write_all(&self.encoded)?;
            file.size += record_len;
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

fn open_log(path: &Path) -> io::Result<OpenLog> {
    let mut file = open_regular(path, true)?.ok_or(io::ErrorKind::NotFound)?;
    let size = file.metadata()?.len();
    let mut last = *b"\n";
    if size != 0 {
        file.seek(SeekFrom::End(-1))?;
        file.read_exact(&mut last)?;
    }
    Ok(OpenLog {
        writer: BufWriter::with_capacity(32 << 10, file),
        size,
        needs_delimiter: last != *b"\n",
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

fn private_file(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}
