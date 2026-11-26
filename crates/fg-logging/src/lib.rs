#![forbid(unsafe_code)]

mod archive;
mod filter;
mod persist;
mod query;
mod queue;

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt::{self, Write as _},
    io::{self, BufWriter, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use arc_swap::ArcSwapOption;
pub use archive::ArchiveOptions;
pub use filter::Filter;
use persist::{Disk, DiskView};
pub use query::{Export, Format, Page};
use queue::{Queue, Worker};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{Layer, fmt::MakeWriter, layer::Context};

const MODULES: [Module; 4] = [
    Module::System,
    Module::Web,
    Module::Ssl,
    Module::PortForward,
];
const MAX_LINES: usize = 20_000;
const MAX_RING_BYTES: usize = 8 << 20;
const ECHO_BYTES: usize = 1 << 20;
const DISK_BYTES: usize = 4 << 20;
const MAX_SOURCES: usize = 1000;
const MAX_JSON_LINE: usize = 16 << 10;
const MAX_FILE_BYTES: u64 = 100 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Module {
    System,
    Web,
    Ssl,
    PortForward,
}

impl Module {
    fn stem(self) -> &'static str {
        match self {
            Self::System => "gately",
            Self::Web => "webservice",
            Self::Ssl => "ssl",
            Self::PortForward => "portforward",
        }
    }

    fn from_target(target: &str) -> Option<(Self, &str)> {
        if let Some(source) = target.strip_prefix("fg_gateway::") {
            let module = match source.split("::").next().unwrap_or(source) {
                "acme" | "certs" | "cert_deploy" | "dns01" | "tls" => Self::Ssl,
                "l4" | "tcp_forward" | "udp_forward" | "forward_metrics" => Self::PortForward,
                "web" | "proxy" | "health" | "websocket" | "site" | "static_files" => Self::Web,
                _ => Self::System,
            };
            return Some((module, source));
        }
        (target == "fgate" || target.starts_with("fg_core::")).then_some((Self::System, target))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Entry {
    pub seq: u64,
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub time: OffsetDateTime,
    pub level: Level,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

impl Entry {
    fn bytes(&self) -> usize {
        self.source.capacity()
            + self.message.capacity()
            + 128
            + self
                .fields
                .iter()
                .map(|(key, value)| key.capacity() + value.capacity() + 96)
                .sum::<usize>()
    }
}

#[derive(Default)]
struct Buffer {
    latest: u64,
    sources: BTreeSet<String>,
    entries: VecDeque<Arc<Entry>>,
    bytes: usize,
}

impl Buffer {
    fn range(&self, after: u64, before: u64) -> impl DoubleEndedIterator<Item = &Arc<Entry>> {
        let start = self.entries.partition_point(|entry| entry.seq <= after);
        let end = if before == 0 {
            self.entries.len()
        } else {
            self.entries.partition_point(|entry| entry.seq < before)
        };
        self.entries.range(start..end.max(start))
    }

    fn add(&mut self, entry: Arc<Entry>, bytes: usize, limit: usize) {
        self.latest = entry.seq;
        if !entry.source.is_empty()
            && self.sources.len() < MAX_SOURCES
            && !self.sources.contains(&entry.source)
        {
            self.sources.insert(entry.source.clone());
        }
        while self.entries.len() >= limit || self.bytes + bytes > MAX_RING_BYTES {
            let Some(old) = self.entries.pop_front() else {
                return;
            };
            self.bytes -= old.bytes();
        }
        self.bytes += bytes;
        self.entries.push_back(entry);
    }
}

pub struct Options {
    pub directory: Option<PathBuf>,
    pub lines: usize,
    pub file_bytes: u64,
    pub web_archive: Option<ArchiveOptions>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            directory: None,
            lines: 2000,
            file_bytes: 2 << 20,
            web_archive: None,
        }
    }
}

struct Record(Module, Arc<Entry>);

struct Shared {
    buffers: [Mutex<Buffer>; MODULES.len()],
    lines: usize,
    disk: ArcSwapOption<DiskTarget>,
    destinations: Mutex<()>,
}

struct DiskTarget {
    queue: Arc<Queue<Record>>,
    view: Arc<DiskView>,
    imported_through: [u64; MODULES.len()],
}

pub struct Logs {
    layer: LogLayer,
    echo: Worker<Vec<u8>>,
    disk: Option<Worker<Record>>,
    draining_disk: Option<Worker<Record>>,
    file_bytes: u64,
    web_archive: Option<ArchiveOptions>,
}

impl Logs {
    pub fn start(options: Options, echo: impl Write + Send + 'static) -> Result<Self> {
        ensure!(
            (1..=MAX_LINES).contains(&options.lines),
            "log line limit must be in 1..={MAX_LINES}"
        );
        ensure!(
            (1..=MAX_FILE_BYTES).contains(&options.file_bytes),
            "invalid log file size limit"
        );
        let mut buffers = std::array::from_fn(|_| Buffer::default());
        ensure!(
            options.web_archive.is_none() || options.directory.is_some(),
            "Web log archives require a log directory"
        );
        let disk = options
            .directory
            .map(|dir| {
                Disk::open(
                    dir,
                    options.file_bytes,
                    options.lines,
                    options.web_archive,
                    &mut buffers,
                )
            })
            .transpose()?;
        let mut output = BufWriter::with_capacity(64 << 10, echo);
        let echo = Worker::<Vec<u8>>::spawn(
            "fg-log-echo",
            ECHO_BYTES,
            1,
            Duration::ZERO,
            move |batch, lost| {
                if lost != 0 {
                    writeln!(output, "ferrumgate: dropped {lost} stderr log lines")?;
                }
                for line in batch {
                    output.write_all(line)?;
                }
                output.flush()
            },
        )?;
        let (disk, target) = disk
            .map(|sink| start_disk(sink, echo.queue.clone(), [0; MODULES.len()]))
            .transpose()?
            .unzip();
        let layer = LogLayer(Arc::new(Shared {
            buffers: buffers.map(Mutex::new),
            lines: options.lines,
            disk: ArcSwapOption::new(target),
            destinations: Mutex::new(()),
        }));
        Ok(Self {
            layer,
            echo,
            disk,
            draining_disk: None,
            file_bytes: options.file_bytes,
            web_archive: options.web_archive,
        })
    }

    pub fn handle(&self) -> LogHandle {
        LogHandle(self.layer.0.clone())
    }

    pub fn layer(&self) -> LogLayer {
        self.layer.clone()
    }

    pub fn echo(&self) -> Echo {
        Echo(self.echo.queue.clone())
    }

    /// Replaces the persistence destination while preserving the active tracing layer.
    /// The caller must keep the new path outside any roots already published by the application.
    pub fn set_directory(&mut self, directory: Option<PathBuf>) -> Result<()> {
        if let Some(path) = &directory {
            ensure!(path.is_absolute(), "log directory must be absolute");
            if self
                .layer
                .0
                .disk
                .load()
                .as_ref()
                .is_some_and(|disk| path.canonicalize().is_ok_and(|path| path == disk.view.dir))
            {
                return Ok(());
            }
        } else if self.disk.is_none() {
            return Ok(());
        }
        if let Some(worker) = &self.draining_disk {
            ensure!(
                worker.finished(),
                "previous log directory is still draining"
            );
            self.draining_disk = None;
        }

        // The destination scan only needs its latest sequence per stream and known sources.
        let mut restored = std::array::from_fn(|_| Buffer::default());
        let (next, target) = directory
            .map(|dir| {
                let sink = Disk::open(dir, self.file_bytes, 1, self.web_archive, &mut restored)?;
                let cutoff = restored.each_ref().map(|buffer| buffer.latest);
                Ok::<_, anyhow::Error>(start_disk(sink, self.echo.queue.clone(), cutoff)?)
            })
            .transpose()?
            .unzip();
        {
            let _destination = self
                .layer
                .0
                .destinations
                .lock()
                .expect("log destination poisoned");
            // Producers choose a queue under their stream lock, so no old-directory enqueue
            // can straddle this boundary.
            let mut buffers = self
                .layer
                .0
                .buffers
                .each_ref()
                .map(|buffer| buffer.lock().expect("log buffer poisoned"));
            for (buffer, restored) in buffers.iter_mut().zip(restored) {
                buffer.latest = buffer.latest.max(restored.latest);
                for source in restored.sources {
                    if buffer.sources.len() == MAX_SOURCES {
                        break;
                    }
                    buffer.sources.insert(source);
                }
            }
            self.layer.0.disk.store(target);
        }
        if let Some(old) = std::mem::replace(&mut self.disk, next) {
            old.close();
            if let Err(error) = old.wait(Instant::now() + Duration::from_secs(3)) {
                let notice = format!(
                    "ferrumgate: previous log directory did not flush ({:?})\n",
                    error.kind()
                )
                .into_bytes();
                let bytes = notice.capacity();
                self.echo.queue.push(notice, bytes);
                if error.kind() == io::ErrorKind::TimedOut {
                    self.draining_disk = Some(old);
                }
            }
        }
        Ok(())
    }

    pub fn recent(&self, module: Module, after: u64, before: u64, limit: usize) -> Vec<Arc<Entry>> {
        self.handle().recent(module, after, before, limit)
    }

    pub fn sources(&self, module: Module) -> Vec<String> {
        self.handle().sources(module)
    }

    pub fn clear(&self, module: Module) -> io::Result<()> {
        self.handle().clear(module)
    }

    pub fn shutdown(self, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        if let Some(disk) = &self.disk {
            disk.close();
        }
        let disk = self
            .disk
            .as_ref()
            .map(|disk| disk.wait(deadline))
            .transpose();
        let draining = self
            .draining_disk
            .as_ref()
            .map(|worker| worker.wait(deadline))
            .transpose();
        self.echo.close();
        let echo = self.echo.wait(deadline);
        disk.and(draining).and(echo)
    }
}

impl Drop for Logs {
    fn drop(&mut self) {
        if self.disk.is_some() {
            let _destination = self
                .layer
                .0
                .destinations
                .lock()
                .expect("log destination poisoned");
            self.layer.0.disk.store(None);
        }
    }
}

/// Access to current logs without taking ownership of their workers.
#[derive(Clone)]
pub struct LogHandle(Arc<Shared>);

impl LogHandle {
    pub fn recent(&self, module: Module, after: u64, before: u64, limit: usize) -> Vec<Arc<Entry>> {
        let buffer = self.0.buffers[module as usize]
            .lock()
            .expect("log buffer poisoned");
        let mut entries: Vec<_> = buffer
            .range(after, before)
            .rev()
            .take(if limit == 0 { usize::MAX } else { limit })
            .cloned()
            .collect();
        entries.reverse();
        entries
    }

    pub fn sources(&self, module: Module) -> Vec<String> {
        self.0.buffers[module as usize]
            .lock()
            .expect("log buffer poisoned")
            .sources
            .iter()
            .cloned()
            .collect()
    }

    /// Clears the selected stream and discards its already queued records.
    pub fn clear(&self, module: Module) -> io::Result<()> {
        let _destination = self
            .0
            .destinations
            .lock()
            .expect("log destination poisoned");
        let disk = self.0.disk.load();
        let view = disk.as_ref().map(|disk| &disk.view);
        let mut files = view.map(|view| view.files.lock().expect("log file mutex poisoned"));
        if let Some(view) = view {
            view.clear_files(module)?;
        }
        let mut buffer = self.0.buffers[module as usize]
            .lock()
            .expect("log buffer poisoned");
        if let Some(files) = &mut files {
            let clear = &mut files[module as usize];
            clear.through = buffer.latest;
            clear.generation += 1;
        }
        let entries = std::mem::take(&mut buffer.entries);
        let sources = std::mem::take(&mut buffer.sources);
        buffer.bytes = 0;
        drop(buffer);
        drop(files);
        drop((entries, sources));
        Ok(())
    }
}

fn start_disk(
    mut sink: Disk,
    echo: Arc<Queue<Vec<u8>>>,
    imported_through: [u64; MODULES.len()],
) -> io::Result<(Worker<Record>, Arc<DiskTarget>)> {
    let view = sink.view.clone();
    let worker = Worker::spawn(
        "fg-log-disk",
        DISK_BYTES,
        256 << 10,
        Duration::from_secs(1),
        move |batch, lost| {
            if lost != 0 {
                let notice =
                    format!("ferrumgate: dropped {lost} pending disk log entries\n").into_bytes();
                let bytes = notice.capacity();
                echo.push(notice, bytes);
            }
            sink.write(batch).inspect_err(|error| {
                let notice = format!(
                    "ferrumgate: runtime log persistence stopped ({:?})\n",
                    error.kind()
                )
                .into_bytes();
                let bytes = notice.capacity();
                echo.push(notice, bytes);
            })?;
            if let Err(error) = sink.maintain_archives() {
                let notice = format!(
                    "ferrumgate: Web log archive maintenance failed ({:?})\n",
                    error.kind()
                )
                .into_bytes();
                let bytes = notice.capacity();
                echo.push(notice, bytes);
            }
            Ok(())
        },
    )?;
    let target = Arc::new(DiskTarget {
        queue: worker.queue.clone(),
        view,
        imported_through,
    });
    Ok((worker, target))
}

#[derive(Clone)]
pub struct LogLayer(Arc<Shared>);

impl<S: Subscriber> Layer<S> for LogLayer {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let Some((module, source)) = Module::from_target(event.metadata().target()) else {
            return;
        };
        let mut visitor = Capture::default();
        event.record(&mut visitor);
        let mut buffer = self.0.buffers[module as usize]
            .lock()
            .expect("log buffer poisoned");
        let Some(seq) = buffer.latest.checked_add(1) else {
            return;
        };
        let level = match *event.metadata().level() {
            tracing::Level::ERROR => Level::Error,
            tracing::Level::WARN => Level::Warn,
            tracing::Level::INFO => Level::Info,
            _ => Level::Debug,
        };
        let entry = Arc::new(Entry {
            seq,
            time: OffsetDateTime::now_utc(),
            level,
            source: source.to_owned(),
            message: visitor.message,
            fields: visitor.fields,
        });
        let bytes = entry.bytes();
        buffer.add(entry.clone(), bytes, self.0.lines);
        if let Some(disk) = &*self.0.disk.load() {
            disk.queue.push(Record(module, entry), bytes);
        }
    }
}

#[derive(Default)]
struct Capture {
    message: String,
    fields: BTreeMap<String, String>,
}

impl Capture {
    fn value(&mut self, field: &Field, value: fmt::Arguments<'_>) {
        let name = field.name();
        if name == "message" {
            let _ = Limited(&mut self.message, 1024).write_fmt(value);
        } else if matches!(
            name,
            "source"
                | "site"
                | "backend"
                | "listen"
                | "metrics_listen"
                | "module"
                | "target"
                | "kind"
                | "domains"
                | "status"
                | "host"
                | "ip"
                | "listener"
                | "deny"
                | "admin"
                | "http"
                | "tls"
                | "required_by"
        ) {
            let mut text = String::new();
            let _ = Limited(&mut text, 256).write_fmt(value);
            self.fields.insert(name.to_owned(), text);
        }
    }
}

impl Visit for Capture {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.value(field, format_args!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.value(field, format_args!("{value}"));
    }
}

struct Limited<'a>(&'a mut String, usize);

impl fmt::Write for Limited<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let room = self.1 - self.0.len();
        self.0
            .push_str(&text[..text.floor_char_boundary(room.min(text.len()))]);
        if text.len() <= room {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

#[derive(Clone)]
pub struct Echo(Arc<Queue<Vec<u8>>>);

pub struct EchoLine<'a> {
    queue: &'a Queue<Vec<u8>>,
    bytes: Vec<u8>,
    too_long: bool,
}

impl<'a> MakeWriter<'a> for Echo {
    type Writer = EchoLine<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        EchoLine {
            queue: &self.0,
            bytes: Vec::new(),
            too_long: false,
        }
    }
}

impl Write for EchoLine<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_JSON_LINE - self.bytes.len() {
            self.too_long = true;
        }
        if !self.too_long {
            self.bytes.extend_from_slice(bytes);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for EchoLine<'_> {
    fn drop(&mut self) {
        if self.too_long {
            self.queue.record_loss();
        } else if !self.bytes.is_empty() {
            let bytes = std::mem::take(&mut self.bytes);
            let size = bytes
                .capacity()
                .saturating_add(std::mem::size_of::<Vec<u8>>());
            self.queue.push(bytes, size);
        }
    }
}
