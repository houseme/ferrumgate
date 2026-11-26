use std::{
    collections::VecDeque,
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::Arc,
};

use flate2::read::GzDecoder;
use time::format_description::well_known::Rfc3339;

use crate::{
    Entry, Filter, Level, Logs, MAX_FILE_BYTES, MAX_JSON_LINE, MAX_LINES, MAX_RING_BYTES, Module,
    Record,
    archive::{self, MAX_ARCHIVES, MAX_RAW},
    persist::open_regular,
};

const BLOCK: usize = 64 << 10;

#[derive(Debug)]
pub struct Page {
    pub entries: Vec<Arc<Entry>>,
    pub oldest_seq: u64,
    pub has_more: bool,
}

#[derive(Clone, Copy)]
pub enum Format {
    JsonLines,
    Csv,
}

impl Logs {
    /// Returns the latest matches in sequence order. A zero limit reads only memory.
    pub fn query(
        &self,
        module: Module,
        after: u64,
        before: u64,
        limit: usize,
        filter: &Filter,
    ) -> io::Result<Page> {
        if limit > MAX_LINES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "log query limit exceeds 20000",
            ));
        }
        let candidates = if limit > 0 && filter == &Filter::default() {
            limit + 1
        } else {
            0
        };
        let mut entries = self.recent(module, after, before, candidates);
        entries.retain(|entry| filter.matches(entry));
        if limit == 0 || entries.len() > limit || self.disk_view.is_none() {
            let has_more = limit > 0 && entries.len() > limit;
            if has_more {
                entries.drain(..entries.len() - limit);
            }
            return Ok(Page {
                oldest_seq: entries.first().map_or(0, |entry| entry.seq),
                entries,
                has_more,
            });
        }
        entries.clear();
        let mut has_more = false;
        let mut bytes = 0usize;
        self.snapshot(module, after, before)?.visit::<true>(|row| {
            let entry = row.entry();
            if entry.seq <= after {
                return Ok(false);
            }
            if in_range(entry.seq, after, before) && filter.matches(entry) {
                let received = entry.bytes();
                if entries.len() == limit || bytes + received > MAX_RING_BYTES {
                    has_more = true;
                    return Ok(false);
                }
                bytes += received;
                entries.push(row.into_arc());
            }
            Ok(true)
        })?;
        entries.reverse();
        Ok(Page {
            oldest_seq: entries.first().map_or(0, |entry| entry.seq),
            entries,
            has_more,
        })
    }

    /// Streams the retained records oldest first. Call on a blocking worker for file-backed logs.
    pub fn export(
        &self,
        module: Module,
        after: u64,
        before: u64,
        filter: &Filter,
        format: Format,
        output: impl Write,
    ) -> io::Result<()> {
        let snapshot = self.snapshot(module, after, before)?;
        let mut output = BufWriter::with_capacity(BLOCK, output);
        if matches!(format, Format::Csv) {
            output.write_all(b"\xEF\xBB\xBFtime,level,source,message,ip,host,site,status,method,path,rule,user,deny\r\n")?;
        }
        snapshot.visit::<false>(|row| {
            let entry = row.entry();
            if before != 0 && entry.seq >= before {
                return Ok(false);
            }
            if in_range(entry.seq, after, before) && filter.matches(entry) {
                match format {
                    Format::JsonLines => {
                        serde_json::to_writer(&mut output, entry)?;
                        output.write_all(b"\n")?;
                    }
                    Format::Csv => write_csv(&mut output, entry)?,
                }
            }
            Ok(true)
        })?;
        output.flush()
    }

    fn snapshot(&self, module: Module, after: u64, before: u64) -> io::Result<Snapshot> {
        let view = self.disk_view.as_ref();
        let files_guard = view.map(|view| view.files.lock().expect("log file mutex poisoned"));
        let buffer = self.layer.0.buffers[module as usize]
            .lock()
            .expect("log buffer poisoned");
        let latest = buffer.latest;
        let mut live: Vec<_> = buffer.range(after, before).cloned().collect();
        drop(buffer);
        let cutoff = files_guard
            .as_ref()
            .map_or(0, |files| files[module as usize].through);
        if let Some(disk) = &self.layer.0.disk {
            disk.snapshot(|Record(origin, entry)| {
                if *origin == module
                    && entry.seq > cutoff
                    && entry.seq <= latest
                    && in_range(entry.seq, after, before)
                {
                    live.push(entry.clone());
                }
            });
        }
        let mut files = Vec::new();
        if let Some(view) = view {
            if let Some(file) =
                LogFile::open(&view.dir.join(format!("{}.log.1", module.stem())), false)?
            {
                files.push(file);
            }
            if module == Module::Web && view.archive_web {
                let archives = archive::list(&view.dir)?;
                for item in &archives[archives.len().saturating_sub(MAX_ARCHIVES)..] {
                    let (path, gzip) = item.preferred();
                    if let Some(file) = LogFile::open(path, gzip)? {
                        files.push(file);
                    }
                }
            }
            if let Some(file) =
                LogFile::open(&view.dir.join(format!("{}.log", module.stem())), false)?
            {
                files.push(file);
            }
        }
        drop(files_guard);
        live.sort_unstable_by_key(|entry| entry.seq);
        live.dedup_by_key(|entry| entry.seq);
        Ok(Snapshot {
            files,
            live: live.into(),
        })
    }
}

fn in_range(seq: u64, after: u64, before: u64) -> bool {
    seq > after && (before == 0 || seq < before)
}

struct Snapshot {
    files: Vec<LogFile>,
    live: VecDeque<Arc<Entry>>,
}

pub(super) struct LogFile {
    pub file: File,
    size: u64,
    gzip: bool,
}

impl LogFile {
    pub fn open(path: &Path, gzip: bool) -> io::Result<Option<Self>> {
        let Some(file) = open_regular(path, false)? else {
            return Ok(None);
        };
        let size = file.metadata()?.len();
        Ok(Some(Self { file, size, gzip }))
    }

    pub fn visit<const REVERSE: bool>(
        self,
        visit: &mut impl FnMut(Entry) -> io::Result<bool>,
    ) -> io::Result<bool> {
        if self.gzip {
            let decoder = GzDecoder::new(self.file.take(self.size));
            if REVERSE {
                let mut contents = Vec::new();
                decoder.take(MAX_RAW + 1).read_to_end(&mut contents)?;
                let size = contents.len() as u64;
                if size > MAX_RAW {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Web log archive exceeds uncompressed limit",
                    ));
                }
                scan_reverse(Cursor::new(contents), size, visit)
            } else {
                scan_lines(
                    BufReader::with_capacity(BLOCK, decoder.take(MAX_RAW)),
                    visit,
                )
            }
        } else if REVERSE {
            scan_reverse(self.file, self.size, visit)
        } else {
            scan_forward(self.file, self.size, visit)
        }
    }
}

enum Row {
    Live(Arc<Entry>),
    File(Entry),
}

impl Row {
    fn entry(&self) -> &Entry {
        match self {
            Self::Live(entry) => entry,
            Self::File(entry) => entry,
        }
    }

    fn into_arc(self) -> Arc<Entry> {
        match self {
            Self::Live(entry) => entry,
            Self::File(entry) => Arc::new(entry),
        }
    }
}

impl Snapshot {
    fn visit<const REVERSE: bool>(
        mut self,
        mut visit: impl FnMut(Row) -> io::Result<bool>,
    ) -> io::Result<()> {
        let peek = |live: &VecDeque<Arc<Entry>>| {
            if REVERSE { live.back() } else { live.front() }.map(|entry| entry.seq)
        };
        let pop = |live: &mut VecDeque<Arc<Entry>>| {
            if REVERSE {
                live.pop_back()
            } else {
                live.pop_front()
            }
        };
        if REVERSE {
            self.files.reverse();
        }
        let mut previous = None;
        let mut merge = |entry: Entry| {
            let seq = entry.seq;
            if previous.is_some_and(|previous| {
                if REVERSE {
                    seq >= previous
                } else {
                    seq <= previous
                }
            }) {
                return Ok(true);
            }
            previous = Some(seq);
            while let Some(live) = peek(&self.live) {
                if if REVERSE { live < seq } else { live > seq } {
                    break;
                }
                let live = pop(&mut self.live).expect("peeked live log");
                let same = live.seq == seq;
                if !visit(Row::Live(live))? {
                    return Ok(false);
                }
                if same {
                    return Ok(true);
                }
            }
            visit(Row::File(entry))
        };
        for file in self.files {
            let proceed = file.visit::<REVERSE>(&mut merge)?;
            if !proceed {
                return Ok(());
            }
        }
        while let Some(live) = pop(&mut self.live) {
            if !visit(Row::Live(live))? {
                break;
            }
        }
        Ok(())
    }
}

pub(super) fn scan_forward(
    mut file: File,
    size: u64,
    mut visit: impl FnMut(Entry) -> io::Result<bool>,
) -> io::Result<bool> {
    let start = size.saturating_sub(MAX_FILE_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let mut reader = BufReader::with_capacity(BLOCK, file.take(size - start));
    if start != 0 {
        reader.skip_until(b'\n')?;
    }
    scan_lines(reader, &mut visit)
}

fn scan_lines(
    mut reader: impl BufRead,
    visit: &mut impl FnMut(Entry) -> io::Result<bool>,
) -> io::Result<bool> {
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = reader
            .by_ref()
            .take((MAX_JSON_LINE + 1) as u64)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(true);
        }
        if read > MAX_JSON_LINE {
            if line.last() != Some(&b'\n') {
                reader.skip_until(b'\n')?;
            }
        } else if !decode(&line, visit)? {
            return Ok(false);
        }
    }
}

fn scan_reverse(
    mut file: impl Read + Seek,
    size: u64,
    visit: &mut impl FnMut(Entry) -> io::Result<bool>,
) -> io::Result<bool> {
    let mut block = vec![0; BLOCK];
    let mut carry = Vec::new();
    let mut joined = Vec::new();
    let mut oversize = false;
    let mut end = size;
    let start = end.saturating_sub(MAX_FILE_BYTES);
    while end > start {
        let size = (end - start).min(BLOCK as u64) as usize;
        end -= size as u64;
        file.seek(SeekFrom::Start(end))?;
        file.read_exact(&mut block[..size])?;
        let mut pieces = block[..size].rsplit(|&byte| byte == b'\n');
        let right = pieces.next().expect("nonempty block");
        joined.clear();
        if right.len() + carry.len() > MAX_JSON_LINE {
            oversize = true;
        }
        if !oversize && !carry.is_empty() {
            joined.extend_from_slice(right);
            joined.extend_from_slice(&carry);
        }
        let boundary = if carry.is_empty() {
            right
        } else {
            joined.as_slice()
        };
        if let Some(mut left) = pieces.next() {
            if !oversize && !decode(boundary, visit)? {
                return Ok(false);
            }
            for next in pieces {
                if !decode(left, visit)? {
                    return Ok(false);
                }
                left = next;
            }
            oversize = left.len() > MAX_JSON_LINE;
            carry.clear();
            if !oversize {
                carry.extend_from_slice(left);
            }
        } else if oversize {
            carry.clear();
        } else if carry.is_empty() {
            carry.extend_from_slice(right);
        } else {
            std::mem::swap(&mut carry, &mut joined);
        }
    }
    if start == 0 && !oversize {
        decode(&carry, visit)
    } else {
        Ok(true)
    }
}

fn decode(line: &[u8], visit: &mut impl FnMut(Entry) -> io::Result<bool>) -> io::Result<bool> {
    if !line.is_empty()
        && line.len() <= MAX_JSON_LINE
        && let Ok(entry) = serde_json::from_slice::<Entry>(line)
        && entry.seq > 0
        && entry.seq < u64::MAX
        && entry.source.len() <= 256
    {
        return visit(entry);
    }
    Ok(true)
}

const CSV_FIELDS: [&str; 9] = [
    "ip", "host", "site", "status", "method", "path", "rule", "user", "deny",
];

fn write_csv(output: &mut impl Write, entry: &Entry) -> io::Result<()> {
    let timestamp = entry.time.format(&Rfc3339).map_err(io::Error::other)?;
    let level = match entry.level {
        Level::Debug => "debug",
        Level::Info => "info",
        Level::Warn => "warn",
        Level::Error => "error",
    };
    let fields = CSV_FIELDS
        .into_iter()
        .map(|key| entry.fields.get(key).map_or("", String::as_str));
    for (index, value) in [
        timestamp.as_str(),
        level,
        entry.source.as_str(),
        entry.message.as_str(),
    ]
    .into_iter()
    .chain(fields)
    .enumerate()
    {
        if index != 0 {
            output.write_all(b",")?;
        }
        output.write_all(b"\"")?;
        if value.starts_with(['\t', '\r', '\n'])
            || value
                .trim_start_matches(|ch: char| {
                    ch.is_whitespace() || ch.is_control() || ch == '\u{feff}'
                })
                .starts_with(['=', '+', '-', '@'])
        {
            output.write_all(b"'")?;
        }
        for part in value.split_inclusive('"') {
            output.write_all(part.as_bytes())?;
            if part.ends_with('"') {
                output.write_all(b"\"")?;
            }
        }
        output.write_all(b"\"")?;
    }
    output.write_all(b"\r\n")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, time::Duration};

    #[test]
    fn open_snapshot_survives_rotation_and_excludes_later_appends() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        let rotated = root.path().join("gately.log.1");
        let current = root.path().join("gately.log");
        let record = |seq: u64| {
            format!(
                "{{\"seq\":{seq},\"level\":\"info\",\"time\":\"2026-11-26T00:00:00Z\",\"message\":\"test\"}}\n"
            )
        };
        fs::write(&rotated, record(1))?;
        fs::write(&current, record(2))?;
        let logs = Logs::start(
            crate::Options {
                directory: Some(root.path().to_owned()),
                ..crate::Options::default()
            },
            io::sink(),
        )?;
        let view = logs.snapshot(Module::System, 0, 0)?;
        fs::rename(&current, &rotated)?;
        fs::OpenOptions::new()
            .append(true)
            .open(&rotated)?
            .write_all(record(3).as_bytes())?;
        fs::write(&current, record(4))?;
        let mut sequences = Vec::new();
        view.visit::<false>(|item| {
            sequences.push(item.entry().seq);
            Ok(true)
        })?;
        assert_eq!(sequences, [1, 2]);
        logs.shutdown(Duration::from_secs(3))?;
        Ok(())
    }
}
