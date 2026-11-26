use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    path::Path,
    time::Duration,
};

use anyhow::Result;
use fg_logging::{ArchiveOptions, Entry, Filter, Format, Level, Logs, Module, Options};
use time::OffsetDateTime;
use tracing_subscriber::layer::SubscriberExt;

fn open(path: &Path) -> Result<Logs> {
    Logs::start(
        Options {
            directory: Some(path.to_owned()),
            lines: 3,
            web_archive: Some(ArchiveOptions {
                keep_bytes: 4 << 20,
                ..ArchiveOptions::default()
            }),
            ..Options::default()
        },
        io::sink(),
    )
}

fn row(seq: u64, time: OffsetDateTime, message: String) -> Result<Vec<u8>> {
    let mut line = serde_json::to_vec(&Entry {
        seq,
        time,
        message,
        level: Level::Info,
        source: "seed".into(),
        fields: BTreeMap::new(),
    })?;
    line.push(b'\n');
    Ok(line)
}

fn emit(logs: &Logs, message: &str) {
    tracing::subscriber::with_default(tracing_subscriber::registry().with(logs.layer()), || {
        tracing::info!(target: "fg_gateway::web", message);
    });
}

fn gzip_archives(dir: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|extension| extension == "gz") {
            files.push(path);
        }
    }
    Ok(files)
}

#[test]
fn archive_rotates_by_utc_day_then_restores_and_exports_gzip() -> Result<()> {
    let root = tempfile::tempdir()?;
    let prior = OffsetDateTime::now_utc() - time::Duration::days(1);
    fs::write(
        root.path().join("webservice.log"),
        row(1, prior, "older day".into())?,
    )?;
    let abandoned = root.path().join(".fg-log-archive.abandoned.tmp");
    fs::write(&abandoned, b"incomplete gzip")?;
    let logs = open(root.path())?;
    assert!(!abandoned.exists());
    emit(&logs, "current day");
    logs.shutdown(Duration::from_secs(3))?;
    assert_eq!(gzip_archives(root.path())?.len(), 1);
    assert!(!root.path().join("webservice.log.1").exists());

    let logs = open(root.path())?;
    let page = logs.query(Module::Web, 0, 0, 10, &Filter::default())?;
    assert_eq!(
        page.entries
            .iter()
            .map(|item| item.message.as_str())
            .collect::<Vec<_>>(),
        ["older day", "current day"]
    );
    let mut output = Vec::new();
    logs.export(
        Module::Web,
        0,
        0,
        &Filter::default(),
        Format::JsonLines,
        &mut output,
    )?;
    let rows = String::from_utf8(output)?
        .lines()
        .map(serde_json::from_str::<Entry>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        rows.iter().map(|entry| entry.seq).collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(logs.recent(Module::Web, 0, 0, 0).len(), 2);
    logs.shutdown(Duration::from_secs(3))?;
    Ok(())
}

#[test]
fn archive_rolls_over_at_byte_limit_during_the_same_day() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut file = fs::File::create(root.path().join("webservice.log"))?;
    let mut used = 0;
    let mut last = 0;
    let now = OffsetDateTime::now_utc();
    for sequence in 1.. {
        let bytes = row(sequence, now, "x".repeat(512))?;
        if used + bytes.len() + 800 > (1 << 20) {
            break;
        }
        file.write_all(&bytes)?;
        used += bytes.len();
        last = sequence;
    }
    drop(file);
    let logs = open(root.path())?;
    emit(&logs, &"f".repeat(1000));
    emit(&logs, &"g".repeat(1000));
    logs.shutdown(Duration::from_secs(3))?;
    assert_eq!(gzip_archives(root.path())?.len(), 1);
    assert!(fs::metadata(root.path().join("webservice.log"))?.len() <= 1 << 20);
    let logs = open(root.path())?;
    let page = logs.query(Module::Web, last - 1, 0, 10, &Filter::default())?;
    assert_eq!(
        page.entries.iter().map(|item| item.seq).collect::<Vec<_>>(),
        [last, last + 1, last + 2]
    );
    logs.shutdown(Duration::from_secs(3))?;
    Ok(())
}

#[test]
fn clear_drops_queued_history_and_preserves_other_modules() -> Result<()> {
    let root = tempfile::tempdir()?;
    let prior = OffsetDateTime::now_utc() - time::Duration::days(1);
    fs::write(
        root.path().join("webservice.log"),
        row(1, prior, "archive candidate".into())?,
    )?;
    let logs = open(root.path())?;
    emit(&logs, "rotate me");
    logs.shutdown(Duration::from_secs(3))?;
    assert_eq!(gzip_archives(root.path())?.len(), 1);

    let logs = open(root.path())?;
    emit(&logs, "clear me before disk flush");
    tracing::subscriber::with_default(tracing_subscriber::registry().with(logs.layer()), || {
        tracing::info!(target: "fg_gateway::server", "system log still present");
    });
    logs.clear(Module::Web)?;
    assert!(logs.sources(Module::Web).is_empty());
    assert!(
        logs.query(Module::Web, 0, 0, 100, &Filter::default())?
            .entries
            .is_empty()
    );
    assert_eq!(logs.recent(Module::System, 0, 0, 1).len(), 1);
    assert!(gzip_archives(root.path())?.is_empty());
    assert!(!root.path().join("webservice.sources").exists());
    emit(&logs, "after clear");
    logs.shutdown(Duration::from_secs(3))?;
    let logs = open(root.path())?;
    let page = logs.query(Module::Web, 0, 0, 100, &Filter::default())?;
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].seq, 4);
    assert_eq!(page.entries[0].message, "after clear");
    assert_eq!(logs.sources(Module::Web), ["web"]);
    logs.shutdown(Duration::from_secs(3))?;
    Ok(())
}
