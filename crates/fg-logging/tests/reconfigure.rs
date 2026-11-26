use std::{
    fs, io,
    path::Path,
    time::{Duration, SystemTime},
};

use anyhow::Result;
use fg_logging::{ArchiveOptions, Entry, Filter, Logs, Module, Options};
use tracing_subscriber::layer::SubscriberExt;

fn open(dir: &Path) -> Result<Logs> {
    Logs::start(
        Options {
            directory: Some(dir.to_owned()),
            ..Options::default()
        },
        io::sink(),
    )
}

fn disk_entries(dir: &Path) -> Result<Vec<Entry>> {
    fs::read_to_string(dir.join("gately.log"))?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

#[test]
fn directory_switch_preserves_old_files_and_uses_destination_sequence() -> Result<()> {
    let old = tempfile::tempdir()?;
    let next = tempfile::tempdir()?;
    let busy = tempfile::tempdir()?;
    let busy_logs = open(busy.path())?;
    fs::write(next.path().join("gately.log"), b"{\"seq\":90,\"time\":\"2026-11-26T00:00:00Z\",\"level\":\"info\",\"source\":\"imported\",\"message\":\"destination history\"}\n")?;
    let mut logs = open(old.path())?;
    let handle = logs.handle();
    let layer = tracing_subscriber::registry().with(logs.layer());
    tracing::subscriber::with_default(layer, || -> Result<()> {
        tracing::info!(target: "fgate", "old first");
        assert!(logs.set_directory(Some(busy.path().to_owned())).is_err());
        assert!(logs.set_directory(Some("relative".into())).is_err());
        tracing::info!(target: "fgate", "remaining in old directory");
        logs.set_directory(Some(next.path().to_owned()))?;
        let page = handle.query(Module::System, 0, 0, 1, &Filter::default())?;
        assert_eq!(page.entries[0].message, "destination history");
        assert!(
            handle
                .sources(Module::System)
                .contains(&"imported".to_owned())
        );
        assert_eq!(
            disk_entries(old.path())?
                .iter()
                .map(|entry| entry.seq)
                .collect::<Vec<_>>(),
            [1, 2]
        );

        tracing::info!(target: "fgate", "new directory");
        logs.set_directory(Some(next.path().join(".")))?;
        logs.set_directory(None)?;
        tracing::info!(target: "fgate", "memory only");
        assert_eq!(handle.recent(Module::System, 0, 0, 1)[0].seq, 92);
        logs.set_directory(Some(old.path().to_owned()))?;
        tracing::info!(target: "fgate", "back in old directory");
        Ok(())
    })?;
    logs.shutdown(Duration::from_secs(3))?;
    busy_logs.shutdown(Duration::from_secs(3))?;
    assert_eq!(
        disk_entries(old.path())?
            .iter()
            .map(|entry| entry.seq)
            .collect::<Vec<_>>(),
        [1, 2, 93]
    );
    assert_eq!(
        disk_entries(next.path())?
            .iter()
            .map(|entry| entry.seq)
            .collect::<Vec<_>>(),
        [90, 91]
    );
    assert!(!busy.path().join("gately.log").exists());
    let reopened = open(old.path())?;
    handle.clear(Module::System)?;
    assert_eq!(disk_entries(old.path())?.last().unwrap().seq, 93);
    reopened.shutdown(Duration::from_secs(3))?;
    Ok(())
}

#[test]
fn producers_keep_one_ordered_sequence_across_a_live_switch() -> Result<()> {
    let old = tempfile::tempdir()?;
    let next = tempfile::tempdir()?;
    let mut logs = open(old.path())?;
    let subscriber = tracing_subscriber::registry().with(logs.layer());
    tracing::subscriber::with_default(subscriber, || tracing::info!(target: "fgate", "before"));
    let producer = tracing_subscriber::registry().with(logs.layer());
    let start = std::sync::Barrier::new(2);
    std::thread::scope(|scope| -> Result<()> {
        let writer = scope.spawn(|| {
            tracing::subscriber::with_default(producer, || {
                start.wait();
                for number in 0..512 {
                    tracing::info!(target: "fgate", number, "during");
                }
            })
        });
        start.wait();
        logs.set_directory(Some(next.path().to_owned()))?;
        writer.join().unwrap();
        Ok(())
    })?;
    let subscriber = tracing_subscriber::registry().with(logs.layer());
    tracing::subscriber::with_default(subscriber, || tracing::info!(target: "fgate", "after"));
    logs.shutdown(Duration::from_secs(3))?;
    let stored: Vec<_> = disk_entries(old.path())?
        .into_iter()
        .chain(disk_entries(next.path())?)
        .map(|entry| entry.seq)
        .collect();
    assert_eq!(stored, (1..=514).collect::<Vec<_>>());
    Ok(())
}

#[test]
fn retention_changes_in_place_trim_the_ring_rotate_and_prune() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut logs = Logs::start(
        Options {
            directory: Some(root.path().into()),
            web_archive: Some(ArchiveOptions::default()),
            ..Options::default()
        },
        io::sink(),
    )?;
    let expired = root.path().join("webservice.20261120T010203Z.log.gz");
    let over_budget = root.path().join("webservice.20261125T010203Z.log.gz");
    fs::File::create(&expired)?
        .set_modified(SystemTime::now() - Duration::from_secs(2 * 86_400))?;
    fs::File::create(&over_budget)?.set_len(5 << 20)?;
    let subscriber = tracing_subscriber::registry().with(logs.layer());
    let message = "r".repeat(180);
    tracing::subscriber::with_default(subscriber, || -> Result<()> {
        for _ in 0..3 {
            tracing::info!(target: "fgate", "{message}");
        }
        logs.configure(Options {
            directory: Some(root.path().into()),
            lines: 2,
            file_bytes: 400,
            web_archive: Some(ArchiveOptions {
                keep_days: 1,
                keep_bytes: 4 << 20,
            }),
        })?;
        assert_eq!(
            logs.recent(Module::System, 0, 0, 0)
                .iter()
                .map(|entry| entry.seq)
                .collect::<Vec<_>>(),
            [2, 3]
        );
        assert!(!expired.exists());
        assert!(!over_budget.exists());
        tracing::info!(target: "fgate", "{message}");
        assert_eq!(logs.recent(Module::System, 0, 0, 0).last().unwrap().seq, 4);
        Ok(())
    })?;
    logs.shutdown(Duration::from_secs(3))?;
    assert!(root.path().join("gately.log.1").is_file());
    assert!(fs::metadata(root.path().join("gately.log"))?.len() <= 400);
    assert_eq!(disk_entries(root.path())?.last().unwrap().seq, 4);
    Ok(())
}
