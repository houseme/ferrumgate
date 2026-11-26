use std::{fs, io, path::Path, time::Duration};

use anyhow::Result;
use fg_logging::{Entry, Filter, Logs, Module, Options};
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
    let layer = tracing_subscriber::registry().with(logs.layer());
    tracing::subscriber::with_default(layer, || -> Result<()> {
        tracing::info!(target: "fgate", "old first");
        assert!(logs.set_directory(Some(busy.path().to_owned())).is_err());
        assert!(logs.set_directory(Some("relative".into())).is_err());
        tracing::info!(target: "fgate", "remaining in old directory");
        logs.set_directory(Some(next.path().to_owned()))?;
        let page = logs.query(Module::System, 0, 0, 1, &Filter::default())?;
        assert_eq!(page.entries[0].message, "destination history");
        assert!(
            logs.sources(Module::System)
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
        assert_eq!(logs.recent(Module::System, 0, 0, 1)[0].seq, 92);
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
