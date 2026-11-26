use std::{
    fs,
    io::{self, Write},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

use anyhow::Result;
use fg_logging::{Entry, Level, Logs, Module, Options};
use tracing_subscriber::{filter::LevelFilter, fmt::MakeWriter, layer::SubscriberExt};

const DEADLINE: Duration = Duration::from_secs(3);

fn capture(logs: &Logs, actions: impl FnOnce()) {
    let layer = tracing_subscriber::registry()
        .with(LevelFilter::INFO)
        .with(logs.layer());
    tracing::subscriber::with_default(layer, actions);
}

#[test]
fn buffer_keeps_recent_sequence_and_allowed_fields() -> Result<()> {
    let logs = Logs::start(
        Options {
            lines: 2,
            ..Options::default()
        },
        io::sink(),
    )?;
    capture(&logs, || {
        tracing::debug!(target: "fg_gateway::health", "filtered");
        tracing::info!(target: "fg_gateway::health", "first");
        tracing::info!(target: "fg_gateway::health", site = "app.test", token = "private-value", "second");
        tracing::warn!(target: "fg_gateway::proxy", "third");
        tracing::info!(target: "fg_gateway::certs", "ssl event");
    });
    let entries = logs.recent(Module::Web, 0, 0, 0);
    assert_eq!(
        entries.iter().map(|entry| entry.seq).collect::<Vec<_>>(),
        [2, 3]
    );
    assert_eq!(entries[0].message, "second");
    assert_eq!(entries[0].fields["site"], "app.test");
    assert_eq!(entries[0].level, Level::Info);
    assert!(!serde_json::to_string(&entries[0].as_ref())?.contains("private-value"));
    assert_eq!(logs.recent(Module::Web, 1, 3, 1)[0].seq, 2);
    assert_eq!(logs.recent(Module::Web, 0, 0, 1)[0].seq, 3);
    assert_eq!(logs.sources(Module::Web), ["health", "proxy"]);
    assert_eq!(logs.recent(Module::Ssl, 0, 0, 0)[0].seq, 1);
    logs.shutdown(DEADLINE)?;
    Ok(())
}

#[test]
fn disk_rotates_once_and_restores_sequence_and_sources() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let options = || Options {
        directory: Some(dir.path().to_owned()),
        lines: 3,
        file_bytes: 650,
    };
    let logs = Logs::start(options(), io::sink())?;
    assert!(Logs::start(options(), io::sink()).is_err());
    capture(&logs, || {
        tracing::info!(target: "fg_gateway::health", "start");
        for index in 0..18 {
            tracing::info!(target: "fg_gateway::proxy", "{index}: {}", "x".repeat(88));
        }
    });
    logs.shutdown(DEADLINE)?;
    for name in ["webservice.log", "webservice.log.1"] {
        let meta = fs::metadata(dir.path().join(name))?;
        assert!(meta.len() <= 650);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }
    assert!(!dir.path().join("webservice.log.2").exists());
    let restored = Logs::start(options(), io::sink())?;
    let entries = restored.recent(Module::Web, 0, 0, 0);
    assert_eq!(
        entries.iter().map(|entry| entry.seq).collect::<Vec<_>>(),
        [17, 18, 19]
    );
    assert_eq!(restored.sources(Module::Web), ["health", "proxy"]);
    capture(
        &restored,
        || tracing::info!(target: "fg_gateway::proxy", "continued"),
    );
    assert_eq!(restored.recent(Module::Web, 0, 0, 1)[0].seq, 20);
    restored.shutdown(DEADLINE)?;
    Ok(())
}

#[test]
fn disk_recovers_past_a_partial_last_record() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let options = || Options {
        directory: Some(dir.path().to_owned()),
        ..Options::default()
    };
    let logs = Logs::start(options(), io::sink())?;
    capture(
        &logs,
        || tracing::info!(target: "fg_gateway::server", "first"),
    );
    logs.shutdown(DEADLINE)?;
    fs::OpenOptions::new()
        .append(true)
        .open(dir.path().join("gately.log"))?
        .write_all(b"{incomplete")?;
    let logs = Logs::start(options(), io::sink())?;
    assert_eq!(logs.recent(Module::System, 0, 0, 1)[0].seq, 1);
    capture(
        &logs,
        || tracing::info!(target: "fg_gateway::server", "second"),
    );
    logs.shutdown(DEADLINE)?;
    let logs = Logs::start(options(), io::sink())?;
    let entries = logs.recent(Module::System, 0, 0, 0);
    assert_eq!(
        entries
            .iter()
            .map(|entry| (entry.seq, entry.message.as_str()))
            .collect::<Vec<_>>(),
        [(1, "first"), (2, "second")]
    );
    logs.shutdown(DEADLINE)?;
    Ok(())
}

#[test]
fn disk_flushes_a_small_batch_while_running() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let logs = Logs::start(
        Options {
            directory: Some(dir.path().to_owned()),
            ..Options::default()
        },
        io::sink(),
    )?;
    capture(&logs, || {
        tracing::info!(target: "fg_gateway::server", "first periodic record");
        tracing::info!(target: "fg_gateway::server", "second periodic record");
    });
    let deadline = Instant::now() + DEADLINE;
    let file = dir.path().join("gately.log");
    loop {
        if let Ok(text) = fs::read_to_string(&file)
            && text.lines().count() == 2
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "disk batch did not flush before shutdown"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    logs.shutdown(DEADLINE)?;
    Ok(())
}

struct SlowEcho {
    entered: Option<mpsc::Sender<()>>,
    resume: mpsc::Receiver<()>,
    output: Arc<Mutex<Vec<u8>>>,
}

impl Write for SlowEcho {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(entered) = self.entered.take() {
            entered.send(()).unwrap();
            self.resume
                .recv_timeout(DEADLINE)
                .map_err(|_| io::ErrorKind::TimedOut)?;
        }
        self.output.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn blocked_stderr_drops_echo_and_keeps_disk_and_memory_active() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let output = Arc::new(Mutex::new(Vec::new()));
    let (entered, blocked) = mpsc::channel();
    let (resume, wait) = mpsc::channel();
    let logs = Logs::start(
        Options {
            directory: Some(dir.path().to_owned()),
            ..Options::default()
        },
        SlowEcho {
            entered: Some(entered),
            resume: wait,
            output: output.clone(),
        },
    )?;
    let echo = logs.echo();
    echo.make_writer().write_all(b"first\n")?;
    blocked.recv_timeout(DEADLINE)?;
    let bytes = [b'z'; 8192];
    for _ in 0..200 {
        echo.make_writer().write_all(&bytes)?;
    }
    capture(
        &logs,
        || tracing::info!(target: "fg_gateway::server", "logging during stderr stall"),
    );
    assert_eq!(logs.recent(Module::System, 0, 0, 1)[0].seq, 1);
    resume.send(())?;
    logs.shutdown(DEADLINE)?;
    let disk = fs::read(dir.path().join("gately.log"))?;
    let entry: Entry = serde_json::from_slice(&disk)?;
    assert_eq!(entry.message, "logging during stderr stall");
    assert!(String::from_utf8_lossy(&output.lock().unwrap()).contains("stderr log lines"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn persistence_rejects_symlinked_files_without_touching_targets() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let target = dir.path().join("outside");
    let logs = dir.path().join("logs");
    fs::write(&target, "outside")?;
    fs::create_dir(&logs)?;
    std::os::unix::fs::symlink(&target, logs.join("gately.log"))?;
    assert!(
        Logs::start(
            Options {
                directory: Some(logs),
                ..Options::default()
            },
            io::sink()
        )
        .is_err()
    );
    assert_eq!(fs::read(&target)?, b"outside");
    Ok(())
}
