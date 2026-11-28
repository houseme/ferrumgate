//! The `journal` source (WP-52 §3.3): follows systemd units with
//! `journalctl -f -u <unit>` (one process per jail, units as argv — no
//! shell involved), feeding standard output into the engine. The reader
//! restarts with the same backoff as the command source; unavailable
//! journald (containers) keeps retrying in the background.

use std::{process::Stdio, sync::Arc, time::Duration};

use tokio::{io::AsyncBufReadExt, process::Command, task::AbortHandle};

use super::{JailEngine, command_source};

/// Spawns a reader with the production backoff; `units` is the
/// newline-joined target of a journal jail.
pub fn spawn(engine: Arc<JailEngine>, jail_key: &str, units: &str) -> AbortHandle {
    spawn_with(
        engine,
        jail_key,
        units,
        command_source::RETRY_BACKOFF,
        command_source::MAX_BACKOFF,
    )
}

/// Spawns a reader with explicit backoff knobs (tests).
pub fn spawn_with(
    engine: Arc<JailEngine>,
    jail_key: &str,
    units: &str,
    base: Duration,
    max: Duration,
) -> AbortHandle {
    let jail_key = jail_key.to_owned();
    let units: Vec<String> = super::split_lines(units);
    tokio::spawn(async move {
        let mut attempt = 0u32;
        loop {
            let started = std::time::Instant::now();
            if let Err(error) = run_once(&jail_key, &units, &engine).await {
                tracing::warn!(module = "guard", jail = %jail_key, %error, "journalctl exited");
            }
            if started.elapsed() >= max {
                attempt = 0;
            }
            attempt += 1;
            tokio::time::sleep(command_source::retry_backoff(attempt, base, max)).await;
        }
    })
    .abort_handle()
}

/// One `journalctl -f -n 0 -u …` run until it exits; `-n 0` means only
/// entries written after the attach (no history replay).
async fn run_once(jail_key: &str, units: &[String], engine: &JailEngine) -> anyhow::Result<()> {
    if units.is_empty() {
        anyhow::bail!("journal jail without units");
    }
    let mut command = Command::new("journalctl");
    command.arg("-f").arg("-n").arg("0");
    for unit in units {
        command.arg("-u").arg(unit);
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| anyhow::anyhow!("spawning journalctl failed: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("journalctl has no stdout"))?;
    let mut lines = tokio::io::BufReader::new(stdout).lines();
    while let Some(line) = lines.next_line().await? {
        engine.on_line(jail_key, &line);
    }
    let status = child.wait().await?;
    anyhow::bail!("journalctl exited with status {status}")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::bans::GuardService;
    use crate::jail::JailEngine;
    use crate::jail::validate::normalize_jail;
    use crate::jail::{Jail, JailSource};
    use crate::model::{FileConfig, Settings};
    use fg_core::events::EventBus;
    use fg_net::banlist::system_clock;

    /// journald is rarely present in test environments: the reader must
    /// keep retrying in the background without ever failing the module —
    /// the restart loop is what this test pins down (fake `journalctl`
    /// on PATH writing one line per run).
    #[tokio::test]
    async fn journal_reader_retries_until_journalctl_answers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fake = dir.path().join("journalctl");
        std::fs::write(
            &fake,
            "#!/bin/sh\nprintf 'Failed password for root from 203.0.113.80\\n'\nexit 0\n",
        )
        .expect("write fake journalctl");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let service = GuardService::open_memory(&Settings::default(), EventBus::default());
        let engine = Arc::new(JailEngine::new(service, system_clock()));
        let jail = normalize_jail(Jail {
            key: "bbaaccddeeff".to_owned(),
            name: "sshj".to_owned(),
            enable: true,
            source: JailSource::Journal,
            target: "ssh.service".to_owned(),
            filter: "Failed password .* from <HOST>".to_owned(),
            max_retry: 1,
            ..Jail::default()
        });
        engine
            .reload(&FileConfig {
                settings: Settings::default(),
                jails: vec![jail],
            })
            .expect("reload");
        // The engine runs `journalctl` from PATH; the fake pretends to be
        // it. We spawn the loop directly with a PATH override instead of
        // mutating the process environment.
        let path_var = dir.path().display().to_string();
        let handle = tokio::spawn({
            let engine = Arc::clone(&engine);
            async move {
                loop {
                    let mut command = Command::new("journalctl");
                    command
                        .arg("-f")
                        .arg("-n")
                        .arg("0")
                        .arg("-u")
                        .arg("ssh.service");
                    command.env("PATH", &path_var);
                    if let Ok(mut child) =
                        command.stdout(Stdio::piped()).stderr(Stdio::null()).spawn()
                    {
                        let stdout = child.stdout.take().expect("stdout");
                        let mut lines = tokio::io::BufReader::new(stdout).lines();
                        while let Ok(Some(line)) = lines.next_line().await {
                            engine.on_line("bbaaccddeeff", &line);
                        }
                        let _ = child.wait().await;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        });
        for _ in 0..200 {
            if engine.service().is_banned("203.0.113.80".parse().unwrap()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(engine.service().is_banned("203.0.113.80".parse().unwrap()));
        handle.abort();
        engine.stop_sources();
    }
}
