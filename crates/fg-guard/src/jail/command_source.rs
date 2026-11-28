//! The `command` source (WP-52 §3.3): runs the jail's command under
//! `sh -c` and feeds standard output lines into the engine. A command
//! that exits is restarted with a doubling backoff — 5 seconds at first,
//! capped at 1 minute — and the backoff resets once a run stayed alive
//! for the cap duration. Only identities with the `guard:write` scope
//! can configure commands (WP-52 §8).

use std::{process::Stdio, sync::Arc, time::Duration};

use tokio::{io::AsyncBufReadExt, process::Command, task::AbortHandle};

use super::JailEngine;

/// Upstream `retryBackoff`: the first restart waits 5 seconds.
pub const RETRY_BACKOFF: Duration = Duration::from_secs(5);
/// Upstream `maxBackoff`: restarts never wait longer than a minute.
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// The restart delay after `attempt`-th failure: 5 s, 10 s, 20 s, 40 s,
/// then capped at 60 s.
pub fn retry_backoff(attempt: u32, base: Duration, max: Duration) -> Duration {
    if attempt <= 1 {
        return base;
    }
    let shift = (attempt - 1).min(20);
    base.checked_mul(1u32 << shift)
        .unwrap_or(max)
        .min(max)
        .max(base)
}

/// Spawns a reader with the production backoff.
pub fn spawn(engine: Arc<JailEngine>, jail_key: &str, command: &str) -> AbortHandle {
    spawn_with(engine, jail_key, command, RETRY_BACKOFF, MAX_BACKOFF)
}

/// Spawns a reader with explicit backoff knobs (tests).
pub fn spawn_with(
    engine: Arc<JailEngine>,
    jail_key: &str,
    command: &str,
    base: Duration,
    max: Duration,
) -> AbortHandle {
    let jail_key = jail_key.to_owned();
    let command = command.to_owned();
    tokio::spawn(async move {
        let mut attempt = 0u32;
        loop {
            let started = std::time::Instant::now();
            match run_once(&jail_key, &command, &engine).await {
                Ok(()) => {}
                Err(error) => {
                    tracing::warn!(
                        module = "guard",
                        jail = %jail_key,
                        %error,
                        "the jail command exited"
                    );
                }
            }
            // A run that stayed alive for the cap period counts as
            // healthy; the next failure starts the backoff over.
            if started.elapsed() >= max {
                attempt = 0;
            }
            attempt += 1;
            tokio::time::sleep(retry_backoff(attempt, base, max)).await;
        }
    })
    .abort_handle()
}

/// Runs one command until it exits, feeding every stdout line.
async fn run_once(jail_key: &str, command: &str, engine: &JailEngine) -> anyhow::Result<()> {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| anyhow::anyhow!("spawning the jail command failed: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("the jail command has no stdout"))?;
    let mut lines = tokio::io::BufReader::new(stdout).lines();
    while let Some(line) = lines.next_line().await? {
        engine.on_line(jail_key, &line);
    }
    let status = child.wait().await?;
    anyhow::bail!("jail command exited with status {status}")
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

    #[test]
    fn command_backoff_starts_at_five_and_caps_at_a_minute() {
        let base = Duration::from_secs(5);
        let max = Duration::from_secs(60);
        assert_eq!(retry_backoff(1, base, max), base);
        assert_eq!(retry_backoff(2, base, max), Duration::from_secs(10));
        assert_eq!(retry_backoff(3, base, max), Duration::from_secs(20));
        assert_eq!(retry_backoff(4, base, max), Duration::from_secs(40));
        assert_eq!(retry_backoff(5, base, max), max);
        assert_eq!(retry_backoff(6, base, max), max);
        assert_eq!(retry_backoff(50, base, max), max);
        assert_eq!(
            retry_backoff(1, Duration::from_millis(10), max),
            Duration::from_millis(10)
        );
    }

    #[tokio::test]
    async fn command_restarts_with_backoff() {
        let service = GuardService::open_memory(&Settings::default(), EventBus::default());
        let engine = Arc::new(JailEngine::new(service, system_clock()));
        let jail = normalize_jail(Jail {
            key: "aabbccddeeff".to_owned(),
            name: "cmd".to_owned(),
            enable: true,
            source: JailSource::Command,
            target: "printf 'Failed password for root from 203.0.113.70\\n'; exit 1".to_owned(),
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
        // Tiny backoff keeps the test fast while still exercising the
        // restart loop: the command exits immediately, so it must run
        // repeatedly, each run feeding its line.
        let handle = super::spawn_with(
            Arc::clone(&engine),
            "aabbccddeeff",
            "printf 'Failed password for root from 203.0.113.70\\n'; exit 1",
            Duration::from_millis(5),
            Duration::from_millis(50),
        );
        for _ in 0..200 {
            if engine.service().is_banned("203.0.113.70".parse().unwrap()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(engine.service().is_banned("203.0.113.70".parse().unwrap()));
        handle.abort();
        engine.stop_sources();
    }
}
