//! The `file` source (WP-52 §3.3): one reader task per target path,
//! polling through [`super::tail::Tail`] and feeding complete lines into
//! the engine. Reads are small and bounded; the task owns the tail and
//! is aborted by the engine's reconcile/shutdown paths.

use std::{sync::Arc, time::Duration};

use tokio::task::AbortHandle;

use super::JailEngine;

/// The poll interval; the tail is poll-based by design (see
/// [`super::tail`] for the rotation trade-off).
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Spawns a reader with the default poll interval.
pub fn spawn(engine: Arc<JailEngine>, jail_key: &str, path: &str) -> AbortHandle {
    spawn_with(engine, jail_key, path, POLL_INTERVAL)
}

/// Spawns a reader with an explicit poll interval (tests).
pub fn spawn_with(
    engine: Arc<JailEngine>,
    jail_key: &str,
    path: &str,
    interval: Duration,
) -> AbortHandle {
    let jail_key = jail_key.to_owned();
    let path = path.to_owned();
    tokio::spawn(async move {
        let mut tail = super::tail::Tail::new(&path);
        loop {
            match tail.poll() {
                Ok(lines) => {
                    for line in lines {
                        engine.on_line(&jail_key, &line);
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        module = "guard",
                        jail = %jail_key,
                        path = %path,
                        %error,
                        "reading the jail log file failed"
                    );
                }
            }
            tokio::time::sleep(interval).await;
        }
    })
    .abort_handle()
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path, time::Duration};

    use crate::bans::GuardService;
    use crate::jail::JailEngine;
    use crate::jail::validate::normalize_jail;
    use crate::jail::{Jail, JailSource};
    use crate::model::{FileConfig, Settings};
    use fg_core::events::EventBus;
    use fg_net::banlist::system_clock;

    #[tokio::test]
    async fn file_source_task_feeds_lines_and_bans() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path: &Path = &dir.path().join("auth.log");
        fs::write(path, "seed\n").expect("seed");
        let service = GuardService::open_memory(&Settings::default(), EventBus::default());
        let engine = std::sync::Arc::new(JailEngine::new(service, system_clock()));
        let jail = normalize_jail(Jail {
            key: "aabbccddeeff".to_owned(),
            name: "ssh".to_owned(),
            enable: true,
            source: JailSource::File,
            target: path.display().to_string(),
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
        // The first attach starts at EOF: the seed line stays history.
        let handle = super::spawn_with(
            std::sync::Arc::clone(&engine),
            "aabbccddeeff",
            &path.display().to_string(),
            Duration::from_millis(10),
        );
        // Let the reader attach at EOF first; the appended line is new
        // content, not history.
        tokio::time::sleep(Duration::from_millis(40)).await;
        fs::write(path, "seed\nFailed password for root from 203.0.113.66\n")
            .expect("append failure line");
        for _ in 0..100 {
            if engine.service().is_banned("203.0.113.66".parse().unwrap()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(engine.service().is_banned("203.0.113.66".parse().unwrap()));
        handle.abort();
        engine.stop_sources();
    }
}
