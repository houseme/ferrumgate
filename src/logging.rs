use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use fg_core::settings::{
    DEFAULT_ACCESS_LOG_DAYS, DEFAULT_ACCESS_LOG_MB, DEFAULT_LOG_FILE_MB, DEFAULT_LOG_LINES,
    Settings,
};
use fg_logging::{ArchiveOptions, LogHandle, Logs, Options};
use tracing::Level;
use tracing_subscriber::{
    Registry, filter::LevelFilter, layer::SubscriberExt, reload, util::SubscriberInitExt,
};

pub(crate) struct RuntimeLogs {
    logs: Arc<Mutex<Option<Logs>>>,
    handle: LogHandle,
    level: reload::Handle<LevelFilter, Registry>,
    level_override: Option<Level>,
    level_default: Level,
    directory_override: Option<PathBuf>,
}

impl RuntimeLogs {
    pub(crate) fn start(
        level_override: Option<Level>,
        directory_override: Option<PathBuf>,
        managed: bool,
    ) -> Result<Self> {
        let logs = Logs::start(
            Options {
                directory: if managed {
                    None
                } else {
                    directory_override.clone()
                },
                ..Options::default()
            },
            std::io::stderr(),
        )?;
        let level_default = std::env::var("FERRUMGATE_LOG_LEVEL")
            .ok()
            .and_then(|level| level.parse().ok())
            .unwrap_or(Level::INFO);
        let (filter, level) = reload::Layer::new(LevelFilter::from_level(
            level_override.unwrap_or(level_default),
        ));
        tracing_subscriber::registry()
            .with(filter)
            .with(logs.layer())
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(logs.echo())
                    .with_ansi(false),
            )
            .try_init()?;
        let handle = logs.handle();
        Ok(Self {
            logs: Arc::new(Mutex::new(Some(logs))),
            handle,
            level,
            level_override,
            level_default,
            directory_override,
        })
    }

    pub(crate) fn handle(&self) -> LogHandle {
        self.handle.clone()
    }

    pub(crate) fn set_level(&self, configured: &str) -> Result<()> {
        let level = self
            .level_override
            .or_else(|| configured.parse().ok())
            .unwrap_or(self.level_default);
        let level = LevelFilter::from_level(level);
        if self.level.with_current(|current| *current != level)? {
            self.level.reload(level)?;
        }
        Ok(())
    }

    pub(crate) fn options(&self, settings: &Settings, config_dir: &Path) -> Options {
        let directory = (!settings.disable_log_persist).then(|| {
            self.directory_override.clone().unwrap_or_else(|| {
                if settings.log_dir.is_empty() {
                    config_dir.join("logs")
                } else {
                    PathBuf::from(&settings.log_dir)
                }
            })
        });
        Options {
            web_archive: directory.as_ref().map(|_| ArchiveOptions {
                keep_days: if settings.access_log_days == 0 {
                    DEFAULT_ACCESS_LOG_DAYS
                } else {
                    settings.access_log_days as u32
                },
                keep_bytes: (if settings.access_log_mb == 0 {
                    DEFAULT_ACCESS_LOG_MB
                } else {
                    settings.access_log_mb as u64
                }) << 20,
            }),
            directory,
            lines: if settings.log_lines <= 0 {
                DEFAULT_LOG_LINES
            } else {
                settings.log_lines as usize
            },
            file_bytes: (if settings.log_file_mb == 0 {
                DEFAULT_LOG_FILE_MB
            } else {
                settings.log_file_mb as u64
            }) << 20,
        }
    }

    pub(crate) async fn configure(&self, options: Options) -> Result<()> {
        let logs = self.logs.clone();
        tokio::task::spawn_blocking(move || {
            logs.lock()
                .expect("runtime logging owner poisoned")
                .as_mut()
                .context("runtime logging has stopped")?
                .configure(options)
        })
        .await?
    }

    pub(crate) async fn shutdown(self) {
        let _ = tokio::task::spawn_blocking(move || {
            let logs = self
                .logs
                .lock()
                .expect("runtime logging owner poisoned")
                .take();
            if let Some(logs) = logs {
                let _ = logs.shutdown(Duration::from_secs(3));
            }
        })
        .await;
    }
}
