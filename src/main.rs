#![forbid(unsafe_code)]

use std::{path::PathBuf, time::Duration};

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{filter::LevelFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "fgate", version, about = "FerrumGate reverse proxy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate and compile the configuration without opening listeners.
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run the gateway.
    Serve {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "info")]
        log_level: tracing::Level,
        /// Persist runtime logs to an absolute directory.
        #[arg(long)]
        log_dir: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Check { config } => {
            fg_gateway::check_config(&config).await?;
            println!("configuration is valid");
            Ok(())
        }
        Command::Serve {
            config,
            log_level,
            log_dir,
        } => {
            let logs = fg_logging::Logs::start(
                fg_logging::Options {
                    directory: log_dir.clone(),
                    ..Default::default()
                },
                std::io::stderr(),
            )?;
            if let Some(dir) = log_dir {
                fg_core::fsperm::protect(&dir.canonicalize()?);
            }
            tracing_subscriber::registry()
                .with(LevelFilter::from_level(log_level))
                .with(logs.layer())
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(logs.echo())
                        .with_ansi(false),
                )
                .try_init()?;
            let result = fg_gateway::serve(config).await;
            let _ = logs.shutdown(Duration::from_secs(3));
            result
        }
    }
}
