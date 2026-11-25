#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

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
        Command::Serve { config, log_level } => {
            tracing_subscriber::fmt()
                .with_max_level(log_level)
                .with_writer(std::io::stderr)
                .with_ansi(false)
                .init();
            fg_gateway::serve(config).await
        }
    }
}
