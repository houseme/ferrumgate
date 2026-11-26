#![forbid(unsafe_code)]

mod bootstrap;
mod logging;

use std::{
    io::{self, Write},
    path::PathBuf,
};

use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "fgate", version, about = "FerrumGate reverse proxy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Export management API documentation without starting a listener.
    ApiDocs { directory: PathBuf },
    /// Validate and compile the configuration without opening listeners.
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run the gateway.
    Serve {
        #[arg(long)]
        config: PathBuf,
        /// Override the runtime log level.
        #[arg(long)]
        log_level: Option<tracing::Level>,
        /// Persist runtime logs to an absolute directory.
        #[arg(long)]
        log_dir: Option<PathBuf>,
        #[command(flatten)]
        admin: bootstrap::AdminOptions,
    },
    /// Reset the administrator password using the private configuration directory.
    ResetPassword {
        #[arg(long)]
        admin_dir: PathBuf,
        #[arg(long)]
        disable_totp: bool,
    },
    /// Disable administrator TOTP using the private configuration directory.
    ResetTotp {
        #[arg(long)]
        admin_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::ApiDocs { directory } => {
            fg_admin::ApiRouter::default().finish().export(&directory)
        }
        Command::Check { config } => {
            fg_gateway::check_config(&config).await?;
            println!("configuration is valid");
            Ok(())
        }
        Command::ResetPassword {
            admin_dir,
            disable_totp,
        } => {
            confirm_reset()?;
            let password = rpassword::prompt_password("New administrator password: ")?;
            let again = rpassword::prompt_password("Repeat administrator password: ")?;
            ensure!(password == again, "passwords do not match");
            submit_reset(
                admin_dir,
                fg_auth::ResetRequest::password(&password, disable_totp)?,
            )
        }
        Command::ResetTotp { admin_dir } => {
            confirm_reset()?;
            submit_reset(admin_dir, fg_auth::ResetRequest::totp()?)
        }
        Command::Serve {
            config,
            log_level,
            log_dir,
            admin,
        } => {
            let logs = logging::RuntimeLogs::start(log_level, log_dir, admin.enabled())?;
            let result = bootstrap::serve(config, admin, &logs).await;
            logs.shutdown().await;
            result
        }
    }
}

fn confirm_reset() -> Result<()> {
    eprint!("Type yes to reset the administrator credentials: ");
    io::stderr().flush()?;
    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    ensure!(response.trim() == "yes", "reset cancelled");
    Ok(())
}

fn submit_reset(directory: PathBuf, request: fg_auth::ResetRequest) -> Result<()> {
    match fg_auth::submit_reset(fg_config::ConfigStore::open(&directory)?, request)? {
        fg_auth::ResetStatus::Applied => println!("Administrator reset applied"),
        fg_auth::ResetStatus::Pending => {
            println!("Administrator reset queued for the running service")
        }
    }
    Ok(())
}
