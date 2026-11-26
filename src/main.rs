#![forbid(unsafe_code)]

mod bootstrap;
mod ctl;
mod logging;
mod mcp;
mod offline;
mod publicip;
mod restart;

use std::{
    io::{self, Write},
    path::PathBuf,
};

use anyhow::{Result, ensure};
use clap::{Args, Parser, Subcommand};

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
        admin: Box<bootstrap::AdminOptions>,
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
    /// Roll back a configuration change using the private configuration directory.
    Rollback {
        /// Private configuration directory (defaults to ./data).
        #[arg(
            short = 'c',
            long = "admin-dir",
            alias = "config-dir",
            default_value = "./data"
        )]
        admin_dir: PathBuf,
        /// List rollback candidates without changing anything.
        #[arg(long)]
        list: bool,
        /// Undo the most recent configuration save.
        #[arg(long)]
        last: bool,
        /// Roll back the pending unconfirmed change.
        #[arg(long)]
        pending: bool,
        /// Target configuration name (requires --version).
        #[arg(long, requires = "version")]
        config: Option<String>,
        /// Target history version (requires --config).
        #[arg(long, requires = "config")]
        version: Option<String>,
        /// Skip the interactive confirmation.
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Call the management API of a running instance with an API token.
    Ctl {
        /// Instance base URL (defaults to the saved config, then http://127.0.0.1:16680).
        #[arg(long, short = 'u')]
        url: Option<String>,
        /// API token (defaults to the saved config or FERRUMGATE_TOKEN).
        #[arg(long, short = 't')]
        token: Option<String>,
        /// Skip TLS certificate verification.
        #[arg(long)]
        insecure: bool,
        /// Print the response body verbatim instead of formatted JSON.
        #[arg(long)]
        raw: bool,
        #[command(subcommand)]
        verb: CtlVerb,
    },
    /// Serve the management API as MCP tools over standard input/output.
    Mcp {
        #[command(flatten)]
        args: McpArgs,
    },
}

#[derive(Subcommand)]
enum CtlVerb {
    /// List operations the token may call, optionally filtered by keyword.
    Ls { filter: Option<String> },
    /// GET an API path.
    Get { path: String },
    /// POST an API path with a JSON body (literal, @file or -).
    Post { path: String, body: Option<String> },
    /// PUT an API path with a JSON body (literal, @file or -).
    Put { path: String, body: Option<String> },
    /// DELETE an API path.
    Delete { path: String },
    /// PATCH an API path with a JSON body (literal, @file or -).
    Patch { path: String, body: Option<String> },
    /// Verify a token against an instance and save the connection.
    Login { url: String, token: String },
}

/// `fgate mcp`: expose the management API as MCP tools over stdio.
#[derive(Args)]
struct McpArgs {
    /// Instance base URL (defaults to the saved config, then FERRUMGATE_URL).
    #[arg(long, short = 'u')]
    url: Option<String>,
    /// API token (defaults to the saved config or FERRUMGATE_TOKEN).
    #[arg(long, short = 't')]
    token: Option<String>,
    /// Also expose write operations (GET/HEAD only by default).
    #[arg(long)]
    write: bool,
    /// Skip TLS certificate verification.
    #[arg(long)]
    insecure: bool,
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
        Command::Ctl {
            url,
            token,
            insecure,
            raw,
            verb,
        } => {
            let command = match verb {
                CtlVerb::Ls { filter } => ctl::commands::Command::Ls { filter },
                CtlVerb::Get { path } => ctl::commands::Command::Get { path },
                CtlVerb::Post { path, body } => ctl::commands::Command::Call {
                    method: hyper::Method::POST,
                    path,
                    body,
                },
                CtlVerb::Put { path, body } => ctl::commands::Command::Call {
                    method: hyper::Method::PUT,
                    path,
                    body,
                },
                CtlVerb::Delete { path } => ctl::commands::Command::Call {
                    method: hyper::Method::DELETE,
                    path,
                    body: None,
                },
                CtlVerb::Patch { path, body } => ctl::commands::Command::Call {
                    method: hyper::Method::PATCH,
                    path,
                    body,
                },
                CtlVerb::Login { url, token } => ctl::commands::Command::Login { url, token },
            };
            // Usage problems exit with 2; transport errors abort with 1.
            match ctl::run(
                ctl::CtlOptions {
                    url,
                    token,
                    insecure,
                    raw,
                },
                command,
            )
            .await
            {
                Err(error) => {
                    eprintln!("Error: {error:#}");
                    std::process::exit(2);
                }
                Ok(code) if code != 0 => std::process::exit(code),
                Ok(_) => Ok(()),
            }
        }
        Command::Mcp { args } => {
            let McpArgs {
                url,
                token,
                write,
                insecure,
            } = args;
            let environment = match (
                std::env::var("FERRUMGATE_URL"),
                std::env::var("FERRUMGATE_TOKEN"),
            ) {
                (Ok(url), Ok(token)) => Some((url, token)),
                (Ok(url), Err(_)) => Some((url, String::new())),
                (Err(_), Ok(token)) => Some((String::new(), token)),
                (Err(_), Err(_)) => None,
            };
            let config = ctl::config::CtlConfig::resolve(
                ctl::config::CtlConfig::load(),
                environment,
                ctl::config::Overrides {
                    url,
                    token,
                    insecure,
                },
            );
            mcp::run(mcp::McpOptions {
                url: config.url,
                token: config.token,
                insecure: config.insecure,
                write,
            })
            .await
        }
        Command::Rollback {
            admin_dir,
            list,
            pending,
            last,
            config,
            version,
            yes,
        } => match offline::run(offline::RollbackOptions {
            config_dir: admin_dir,
            list,
            pending,
            last,
            config,
            version,
            yes,
        }) {
            Ok(code) => {
                std::process::exit(code);
            }
            Err(error) => {
                eprintln!("Error: {error:#}");
                std::process::exit(1);
            }
        },
        Command::Serve {
            config,
            log_level,
            log_dir,
            admin,
        } => {
            let admin = *admin;
            let logs = logging::RuntimeLogs::start(log_level, log_dir, admin.enabled())?;
            let outcome = bootstrap::serve(config, admin, &logs).await;
            logs.shutdown().await;
            match outcome? {
                bootstrap::Outcome::Exit => Ok(()),
                bootstrap::Outcome::Restart => restart::exec_self(
                    std::env::current_exe()?,
                    std::env::args_os().skip(1).collect(),
                ),
            }
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
