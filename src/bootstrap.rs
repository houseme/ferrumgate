use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use clap::Args;
use fg_admin::{ApiRouter, SecurityExposure, SettingsState};
use fg_auth::{
    AccountManager, LoginLimits,
    passkey::Url,
    third_login::{ThirdLogin, ThirdLoginConfig},
    token::TokenManager,
};
use fg_config::{ConfigStore, Loaded};
use fg_core::{
    events::EventBus,
    settings::{
        DEFAULT_LOCK_MINUTES, DEFAULT_LOGIN_GLOBAL_LIMIT, DEFAULT_MAX_LOGIN_FAILURES, Settings,
    },
};
use fg_gateway::ManagementReady;
use fg_logging::LogHandle;
use tokio::{
    net::TcpListener,
    sync::{oneshot, watch},
};

#[derive(Args)]
pub struct AdminOptions {
    /// Enable the management service on a loopback address.
    #[arg(long, requires = "admin_dir")]
    admin_listen: Option<SocketAddr>,
    /// Enable management using this private directory and its configured listener.
    #[arg(long)]
    admin_dir: Option<PathBuf>,
    /// External management origin, used for Passkey and HTTPS cookies.
    #[arg(long, requires = "admin_dir")]
    admin_origin: Option<Url>,
    /// External path prefix removed by the trusted reverse proxy.
    #[arg(long, default_value = "", requires = "admin_dir")]
    admin_prefix: String,
}

pub async fn serve(
    config: PathBuf,
    mut options: AdminOptions,
    logs: LogHandle,
    set_log_level: impl Fn(&str) -> Result<()>,
) -> Result<()> {
    let Some(directory) = options.admin_dir.take() else {
        return fg_gateway::serve(config).await;
    };
    ensure!(
        options
            .admin_listen
            .is_none_or(|address| address.ip().is_loopback()),
        "management listener must bind to loopback"
    );
    let events = EventBus::default();
    let _auth_log = events.subscribe(|event| {
        tracing::info!(target: "fg_core::auth", kind = event.kind.info().name, "administrator authentication event");
        std::future::ready(())
    })?;
    let (accounts, tokens, settings, third_login) = tokio::task::spawn_blocking(move || {
        let store = ConfigStore::open(&directory)?;
        let third_login = match store.load::<ThirdLoginConfig>("third-login")? {
            Loaded::Found(config) => Some(config),
            Loaded::Missing => None,
        };
        let initial = std::env::var("FERRUMGATE_INITIAL_PASSWORD");
        let initial = match &initial {
            Ok(password) => Some(password.as_str()),
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => anyhow::bail!("initial password must be UTF-8"),
        };
        let (manager, generated) = AccountManager::open(store.clone(), initial)?;
        if let Some(password) = generated {
            eprintln!("Initial administrator password: {password}");
        }
        let manager = manager.with_login_events(events);
        manager.apply_pending_reset()?;
        let tokens = TokenManager::open(store.clone(), [], Instant::now())?;
        if tokens.migrate_legacy_settings("ferrumgate", time::OffsetDateTime::now_utc())? {
            tracing::info!(target: "fg_core::auth", "legacy API token migrated");
        }
        let settings = SettingsState::open(store, fg_gateway::REGISTRY)?;
        Ok::<_, anyhow::Error>((
            Arc::new(manager),
            Arc::new(tokens),
            Arc::new(settings),
            third_login,
        ))
    })
    .await??;
    let started = settings.snapshot();
    accounts.configure_login_limits(login_limits(&started))?;
    set_log_level(&started.log_level)?;
    let address = match options.admin_listen {
        Some(address) => address,
        None => match started.listen.strip_prefix(':') {
            Some(port) => SocketAddr::from((Ipv4Addr::LOCALHOST, port.parse::<u16>()?)),
            None => started.listen.parse()?,
        },
    };
    ensure!(
        address.ip().is_loopback(),
        "management listener must bind to loopback"
    );
    let listener = TcpListener::bind(address)
        .await
        .context("bind management listener")?;
    let third_login = if let Some(config) = third_login {
        let mut base = options
            .admin_origin
            .clone()
            .context("third-party login requires --admin-origin")?;
        ensure!(
            base.path() == "/" && base.query().is_none(),
            "management origin cannot have a path or query"
        );
        base.set_path(&format!("{}/", options.admin_prefix.trim_end_matches('/')));
        Some(Arc::new(
            ThirdLogin::new(accounts.clone(), base, config).await?,
        ))
    } else {
        None
    };
    let result = async {
        let (ready, waiting) = oneshot::channel();
        let gateway = fg_gateway::serve_with_management(config, &started.disabled_modules, ready);
        let management = async {
            let Ok(ready) = waiting.await else {
                return Ok(());
            };
            ManagementService {
                listener,
                options,
                accounts,
                tokens: tokens.clone(),
                logs,
                settings,
                third_login,
            }
            .run(ready, &set_log_level)
            .await
        };
        tokio::pin!(gateway, management);
        tokio::select! {
            biased;
            result = &mut gateway => {
                result?;
                tokio::time::timeout(Duration::from_secs(3), management).await
                    .context("management drain deadline expired")?
            }
            result = &mut management => {
                result?;
                // The gateway owns the process signal and data-plane drain.
                gateway.await
            }
        }
    }
    .await;
    let flushed = tokio::task::spawn_blocking(move || tokens.flush_usage_on_shutdown())
        .await
        .context("join API token shutdown flush")
        .and_then(|saved| saved.context("flush API token usage on shutdown"));
    result.and(flushed.map(|_| ()))
}

struct ManagementService {
    listener: TcpListener,
    options: AdminOptions,
    accounts: Arc<AccountManager>,
    tokens: Arc<TokenManager>,
    logs: LogHandle,
    settings: Arc<SettingsState>,
    third_login: Option<Arc<ThirdLogin>>,
}

impl ManagementService {
    async fn run(
        self,
        ready: ManagementReady,
        set_log_level: &impl Fn(&str) -> Result<()>,
    ) -> Result<()> {
        let Self {
            listener,
            options,
            accounts,
            tokens,
            logs,
            settings,
            third_login,
        } = self;
        let started = settings.snapshot();
        let updates = settings.subscribe();
        let router = ApiRouter::default()
            .with_modules(ready.registry, ready.enabled)
            .with_token_authentication(tokens.clone());
        let origin = options.admin_origin.as_ref();
        let router = if let Some(origin) = origin {
            router.with_passkey_accounts(accounts.clone(), &options.admin_prefix, origin)?
        } else {
            router.with_accounts(accounts.clone(), &options.admin_prefix, false)?
        };
        let exposure = SecurityExposure {
            exposed: origin.is_some_and(|url| url.domain() != Some("localhost")),
            secure: origin.is_some_and(|url| url.scheme() == "https"),
            protected_entry: false,
            passkey_rp: origin.and_then(Url::domain).map(str::to_owned),
        };
        let router = if let Some(service) = third_login {
            router.with_third_login(service)?
        } else {
            router
        };
        let admin = router
            .with_logs(logs)
            .with_security_status(accounts.clone(), exposure)
            .with_token_management(tokens.clone())
            .with_settings(settings, accounts.clone())
            .finish();
        tracing::info!(listen = %listener.local_addr()?, "management ready");
        let mut drain = ready.drain;
        let maintenance = poll_auth_maintenance(accounts.clone(), tokens, drain.clone());
        let runtime = apply_settings_updates(updates, started, &accounts, set_log_level);
        let server = axum::serve(
            listener,
            admin
                .router
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = drain.wait_for(|&draining| draining).await;
        })
        .into_future();
        tokio::pin!(server);
        tokio::select! {
            result = &mut server => result.context("serve management"),
            () = maintenance => server.await.context("drain management"),
            () = runtime => server.await.context("serve management after settings watcher closed"),
        }
    }
}

fn login_limits(settings: &Settings) -> LoginLimits {
    LoginLimits {
        max_failures: if settings.max_login_failures == 0 {
            DEFAULT_MAX_LOGIN_FAILURES
        } else {
            settings.max_login_failures as u32
        },
        lock_duration: Duration::from_secs(
            if settings.lock_minutes == 0 {
                DEFAULT_LOCK_MINUTES
            } else {
                settings.lock_minutes as u64
            } * 60,
        ),
        unknown_failures: match settings.login_global_limit {
            limit if limit < 0 => None,
            0 => Some(DEFAULT_LOGIN_GLOBAL_LIMIT),
            limit => Some(limit as u32),
        },
    }
}

async fn apply_settings_updates(
    mut updates: watch::Receiver<Arc<Settings>>,
    mut previous: Arc<Settings>,
    accounts: &AccountManager,
    set_log_level: &impl Fn(&str) -> Result<()>,
) {
    while updates.changed().await.is_ok() {
        let current = updates.borrow_and_update().clone();
        let limits = login_limits(&current);
        if limits != login_limits(&previous) && accounts.configure_login_limits(limits).is_err() {
            tracing::error!(target: "fg_core::settings", "login limits could not be applied");
        }
        if current.log_level != previous.log_level && set_log_level(&current.log_level).is_err() {
            tracing::error!(target: "fg_core::settings", "log level could not be applied");
        }
        previous = current;
    }
}

async fn poll_auth_maintenance(
    accounts: Arc<AccountManager>,
    tokens: Arc<TokenManager>,
    mut drain: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = drain.wait_for(|&draining| draining) => return,
            _ = interval.tick() => {},
        }
        let accounts = accounts.clone();
        let tokens = tokens.clone();
        let work = tokio::task::spawn_blocking(move || {
            if accounts.apply_pending_reset().is_err() {
                tracing::error!(target: "fg_core::auth", "administrator reset could not be applied");
            }
            if tokens.flush_usage(Instant::now()).is_err() {
                tracing::error!(target: "fg_core::auth", "API token usage could not be persisted");
            }
        })
        .await;
        if let Err(error) = work {
            tracing::error!(target: "fg_core::auth", %error, "authentication maintenance failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn auth_maintenance_flushes_due_token_usage() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = ConfigStore::open(directory.path())?;
        let (accounts, _) = AccountManager::open(store.clone(), Some("Fixture$Password-23"))?;
        let raw = "fixture-legacy-for-periodic-flush";
        let now = time::OffsetDateTime::now_utc();
        store.save("ferrumgate", &serde_json::json!({"apiToken": raw}))?;
        let tokens = TokenManager::open(store.clone(), [], Instant::now())?;
        assert!(tokens.migrate_legacy_settings("ferrumgate", now)?);
        drop(tokens);

        let tokens = Arc::new(TokenManager::open(
            store.clone(),
            [],
            Instant::now() - Duration::from_secs(60),
        )?);
        tokens.authenticate(raw, now, Some("127.0.0.1".parse()?))?;
        let (shutdown, drain) = watch::channel(false);
        let maintenance = tokio::spawn(poll_auth_maintenance(Arc::new(accounts), tokens, drain));
        let saved = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let data = store.load_raw("tokens")?.context("persisted tokens")?;
                let data: serde_json::Value = serde_json::from_slice(&data)?;
                if data["tokens"][0]["lastUsedIP"] == "127.0.0.1" {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        shutdown.send_replace(true);
        maintenance.await?;
        saved??;
        Ok(())
    }
}
