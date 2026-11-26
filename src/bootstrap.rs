use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use clap::Args;
use fg_admin::{ApiRouter, SecurityExposure};
use fg_auth::{
    AccountManager,
    passkey::Url,
    third_login::{ThirdLogin, ThirdLoginConfig},
    token::TokenManager,
};
use fg_config::{ConfigStore, Loaded};
use fg_core::events::EventBus;
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
    /// Directory containing private management configuration.
    #[arg(long, requires = "admin_listen")]
    admin_dir: Option<PathBuf>,
    /// External management origin, used for Passkey and HTTPS cookies.
    #[arg(long, requires = "admin_listen")]
    admin_origin: Option<Url>,
    /// External path prefix removed by the trusted reverse proxy.
    #[arg(long, default_value = "", requires = "admin_listen")]
    admin_prefix: String,
}

pub async fn serve(config: PathBuf, mut options: AdminOptions, logs: LogHandle) -> Result<()> {
    let Some(address) = options.admin_listen else {
        return fg_gateway::serve(config).await;
    };
    ensure!(
        address.ip().is_loopback(),
        "management listener must bind to loopback"
    );
    let listener = TcpListener::bind(address)
        .await
        .context("bind management listener")?;
    let directory = options
        .admin_dir
        .take()
        .context("management configuration directory is required")?;
    let events = EventBus::default();
    let _auth_log = events.subscribe(|event| {
        tracing::info!(target: "fg_core::auth", kind = event.kind.info().name, "administrator authentication event");
        std::future::ready(())
    })?;
    let (accounts, third_login) = tokio::task::spawn_blocking(move || {
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
        let tokens = TokenManager::open(store, [], Instant::now())?;
        if tokens.migrate_legacy_settings("ferrumgate", time::OffsetDateTime::now_utc())? {
            tracing::info!(target: "fg_core::auth", "legacy API token migrated");
        }
        Ok::<_, anyhow::Error>((Arc::new(manager), third_login))
    })
    .await??;
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
    let (ready, waiting) = oneshot::channel();
    let gateway = fg_gateway::serve_with_ready(config, ready);
    let management = async {
        let Ok(ready) = waiting.await else {
            return Ok(());
        };
        serve_management(listener, options, accounts, logs, ready, third_login).await
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

async fn serve_management(
    listener: TcpListener,
    options: AdminOptions,
    accounts: Arc<AccountManager>,
    logs: LogHandle,
    ready: ManagementReady,
    third_login: Option<Arc<ThirdLogin>>,
) -> Result<()> {
    let router = ApiRouter::default().with_modules(ready.registry, ready.enabled);
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
        .finish();
    tracing::info!(listen = %listener.local_addr()?, "management ready");
    let mut drain = ready.drain;
    let resets = poll_resets(accounts, drain.clone());
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
        () = resets => server.await.context("drain management"),
    }
}

async fn poll_resets(accounts: Arc<AccountManager>, mut drain: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = drain.wait_for(|&draining| draining) => return,
            _ = interval.tick() => {
                let accounts = accounts.clone();
                match tokio::task::spawn_blocking(move || accounts.apply_pending_reset()).await {
                    Ok(Ok(_)) => {}
                    _ => tracing::error!(target: "fg_core::auth", "administrator reset could not be applied"),
                }
            }
        }
    }
}
