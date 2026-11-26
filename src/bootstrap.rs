use std::{
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use clap::Args;
use fg_admin::{ApiRouter, AuditLog, Category, ManagedThirdLogin, SecurityExposure, SettingsState};
use fg_auth::{AccountManager, LoginLimits, passkey::Url, token::TokenManager};
use fg_config::ConfigStore;
use fg_core::{
    events::EventBus,
    settings::{
        DEFAULT_LOCK_MINUTES, DEFAULT_LOGIN_GLOBAL_LIMIT, DEFAULT_MAX_LOGIN_FAILURES, Settings,
    },
};
use fg_gateway::ManagementReady;
use tokio::{
    net::TcpListener,
    sync::{Notify, oneshot, watch},
};

use crate::logging::RuntimeLogs;

/// How `bootstrap::serve` finished: a normal drain or a restart request.
pub enum Outcome {
    Exit,
    Restart,
}

/// Shared signal behind `POST /api/system/restart`; the response is written
/// before the trigger fires so the client observes it.
#[derive(Clone, Default)]
struct RestartTrigger(Arc<Notify>);

impl RestartTrigger {
    fn notify(&self) {
        self.0.notify_one();
    }

    async fn notified(&self) {
        self.0.notified().await;
    }
}

/// Names that never get history snapshots: credential and runtime state.
const HISTORY_SKIP: [&str; 3] = ["account", "tokens", "login-ips"];

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
    /// Apply declarative <name>.json files from this directory at startup.
    #[arg(long = "apply", env = "FERRUMGATE_APPLY_DIR", requires = "admin_dir")]
    apply_dir: Option<PathBuf>,
}

impl AdminOptions {
    pub(crate) fn enabled(&self) -> bool {
        self.admin_dir.is_some()
    }
}

pub async fn serve(
    config: PathBuf,
    mut options: AdminOptions,
    logs: &RuntimeLogs,
) -> Result<Outcome> {
    let Some(directory) = options.admin_dir.take() else {
        return fg_gateway::serve(config).await.map(|()| Outcome::Exit);
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
    let origin = options.admin_origin.clone();
    let setup_events = events.clone();
    let apply_dir = options.apply_dir.take();
    let (accounts, tokens, settings, store) = tokio::task::spawn_blocking(move || {
        let store = ConfigStore::open(&directory)?;
        // Snapshot every configuration change except credential and
        // runtime state, so offline rollback requests have versions to use.
        store.enable_history(30, &HISTORY_SKIP);
        // Declarative files state the operator's intent: apply them before
        // any configuration, account or settings is read.
        if let Some(apply_dir) = &apply_dir {
            let report = fg_config::apply::apply_config_dir(&store, apply_dir)
                .context("apply declarative configuration")?;
            tracing::info!(
                target: "fgate::bootstrap",
                applied = report.applied,
                skipped = report.skipped,
                names = ?report.names,
                "declarative configuration applied"
            );
        }
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
        let manager = manager.with_login_events(setup_events);
        manager.apply_pending_reset()?;
        let tokens = TokenManager::open(store.clone(), [], Instant::now())?;
        if tokens.migrate_legacy_settings("ferrumgate", time::OffsetDateTime::now_utc())? {
            tracing::info!(target: "fg_core::auth", "legacy API token migrated");
        }
        let settings =
            SettingsState::open_with_origin(store.clone(), fg_gateway::REGISTRY, origin)?;
        Ok::<_, anyhow::Error>((
            Arc::new(manager),
            Arc::new(tokens),
            Arc::new(settings),
            store,
        ))
    })
    .await??;
    let started = settings.snapshot();
    accounts.configure_login_limits(login_limits(&started))?;
    logs.set_level(&started.log_level)?;
    logs.configure(logs.options(&started, settings.directory()))
        .await
        .context("configure runtime logging")?;
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
    let restart = RestartTrigger::default();
    let result: Result<Outcome> = async {
        let (ready, waiting) = oneshot::channel();
        let gateway = fg_gateway::serve_with_management(config, &started.disabled_modules, ready);
        let restarted = restart.clone();
        let management = async {
            let Ok(ready) = waiting.await else {
                return Ok(Outcome::Exit);
            };
            ManagementService {
                listener,
                options,
                accounts,
                tokens: tokens.clone(),
                settings,
                store,
                events,
                restart,
            }
            .run(ready, logs)
            .await
        };
        tokio::pin!(gateway, management);
        tokio::select! {
            biased;
            // Restart wins over concurrent drains: re-execute flushes state
            // below and replaces the process in main.
            () = restarted.notified() => Ok(Outcome::Restart),
            result = &mut gateway => {
                result?;
                tokio::time::timeout(Duration::from_secs(3), management).await
                    .context("management drain deadline expired")?
            }
            result = &mut management => {
                result?;
                // The gateway owns the process signal and data-plane drain.
                gateway.await.map(|()| Outcome::Exit)
            }
        }
    }
    .await;
    let outcome = result?;
    let flushed = tokio::task::spawn_blocking(move || tokens.flush_usage_on_shutdown())
        .await
        .context("join API token shutdown flush")
        .and_then(|saved| saved.context("flush API token usage on shutdown"));
    flushed?;
    Ok(outcome)
}

struct ManagementService {
    listener: TcpListener,
    options: AdminOptions,
    accounts: Arc<AccountManager>,
    tokens: Arc<TokenManager>,
    settings: Arc<SettingsState>,
    store: Arc<ConfigStore>,
    events: EventBus,
    restart: RestartTrigger,
}

impl ManagementService {
    async fn run(self, ready: ManagementReady, logs: &RuntimeLogs) -> Result<Outcome> {
        let Self {
            listener,
            options,
            accounts,
            tokens,
            settings,
            store,
            events,
            restart,
        } = self;
        let started = settings.snapshot();
        let updates = settings.subscribe();
        let directory = settings.directory().to_owned();
        let audit = AuditLog::open(&directory).context("open the audit log")?;
        {
            let events = events.clone();
            audit.set_hook(Box::new(move |entry| {
                let kind = match entry.category {
                    Category::Change => fg_core::events::Kind::AuditChange,
                    Category::Access => fg_core::events::Kind::AuditAccess,
                    Category::Login => return,
                };
                events.publish_with(|| {
                    let mut event = fg_core::events::Event::new(kind, "audit");
                    event.fields.push(("actor", entry.actor.clone()));
                    event
                        .fields
                        .push(("ip", entry.ip.to_canonical().to_string()));
                    if !entry.module.is_empty() {
                        event.fields.push(("module", entry.module.clone()));
                    }
                    event.fields.push(("method", entry.method.clone()));
                    event.fields.push(("path", entry.path.clone()));
                    event
                });
            }));
        }
        let router = ApiRouter::default()
            .with_modules(ready.registry, ready.enabled)
            .with_token_authentication(tokens.clone())
            .with_audit(audit.clone());
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
        let third_login = Arc::new(ManagedThirdLogin::new(
            settings.subscribe_third_login(),
            accounts.clone(),
            &options.admin_prefix,
            Some(audit.clone()),
        )?);
        let delayed = restart.clone();
        let admin = router
            .with_logs(logs.handle())
            .with_security_status(accounts.clone(), exposure)
            .with_token_management(tokens.clone())
            .with_managed_third_login(third_login.clone())
            .with_settings(settings, accounts.clone())
            .route(
                axum::http::Method::POST,
                "/api/system/restart",
                "Restart the service",
                move || {
                    let delayed = delayed.clone();
                    async move {
                        // Let the response leave before the process is
                        // replaced.
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            delayed.notify();
                        });
                        axum::Json(serde_json::json!({"ok": true}))
                    }
                },
            )
            .finish();
        tracing::info!(listen = %listener.local_addr()?, "management ready");
        let mut drain = ready.drain;
        let maintenance = poll_auth_maintenance(accounts.clone(), tokens, store, drain.clone());
        let runtime = apply_settings_updates(updates, started, &accounts, logs, &directory);
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
        let served = tokio::select! {
            result = &mut server => result.context("serve management"),
            () = maintenance => server.await.context("drain management"),
            () = runtime => server.await.context("serve management after settings watcher closed"),
            () = third_login.run() => server.await.context("serve management after OAuth settings watcher closed"),
        };
        audit.flush();
        served.map(|()| Outcome::Exit)
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
    logs: &RuntimeLogs,
    directory: &Path,
) {
    let mut applied = logs.options(&previous, directory);
    let mut retry: Option<Duration> = None;
    loop {
        tokio::select! {
            biased;
            changed = updates.changed() => {
                if changed.is_err() {
                    return;
                }
                retry = None;
            }
            _ = tokio::time::sleep(retry.unwrap_or_default()), if retry.is_some() => {},
        }
        let current = updates.borrow_and_update().clone();
        let limits = login_limits(&current);
        if limits != login_limits(&previous) && accounts.configure_login_limits(limits).is_err() {
            tracing::error!(target: "fg_core::settings", "login limits could not be applied");
        }
        if current.log_level != previous.log_level && logs.set_level(&current.log_level).is_err() {
            tracing::error!(target: "fg_core::settings", "log level could not be applied");
        }
        let options = logs.options(&current, directory);
        if options == applied {
            retry = None;
        } else {
            match logs.configure(options.clone()).await {
                Ok(()) => {
                    applied = options;
                    retry = None;
                    tracing::info!(target: "fg_core::settings", "runtime logging options applied");
                }
                Err(_) => {
                    if retry.is_none() {
                        tracing::error!(target: "fg_core::settings", "runtime logging options could not be applied");
                    }
                    retry = Some(retry.map_or(Duration::from_secs(2), |delay| {
                        (delay * 2).min(Duration::from_secs(60))
                    }));
                }
            }
        }
        previous = current;
    }
}

async fn poll_auth_maintenance(
    accounts: Arc<AccountManager>,
    tokens: Arc<TokenManager>,
    store: Arc<ConfigStore>,
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
        let rollback = store.clone();
        let work = tokio::task::spawn_blocking(move || {
            if accounts.apply_pending_reset().is_err() {
                tracing::error!(target: "fg_core::auth", "administrator reset could not be applied");
            }
            if tokens.flush_usage(Instant::now()).is_err() {
                tracing::error!(target: "fg_core::auth", "API token usage could not be persisted");
            }
            // Offline rollback requests are claimed in the configuration
            // directory and applied while the service keeps running.
            match fg_config::rollback::take_request(rollback.dir()) {
                Ok(Some(request)) => match fg_config::rollback::apply_offline(&rollback, request) {
                    Ok(summary) => {
                        tracing::info!(target: "fg_config::rollback", summary = %summary, "offline rollback applied");
                    }
                    Err(error) => {
                        tracing::error!(target: "fg_config::rollback", %error, "offline rollback failed");
                    }
                },
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(target: "fg_config::rollback", %error, "rollback request could not be read");
                }
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
        let maintenance = tokio::spawn(poll_auth_maintenance(
            Arc::new(accounts),
            tokens,
            store.clone(),
            drain,
        ));
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
