//! WP-63 WebDAV file sharing service module (`fg-webdav`, Cargo feature `webdav`).

#![forbid(unsafe_code)]

pub mod handler;
pub mod model;
pub mod routes;
pub mod runtime;
pub mod validate;

use std::{collections::HashSet, sync::Arc};

use anyhow::{Context, Result};
use fg_config::{ConfigStore, Loaded};
use fg_files::{FileUsersStore, ServiceKind, ServiceUsage};
use fg_net::openports::OpenPorts;
use rustls::server::ResolvesServerCert;
use tokio::sync::{RwLock, watch};

pub use model::{LocalUser, RuntimeTimeouts, Settings, limits};
pub use routes::{PersistFn, RoutesState, mount, mount_fileusers};
pub use runtime::{RuntimeSnapshot, RuntimeStatus, WebDavRuntime};
pub use validate::Problem;

/// Configuration file stem (`webdav.json`).
pub const CONFIG_NAME: &str = "webdav";

/// External capabilities injected by the assembler (conventions §3.4).
#[derive(Clone)]
pub struct Deps {
    /// Shared file-service users store (reused by WebDAV, FTP, SMB).
    pub shared_users: Arc<FileUsersStore>,
    /// Certificate provider for SNI TLS when `settings.tls` is enabled.
    pub certs: Option<Arc<dyn ResolvesServerCert>>,
    /// Open-port registry so intrusion protection recognizes listening ports.
    pub open_ports: Option<Arc<OpenPorts>>,
    /// Optional runtime log handle (conventions §3.5).
    pub logs: Option<fg_logging::LogHandle>,
    /// Connection and upload idle timeouts (defaults match WP-63 §3.4).
    pub timeouts: RuntimeTimeouts,
    /// Bcrypt hashing cost for newly submitted local user passwords.
    pub bcrypt_cost: u32,
}

impl Deps {
    /// Builds default dependencies around an existing `FileUsersStore`.
    pub fn new(shared_users: Arc<FileUsersStore>) -> Self {
        Self {
            shared_users,
            certs: None,
            open_ports: None,
            logs: None,
            timeouts: RuntimeTimeouts::default(),
            bcrypt_cost: 10,
        }
    }
}

/// The WebDAV module: owns loaded settings, runtime listener, and management routes.
pub struct Module {
    runtime: Arc<WebDavRuntime>,
    state: Arc<RoutesState>,
}

impl Module {
    /// Loads `webdav.json`, registers WebDAV usage with `deps.shared_users`,
    /// and prepares the runtime and management route state.
    pub fn new(store: Arc<ConfigStore>, deps: Deps) -> Result<Self> {
        let settings = match store.load::<Settings>(CONFIG_NAME)? {
            Loaded::Found(s) => s,
            Loaded::Missing => Settings::default(),
        };

        let runtime = WebDavRuntime::new(
            settings.clone(),
            Arc::clone(&deps.shared_users),
            deps.certs,
            deps.open_ports,
            deps.timeouts,
        );

        let settings_lock = Arc::new(RwLock::new(settings));
        let usage_runtime = Arc::clone(&runtime);
        deps.shared_users.register_service(Arc::new(move || {
            let snap = usage_runtime.snapshot();
            let local_usernames: HashSet<String> = snap
                .settings
                .users
                .iter()
                .map(|u| u.name.to_lowercase())
                .collect();
            ServiceUsage {
                kind: ServiceKind::Webdav,
                enabled: snap.settings.enable,
                shared_users: snap.settings.shared_users,
                local_user_count: snap.settings.users.len(),
                local_usernames,
            }
        }));

        let persist_store = Arc::clone(&store);
        let persist: PersistFn = Arc::new(move |cfg: &Settings| {
            persist_store
                .save(CONFIG_NAME, cfg)
                .map(|_| ())
                .with_context(|| format!("save {CONFIG_NAME}.json"))
        });

        let state = Arc::new(RoutesState {
            settings: settings_lock,
            shared_users: deps.shared_users,
            runtime: Arc::clone(&runtime),
            persist,
            bcrypt_cost: deps.bcrypt_cost,
        });

        Ok(Self { runtime, state })
    }

    /// Mounts `/api/webdav/*` routes onto the management router.
    pub fn mount(&self, router: axum::Router) -> axum::Router {
        routes::mount(router, Arc::clone(&self.state))
    }

    /// Mounts both `/api/webdav/*` and `/api/fileusers*` routes onto `router`.
    pub fn mount_with_fileusers(&self, router: axum::Router) -> axum::Router {
        let router = self.mount(router);
        routes::mount_fileusers(router, Arc::clone(&self.state.shared_users))
    }

    /// Returns the runtime handle (status inspection, tests).
    pub fn runtime(&self) -> Arc<WebDavRuntime> {
        Arc::clone(&self.runtime)
    }

    /// Returns the shared route state (for tests).
    pub fn routes_state(&self) -> Arc<RoutesState> {
        Arc::clone(&self.state)
    }
}

impl fg_core::module::Module for Module {
    const ID: &'static str = "webdav";

    async fn run(self, mut drain: watch::Receiver<bool>) -> Result<()> {
        let initial = self.state.settings.read().await.clone();
        if initial.enable
            && let Err(err) = self.runtime.apply(initial).await
        {
            tracing::warn!(%err, "WebDAV failed to start on module launch");
        }
        tokio::select! {
            () = std::future::pending::<()>() => {}
            _ = drain.changed() => {
                self.runtime.stop().await;
            }
        }
        Ok(())
    }
}
