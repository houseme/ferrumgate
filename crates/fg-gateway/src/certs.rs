use std::{fs::File, sync::Arc};

use anyhow::{Context, Result};
use fg_core::module::Module;
use tokio::{net::TcpListener, sync::watch, task::JoinSet};

use crate::acme::{self, AcmeConfig, Managed};

pub(crate) struct Certificates {
    config: AcmeConfig,
    managed: Arc<Managed>,
    lock: Arc<File>,
    renew_at: i64,
    challenge: Option<TcpListener>,
}

impl Certificates {
    pub async fn prepare(config: AcmeConfig, managed: Arc<Managed>) -> Result<Self> {
        let (lock, renew_at) = config.restore(&managed).await?;
        let challenge = match config.challenge_listen {
            Some(addr) => Some(
                TcpListener::bind(addr)
                    .await
                    .context("bind ACME HTTP-01 listener")?,
            ),
            None => None,
        };
        Ok(Self {
            config,
            managed,
            lock: Arc::new(lock),
            renew_at,
            challenge,
        })
    }
}

impl Module for Certificates {
    const ID: &'static str = "ssl";

    async fn run(self, mut drain: watch::Receiver<bool>) -> Result<()> {
        let mut tasks = JoinSet::new();
        if let Some(listener) = self.challenge {
            tracing::info!(listen = %listener.local_addr()?, "ACME HTTP-01 listener ready");
            tasks.spawn(acme::serve_challenges(listener, self.managed.clone()));
        }
        #[cfg(unix)]
        tasks.spawn(
            self.config
                .clone()
                .run_deployments(self.managed.clone(), self.lock.clone()),
        );
        tasks.spawn(self.config.run(self.managed, self.lock, self.renew_at));
        loop {
            tokio::select! {
                biased;
                _ = drain.changed() => break,
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    result.context("ACME task failed")?;
                }
            }
        }
        tasks.shutdown().await;
        Ok(())
    }
}
