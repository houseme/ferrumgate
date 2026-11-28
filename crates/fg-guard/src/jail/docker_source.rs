//! The `docker` source (WP-52 §3.3): container logs arrive through the
//! docker module's follow handle (`Deps.docker_follow`, WP-60). The
//! contract lives here because this crate consumes it; the assembly
//! layer injects the implementation. Without a compiled docker module
//! the slot stays empty and `docker` jails are refused at save time
//! (WP-52 §3.3 "未编译时规则保存报错") — an existing jail simply idles.

use std::{future::Future, pin::Pin, sync::Arc};

use tokio::task::AbortHandle;

use super::JailEngine;

/// The follow contract WP-60 provides: attach to a container's new stdout
/// lines until the returned future is cancelled, handing each line to
/// `on_line`. Cancellation = dropping the future.
pub type FollowFut = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;

pub trait DockerFollow: Send + Sync {
    fn follow(&self, container: &str, on_line: Arc<dyn Fn(String) + Send + Sync>) -> FollowFut;
}

/// Spawns a reader task for one container: attach, feed lines until the
/// follow ends, wait out the shared retry backoff, attach again (a
/// restarted container is picked up).
pub fn spawn(
    engine: Arc<JailEngine>,
    jail_key: &str,
    container: &str,
    follow: Arc<dyn DockerFollow>,
) -> AbortHandle {
    let jail_key = jail_key.to_owned();
    let container = container.to_owned();
    tokio::spawn(async move {
        loop {
            let feeder: Arc<dyn Fn(String) + Send + Sync> = {
                let engine = Arc::clone(&engine);
                let jail_key = jail_key.clone();
                Arc::new(move |line| engine.on_line(&jail_key, &line))
            };
            let mut fut = follow.follow(&container, feeder);
            match fut.as_mut().await {
                Ok(()) => {
                    tracing::info!(module = "guard", jail = %jail_key, container = %container, "docker follow ended; restarting");
                }
                Err(error) => {
                    tracing::warn!(module = "guard", jail = %jail_key, container = %container, %error, "docker follow failed");
                }
            }
            tokio::time::sleep(super::command_source::RETRY_BACKOFF).await;
        }
    })
    .abort_handle()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex as StdMutex};

    use super::*;
    use crate::bans::GuardService;
    use crate::jail::JailEngine;
    use crate::jail::validate::normalize_jail;
    use crate::jail::{Jail, JailSource};
    use crate::model::{FileConfig, Settings};
    use fg_core::events::EventBus;
    use fg_net::banlist::system_clock;

    /// A stub follow handle feeding canned lines (WP-52 §5 step 7).
    struct StubFollow {
        lines: Vec<&'static str>,
        attaches: StdMutex<usize>,
    }

    impl DockerFollow for StubFollow {
        fn follow(
            &self,
            _container: &str,
            on_line: Arc<dyn Fn(String) + Send + Sync>,
        ) -> FollowFut {
            *self.attaches.lock().expect("stub attaches") += 1;
            let lines: Vec<String> = self.lines.iter().map(|line| (*line).to_owned()).collect();
            Box::pin(async move {
                for line in lines {
                    on_line(line);
                }
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn docker_source_feeds_lines_through_the_follow_handle() {
        let service = GuardService::open_memory(&Settings::default(), EventBus::default());
        let engine = Arc::new(JailEngine::new(service, system_clock()));
        let jail = normalize_jail(Jail {
            key: "ccaabbddeeff".to_owned(),
            name: "vault".to_owned(),
            enable: true,
            source: JailSource::Docker,
            target: "vaultwarden".to_owned(),
            filter: "Incorrect password for .* from <HOST>|IP: <HOST>".to_owned(),
            max_retry: 1,
            ..Jail::default()
        });
        engine
            .reload(&FileConfig {
                settings: Settings::default(),
                jails: vec![jail],
            })
            .expect("reload");
        let stub = Arc::new(StubFollow {
            lines: vec!["IP: 203.0.113.90"],
            attaches: StdMutex::new(0),
        });
        let handle = spawn(
            Arc::clone(&engine),
            "ccaabbddeeff",
            "vaultwarden",
            Arc::clone(&stub) as Arc<dyn DockerFollow>,
        );
        for _ in 0..100 {
            if engine.service().is_banned("203.0.113.90".parse().unwrap()) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(engine.service().is_banned("203.0.113.90".parse().unwrap()));
        assert!(*stub.attaches.lock().expect("attaches") >= 1);
        handle.abort();
        engine.stop_sources();
    }
}
