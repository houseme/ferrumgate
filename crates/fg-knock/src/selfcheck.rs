//! The knock module's self-check (conventions §2): machine findings over
//! the compiled rules and credentials, the listener port, the grant table
//! fill level and the replay/rate state; the interface translates ids
//! into text.

use std::sync::Arc;

use fg_core::check::{BoxFut, CheckEnv, CheckResult, SelfCheck};
use tokio::sync::RwLock;

use crate::engine::Engine;
use crate::model::{FileConfig, limits};

/// One knock module check set over the shared engine.
pub struct KnockCheck {
    pub engine: Arc<Engine>,
    pub config: Arc<RwLock<FileConfig>>,
}

impl SelfCheck for KnockCheck {
    fn check(&self, _env: &CheckEnv) -> BoxFut<'_, Vec<CheckResult>> {
        Box::pin(async move {
            let now = self.engine.now();
            let snapshot = self.engine.snapshot();
            let stats = self.engine.stats(now);
            let config = self.config.read().await;
            let enabled = config.rules.iter().filter(|rule| rule.enable).count();
            let total = config.rules.len();
            let mut results = Vec::new();
            // Module overview: rules, listener, firewall sync.
            results.push(
                if enabled > 0 {
                    CheckResult::ok("knock.module")
                } else {
                    CheckResult::info("knock.module")
                }
                .param("rules", enabled)
                .param("total", total)
                .param("port", snapshot.settings.port)
                .param(
                    "firewall",
                    snapshot.rules.values().filter(|r| r.firewall).count(),
                ),
            );
            // Credentials: knocks are impossible without any.
            results.push(
                if snapshot.keys.is_empty() || snapshot.keys.len() > limits::TOTAL_KEYS_MAX / 2 {
                    CheckResult::warn("knock.keys")
                } else {
                    CheckResult::ok("knock.keys")
                }
                .param("keys", snapshot.keys.len())
                .param("limit", limits::TOTAL_KEYS_MAX),
            );
            // Grant table fill level.
            let limit = limits::GRANTS_LIMIT;
            let fill = f64::from(u32::try_from(stats.grants).unwrap_or(u32::MAX)) / limit as f64;
            results.push(
                if fill > 0.9 {
                    CheckResult::warn("knock.grants")
                } else {
                    CheckResult::ok("knock.grants")
                }
                .param("grants", stats.grants)
                .param("limit", limit),
            );
            // Pre-authentication state: replay cache and per-source table.
            results.push(
                CheckResult::info("knock.preauth")
                    .param("replayCache", stats.replay_cache)
                    .param("rateSources", stats.rate_sources)
                    .param("invalid", stats.invalid)
                    .param("ignored", stats.ignored)
                    .param("rateLimited", stats.rate_limited),
            );
            results
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use fg_core::check::Status;
    use tokio::sync::RwLock;

    use super::*;
    use crate::engine::Hooks;
    use crate::grants::Grants;
    use crate::limit::RateLimiter;
    use crate::model::{Access, Proto, Rule};
    use crate::replay::ReplayCache;
    use crate::spa::test_support::b64;

    #[tokio::test]
    async fn selfcheck_reports_module_keys_grants_and_preauth() {
        let mut config = FileConfig::default();
        config.rules.push(Rule {
            key: "a1b2c3d4e5f6".into(),
            name: "ssh".into(),
            enable: true,
            ports: vec![Access::new(Proto::Tcp, 22)],
            enc_key: b64(&[7u8; 16]),
            hmac_key: b64(&[9u8; 32]),
            ..Rule::default()
        });
        let config = Arc::new(RwLock::new(crate::validate::normalize(config)));
        let engine = Engine::new(
            Arc::new(Grants::new()),
            ReplayCache::new(std::time::SystemTime::now() - Duration::from_secs(60)),
            RateLimiter::new(),
            Hooks::default(),
            crate::engine::system_clock(),
        );
        let guard = config.read().await;
        engine.apply_config(None, &guard);
        let results = KnockCheck {
            engine: Arc::clone(&engine),
            config: Arc::clone(&config),
        }
        .check(&CheckEnv::default())
        .await;
        let ids: Vec<&'static str> = results.iter().map(|result| result.id).collect();
        assert_eq!(
            ids,
            [
                "knock.module",
                "knock.keys",
                "knock.grants",
                "knock.preauth"
            ]
        );
        let module = results
            .iter()
            .find(|result| result.id == "knock.module")
            .unwrap();
        assert_eq!(module.params["rules"], "1");
        assert_eq!(module.params["port"], "62201");
        assert_eq!(module.status, Status::Ok, "one enabled rule is healthy");
        let keys = results
            .iter()
            .find(|result| result.id == "knock.keys")
            .unwrap();
        assert_eq!(keys.status, Status::Ok, "one credential is healthy");
        assert_eq!(keys.params["keys"], "1");
    }

    #[tokio::test]
    async fn selfcheck_warns_without_any_credential() {
        let config = Arc::new(RwLock::new(FileConfig::default()));
        let engine = Engine::new(
            Arc::new(Grants::new()),
            ReplayCache::new(std::time::SystemTime::now()),
            RateLimiter::new(),
            Hooks::default(),
            crate::engine::system_clock(),
        );
        {
            let guard = config.read().await;
            engine.apply_config(None, &guard);
        }
        let results = KnockCheck { engine, config }
            .check(&CheckEnv::default())
            .await;
        let keys = results
            .iter()
            .find(|result| result.id == "knock.keys")
            .unwrap();
        assert_eq!(
            keys.status,
            Status::Warn,
            "no keys means knocks are impossible"
        );
        let module = results
            .iter()
            .find(|result| result.id == "knock.module")
            .unwrap();
        assert_eq!(
            module.status,
            Status::Info,
            "no enabled rules is informational"
        );
    }
}
