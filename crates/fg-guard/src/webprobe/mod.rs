//! The web probe report surface (WP-52 §3.3 "调用约定"): the trait the
//! web service (WP-21 / WP-28) calls synchronously on every finished
//! request and handshake failure. The implementation must stay lock-free
//! and allocation-free for non-matching probes — it reads one published
//! rules snapshot and only touches a per-rule counter when a rule
//! actually matches.

pub mod path_rule;
pub mod rule_match;
pub mod tls;

pub use path_rule::{
    MAX_PATH_MATCH_BYTES, PathRule, PathRuleError, clamp_path_pair, compile_paths, normalize_path,
    path_matches,
};
pub use rule_match::{
    DEFAULT_COUNTED_STATUSES, WebRequestSummary, effective_status, web_jail_counts,
};
pub use tls::{TlsFail, TlsFailKind, classify, tls_jail_counts};

use std::sync::Arc;

use crate::jail::JailEngine;

/// The report surface the web service holds. Both calls run on the
/// request path: no locks beyond the published snapshot load, no
/// allocation unless a rule matches.
pub trait ProbeSink: Send + Sync {
    fn on_web_hit(&self, request: &WebRequestSummary<'_>);
    fn on_tls_fail(&self, fail: &TlsFail<'_>);
}

/// The engine-backed [`ProbeSink`]; the assembly layer hands an
/// `Arc<dyn ProbeSink>` of this to the web module.
pub struct ProbeHub {
    engine: Arc<JailEngine>,
}

impl ProbeHub {
    pub fn new(engine: Arc<JailEngine>) -> Self {
        Self { engine }
    }
}

impl ProbeSink for ProbeHub {
    fn on_web_hit(&self, request: &WebRequestSummary<'_>) {
        self.engine.on_web_hit(request);
    }

    fn on_tls_fail(&self, fail: &TlsFail<'_>) {
        self.engine.on_tls_fail(fail);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::bans::GuardService;
    use crate::jail::model::{Jail, Source};
    use crate::jail::validate::normalize_jail;
    use crate::model::Settings;
    use fg_core::events::EventBus;
    use fg_net::banlist::system_clock;

    fn engine_with_web_jail(filter: &str, any_status: bool) -> Arc<JailEngine> {
        let service = GuardService::open_memory(&Settings::default(), EventBus::default());
        let engine = Arc::new(JailEngine::new(Arc::clone(&service), system_clock()));
        let jail = normalize_jail(Jail {
            key: "webtest00001".to_owned(),
            name: "web".to_owned(),
            enable: true,
            source: Source::Web,
            filter: filter.to_owned(),
            any_status,
            max_retry: 1,
            ..Jail::default()
        });
        engine
            .reload(&crate::model::FileConfig {
                settings: Settings::default(),
                jails: vec![jail],
            })
            .expect("reload");
        engine
    }

    fn request(path: &'static str, status: u16) -> WebRequestSummary<'static> {
        WebRequestSummary {
            listener: "web",
            path,
            host: "example.test",
            status,
            ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4)),
            unknown_host: false,
            default_site: false,
            trusted_user: false,
            access_denied: false,
        }
    }

    fn bans(engine: &JailEngine) -> u64 {
        engine.stats().bans.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn probe_sink_is_lock_free_and_fast() {
        let engine = engine_with_web_jail("*/.env", true);
        let sink: Arc<dyn ProbeSink> = Arc::new(ProbeHub::new(Arc::clone(&engine)));
        // 10 000 non-matching probes must not allocate per-rule state or
        // wait on any lock: the whole loop stays far under the budget a
        // lock contention would blow.
        let start = Instant::now();
        for step in 0..10_000 {
            sink.on_web_hit(&WebRequestSummary {
                ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, (step % 250) as u8 + 1)),
                ..request("/plain", 200)
            });
        }
        let elapsed = start.elapsed();
        assert_eq!(bans(engine.as_ref()), 0, "nothing matched");
        assert!(
            elapsed < Duration::from_secs(2),
            "non-matching probes must stay lock-free and fast, took {elapsed:?}"
        );
        // A matching probe counts and bans (anyStatus, first hit).
        sink.on_web_hit(&request("/.env", 200));
        assert_eq!(bans(engine.as_ref()), 1);
    }

    #[tokio::test]
    async fn probe_sink_survives_snapshot_swaps_and_concurrency() {
        let engine = engine_with_web_jail("*/.env", true);
        let sink: Arc<dyn ProbeSink> = Arc::new(ProbeHub::new(Arc::clone(&engine)));
        // Reload continuously (snapshot swap) while probes flow: readers
        // never block on the writer.
        let reloader = tokio::spawn({
            let engine = Arc::clone(&engine);
            async move {
                for _ in 0..20 {
                    let _ = engine.reload(&crate::model::FileConfig::default());
                    let _ = tokio::task::yield_now().await;
                }
            }
        });
        for _ in 0..64 {
            sink.on_web_hit(&request("/.env", 200));
        }
        reloader.await.expect("reloader");
        assert_eq!(bans(engine.as_ref()), 1, "one source reached the threshold");
    }

    #[tokio::test]
    async fn probe_sink_bans_decoy_and_tls_via_trait() {
        // A decoy path jail with a first-hit threshold.
        let engine = engine_with_web_jail("*/.env\n*/phpinfo.php", true);
        let sink: Arc<dyn ProbeSink> = Arc::new(ProbeHub::new(Arc::clone(&engine)));
        sink.on_web_hit(&request("/.env", 200));
        assert_eq!(bans(engine.as_ref()), 1, "decoy path bans on the first hit");

        // A TLS jail counting EOFs.
        let service = GuardService::open_memory(&Settings::default(), EventBus::default());
        let tls_engine = Arc::new(JailEngine::new(Arc::clone(&service), system_clock()));
        let jail = normalize_jail(Jail {
            key: "tlstest00001".to_owned(),
            name: "tls".to_owned(),
            enable: true,
            source: Source::Tls,
            filter: "eof".to_owned(),
            max_retry: 2,
            ..Jail::default()
        });
        tls_engine
            .reload(&crate::model::FileConfig {
                settings: Settings::default(),
                jails: vec![jail],
            })
            .expect("reload");
        let sink: Arc<dyn ProbeSink> = Arc::new(ProbeHub::new(Arc::clone(&tls_engine)));
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 6));
        sink.on_tls_fail(&TlsFail {
            listener: "web",
            ip,
            kind: TlsFailKind::Eof,
            reason: "unexpected eof",
            trusted_proxy: false,
        });
        assert_eq!(bans(tls_engine.as_ref()), 0, "1 of 2");
        sink.on_tls_fail(&TlsFail {
            listener: "web",
            ip,
            kind: TlsFailKind::Timeout,
            reason: "timed out",
            trusted_proxy: false,
        });
        assert_eq!(
            bans(tls_engine.as_ref()),
            0,
            "timeout is not a selected kind"
        );
        sink.on_tls_fail(&TlsFail {
            listener: "web",
            ip,
            kind: TlsFailKind::Eof,
            reason: "eof again",
            trusted_proxy: false,
        });
        assert_eq!(bans(tls_engine.as_ref()), 1);
    }
}
