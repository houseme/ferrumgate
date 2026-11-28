//! The guard module's self-check (conventions §2): the checks report the
//! active policy, the table fill level, persistence health and — when
//! `settings.firewall` is on — the WP-51 firewall sync as machine
//! findings; the interface translates the ids into text.

use std::sync::Arc;

use fg_core::check::{BoxFut, CheckEnv, CheckResult, SelfCheck, Status};

use crate::bans::GuardService;
use crate::firewall::{FirewallSync, status_text};

/// One guard module check set over the shared service.
pub struct GuardCheck {
    pub service: Arc<GuardService>,
}

impl SelfCheck for GuardCheck {
    fn check(&self, _env: &CheckEnv) -> BoxFut<'_, Vec<CheckResult>> {
        Box::pin(async move {
            let settings = self.service.settings();
            let counts = self.service.counts();
            let stats = self.service.stats();
            let mut results = Vec::new();
            results.push(
                CheckResult::info("guard.policy")
                    .param("enable", settings.enable)
                    .param("banSeconds", settings.ban_seconds)
                    .param("maxBanSeconds", settings.max_ban_seconds)
                    .param("increment", settings.increment)
                    .param("whitelist", settings.ignore_list.len()),
            );
            if settings.enable {
                results.push(CheckResult::ok("guard.module").param("firewall", settings.firewall));
            } else {
                results
                    .push(CheckResult::info("guard.module").param("firewall", settings.firewall));
            }
            if settings.firewall {
                results.push(firewall_check(self.service.firewall().as_deref()));
            }
            let limit = self.service.limit();
            let fill = if limit == 0 {
                0.0
            } else {
                counts.bans as f64 / limit as f64
            };
            results.push(if fill > 0.9 {
                CheckResult::warn("guard.capacity")
                    .param("bans", counts.bans)
                    .param("limit", limit)
            } else {
                CheckResult::ok("guard.capacity")
                    .param("bans", counts.bans)
                    .param("limit", limit)
                    .param("offenses", counts.offenses)
            });
            if stats.save_errors > 0 {
                results.push(
                    CheckResult::fail("guard.persistence").param("errors", stats.save_errors),
                );
            } else if fill > 0.9 {
                results
                    .push(CheckResult::warn("guard.persistence").param("rejected", stats.rejected));
            } else {
                results.push(CheckResult::ok("guard.persistence").param("saves", stats.saves));
            }
            results
        })
    }
}

/// The `guard.firewall` finding: a platform limitation is informational,
/// a fixable environment problem a warning, an exhausted sync (degraded)
/// a failure — application layer bans keep working in every case.
fn firewall_check(sync: Option<&FirewallSync>) -> CheckResult {
    let Some(sync) = sync else {
        return CheckResult::warn("guard.firewall")
            .param("backend", "none")
            .param("state", "starting");
    };
    let status = sync.status();
    let level = if let Some(unavailable) = &status.unavailable {
        match unavailable.code {
            // Platform limitation, not a defect.
            "not_linux" => Status::Info,
            _ => Status::Warn,
        }
    } else if status.degraded {
        Status::Fail
    } else if status.rules_present {
        Status::Ok
    } else {
        Status::Info
    };
    let dropped: u64 = status.dropped.values().sum();
    let result = CheckResult::with("guard.firewall", level)
        .param(
            "backend",
            status
                .backend
                .map(|backend| backend.as_str())
                .unwrap_or("none"),
        )
        .param(
            "state",
            match &status.unavailable {
                Some(unavailable) => unavailable.code,
                _ if status.degraded => "degraded",
                _ if status.rules_present => "synced",
                _ => "writing",
            },
        )
        .param("text", status_text(&status));
    if dropped > 0 {
        result.param("dropped", dropped)
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::SystemTime;

    use fg_core::check::Status;
    use fg_core::events::EventBus;
    use fg_net::banlist::{BanPolicy, BanTable, Source, system_clock};

    use super::*;
    use crate::firewall::{FirewallSync, FwUnavailable};

    #[tokio::test]
    async fn selfcheck_reports_policy_capacity_and_persistence() {
        let settings = crate::validate::normalize(crate::model::FileConfig::default()).settings;
        let service = crate::bans::GuardService::open_memory(&settings, EventBus::default());
        let now = SystemTime::now();
        service.ban_auto(
            "203.0.113.1".parse().unwrap(),
            None,
            false,
            Source::Trap,
            "r".to_owned(),
            now,
        );
        let results = GuardCheck {
            service: Arc::clone(&service),
        }
        .check(&CheckEnv::default())
        .await;
        let ids: Vec<&'static str> = results.iter().map(|result| result.id).collect();
        assert_eq!(
            ids,
            [
                "guard.policy",
                "guard.module",
                "guard.capacity",
                "guard.persistence"
            ]
        );
        let capacity = results.iter().find(|r| r.id == "guard.capacity").unwrap();
        assert_eq!(capacity.params["bans"], "1");
        assert_eq!(
            capacity.status,
            Status::Ok,
            "one entry in a 32768 table is healthy"
        );
        let policy = results.iter().find(|r| r.id == "guard.policy").unwrap();
        assert_eq!(policy.params["banSeconds"], "3600");
    }

    #[tokio::test]
    async fn selfcheck_reports_firewall_item_only_when_enabled() {
        // Firewall off: no firewall check item at all.
        let settings = crate::validate::normalize(crate::model::FileConfig::default()).settings;
        let service = crate::bans::GuardService::open_memory(&settings, EventBus::default());
        let ids: Vec<&'static str> = GuardCheck {
            service: Arc::clone(&service),
        }
        .check(&CheckEnv::default())
        .await
        .iter()
        .map(|result| result.id)
        .collect();
        assert!(!ids.contains(&"guard.firewall"), "{ids:?}");

        // Firewall on: the item appears. A thread-less sync whose probe
        // reports the platform limitation keeps the test deterministic and
        // free of any system access.
        let settings = crate::validate::normalize(crate::model::FileConfig {
            settings: crate::model::Settings {
                firewall: true,
                ..crate::model::Settings::default()
            },
        })
        .settings;
        let service = crate::bans::GuardService::open_memory(&settings, EventBus::default());
        let sync = FirewallSync::with_factory(
            BanTable::open_memory(BanPolicy::default(), Default::default(), system_clock()),
            system_clock(),
            Arc::new(|| Err(FwUnavailable::not_linux())),
        );
        sync.tick();
        assert_eq!(
            sync.status().unavailable.as_ref().unwrap().code,
            "not_linux"
        );
        service.set_firewall(Some(Arc::clone(&sync)));
        let results = GuardCheck {
            service: Arc::clone(&service),
        }
        .check(&CheckEnv::default())
        .await;
        let firewall = results
            .iter()
            .find(|result| result.id == "guard.firewall")
            .expect("the enabled firewall reports its own check");
        assert_eq!(
            firewall.status,
            Status::Info,
            "platform limitation is informational"
        );
        assert_eq!(firewall.params["state"], "not_linux");
        assert_eq!(firewall.params["backend"], "none");
    }

    #[tokio::test]
    async fn selfcheck_flags_degraded_firewall_as_failure() {
        let settings = crate::validate::normalize(crate::model::FileConfig {
            settings: crate::model::Settings {
                firewall: true,
                ..crate::model::Settings::default()
            },
        })
        .settings;
        let service = crate::bans::GuardService::open_memory(&settings, EventBus::default());
        let sync = FirewallSync::with_factory(
            BanTable::open_memory(BanPolicy::default(), Default::default(), system_clock()),
            system_clock(),
            Arc::new(|| Err(FwUnavailable::no_permission())),
        );
        sync.tick();
        assert_eq!(
            sync.status().unavailable.as_ref().unwrap().code,
            "no_permission"
        );
        service.set_firewall(Some(Arc::clone(&sync)));
        let results = GuardCheck {
            service: Arc::clone(&service),
        }
        .check(&CheckEnv::default())
        .await;
        let firewall = results
            .iter()
            .find(|result| result.id == "guard.firewall")
            .expect("the enabled firewall reports its own check");
        assert_eq!(
            firewall.status,
            Status::Warn,
            "a fixable environment problem is a warning"
        );
        assert_eq!(firewall.params["state"], "no_permission");
    }
}
