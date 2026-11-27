//! The guard module's self-check (conventions §2): the checks report the
//! active policy, the table fill level and persistence health as machine
//! findings; the interface translates the ids into text.

use std::sync::Arc;

use fg_core::check::{BoxFut, CheckEnv, CheckResult, SelfCheck};

use crate::bans::GuardService;

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

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use fg_core::check::Status;
    use fg_core::events::EventBus;
    use fg_net::banlist::Source;

    use super::*;

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
}
