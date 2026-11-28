//! The DDNS module's self-check (WP-40 §3.3): compares the current DNS
//! resolution of each A/AAAA record with the value of its last successful
//! sync — `ddns.match` / `ddns.mismatch` / `ddns.unresolved` (details
//! follow the upstream `selfcheck.go` semantics: only records with a
//! synced value are compared; everything else reports unresolved).

use std::net::IpAddr;
use std::sync::Arc;

use fg_core::check::{BoxFut, CheckEnv, CheckResult, SelfCheck};

use crate::ip_source::Family;
use crate::model::RecordType;
use crate::runtime::Scheduler;

/// DNS resolver hook injected by the assembler: `(fqdn, family) ->
/// resolved addresses`. Without a resolver every record reports
/// `unresolved`.
pub type ResolveFn = Arc<dyn Fn(&str, Family) -> Vec<IpAddr> + Send + Sync>;

/// The DDNS self-check over the scheduler's live state.
pub struct DdnsCheck {
    pub scheduler: Arc<Scheduler>,
    pub resolve: Option<ResolveFn>,
}

impl SelfCheck for DdnsCheck {
    fn check(&self, _env: &CheckEnv) -> BoxFut<'_, Vec<CheckResult>> {
        Box::pin(async move {
            let mut results = Vec::new();
            let summary = self.scheduler.summary().await;
            results.push(
                CheckResult::info("ddns.module")
                    .param("tasks", summary.tasks)
                    .param("enabled", summary.enabled)
                    .param("failingRecords", summary.failing_records),
            );
            let statuses = self.scheduler.statuses();
            for (task_key, status) in &statuses {
                for (record_key, record) in &status.records {
                    if let Some(error) = &record.error {
                        results.push(
                            CheckResult::warn("ddns.unresolved")
                                .param("task", task_key.as_str())
                                .param("record", record_key.as_str())
                                .param("reason", error.as_str()),
                        );
                    }
                }
                let Some(task) = self.scheduler.task_of(task_key).await else {
                    continue;
                };
                for record in &task.records {
                    if !record.enable || !matches!(record.typ, RecordType::A | RecordType::AAAA) {
                        continue;
                    }
                    let Some(record_state) = status.records.get(&record.key) else {
                        continue;
                    };
                    let fqdn = crate::remote::fqdn_of(record);
                    let family = match record.typ {
                        RecordType::AAAA => Family::V6,
                        _ => Family::V4,
                    };
                    if record_state.value.is_empty() {
                        results.push(
                            CheckResult::info("ddns.unresolved")
                                .param("task", task_key.as_str())
                                .param("record", record.key.as_str())
                                .param("reason", "还没有同步过"),
                        );
                        continue;
                    }
                    results.push(check_record(
                        self.resolve.as_ref(),
                        task_key,
                        &record.key,
                        &fqdn,
                        family,
                        record_state.value.as_str(),
                    ));
                }
            }
            results
        })
    }
}

/// One record comparison: resolves the record's FQDN in the record's
/// family and compares with the last synced value.
pub fn check_record(
    resolve: Option<&ResolveFn>,
    task_key: &str,
    record_key: &str,
    fqdn: &str,
    family: Family,
    expected: &str,
) -> CheckResult {
    let Ok(expected_ip) = expected.parse::<IpAddr>() else {
        return CheckResult::info("ddns.unresolved")
            .param("task", task_key)
            .param("record", record_key)
            .param("reason", "最近同步的值不是地址");
    };
    let Some(resolve) = resolve else {
        return CheckResult::info("ddns.unresolved")
            .param("task", task_key)
            .param("record", record_key)
            .param("expected", expected_ip.to_string())
            .param("reason", "没有配置 DNS 解析器");
    };
    let got = resolve(fqdn, family);
    if got.contains(&expected_ip) {
        CheckResult::ok("ddns.match")
            .param("task", task_key)
            .param("record", record_key)
            .param("ip", expected_ip.to_string())
    } else if got.is_empty() {
        CheckResult::info("ddns.unresolved")
            .param("task", task_key)
            .param("record", record_key)
            .param("expected", expected_ip.to_string())
    } else {
        CheckResult::warn("ddns.mismatch")
            .param("task", task_key)
            .param("record", record_key)
            .param("expected", expected_ip.to_string())
            .param(
                "got",
                got.iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" "),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve_ok(fqdn: &str, _family: Family) -> Vec<IpAddr> {
        assert_eq!(fqdn, "home.example.com");
        vec!["1.2.3.4".parse().expect("ip")]
    }

    fn resolve_moved(_fqdn: &str, _family: Family) -> Vec<IpAddr> {
        vec!["9.9.9.9".parse().expect("ip")]
    }

    #[test]
    fn records_up_metric_and_selfcheck() {
        let resolver: ResolveFn = Arc::new(resolve_ok);
        let result = check_record(
            Some(&resolver),
            "task00000001",
            "rec000000001",
            "home.example.com",
            Family::V4,
            "1.2.3.4",
        );
        assert_eq!(result.id, "ddns.match");
        assert_eq!(result.params["ip"], "1.2.3.4");

        let resolver: ResolveFn = Arc::new(resolve_moved);
        let result = check_record(
            Some(&resolver),
            "task00000001",
            "rec000000001",
            "home.example.com",
            Family::V4,
            "1.2.3.4",
        );
        assert_eq!(result.id, "ddns.mismatch");
        assert_eq!(result.params["expected"], "1.2.3.4");
        assert_eq!(result.params["got"], "9.9.9.9");

        let empty: ResolveFn = Arc::new(|_, _| Vec::new());
        let result = check_record(
            Some(&empty),
            "task00000001",
            "rec000000001",
            "home.example.com",
            Family::V4,
            "1.2.3.4",
        );
        assert_eq!(result.id, "ddns.unresolved");

        // No resolver wired: everything reports unresolved.
        let result = check_record(
            None,
            "task00000001",
            "rec000000001",
            "home.example.com",
            Family::V4,
            "1.2.3.4",
        );
        assert_eq!(result.id, "ddns.unresolved");

        // A non-address last value cannot be compared.
        let result = check_record(
            Some(&resolver),
            "task00000001",
            "rec000000001",
            "home.example.com",
            Family::V4,
            "not-an-address",
        );
        assert_eq!(result.id, "ddns.unresolved");
    }
}
