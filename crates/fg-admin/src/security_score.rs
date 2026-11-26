use std::{sync::Arc, time::Duration};

use axum::{Json, http::Method};
use fg_auth::{AccountManager, SecurityFacts};
use schemars::JsonSchema;
use serde::Serialize;

use crate::{ApiRouter, RouteModels};

#[derive(Clone)]
pub struct SecurityExposure {
    pub exposed: bool,
    pub secure: bool,
    pub protected_entry: bool,
    pub passkey_rp: Option<String>,
}

impl ApiRouter {
    pub fn with_security_status(
        self,
        accounts: Arc<AccountManager>,
        exposure: SecurityExposure,
    ) -> Self {
        let exposure = Arc::new(exposure);
        self.modeled_route(
            Method::GET,
            "/api/system/security",
            "Get management security score",
            RouteModels::default().response::<SecurityStatus>(),
            move || async move {
                let facts = accounts.security_facts(exposure.passkey_rp.as_deref());
                Json(score(facts, &exposure))
            },
        )
    }
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct SecurityStatus {
    score: u8,
    level: &'static str,
    exposed: bool,
    password_issue: &'static str,
    items: [Item; 7],
}

#[derive(Serialize, JsonSchema)]
struct Item {
    id: &'static str,
    status: &'static str,
    points: u8,
    max: u8,
}

fn score(facts: SecurityFacts, exposure: &SecurityExposure) -> SecurityStatus {
    let exposed = exposure.exposed;
    let weak = !facts.password_issue.is_empty();
    let limits = facts.login_limits;
    let item = |id, max, points| Item {
        id,
        status: if points == 0 {
            "ok"
        } else if id == "password" {
            "risk"
        } else {
            "warn"
        },
        points,
        max,
    };
    let items = [
        item("password", 35, if weak { 35 } else { 0 }),
        item(
            "twoFactor",
            20,
            if facts.second_factor {
                0
            } else if exposed {
                20
            } else {
                10
            },
        ),
        item(
            "entry",
            15,
            if exposed && !exposure.protected_entry {
                15
            } else {
                0
            },
        ),
        item(
            "lockout",
            10,
            if limits.max_failures > 10 || limits.lock_duration < Duration::from_secs(300) {
                10
            } else {
                0
            },
        ),
        item(
            "https",
            10,
            if exposed && !exposure.secure { 10 } else { 0 },
        ),
        item(
            "globalLimit",
            5,
            if limits.unknown_failures.is_none() {
                5
            } else {
                0
            },
        ),
        item(
            "username",
            5,
            if exposed && facts.common_username {
                5
            } else {
                0
            },
        ),
    ];
    let score = 100 - items.iter().map(|item| item.points).sum::<u8>();
    let level = if weak || (exposed && score < 60) {
        "risk"
    } else if score < 90 {
        "warn"
    } else {
        "good"
    };
    SecurityStatus {
        score,
        level,
        exposed,
        password_issue: facts.password_issue,
        items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fg_auth::LoginLimits;

    #[test]
    fn security_score_covers_exposed_and_local_installations() {
        let facts = || SecurityFacts {
            password_issue: "weak",
            second_factor: false,
            common_username: true,
            login_limits: LoginLimits {
                max_failures: 11,
                lock_duration: Duration::from_secs(60),
                unknown_failures: None,
            },
        };
        let mut exposure = SecurityExposure {
            exposed: true,
            secure: false,
            protected_entry: false,
            passkey_rp: None,
        };
        let report = score(facts(), &exposure);
        assert_eq!(report.score, 0);
        assert_eq!(report.level, "risk");
        assert_eq!(
            report.items.map(|item| item.points),
            [35, 20, 15, 10, 10, 5, 5]
        );
        exposure.exposed = false;
        assert_eq!(
            score(facts(), &exposure).items.map(|item| item.points),
            [35, 10, 0, 10, 0, 5, 0]
        );
        let healthy = SecurityFacts {
            password_issue: "",
            second_factor: true,
            common_username: false,
            login_limits: LoginLimits::default(),
        };
        assert_eq!(score(healthy, &exposure).score, 100);
    }
}
