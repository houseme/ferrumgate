//! Built-in rule templates (WP-68 §3.3): the six presets the management UI
//! offers for one-click rules — severe failures, certificate expiry,
//! address changes, logins, config changes and program updates. Names are
//! simplified-Chinese source keys for [`fg_i18n::tr`]; the event sets and
//! levels follow the fg-core event kinds.

use fg_core::events::Level;

use crate::model::{Rule, limits, new_key};

/// One built-in rule preset.
#[derive(Clone, Copy, Debug)]
pub struct RuleTemplate {
    /// Stable id (`critical`, `cert-expiry`, …) for the API listing.
    pub id: &'static str,
    /// Display name (simplified-Chinese source key).
    pub name: &'static str,
    /// Event type patterns the preset matches.
    pub events: &'static [&'static str],
    pub min_level: Level,
    /// The preset's message template.
    pub template: &'static str,
}

/// The built-in presets, in offering order.
pub const TEMPLATES: &[RuleTemplate] = &[
    // 严重故障：every error-level kind of the bus.
    RuleTemplate {
        id: "critical",
        name: "严重故障",
        events: &[
            "ddns.failed",
            "ssl.renew_failed",
            "ssl.deploy_failed",
            "upstream.down",
            "process.exited",
            "backup.failed",
            "system.security",
        ],
        min_level: Level::Error,
        template: limits::DEFAULT_TEMPLATE,
    },
    // 证书到期。
    RuleTemplate {
        id: "cert-expiry",
        name: "证书到期",
        events: &["ssl.expiring"],
        min_level: Level::Warn,
        template: limits::DEFAULT_TEMPLATE,
    },
    // 地址变化。
    RuleTemplate {
        id: "address-change",
        name: "地址变化",
        events: &["ddns.changed", "stun.changed"],
        min_level: Level::Info,
        template: limits::DEFAULT_TEMPLATE,
    },
    // 登录（成功、新地址与失败相关事件）。
    RuleTemplate {
        id: "login",
        name: "登录",
        events: &[
            "auth.failed",
            "fileauth.failed",
            "auth.banned",
            "auth.flood",
            "guard.banned",
            "knock.failed",
            "knock.opened",
            "login.success",
            "login.newip",
        ],
        min_level: Level::Info,
        template: limits::DEFAULT_TEMPLATE,
    },
    // 配置变更。
    RuleTemplate {
        id: "config-change",
        name: "配置变更",
        events: &["audit.change", "config.rolledback"],
        min_level: Level::Info,
        template: limits::DEFAULT_TEMPLATE,
    },
    // 版本更新。
    RuleTemplate {
        id: "update",
        name: "版本更新",
        events: &["system.update", "program.update", "docker.update"],
        min_level: Level::Info,
        template: limits::DEFAULT_TEMPLATE,
    },
];

/// Builds an enabled rule from a preset (fresh key; the caller appends the
/// channel keys it should push to).
pub fn make_rule(preset: &RuleTemplate) -> Rule {
    Rule {
        key: new_key(),
        name: preset.name.to_owned(),
        enable: true,
        events: preset
            .events
            .iter()
            .map(|event| (*event).to_owned())
            .collect(),
        min_level: preset.min_level,
        template: preset.template.to_owned(),
        ..Rule::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fg_core::events::KINDS;

    #[test]
    fn templates_cover_known_event_kinds_and_make_valid_rules() {
        let names: Vec<_> = KINDS.iter().map(|info| info.name).collect();
        for preset in TEMPLATES {
            assert!(!preset.events.is_empty(), "{} has no events", preset.id);
            for event in preset.events {
                assert!(
                    names.contains(event),
                    "{} references unknown kind {}",
                    preset.id,
                    event
                );
            }
            let rule = make_rule(preset);
            assert!(rule.enable);
            assert_eq!(rule.name, preset.name);
            assert_eq!(rule.events.len(), preset.events.len());
            assert_eq!(rule.min_level, preset.min_level);
            assert_eq!(rule.channels, Vec::<String>::new());
        }
    }

    #[test]
    fn template_ids_are_unique() {
        let mut ids: Vec<_> = TEMPLATES.iter().map(|preset| preset.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), TEMPLATES.len());
        assert_eq!(
            TEMPLATES.len(),
            6,
            "six presets: critical, cert, address, login, config, update"
        );
    }
}
