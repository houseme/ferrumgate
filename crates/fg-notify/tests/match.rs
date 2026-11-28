//! Rule-matching integration tests (WP-68 §6): the fg-core event catalog
//! against rule patterns, silence-key rendering over real event variables
//! and the built-in templates.

use fg_core::events::{Event, Kind, Level};
use fg_notify::{
    Dedup, RuleTemplate, TEMPLATES, make_rule, rule_matches, silence_key, templates,
    wildcard_matches,
};

fn event(kind: Kind) -> Event {
    let mut event = Event::new(kind, "test");
    event.args = vec![("sourceAddr", "10.0.0.9".to_owned())];
    event
}

fn rule(patterns: &[&str], min_level: Level) -> fg_notify::Rule {
    fg_notify::Rule {
        enable: true,
        events: patterns
            .iter()
            .map(|pattern| (*pattern).to_owned())
            .collect(),
        min_level,
        ..fg_notify::Rule::default()
    }
}

#[test]
fn event_patterns_match_every_fg_core_kind() {
    for info in fg_core::events::KINDS {
        let event = event(info.kind);
        // The exact kind name matches at (or below) the default level.
        assert!(
            rule_matches(&rule(&[info.name], info.default_level), &event),
            "{} should match its own name",
            info.name
        );
        assert!(
            rule_matches(&rule(&["*"], info.default_level), &event),
            "{} should match the catch-all",
            info.name
        );
        // A non-matching prefix does not.
        assert!(
            !rule_matches(&rule(&["totally.other"], info.default_level), &event),
            "{} should not match another kind",
            info.name
        );
        // One level above the default does not fire.
        let above = match info.default_level {
            Level::Info => Level::Warn,
            Level::Warn | Level::Error => Level::Error,
        };
        if above != info.default_level {
            assert!(
                !rule_matches(&rule(&["*"], above), &event),
                "{} at {:?} should not fire a {:?} rule",
                info.name,
                info.default_level,
                above
            );
        }
    }
}

#[test]
fn silence_key_renders_event_variables_scoped_per_rule() {
    let mut first = rule(&["auth.*"], Level::Info);
    first.key = "rule00000001".into();
    first.silence = Some(fg_notify::Silence {
        dedup_key: "auth.failed from {sourceAddr}".into(),
        window_minutes: 5,
    });
    let mut second = first.clone();
    second.key = "rule00000002".into();
    let event = event(Kind::AuthFailed);
    let resolve = |name: &str| match name {
        "sourceAddr" => Some("10.0.0.9".to_owned()),
        _ => None,
    };
    let first_key = silence_key(&first, &event, &resolve).expect("silence");
    let second_key = silence_key(&second, &event, &resolve).expect("silence");
    assert_eq!(first_key, "rule00000001\u{1}auth.failed from 10.0.0.9");
    assert_ne!(first_key, second_key, "rules never share a silence key");
    // An empty dedup key falls back to the event kind.
    let mut plain = first.clone();
    plain.silence = Some(fg_notify::Silence::default());
    let plain_key = silence_key(&plain, &event, &resolve).expect("silence");
    assert_eq!(plain_key, "rule00000001\u{1}auth.failed");
    // Rules without silence produce nothing.
    assert!(silence_key(&rule(&["*"], Level::Info), &event, &resolve).is_none());
}

#[test]
fn silence_window_dedups_independent_keys() {
    let mut dedup = Dedup::default();
    let start = std::time::SystemTime::UNIX_EPOCH;
    let window = std::time::Duration::from_secs(300);
    assert!(dedup.should_send("rule1\u{1}10.0.0.9", window, start));
    assert!(!dedup.should_send(
        "rule1\u{1}10.0.0.9",
        window,
        start + std::time::Duration::from_secs(299)
    ));
    assert!(dedup.should_send("rule1\u{1}10.0.0.8", window, start));
    assert!(dedup.should_send("rule2\u{1}10.0.0.9", window, start));
    assert!(
        dedup.should_send(
            "rule1\u{1}10.0.0.9",
            window,
            start + std::time::Duration::from_secs(300)
        ),
        "after the window the same key may send again"
    );
}

#[test]
fn templates_make_rules_matching_their_event_sets() {
    assert_eq!(TEMPLATES.len(), 6);
    let ids: Vec<&str> = TEMPLATES.iter().map(|preset| preset.id).collect();
    for (id, expected) in [
        ("critical", 7usize),
        ("cert-expiry", 1),
        ("address-change", 2),
        ("login", 9),
        ("config-change", 2),
        ("update", 3),
    ] {
        assert_eq!(
            ids.iter().filter(|name| **name == id).count(),
            1,
            "{id} listed once"
        );
        let preset: &RuleTemplate = TEMPLATES
            .iter()
            .find(|preset| preset.id == id)
            .expect("preset");
        assert_eq!(preset.events.len(), expected, "{id} event count");
        let made = make_rule(preset);
        assert!(made.enable);
        for event_name in preset.events {
            let kind = fg_core::events::KINDS
                .iter()
                .find(|info| info.name == *event_name)
                .expect("kind exists");
            assert!(
                rule_matches(&made, &event(kind.kind)),
                "{} template matches {}",
                id,
                event_name
            );
        }
    }
    // The templates module is re-exported at the crate root as well.
    assert_eq!(templates::TEMPLATES.len(), TEMPLATES.len());
    // Wildcards stay available to user rules (template events are exact).
    assert!(
        TEMPLATES
            .iter()
            .all(|preset| preset.events.iter().all(|event| !event.contains('*')))
    );
}

#[test]
fn wildcard_matches_multisegment_patterns() {
    assert!(wildcard_matches("ssl.*", "ssl.expiring"));
    assert!(!wildcard_matches("ssl.*", "backup.done"));
    assert!(wildcard_matches("*", "auth.failed"));
    assert!(wildcard_matches("a*b*c", "abc"));
    assert!(!wildcard_matches("a?c", "abc"), "only * is a wildcard");
}
