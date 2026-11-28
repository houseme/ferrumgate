//! Rule matching (WP-68 §3.3): pure functions over the rule model and a
//! bus event. Event type patterns support `*` wildcards (`ddns.*`, `*`);
//! the event level must be at least the rule's minimum level; the silence
//! window drops repeats of the same rendered dedup key ([`Dedup`]).

use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

use fg_core::events::Event;

use crate::model::{Rule, limits};

/// Wildcard match: `*` matches any (possibly empty) sequence; everything
/// else compares literally. A pattern may contain several `*`.
pub fn wildcard_matches(pattern: &str, name: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == name;
    }
    let mut parts = pattern.split('*');
    // Everything before the first `*` must be a prefix.
    let mut rest = name;
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(stripped) = rest.strip_prefix(first) else {
        return false;
    };
    rest = stripped;
    let segments: Vec<&str> = parts.collect();
    let Some((last, middle)) = segments.split_last() else {
        return true;
    };
    for part in middle {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

/// Whether the rule fires for `event`: enabled, an event pattern matches
/// the event type name, and the level is at least the rule's minimum.
pub fn rule_matches(rule: &Rule, event: &Event) -> bool {
    rule.enable
        && !rule.events.is_empty()
        && rule
            .events
            .iter()
            .any(|pattern| wildcard_matches(pattern, event.kind.info().name))
        && event.level >= rule.min_level
}

/// The dedup key for a rule and event: the rule's silence template
/// rendered over the event variables, scoped by the rule key. An empty
/// template uses the event kind itself. `None` when the rule has no
/// silence window.
pub fn silence_key(
    rule: &Rule,
    event: &Event,
    vars: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    let silence = rule.silence.as_ref()?;
    let rendered = if silence.dedup_key.is_empty() {
        event.kind.info().name.to_owned()
    } else {
        crate::channels::render_values(&silence.dedup_key, vars)
    };
    Some(format!("{}\u{1}{}", rule.key, rendered))
}

/// Bounded key → last-sent-time map backing the silence windows. Keys not
/// sent within the window may send again; the oldest entries are evicted
/// beyond [`limits::DEDUP_MAX`].
#[derive(Debug, Default)]
pub struct Dedup {
    recent: HashMap<String, SystemTime>,
    order: Vec<String>,
}

impl Dedup {
    /// Whether `key` may send now: yes on first sight and outside the
    /// window; a `true` answer records the send at `now`.
    pub fn should_send(&mut self, key: &str, window: Duration, now: SystemTime) -> bool {
        match self.recent.get(key) {
            Some(&last) if now.duration_since(last).unwrap_or(Duration::ZERO) < window => false,
            _ => {
                self.record(key, now);
                true
            }
        }
    }

    /// Records a send without deciding (used by callers that decide
    /// elsewhere).
    pub fn record(&mut self, key: &str, now: SystemTime) {
        if self.recent.contains_key(key) {
            self.recent.insert(key.to_owned(), now);
            return;
        }
        if self.order.len() >= limits::DEDUP_MAX {
            let oldest = self.order.remove(0);
            self.recent.remove(&oldest);
        }
        self.order.push(key.to_owned());
        self.recent.insert(key.to_owned(), now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fg_core::events::{Event, Kind, Level};

    fn make_event(kind: Kind, level: Level) -> Event {
        let mut event = Event::new(kind, "test");
        event.level = level;
        event
    }

    fn rule(patterns: &[&str], min_level: Level) -> Rule {
        Rule {
            enable: true,
            events: patterns
                .iter()
                .map(|pattern| (*pattern).to_owned())
                .collect(),
            min_level,
            ..Rule::default()
        }
    }

    #[test]
    fn rule_matches_wildcard_and_level() {
        let event = make_event(Kind::DdnsChanged, Level::Info);
        assert!(rule_matches(&rule(&["ddns.*"], Level::Info), &event));
        assert!(rule_matches(&rule(&["*"], Level::Info), &event));
        assert!(rule_matches(
            &rule(&["ddns.changed", "stun.*"], Level::Info),
            &event
        ));
        assert!(!rule_matches(&rule(&["ddns"], Level::Info), &event));
        assert!(rule_matches(&rule(&["*.changed"], Level::Info), &event));
        // Level below the rule's minimum never fires.
        assert!(!rule_matches(&rule(&["ddns.*"], Level::Warn), &event));
        assert!(rule_matches(
            &rule(&["ddns.*"], Level::Info),
            &make_event(Kind::DdnsFailed, Level::Error)
        ));
        // Disabled rules never fire.
        let mut disabled = rule(&["*"], Level::Info);
        disabled.enable = false;
        assert!(!rule_matches(&disabled, &event));
    }

    #[test]
    fn wildcard_matches_star_segments() {
        assert!(wildcard_matches("*", "anything.at.all"));
        assert!(wildcard_matches("auth.*", "auth.failed"));
        assert!(wildcard_matches("*.failed", "auth.failed"));
        assert!(wildcard_matches("a*b*c", "a-x-b-y-c"));
        assert!(wildcard_matches("a*b*c", "abc"));
        assert!(!wildcard_matches("a*b*c", "a-x-b"));
        assert!(!wildcard_matches("auth.*", "guard.banned"));
        assert!(wildcard_matches("", ""));
        assert!(!wildcard_matches("", "x"));
    }

    #[test]
    fn dedup_window() {
        let mut dedup = Dedup::default();
        let start = SystemTime::UNIX_EPOCH;
        assert!(dedup.should_send("k", Duration::from_secs(60), start));
        assert!(!dedup.should_send(
            "k",
            Duration::from_secs(60),
            start + Duration::from_secs(59)
        ));
        assert!(dedup.should_send(
            "k",
            Duration::from_secs(60),
            start + Duration::from_secs(60)
        ));
        // Other keys are independent; the map is bounded.
        for index in 0..(limits::DEDUP_MAX + 10) {
            let key = format!("k{index}");
            assert!(dedup.should_send(&key, Duration::from_secs(60), start));
        }
        assert!(
            dedup.should_send("k", Duration::from_secs(60), start),
            "evicted keys may send again"
        );
    }
}
