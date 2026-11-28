//! The rule set model for the first WAF engine tier (WP-55): a JSON
//! document describing ordered rules with a matcher tree and an action.
//! This is the FerrumGate-native format consumed by
//! [`RuleSetFile::from_json`]; the SecLang directive parser (WP-55 step
//! E1/E2) compiles into the same [`crate::compile`] types later.
//!
//! JSON conventions follow `docs/plan/00-conventions.md` §2: camelCase
//! field names, `deny_unknown_fields`, and `default` for every optional
//! field, so a minimal rule needs only `id` and `match`:
//!
//! ```json
//! {
//!   "version": 1,
//!   "name": "custom",
//!   "rules": [
//!     {
//!       "id": "1001",
//!       "name": "block php probes",
//!       "enable": true,
//!       "match": { "field": "path", "op": "regex", "value": "\\.php($|[?#])" },
//!       "action": "deny",
//!       "status": 403,
//!       "message": "php files are not served",
//!       "tags": ["scanner"]
//!     }
//!   ]
//! }
//! ```
//!
//! A matcher is exactly one of: a single field condition with `field`,
//! `op` and `value` (optional `name` for headers, `negate`,
//! `caseInsensitive`), or one of the group forms `{"all": [...]}`,
//! `{"any": [...]}` and `{"not": {...}}`. The XOR shape is validated at
//! compile time ([`crate::compile`]) with per-rule errors; serde alone
//! rejects unknown keys and wrong types.

use serde::{Deserialize, Serialize};

use crate::limits::{DEFAULT_DENY_STATUS, SUPPORTED_RULE_SET_VERSION};

/// The persisted rule set document (`waf-rules.json` at the integration
/// layer; the engine only sees the parsed form).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct RuleSetFile {
    /// Format version; only [`crate::limits::SUPPORTED_RULE_SET_VERSION`]
    /// is accepted by the compiler.
    #[serde(
        default = "default_version",
        skip_serializing_if = "is_default_version"
    )]
    pub version: u32,
    /// Display name used in logs; informational only.
    #[serde(skip_serializing_if = "is_empty")]
    pub name: String,
    /// Rules in evaluation order.
    #[serde(skip_serializing_if = "is_empty_rules")]
    pub rules: Vec<Rule>,
}

impl RuleSetFile {
    /// Parses a rule set from JSON bytes. Unknown keys and wrong types
    /// are rejected; semantic validation happens in
    /// [`crate::compile::compile`].
    pub fn from_json(bytes: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(bytes)
    }
}

/// One rule: a matcher tree plus the action to take on a hit.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Rule {
    /// Stable identifier, unique within the rule set; required.
    #[serde(skip_serializing_if = "is_empty")]
    pub id: String,
    /// Human-readable label for hit logs; optional.
    #[serde(skip_serializing_if = "is_empty")]
    pub name: String,
    /// Disabled rules are skipped entirely (not compiled, not evaluated).
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub enable: bool,
    /// What the rule matches on; required (an empty matcher is a compile
    /// error).
    #[serde(rename = "match")]
    pub match_: Matcher,
    /// What happens on a hit; defaults to [`ActionKind::Deny`].
    #[serde(skip_serializing_if = "is_default_action")]
    pub action: ActionKind,
    /// Response status for `deny` rules; defaults to 403 and must stay in
    /// 400..=599. Ignored for the other actions.
    #[serde(
        default = "default_deny_status",
        skip_serializing_if = "is_default_status"
    )]
    pub status: u16,
    /// Hit description for logs; optional.
    #[serde(skip_serializing_if = "is_empty")]
    pub message: String,
    /// Free-form labels for filtering hit logs.
    #[serde(skip_serializing_if = "is_empty_tags")]
    pub tags: Vec<String>,
}

/// The condition tree of one rule. See the module docs for the JSON
/// shape; exactly one form must be set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Matcher {
    /// Every nested condition must hold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all: Option<Vec<Matcher>>,
    /// At least one nested condition must hold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub any: Option<Vec<Matcher>>,
    /// The nested condition must not hold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not: Option<Box<Matcher>>,
    /// Request part the condition inspects; required for a single
    /// condition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<Field>,
    /// Header name (ASCII-case-insensitive); only valid with
    /// [`Field::Header`].
    #[serde(skip_serializing_if = "is_empty")]
    pub name: String,
    /// How the value is compared; required for a single condition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op: Option<Operator>,
    /// Pattern, literal or IP list depending on `op`; must not be empty.
    #[serde(skip_serializing_if = "is_empty")]
    pub value: String,
    /// Flips the condition result. A condition on an unavailable subject
    /// (missing header, no client IP, no body) evaluates to `false`
    /// first, so `negate` turns "subject absent" into a match.
    #[serde(skip_serializing_if = "is_false")]
    pub negate: bool,
    /// ASCII-case-insensitive comparison for the string operators;
    /// Unicode-aware for [`Operator::Regex`] (the regex crate's case
    /// folding).
    #[serde(skip_serializing_if = "is_false")]
    pub case_insensitive: bool,
}

/// The request part a single condition inspects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Field {
    /// HTTP method.
    Method,
    /// Host (without port).
    Host,
    /// Request path.
    Path,
    /// Raw query string without the leading `?`.
    Query,
    /// One request header, selected by `name`.
    Header,
    /// `User-Agent` header value.
    UserAgent,
    /// Body excerpt (truncated to the engine's inspection limit).
    Body,
    /// Client address; only usable with [`Operator::IpIn`].
    ClientIp,
}

impl Field {
    /// Stable spelling used in compile error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Method => "method",
            Self::Host => "host",
            Self::Path => "path",
            Self::Query => "query",
            Self::Header => "header",
            Self::UserAgent => "userAgent",
            Self::Body => "body",
            Self::ClientIp => "clientIp",
        }
    }
}

impl std::fmt::Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The comparison applied to the condition subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Operator {
    /// Regular expression (Rust `regex` syntax; backreferences and
    /// look-around are rejected at compile time in this tier).
    Regex,
    /// Substring search.
    Contains,
    /// Exact equality.
    Equals,
    /// Byte-prefix match.
    Prefix,
    /// Byte-suffix match.
    Suffix,
    /// The client address is inside one of the listed IPs / CIDRs
    /// (entries separated by commas, whitespace or newlines).
    IpIn,
}

impl Operator {
    /// Stable spelling used in compile error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Regex => "regex",
            Self::Contains => "contains",
            Self::Equals => "equals",
            Self::Prefix => "prefix",
            Self::Suffix => "suffix",
            Self::IpIn => "ipIn",
        }
    }
}

impl std::fmt::Display for Operator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What happens when a rule hits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ActionKind {
    /// Stop evaluating and let the request through.
    Allow,
    /// Stop evaluating and reject with the rule's status.
    #[default]
    Deny,
    /// Record the hit and keep evaluating (used for observation and
    /// threshold-style rules upstream of a `deny` rule).
    Count,
}

impl ActionKind {
    /// Stable spelling used in logs and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Count => "count",
        }
    }
}

impl std::fmt::Display for ActionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

fn default_true() -> bool {
    true
}

fn default_version() -> u32 {
    SUPPORTED_RULE_SET_VERSION
}

fn default_deny_status() -> u16 {
    DEFAULT_DENY_STATUS
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_true(value: &bool) -> bool {
    *value
}

// serde passes `&String` to `skip_serializing_if`; the slice form does
// not fit that signature.
#[allow(clippy::ptr_arg)]
fn is_empty(value: &String) -> bool {
    value.is_empty()
}

fn is_empty_tags(value: &[String]) -> bool {
    value.is_empty()
}

fn is_empty_rules(value: &[Rule]) -> bool {
    value.is_empty()
}

fn is_default_version(value: &u32) -> bool {
    *value == SUPPORTED_RULE_SET_VERSION
}

fn is_default_action(value: &ActionKind) -> bool {
    *value == ActionKind::default()
}

fn is_default_status(value: &u16) -> bool {
    *value == DEFAULT_DENY_STATUS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::DEFAULT_DENY_STATUS;

    #[test]
    fn parser_reads_minimal_rule_and_fills_defaults() {
        let set = RuleSetFile::from_json(
            br#"{ "rules": [ { "id": "1", "match": { "field": "path", "op": "contains", "value": "/x" } } ] }"#,
        )
        .expect("minimal rule set parses");
        assert_eq!(set.version, SUPPORTED_RULE_SET_VERSION);
        assert_eq!(set.rules.len(), 1);
        let rule = &set.rules[0];
        assert_eq!(rule.id, "1");
        assert!(rule.enable, "rules are enabled by default");
        assert_eq!(rule.action, ActionKind::Deny, "deny is the default action");
        assert_eq!(
            rule.status, DEFAULT_DENY_STATUS,
            "403 is the default status"
        );
        assert_eq!(rule.name, "");
        assert!(rule.tags.is_empty());
        assert_eq!(rule.match_.field, Some(Field::Path));
        assert_eq!(rule.match_.op, Some(Operator::Contains));
        assert_eq!(rule.match_.value, "/x");
        assert!(!rule.match_.negate);
        assert!(!rule.match_.case_insensitive);
    }

    #[test]
    fn parser_reads_camel_case_fields_and_enum_values() {
        let set = RuleSetFile::from_json(
            br#"{
                "version": 1,
                "name": "set",
                "rules": [ {
                    "id": "2",
                    "match": {
                        "field": "header",
                        "name": "Referer",
                        "op": "ipIn",
                        "value": "",
                        "negate": true,
                        "caseInsensitive": true
                    }
                } ]
            }"#,
        );
        // ipIn with an empty value parses; the field/op restrictions are
        // compile-time concerns.
        let set = set.expect("camelCase fields parse");
        let matcher = &set.rules[0].match_;
        assert_eq!(matcher.field, Some(Field::Header));
        assert_eq!(matcher.op, Some(Operator::IpIn));
        assert!(matcher.negate);
        assert!(matcher.case_insensitive);
        assert_eq!(matcher.name, "Referer");
    }

    #[test]
    fn parser_reads_group_matcher_forms() {
        let set = RuleSetFile::from_json(
            br#"{
                "rules": [ {
                    "id": "3",
                    "match": { "any": [
                        { "all": [
                            { "field": "userAgent", "op": "contains", "value": "bot" },
                            { "not": { "field": "method", "op": "equals", "value": "HEAD" } }
                        ] },
                        { "field": "clientIp", "op": "ipIn", "value": "10.0.0.0/8" }
                    ] }
                } ]
            }"#,
        )
        .expect("group matchers parse");
        let matcher = &set.rules[0].match_;
        assert!(matcher.any.is_some());
        assert_eq!(matcher.any.as_ref().expect("any").len(), 2);
    }

    #[test]
    fn parser_rejects_unknown_fields_at_every_level() {
        let top = RuleSetFile::from_json(br#"{ "unknown": 1, "rules": [] }"#);
        assert!(top.is_err(), "unknown top-level key rejected");
        let rule = RuleSetFile::from_json(
            br#"{ "rules": [ { "id": "1", "match": { "field": "path", "op": "contains", "value": "x" }, "unknown": 1 } ] }"#,
        );
        assert!(rule.is_err(), "unknown rule key rejected");
        let matcher = RuleSetFile::from_json(
            br#"{ "rules": [ { "id": "1", "match": { "field": "path", "op": "contains", "value": "x", "unknown": 1 } } ] }"#,
        );
        assert!(matcher.is_err(), "unknown matcher key rejected");
    }

    #[test]
    fn parser_rejects_unknown_enum_values() {
        let action = RuleSetFile::from_json(
            br#"{ "rules": [ { "id": "1", "action": "drop", "match": { "field": "path", "op": "contains", "value": "x" } } ] }"#,
        );
        assert!(action.is_err(), "unknown action rejected");
        let field = RuleSetFile::from_json(
            br#"{ "rules": [ { "id": "1", "match": { "field": "cookie", "op": "contains", "value": "x" } } ] }"#,
        );
        assert!(field.is_err(), "unknown field rejected");
        let op = RuleSetFile::from_json(
            br#"{ "rules": [ { "id": "1", "match": { "field": "path", "op": "rbl", "value": "x" } } ] }"#,
        );
        assert!(op.is_err(), "unknown operator rejected");
    }

    #[test]
    fn parser_rejects_malformed_json_and_wrong_types() {
        assert!(
            RuleSetFile::from_json(b"{").is_err(),
            "truncated json rejected"
        );
        assert!(RuleSetFile::from_json(b"null").is_err(), "null rejected");
        assert!(RuleSetFile::from_json(b"5").is_err(), "scalar rejected");
        // serde also accepts a positional sequence for structs; an empty
        // one fills every field from its default.
        let from_seq = RuleSetFile::from_json(b"[]").expect("empty positional sequence");
        assert!(from_seq.rules.is_empty());
        let wrong_match = RuleSetFile::from_json(br#"{ "rules": [ { "id": "1", "match": 5 } ] }"#);
        assert!(wrong_match.is_err(), "non-object match rejected");
        let not_array = RuleSetFile::from_json(
            br#"{ "rules": [ { "id": "1", "match": { "all": { "field": "path", "op": "contains", "value": "x" } } } ] }"#,
        );
        assert!(not_array.is_err(), "non-array all rejected");
        let invalid_utf8 = RuleSetFile::from_json(&[b'{', b'"', 0xff, b'}']);
        assert!(invalid_utf8.is_err(), "invalid utf-8 rejected");
    }

    #[test]
    fn rule_set_serializes_back_to_an_equivalent_document() {
        let set = RuleSetFile::from_json(
            br#"{
                "version": 1,
                "name": "roundtrip",
                "rules": [ {
                    "id": "9",
                    "name": "bot",
                    "match": { "field": "userAgent", "op": "contains", "value": "bot", "caseInsensitive": true },
                    "action": "count",
                    "message": "seen",
                    "tags": ["obs"]
                } ]
            }"#,
        )
        .expect("parses");
        let bytes = serde_json::to_vec(&set).expect("serializes");
        let reparsed = RuleSetFile::from_json(&bytes).expect("reparses");
        assert_eq!(set, reparsed, "round trip preserves the rule set");
        let text = String::from_utf8(bytes).expect("utf-8");
        assert!(text.contains("\"match\""), "match key keeps its JSON name");
        assert!(
            text.contains("\"caseInsensitive\""),
            "camelCase keys survive the round trip"
        );
    }
}
