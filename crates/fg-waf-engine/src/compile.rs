//! Compilation: turns a parsed [`RuleSetFile`] into the immutable
//! [`Compiled`] snapshot the evaluator reads. Compilation validates every
//! enabled rule (ids, lengths, matcher shape, regexes, IP lists) against
//! the centralized limits, collects *all* errors instead of failing on
//! the first, and precompiles regexes and IP networks so the hot path
//! never parses again. Disabled rules are skipped entirely — they are
//! neither validated nor compiled, so a broken rule can be disabled and
//! saved from the admin UI.
//!
//! Rule sets are untrusted input (WP-55 §8.2): size limits come from
//! [`crate::limits`], regex programs are size-capped, and every check
//! runs in time linear in the input.

use std::{
    collections::HashSet,
    fmt,
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
};

use ipnet::IpNet;
use regex::bytes::RegexBuilder;

use crate::{
    limits::{
        EngineConfig, MAX_COMPILED_REGEX_BYTES, MAX_CONDITION_DEPTH, MAX_DENY_STATUS,
        MAX_HEADER_NAME_LEN, MAX_IP_ENTRIES, MAX_REGEX_PATTERN_LEN, MAX_RULE_ID_LEN,
        MAX_RULE_MESSAGE_LEN, MAX_RULE_NAME_LEN, MAX_RULE_SET_NAME_LEN, MAX_RULES, MAX_TAG_LEN,
        MAX_TAGS_PER_RULE, MIN_DENY_STATUS, SUPPORTED_RULE_SET_VERSION,
    },
    request::Request,
    rule::{ActionKind, Field, Matcher, Operator, Rule, RuleSetFile},
};

/// One reason a rule set failed to compile. Errors carry the rule index
/// (0-based, as written in the file) and the rule's id as written, so the
/// integration layer can point at the offending rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileError {
    /// 0-based rule position; `None` for rule-set-level errors.
    pub index: Option<usize>,
    /// The rule's `id` as written (may be empty when the id itself is the
    /// problem).
    pub rule_id: Option<String>,
    /// Human-readable reason.
    pub message: String,
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.index, &self.rule_id) {
            (Some(index), Some(id)) if !id.is_empty() => {
                write!(f, "rule #{} (id \"{id}\"): {}", index + 1, self.message)
            }
            (Some(index), _) => write!(f, "rule #{}: {}", index + 1, self.message),
            (None, Some(id)) if !id.is_empty() => write!(f, "rule \"{id}\": {}", self.message),
            (None, _) => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for CompileError {}

/// The compiled, immutable rule set. Published through
/// `arc_swap::ArcSwap` by [`crate::engine::Engine`]; a request reads one
/// snapshot and every rule evaluation only touches that snapshot.
#[derive(Debug)]
pub struct Compiled {
    /// Rule set display name (informational, used in logs).
    pub name: String,
    /// Normalized body inspection limit: subjects of `body` conditions
    /// are truncated to this many bytes.
    pub body_inspect_limit: usize,
    rules: Vec<CompiledRule>,
}

impl Compiled {
    /// The enabled rules in evaluation order.
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// How many rules are in this snapshot.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// One enabled rule, fully precompiled.
#[derive(Debug)]
pub struct CompiledRule {
    /// Rule id (unique within the snapshot).
    pub id: Box<str>,
    /// Display name (falls back to the id when unset).
    pub name: Box<str>,
    /// Hit description for logs.
    pub message: Box<str>,
    /// Free-form labels.
    pub tags: Box<[Box<str>]>,
    /// Action on a hit.
    pub action: ActionKind,
    /// Response status for `deny` rules.
    pub status: u16,
    matcher: CompiledMatcher,
    hits: AtomicU64,
}

impl CompiledRule {
    /// Hits recorded against this rule since its snapshot was published
    /// (counters live in the snapshot and reset on every reload).
    pub fn hit_count(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Whether the rule's matcher holds for this request.
    pub(crate) fn matches(&self, req: &Request<'_>, body_inspect_limit: usize) -> bool {
        self.matcher.matches(req, body_inspect_limit)
    }

    /// Counts one hit (called by the evaluator; `count` rules keep
    /// evaluating on a hit, so their counter is their primary effect).
    pub(crate) fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }
}

/// The precompiled condition tree.
#[derive(Debug)]
pub(crate) enum CompiledMatcher {
    Single(CompiledCondition),
    All(Vec<CompiledMatcher>),
    Any(Vec<CompiledMatcher>),
    Not(Box<CompiledMatcher>),
}

impl CompiledMatcher {
    pub(crate) fn matches(&self, req: &Request<'_>, body_inspect_limit: usize) -> bool {
        match self {
            Self::Single(condition) => condition.matches(req, body_inspect_limit),
            Self::All(items) => items
                .iter()
                .all(|item| item.matches(req, body_inspect_limit)),
            Self::Any(items) => items
                .iter()
                .any(|item| item.matches(req, body_inspect_limit)),
            Self::Not(inner) => !inner.matches(req, body_inspect_limit),
        }
    }
}

#[derive(Debug)]
pub(crate) struct CompiledCondition {
    field: Field,
    /// Lower-cased header name; `Some` exactly when `field` is
    /// [`Field::Header`].
    header_name: Option<Box<str>>,
    op: CompiledOp,
    negate: bool,
}

impl CompiledCondition {
    fn matches(&self, req: &Request<'_>, body_inspect_limit: usize) -> bool {
        let hit = match &self.op {
            CompiledOp::IpIn(nets) => req
                .client_ip
                .is_some_and(|ip| nets.iter().any(|net| net.contains(&ip))),
            op => subject_bytes(self, req, body_inspect_limit)
                .is_some_and(|subject| op_matches(subject, op)),
        };
        hit != self.negate
    }
}

#[derive(Debug)]
pub(crate) enum CompiledOp {
    Regex(regex::bytes::Regex),
    Contains { needle: Box<[u8]>, ci: bool },
    Equals { value: Box<[u8]>, ci: bool },
    Prefix { value: Box<[u8]>, ci: bool },
    Suffix { value: Box<[u8]>, ci: bool },
    IpIn(Box<[IpNet]>),
}

/// The bytes a condition inspects; `None` when the subject is absent
/// (missing header, no body). The body is truncated to the inspection
/// limit so the engine's cost never exceeds it.
fn subject_bytes<'a>(
    condition: &CompiledCondition,
    req: &'a Request<'_>,
    body_inspect_limit: usize,
) -> Option<&'a [u8]> {
    match condition.field {
        Field::Method => Some(req.method.as_bytes()),
        Field::Host => Some(req.host.as_bytes()),
        Field::Path => Some(req.path.as_bytes()),
        Field::Query => Some(req.query.as_bytes()),
        Field::UserAgent => Some(req.user_agent.as_bytes()),
        Field::Header => req
            .header(condition.header_name.as_deref().unwrap_or(""))
            .map(str::as_bytes),
        Field::Body => req
            .body
            .map(|body| &body[..body.len().min(body_inspect_limit)]),
        Field::ClientIp => None,
    }
}

/// Compares one subject against a non-IP operator. Case-insensitive
/// comparisons fold ASCII only (the regex operator does full Unicode
/// folding inside the regex crate).
fn op_matches(subject: &[u8], op: &CompiledOp) -> bool {
    match op {
        CompiledOp::Regex(re) => re.is_match(subject),
        CompiledOp::Equals { value, ci } => {
            if *ci {
                subject.eq_ignore_ascii_case(value)
            } else {
                subject == value.as_ref()
            }
        }
        CompiledOp::Contains { needle, ci } => {
            if needle.is_empty() {
                return true;
            }
            if *ci {
                ci_contains(subject, needle)
            } else {
                subject
                    .windows(needle.len())
                    .any(|window| window == needle.as_ref())
            }
        }
        CompiledOp::Prefix { value, ci } => {
            if subject.len() < value.len() {
                return false;
            }
            let head = &subject[..value.len()];
            if *ci {
                head.eq_ignore_ascii_case(value)
            } else {
                head == value.as_ref()
            }
        }
        CompiledOp::Suffix { value, ci } => {
            if subject.len() < value.len() {
                return false;
            }
            let tail = &subject[subject.len() - value.len()..];
            if *ci {
                tail.eq_ignore_ascii_case(value)
            } else {
                tail == value.as_ref()
            }
        }
        // IpIn subjects come from `client_ip`, never from `subject_bytes`.
        CompiledOp::IpIn(_) => false,
    }
}

/// ASCII-case-insensitive substring search over bytes, allocation-free.
fn ci_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Compiles a rule set into the snapshot, or reports every error found.
/// Disabled rules are skipped without validation.
pub fn compile(
    rule_set: &RuleSetFile,
    config: EngineConfig,
) -> Result<Compiled, Vec<CompileError>> {
    let config = EngineConfig::clamped(config.body_inspect_limit);
    if rule_set.version != SUPPORTED_RULE_SET_VERSION {
        return Err(vec![CompileError {
            index: None,
            rule_id: None,
            message: format!(
                "unsupported rule set version {} (this engine supports version {SUPPORTED_RULE_SET_VERSION})",
                rule_set.version
            ),
        }]);
    }
    if rule_set.rules.len() > MAX_RULES {
        return Err(vec![CompileError {
            index: None,
            rule_id: None,
            message: format!(
                "rule set holds {} rules; the limit is {MAX_RULES}",
                rule_set.rules.len()
            ),
        }]);
    }
    if rule_set.name.len() > MAX_RULE_SET_NAME_LEN {
        return Err(vec![CompileError {
            index: None,
            rule_id: None,
            message: format!("rule set name is longer than {MAX_RULE_SET_NAME_LEN} bytes"),
        }]);
    }

    let mut errors: Vec<CompileError> = Vec::new();
    let mut seen_ids: HashSet<&str> = HashSet::new();
    let mut rules = Vec::new();
    for (index, rule) in rule_set.rules.iter().enumerate() {
        if !rule.enable {
            continue;
        }
        let before = errors.len();
        compile_rule(index, rule, &mut seen_ids, &mut errors);
        if errors.len() > before {
            continue;
        }
        let mut matcher_errors = Vec::new();
        let Some(matcher) = compile_matcher(&rule.match_, 1, &mut matcher_errors) else {
            errors.extend(matcher_errors.into_iter().map(|message| CompileError {
                index: Some(index),
                rule_id: Some(rule.id.clone()),
                message,
            }));
            continue;
        };
        rules.push(CompiledRule {
            id: rule.id.as_str().into(),
            name: if rule.name.is_empty() {
                rule.id.as_str().into()
            } else {
                rule.name.as_str().into()
            },
            message: rule.message.as_str().into(),
            tags: rule
                .tags
                .iter()
                .map(|tag| tag.as_str().into())
                .collect::<Vec<_>>()
                .into(),
            action: rule.action,
            status: rule.status,
            matcher,
            hits: AtomicU64::new(0),
        });
    }
    if errors.is_empty() {
        Ok(Compiled {
            name: rule_set.name.clone(),
            body_inspect_limit: config.body_inspect_limit,
            rules,
        })
    } else {
        Err(errors)
    }
}

/// Validates a single rule's scalar fields; pushes one error per problem.
fn compile_rule<'a>(
    index: usize,
    rule: &'a Rule,
    seen_ids: &mut HashSet<&'a str>,
    errors: &mut Vec<CompileError>,
) {
    let mut push = |message: String| {
        errors.push(CompileError {
            index: Some(index),
            rule_id: Some(rule.id.clone()),
            message,
        });
    };
    if rule.id.is_empty() {
        push("rule id must not be empty".to_owned());
    } else {
        if rule.id.len() > MAX_RULE_ID_LEN {
            push(format!("rule id is longer than {MAX_RULE_ID_LEN} bytes"));
        }
        if !seen_ids.insert(rule.id.as_str()) {
            push(format!("duplicate rule id \"{}\"", rule.id));
        }
    }
    if rule.name.len() > MAX_RULE_NAME_LEN {
        push(format!(
            "rule name is longer than {MAX_RULE_NAME_LEN} bytes"
        ));
    }
    if rule.message.len() > MAX_RULE_MESSAGE_LEN {
        push(format!(
            "rule message is longer than {MAX_RULE_MESSAGE_LEN} bytes"
        ));
    }
    if rule.tags.len() > MAX_TAGS_PER_RULE {
        push(format!("rule carries more than {MAX_TAGS_PER_RULE} tags"));
    }
    if rule.tags.iter().any(|tag| tag.len() > MAX_TAG_LEN) {
        push(format!("a rule tag is longer than {MAX_TAG_LEN} bytes"));
    }
    if rule.action == ActionKind::Deny
        && !(MIN_DENY_STATUS..=MAX_DENY_STATUS).contains(&rule.status)
    {
        push(format!(
            "deny status {} is outside {}..={}",
            rule.status, MIN_DENY_STATUS, MAX_DENY_STATUS
        ));
    }
}

/// Compiles a matcher tree; pushes every problem into `errors` and
/// returns `None` when anything failed. `depth` starts at 1 for a rule's
/// root matcher.
fn compile_matcher(
    matcher: &Matcher,
    depth: usize,
    errors: &mut Vec<String>,
) -> Option<CompiledMatcher> {
    if depth > MAX_CONDITION_DEPTH {
        errors.push(format!(
            "condition nesting is deeper than the limit of {MAX_CONDITION_DEPTH}"
        ));
        return None;
    }
    let forms = usize::from(matcher.all.is_some())
        + usize::from(matcher.any.is_some())
        + usize::from(matcher.not.is_some())
        + usize::from(matcher.field.is_some());
    if forms == 0 {
        errors.push(
            "matcher is empty: set one of all/any/not or a single field condition".to_owned(),
        );
        return None;
    }
    if forms > 1 {
        errors.push(
            "matcher must use exactly one of all/any/not or a single field condition".to_owned(),
        );
        return None;
    }
    if let Some(items) = &matcher.all {
        if !group_fields_are_clean(matcher, "\"all\"", errors) {
            return None;
        }
        if items.is_empty() {
            errors.push("\"all\" needs at least one condition".to_owned());
            return None;
        }
        let mut compiled = Vec::with_capacity(items.len());
        for item in items {
            compiled.push(compile_matcher(item, depth + 1, errors)?);
        }
        return Some(CompiledMatcher::All(compiled));
    }
    if let Some(items) = &matcher.any {
        if !group_fields_are_clean(matcher, "\"any\"", errors) {
            return None;
        }
        if items.is_empty() {
            errors.push("\"any\" needs at least one condition".to_owned());
            return None;
        }
        let mut compiled = Vec::with_capacity(items.len());
        for item in items {
            compiled.push(compile_matcher(item, depth + 1, errors)?);
        }
        return Some(CompiledMatcher::Any(compiled));
    }
    if let Some(inner) = &matcher.not {
        if !group_fields_are_clean(matcher, "\"not\"", errors) {
            return None;
        }
        return compile_matcher(inner, depth + 1, errors)
            .map(Box::new)
            .map(CompiledMatcher::Not);
    }
    compile_single(matcher, errors)
}

/// Group matchers must not carry single-condition fields.
fn group_fields_are_clean(matcher: &Matcher, form: &str, errors: &mut Vec<String>) -> bool {
    if matcher.op.is_some()
        || !matcher.value.is_empty()
        || !matcher.name.is_empty()
        || matcher.negate
        || matcher.case_insensitive
    {
        errors.push(format!(
            "{form} must not set field/op/value/name/negate/caseInsensitive"
        ));
        return false;
    }
    true
}

/// Compiles a single field condition.
fn compile_single(matcher: &Matcher, errors: &mut Vec<String>) -> Option<CompiledMatcher> {
    let field = matcher.field?;
    let Some(op) = matcher.op else {
        errors.push("condition needs an operator (op)".to_owned());
        return None;
    };
    if matcher.value.is_empty() {
        errors.push("condition value must not be empty".to_owned());
        return None;
    }
    let header_name = if field == Field::Header {
        if matcher.name.is_empty() {
            errors.push("header condition needs a header name (name)".to_owned());
            return None;
        }
        if matcher.name.len() > MAX_HEADER_NAME_LEN {
            errors.push(format!(
                "header name is longer than {MAX_HEADER_NAME_LEN} bytes"
            ));
            return None;
        }
        Some(matcher.name.to_ascii_lowercase().into_boxed_str())
    } else {
        if !matcher.name.is_empty() {
            errors.push("name is only valid with the header field".to_owned());
            return None;
        }
        None
    };
    let compiled_op = match op {
        Operator::IpIn => {
            if field != Field::ClientIp {
                errors.push(format!("ipIn requires the clientIp field, not \"{field}\""));
                return None;
            }
            match parse_ip_list(&matcher.value) {
                Ok(nets) if nets.len() > MAX_IP_ENTRIES => {
                    errors.push(format!(
                        "ipIn lists more than {MAX_IP_ENTRIES} addresses or networks"
                    ));
                    return None;
                }
                Ok(nets) => CompiledOp::IpIn(nets.into_boxed_slice()),
                Err(message) => {
                    errors.push(message);
                    return None;
                }
            }
        }
        Operator::Regex => {
            if field == Field::ClientIp {
                errors.push("regex requires a text field, not \"clientIp\"".to_owned());
                return None;
            }
            if matcher.value.len() > MAX_REGEX_PATTERN_LEN {
                errors.push(format!(
                    "regex pattern is longer than {MAX_REGEX_PATTERN_LEN} bytes"
                ));
                return None;
            }
            match RegexBuilder::new(&matcher.value)
                .case_insensitive(matcher.case_insensitive)
                .size_limit(MAX_COMPILED_REGEX_BYTES)
                .build()
            {
                Ok(re) => CompiledOp::Regex(re),
                Err(error) => {
                    errors.push(format!("invalid regex {:?}: {error}", matcher.value));
                    return None;
                }
            }
        }
        Operator::Contains | Operator::Equals | Operator::Prefix | Operator::Suffix => {
            if field == Field::ClientIp {
                errors.push(format!("{op} requires a text field, not \"clientIp\""));
                return None;
            }
            let value = matcher.value.as_bytes().to_vec().into_boxed_slice();
            match op {
                Operator::Contains => CompiledOp::Contains {
                    needle: value,
                    ci: matcher.case_insensitive,
                },
                Operator::Equals => CompiledOp::Equals {
                    value,
                    ci: matcher.case_insensitive,
                },
                Operator::Prefix => CompiledOp::Prefix {
                    value,
                    ci: matcher.case_insensitive,
                },
                Operator::Suffix => CompiledOp::Suffix {
                    value,
                    ci: matcher.case_insensitive,
                },
                Operator::Regex | Operator::IpIn => unreachable!("handled above"),
            }
        }
    };
    Some(CompiledMatcher::Single(CompiledCondition {
        field,
        header_name,
        op: compiled_op,
        negate: matcher.negate,
    }))
}

/// Parses an `ipIn` value: entries separated by commas, semicolons or
/// whitespace, each a bare IP address (host network) or CIDR.
fn parse_ip_list(value: &str) -> Result<Vec<IpNet>, String> {
    let mut nets = Vec::new();
    for item in value
        .split([',', ';', ' ', '\t', '\r', '\n'])
        .filter(|item| !item.is_empty())
    {
        let net = item
            .parse::<IpNet>()
            .or_else(|_| item.parse::<IpAddr>().map(host_net))
            .map_err(|_| format!("\"{item}\" is not an IP address or CIDR"))?;
        nets.push(net);
    }
    if nets.is_empty() {
        return Err("ipIn value lists no addresses or networks".to_owned());
    }
    Ok(nets)
}

/// The /32 or /128 network covering exactly `ip`.
fn host_net(ip: IpAddr) -> IpNet {
    match ip {
        IpAddr::V4(v4) => IpNet::new(IpAddr::V4(v4), 32).expect("32 is a valid prefix"),
        IpAddr::V6(v6) => IpNet::new(IpAddr::V6(v6), 128).expect("128 is a valid prefix"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::RuleSetFile;

    fn compile_json(json: &str) -> Result<Compiled, Vec<CompileError>> {
        let set = RuleSetFile::from_json(json.as_bytes()).expect("test rule set parses");
        compile(&set, EngineConfig::default())
    }

    fn one_rule(matcher: &str) -> String {
        format!(r#"{{ "rules": [ {{ "id": "1", "match": {matcher} }} ] }}"#)
    }

    #[test]
    fn compile_accepts_a_valid_ruleset_and_counts_rules() {
        let compiled = compile_json(
            r#"{
                "name": "set",
                "rules": [
                    { "id": "1", "match": { "field": "path", "op": "regex", "value": "\\.php" } },
                    { "id": "2", "name": "skip", "enable": false, "match": { "field": "path", "op": "contains", "value": "never" } },
                    { "id": "3", "match": { "field": "clientIp", "op": "ipIn", "value": "10.0.0.0/8, 192.168.1.1" } }
                ]
            }"#,
        )
        .expect("compiles");
        assert_eq!(compiled.name, "set");
        assert_eq!(compiled.rule_count(), 2, "disabled rules are skipped");
        assert_eq!(
            compiled.body_inspect_limit,
            crate::limits::DEFAULT_BODY_INSPECT_LIMIT
        );
        let [first, second] = compiled.rules() else {
            panic!("two rules expected");
        };
        assert_eq!(&*first.id, "1");
        assert_eq!(&*second.id, "3");
    }

    #[test]
    fn compile_collects_multiple_errors_in_one_pass() {
        // Rules with scalar problems skip matcher compilation, so each
        // broken rule contributes the errors found at its own level.
        let errors = compile_json(
            r#"{ "rules": [
                { "id": "", "match": { "field": "path", "op": "contains", "value": "x" } },
                { "id": "A", "match": { "field": "path", "op": "regex", "value": "[" } },
                { "id": "B", "match": { "field": "path", "op": "contains", "value": "y" } },
                { "id": "A", "match": { "field": "path", "op": "contains", "value": "z" } }
            ] }"#,
        )
        .expect_err("three broken rules");
        assert_eq!(errors.len(), 3, "empty id + invalid regex + duplicate id");
        assert!(errors.iter().all(|error| error.index.is_some()));
        let indexes: Vec<usize> = errors.iter().filter_map(|error| error.index).collect();
        assert_eq!(indexes, vec![0, 1, 3], "errors point at their rules");
    }

    #[test]
    fn compile_rejects_rule_counts_over_the_limit() {
        let rules: Vec<String> = (0..=MAX_RULES)
            .map(|index| {
                format!(
                    r#"{{ "id": "{index}", "match": {{ "field": "path", "op": "contains", "value": "x" }} }}"#
                )
            })
            .collect();
        let json = format!(r#"{{ "rules": [{}] }}"#, rules.join(","));
        let errors = compile_json(&json).expect_err("over the rule limit");
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("the limit is"), "{}", errors[0]);
    }

    #[test]
    fn compile_rejects_unsupported_rule_set_versions() {
        let errors = compile_json(r#"{ "version": 2, "rules": [] }"#).expect_err("bad version");
        assert!(
            errors[0].message.contains("unsupported rule set version"),
            "{}",
            errors[0]
        );
    }

    #[test]
    fn compile_rejects_oversized_regex_patterns() {
        let pattern = "a".repeat(MAX_REGEX_PATTERN_LEN + 1);
        let json = one_rule(&format!(
            r#"{{ "field": "path", "op": "regex", "value": "{pattern}" }}"#
        ));
        let errors = compile_json(&json).expect_err("pattern over the limit");
        assert!(
            errors[0].message.contains("regex pattern is longer"),
            "{}",
            errors[0]
        );
    }

    #[test]
    fn compile_rejects_invalid_and_unsupported_regex_syntax() {
        let errors = compile_json(&one_rule(
            r#"{ "field": "path", "op": "regex", "value": "[" }"#,
        ))
        .expect_err("invalid regex");
        assert!(errors[0].message.contains("invalid regex"), "{}", errors[0]);
        // Backreferences are not supported by the `regex` backend in this
        // tier (WP-55 §3.3 正则: fancy-regex comes with the SecLang steps).
        let errors = compile_json(&one_rule(
            r#"{ "field": "path", "op": "regex", "value": "(a)\\1" }"#,
        ))
        .expect_err("backreference");
        assert!(errors[0].message.contains("invalid regex"), "{}", errors[0]);
    }

    #[test]
    fn compile_rejects_duplicate_rule_ids() {
        let errors = compile_json(
            r#"{ "rules": [
                { "id": "7", "match": { "field": "path", "op": "contains", "value": "a" } },
                { "id": "7", "match": { "field": "path", "op": "contains", "value": "b" } }
            ] }"#,
        )
        .expect_err("duplicate id");
        assert!(
            errors[0].message.contains("duplicate rule id"),
            "{}",
            errors[0]
        );
    }

    #[test]
    fn compile_rejects_mixed_and_empty_matcher_forms() {
        let errors = compile_json(&one_rule(
            r#"{ "all": [ { "field": "path", "op": "contains", "value": "x" } ], "field": "path", "op": "contains", "value": "y" }"#,
        ))
        .expect_err("mixed forms");
        assert!(errors[0].message.contains("exactly one"), "{}", errors[0]);
        let errors = compile_json(&one_rule("{}")).expect_err("empty matcher");
        assert!(
            errors[0].message.contains("matcher is empty"),
            "{}",
            errors[0]
        );
        let errors = compile_json(&one_rule(r#"{ "all": [] }"#)).expect_err("empty all");
        assert!(errors[0].message.contains("at least one"), "{}", errors[0]);
        let errors = compile_json(&one_rule(
            r#"{ "any": [ { "field": "path", "op": "contains", "value": "x" } ], "negate": true }"#,
        ))
        .expect_err("group with single-condition fields");
        assert!(
            errors[0].message.contains("must not set field/op/value"),
            "{}",
            errors[0]
        );
    }

    #[test]
    fn compile_rejects_condition_nesting_over_the_depth_limit() {
        let mut matcher = r#"{ "field": "path", "op": "contains", "value": "x" }"#.to_owned();
        for _ in 0..=MAX_CONDITION_DEPTH {
            matcher = format!(r#"{{ "not": {matcher} }}"#);
        }
        let errors = compile_json(&one_rule(&matcher)).expect_err("too deep");
        assert!(
            errors[0].message.contains("nesting is deeper"),
            "{}",
            errors[0]
        );
    }

    #[test]
    fn compile_rejects_field_operator_mismatches() {
        let errors = compile_json(&one_rule(
            r#"{ "field": "path", "op": "ipIn", "value": "10.0.0.0/8" }"#,
        ))
        .expect_err("ipIn on a text field");
        assert!(errors[0].message.contains("clientIp"), "{}", errors[0]);
        let errors = compile_json(&one_rule(
            r#"{ "field": "clientIp", "op": "regex", "value": "a" }"#,
        ))
        .expect_err("regex on the client ip");
        assert!(errors[0].message.contains("text field"), "{}", errors[0]);
        let errors = compile_json(&one_rule(
            r#"{ "field": "path", "op": "contains", "value": "x", "name": "referer" }"#,
        ))
        .expect_err("name outside header field");
        assert!(
            errors[0].message.contains("only valid with the header"),
            "{}",
            errors[0]
        );
        let errors = compile_json(&one_rule(
            r#"{ "field": "header", "op": "contains", "value": "x" }"#,
        ))
        .expect_err("header without a name");
        assert!(errors[0].message.contains("header name"), "{}", errors[0]);
    }

    #[test]
    fn compile_rejects_bad_ip_lists() {
        let errors = compile_json(&one_rule(
            r#"{ "field": "clientIp", "op": "ipIn", "value": "10.0.0.0/8, not-an-ip" }"#,
        ))
        .expect_err("bad entry");
        assert!(
            errors[0].message.contains("not an IP address"),
            "{}",
            errors[0]
        );
        let errors = compile_json(&one_rule(
            r#"{ "field": "clientIp", "op": "ipIn", "value": ", ; ," }"#,
        ))
        .expect_err("separator-only value");
        assert!(
            errors[0].message.contains("lists no addresses"),
            "{}",
            errors[0]
        );
        let entries: Vec<String> = (0..=MAX_IP_ENTRIES)
            .map(|index| format!("10.{}.{}.0/24", index / 256, index % 256))
            .collect();
        let json = one_rule(&format!(
            r#"{{ "field": "clientIp", "op": "ipIn", "value": "{}" }}"#,
            entries.join(", ")
        ));
        let errors = compile_json(&json).expect_err("ip list over the limit");
        assert!(errors[0].message.contains("more than"), "{}", errors[0]);
    }

    #[test]
    fn compile_rejects_deny_status_outside_the_error_range() {
        let errors = compile_json(
            r#"{ "rules": [ { "id": "1", "status": 302, "match": { "field": "path", "op": "contains", "value": "x" } } ] }"#,
        )
        .expect_err("302 is not a deny status");
        assert!(errors[0].message.contains("outside"), "{}", errors[0]);
        compile_json(
            r#"{ "rules": [ { "id": "1", "status": 503, "match": { "field": "path", "op": "contains", "value": "x" } } ] }"#,
        )
        .expect("503 is a valid deny status");
        compile_json(
            r#"{ "rules": [ { "id": "1", "status": 302, "action": "count", "match": { "field": "path", "op": "contains", "value": "x" } } ] }"#,
        )
        .expect("status is ignored for non-deny actions");
    }

    #[test]
    fn compile_enforces_the_scalar_field_limits() {
        let long_id = "i".repeat(MAX_RULE_ID_LEN + 1);
        let errors = compile_json(&format!(
            r#"{{ "rules": [ {{ "id": "{long_id}", "match": {{ "field": "path", "op": "contains", "value": "x" }} }} ] }}"#
        ))
        .expect_err("id over the limit");
        assert!(
            errors[0].message.contains("rule id is longer"),
            "{}",
            errors[0]
        );
        let long_message = "m".repeat(MAX_RULE_MESSAGE_LEN + 1);
        let errors = compile_json(&format!(
            r#"{{ "rules": [ {{ "id": "1", "message": "{long_message}", "match": {{ "field": "path", "op": "contains", "value": "x" }} }} ] }}"#
        ))
        .expect_err("message over the limit");
        assert!(
            errors[0].message.contains("message is longer"),
            "{}",
            errors[0]
        );
        let tags: Vec<String> = (0..=MAX_TAGS_PER_RULE)
            .map(|index| format!("\"t{index}\""))
            .collect();
        let errors = compile_json(&format!(
            r#"{{ "rules": [ {{ "id": "1", "tags": [{}], "match": {{ "field": "path", "op": "contains", "value": "x" }} }} ] }}"#,
            tags.join(",")
        ))
        .expect_err("too many tags");
        assert!(errors[0].message.contains("more than"), "{}", errors[0]);
    }

    #[test]
    fn compile_requires_operators_and_values() {
        let errors = compile_json(&one_rule(r#"{ "field": "path", "value": "x" }"#))
            .expect_err("missing operator");
        assert!(errors[0].message.contains("operator"), "{}", errors[0]);
        let errors = compile_json(&one_rule(r#"{ "field": "path", "op": "contains" }"#))
            .expect_err("missing value");
        assert!(
            errors[0].message.contains("value must not be empty"),
            "{}",
            errors[0]
        );
    }

    #[test]
    fn compile_skips_disabled_rules_entirely() {
        let compiled = compile_json(
            r#"{ "rules": [
                { "id": "1", "enable": false, "match": { "field": "path", "op": "regex", "value": "[" } },
                { "id": "2", "match": { "field": "path", "op": "contains", "value": "x" } }
            ] }"#,
        )
        .expect("a broken disabled rule does not block compilation");
        assert_eq!(compiled.rule_count(), 1);
        assert_eq!(&*compiled.rules()[0].id, "2");
    }

    #[test]
    fn compile_names_rules_default_to_their_id() {
        let compiled = compile_json(&one_rule(
            r#"{ "field": "path", "op": "contains", "value": "x" }"#,
        ))
        .expect("compiles");
        assert_eq!(
            &*compiled.rules()[0].name,
            "1",
            "unset names fall back to the id"
        );
    }
}
