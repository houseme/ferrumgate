//! Compiled SecLang ruleset ([`Waf`]) and 5-phase transaction evaluator
//! ([`Transaction`]) with anomaly scoring, chained rules, control flow,
//! macro expansion, and bounded TTL persistent collections (WP-55 steps E4, E5, E8).

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ipnet::IpNet;
use regex::RegexBuilder;

use crate::{
    body::{BodyProcessor, MAX_BODY_ARGS, ParsedBody, parse_body, parse_query_string},
    detect::{detect_sqli, detect_xss},
    limits::{
        DEFAULT_BODY_INSPECT_LIMIT, DEFAULT_DENY_STATUS, MAX_COMPILED_REGEX_BYTES,
        MAX_REGEX_PATTERN_LEN,
    },
    prefilter::Prefilter,
    seclang::{
        Action, AllowScope, BodyLimitAction, CtlAction, Directive, DisruptiveAction, ExpireVarSpec,
        IdRange, IncludeResolver, NoopResolver, OperatorKind, OperatorSpec, RuleEngineMode,
        SecLangError, SecRuleAst, SetVarOp, SetVarSpec, SourceSpan, VarSelector, VarSpec, parse,
        parse_with_includes,
    },
    transforms::{Transform, apply_transforms},
};

/// Default response body inspection limit (512 KiB).
pub const DEFAULT_RESPONSE_BODY_LIMIT: usize = 512 * 1024;
/// Default inbound anomaly score threshold (OWASP CRS default = 5).
pub const DEFAULT_INBOUND_THRESHOLD: i32 = 5;
/// Default outbound anomaly score threshold (OWASP CRS default = 4).
pub const DEFAULT_OUTBOUND_THRESHOLD: i32 = 4;
/// Default persistent collection timeout (1 hour).
pub const DEFAULT_COLLECTION_TIMEOUT_SECS: u64 = 3600;
/// Maximum number of persistent collection buckets held in memory.
pub const MAX_PERSISTENT_COLLECTIONS: usize = 4096;
/// Maximum number of keys per persistent collection bucket.
pub const MAX_PERSISTENT_KEYS: usize = 256;

/// Evaluation phases of a ModSecurity / CRS HTTP transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Phase {
    RequestHeaders = 1,
    RequestBody = 2,
    ResponseHeaders = 3,
    ResponseBody = 4,
    Logging = 5,
}

impl Phase {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::RequestHeaders),
            2 => Some(Self::RequestBody),
            3 => Some(Self::ResponseHeaders),
            4 => Some(Self::ResponseBody),
            5 => Some(Self::Logging),
            _ => None,
        }
    }

    pub const fn index(self) -> usize {
        (self as usize) - 1
    }
}

/// Configuration for compiling and executing a [`Waf`] SecLang ruleset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WafConfig {
    /// OWASP CRS paranoia level (`1..=4`, clamped).
    pub paranoia_level: u8,
    /// Inbound anomaly score threshold (`<= 0` disables automatic threshold blocking).
    pub inbound_threshold: i32,
    /// Outbound anomaly score threshold (`<= 0` disables automatic threshold blocking).
    pub outbound_threshold: i32,
    /// Enables literal substring prefiltering before `@rx` regex evaluation.
    pub regex_prefilter: bool,
    /// Maximum request body bytes inspected.
    pub request_body_limit: usize,
    /// Action when request body exceeds `request_body_limit`.
    pub request_body_limit_action: BodyLimitAction,
    /// Maximum response body bytes inspected.
    pub response_body_limit: usize,
    /// Enables WebDAV methods & headers in default CRS variables.
    pub webdav: bool,
    /// Initial rule engine mode (`On`, `DetectionOnly`, `Off`).
    pub rule_engine: RuleEngineMode,
    /// Default persistent collection TTL in seconds.
    pub collection_timeout_secs: u64,
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            paranoia_level: 1,
            inbound_threshold: DEFAULT_INBOUND_THRESHOLD,
            outbound_threshold: DEFAULT_OUTBOUND_THRESHOLD,
            regex_prefilter: true,
            request_body_limit: DEFAULT_BODY_INSPECT_LIMIT,
            request_body_limit_action: BodyLimitAction::Reject,
            response_body_limit: DEFAULT_RESPONSE_BODY_LIMIT,
            webdav: false,
            rule_engine: RuleEngineMode::On,
            collection_timeout_secs: DEFAULT_COLLECTION_TIMEOUT_SECS,
        }
    }
}

/// Non-fatal diagnostic recorded when a rule is skipped during compilation
/// (e.g., unsupported operator or incompatible regex feature).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileWarning {
    pub file: String,
    pub line: u32,
    pub rule_id: Option<u64>,
    pub message: String,
}

/// Request metadata passed into Phase 1 ([`Transaction::process_request_headers`]).
#[derive(Clone, Debug, Default)]
pub struct RequestHead {
    pub method: String,
    /// Raw request target URI (path + optional `?query`).
    pub uri: String,
    pub protocol: String,
    pub headers: Vec<(String, String)>,
    pub remote_addr: Option<IpAddr>,
}

impl RequestHead {
    pub fn new(method: impl Into<String>, uri: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            uri: uri.into(),
            protocol: "HTTP/1.1".to_owned(),
            headers: Vec::new(),
            remote_addr: None,
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_remote_addr(mut self, ip: IpAddr) -> Self {
        self.remote_addr = Some(ip);
        self
    }

    pub fn with_protocol(mut self, proto: impl Into<String>) -> Self {
        self.protocol = proto.into();
        self
    }
}

/// Response metadata passed into Phase 3 ([`Transaction::process_response_headers`]).
#[derive(Clone, Debug, Default)]
pub struct ResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

impl ResponseHead {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// Disruptive intervention action produced by a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InterventionAction {
    Deny,
    Drop,
    Redirect(String),
}

/// Final disruptive decision on a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intervention {
    pub status: u16,
    pub action: InterventionAction,
    pub rule_id: u64,
    pub message: String,
    pub logdata: String,
}

/// Record of one rule match during a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchedRule {
    pub id: u64,
    pub message: String,
    pub severity: u8,
    pub file: String,
    pub line: u32,
    pub data: String,
    pub tags: Vec<String>,
    pub phase: Phase,
}

// ---------------------------------------------------------------------------
// Bounded TTL Persistent Collections (`IP`, `USER`, `GLOBAL`, `SESSION`)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct PersistentEntry {
    value: String,
    expires_at: Instant,
}

#[derive(Default)]
struct PersistentInner {
    /// Keyed by `(COLLECTION_UPPER, collection_id)` -> `(key_lower -> entry)`.
    buckets: HashMap<(String, String), HashMap<String, PersistentEntry>>,
}

/// Bounded, thread-safe in-memory store for `IP`, `USER`, `GLOBAL`, and
/// `SESSION` persistent collections with per-key TTL expiration.
pub struct PersistentStore {
    default_ttl: Duration,
    inner: Mutex<PersistentInner>,
}

impl PersistentStore {
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            default_ttl,
            inner: Mutex::new(PersistentInner::default()),
        }
    }

    /// Reads a key at timestamp `now`, returning `None` if absent or expired.
    pub fn get_at(
        &self,
        collection: &str,
        bucket_id: &str,
        key: &str,
        now: Instant,
    ) -> Option<String> {
        let mut guard = self.inner.lock().expect("persistent store lock");
        let bucket_key = (collection.to_ascii_uppercase(), bucket_id.to_owned());
        let map = guard.buckets.get_mut(&bucket_key)?;
        let key_lower = key.to_ascii_lowercase();
        if let Some(entry) = map.get(&key_lower) {
            if entry.expires_at > now {
                return Some(entry.value.clone());
            }
            map.remove(&key_lower);
        }
        None
    }

    /// Reads all live (non-expired) entries in a bucket at timestamp `now`.
    pub fn entries_at(
        &self,
        collection: &str,
        bucket_id: &str,
        now: Instant,
    ) -> Vec<(String, String)> {
        let mut guard = self.inner.lock().expect("persistent store lock");
        let bucket_key = (collection.to_ascii_uppercase(), bucket_id.to_owned());
        let Some(map) = guard.buckets.get_mut(&bucket_key) else {
            return Vec::new();
        };
        map.retain(|_, entry| entry.expires_at > now);
        let mut out: Vec<(String, String)> = map
            .iter()
            .map(|(k, v)| (k.clone(), v.value.clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Writes a key with optional explicit TTL (falling back to `default_ttl`).
    pub fn set_at(
        &self,
        collection: &str,
        bucket_id: &str,
        key: &str,
        value: String,
        ttl: Option<Duration>,
        now: Instant,
    ) {
        let mut guard = self.inner.lock().expect("persistent store lock");
        let bucket_key = (collection.to_ascii_uppercase(), bucket_id.to_owned());
        if !guard.buckets.contains_key(&bucket_key)
            && guard.buckets.len() >= MAX_PERSISTENT_COLLECTIONS
        {
            // Evict expired entries first; if still full, drop one arbitrary bucket.
            purge_locked(&mut guard, now);
            if guard.buckets.len() >= MAX_PERSISTENT_COLLECTIONS
                && let Some(first_key) = guard.buckets.keys().next().cloned()
            {
                guard.buckets.remove(&first_key);
            }
        }
        let map = guard.buckets.entry(bucket_key).or_default();
        let key_lower = key.to_ascii_lowercase();
        if !map.contains_key(&key_lower) && map.len() >= MAX_PERSISTENT_KEYS {
            map.retain(|_, e| e.expires_at > now);
            if map.len() >= MAX_PERSISTENT_KEYS {
                return;
            }
        }
        let expires_at = now + ttl.unwrap_or(self.default_ttl);
        map.insert(key_lower, PersistentEntry { value, expires_at });
    }

    /// Updates expiration TTL of an existing key (implements `expirevar`).
    pub fn expire_key_at(
        &self,
        collection: &str,
        bucket_id: &str,
        key: &str,
        ttl: Duration,
        now: Instant,
    ) {
        let mut guard = self.inner.lock().expect("persistent store lock");
        let bucket_key = (collection.to_ascii_uppercase(), bucket_id.to_owned());
        if let Some(map) = guard.buckets.get_mut(&bucket_key)
            && let Some(entry) = map.get_mut(&key.to_ascii_lowercase())
        {
            entry.expires_at = now + ttl;
        }
    }

    /// Deletes a key from a persistent collection.
    pub fn delete(&self, collection: &str, bucket_id: &str, key: &str) {
        let mut guard = self.inner.lock().expect("persistent store lock");
        let bucket_key = (collection.to_ascii_uppercase(), bucket_id.to_owned());
        if let Some(map) = guard.buckets.get_mut(&bucket_key) {
            map.remove(&key.to_ascii_lowercase());
        }
    }

    /// Removes all expired keys and empty buckets as of `now`.
    pub fn purge_expired_at(&self, now: Instant) {
        let mut guard = self.inner.lock().expect("persistent store lock");
        purge_locked(&mut guard, now);
    }

    /// Current number of active buckets.
    pub fn bucket_count(&self) -> usize {
        self.inner
            .lock()
            .expect("persistent store lock")
            .buckets
            .len()
    }
}

fn purge_locked(inner: &mut PersistentInner, now: Instant) {
    inner.buckets.retain(|_, map| {
        map.retain(|_, entry| entry.expires_at > now);
        !map.is_empty()
    });
}

// ---------------------------------------------------------------------------
// Compiled SecLang Ruleset (`Waf`)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct PhaseDefaults {
    disruptive: DisruptiveAction,
    transforms: Vec<Transform>,
    log: bool,
}

impl Default for PhaseDefaults {
    fn default() -> Self {
        Self {
            disruptive: DisruptiveAction::Pass,
            transforms: Vec::new(),
            log: true,
        }
    }
}

#[derive(Clone, Debug)]
enum CompiledVarSelector {
    Key(String),
    Regex(regex::Regex),
}

#[derive(Clone, Debug)]
struct CompiledVarSpec {
    name: String,
    selector: Option<CompiledVarSelector>,
    negated: bool,
    count: bool,
}

#[derive(Clone, Debug)]
enum CompiledSecOp {
    Rx {
        regex: regex::Regex,
        prefilter: Option<Prefilter>,
    },
    Pm {
        /// Lowercased phrases for fast ASCII-CI matching.
        phrases: Vec<Box<str>>,
    },
    Contains(String),
    StrEq(String),
    StartsWith(String),
    EndsWith(String),
    Within(String),
    Eq(String),
    Gt(String),
    Lt(String),
    Ge(String),
    Le(String),
    IpMatch(Vec<IpNet>),
    ValidateByteRange(Vec<(u8, u8)>),
    ValidateUtf8,
    UnconditionalMatch,
    NoMatch,
    DetectSqli,
    DetectXss,
}

#[derive(Clone, Debug)]
struct CompiledSecRule {
    id: u64,
    phase: Phase,
    paranoia_level: u8,
    variables: Vec<CompiledVarSpec>,
    op_negated: bool,
    op: CompiledSecOp,
    transforms: Vec<Transform>,
    disruptive: DisruptiveAction,
    status: u16,
    msg: String,
    logdata: String,
    severity: u8,
    tags: Vec<String>,
    capture: bool,
    log: bool,
    skip: usize,
    skip_after: Option<String>,
    setvars: Vec<SetVarSpec>,
    expirevars: Vec<ExpireVarSpec>,
    ctls: Vec<CtlAction>,
    setenvs: Vec<(String, String)>,
    initcols: Vec<(String, String)>,
    span: SourceSpan,
    chain: Option<Box<CompiledSecRule>>,
}

#[derive(Clone, Debug)]
enum PhaseEntry {
    Rule(Box<CompiledSecRule>),
    Marker(String),
}

struct CompiledWaf {
    config: WafConfig,
    request_body_access: bool,
    response_body_access: bool,
    arg_separator: u8,
    phases: [Vec<PhaseEntry>; 5],
    warnings: Vec<CompileWarning>,
    rule_count: usize,
    persistent: Arc<PersistentStore>,
}

/// Compiled, immutable SecLang WAF ruleset. Cheaply cloneable (`Arc` backed).
#[derive(Clone)]
pub struct Waf {
    inner: Arc<CompiledWaf>,
}

impl Waf {
    /// Parses and compiles a SecLang ruleset string (without `Include` resolution).
    pub fn from_seclang(config: WafConfig, rules: &str) -> Result<Self, Vec<SecLangError>> {
        let directives = parse("rules.conf", rules)?;
        Self::from_directives(config, directives, &HashMap::new())
    }

    /// Parses and compiles a SecLang ruleset string, resolving `Include`
    /// directives through `resolver`.
    pub fn from_seclang_with_includes<R: IncludeResolver>(
        config: WafConfig,
        rules: &str,
        resolver: &R,
    ) -> Result<Self, Vec<SecLangError>> {
        let directives = parse_with_includes("rules.conf", rules, resolver)?;
        Self::from_directives(config, directives, &HashMap::new())
    }

    /// Parses and compiles a SecLang ruleset string with both an `Include`
    /// resolver and external data files (for `@pmFromFile` / `@ipMatchFromFile`).
    pub fn from_seclang_with_data<R: IncludeResolver>(
        config: WafConfig,
        rules: &str,
        resolver: &R,
        data_files: &HashMap<String, String>,
    ) -> Result<Self, Vec<SecLangError>> {
        let directives = parse_with_includes("rules.conf", rules, resolver)?;
        Self::from_directives(config, directives, data_files)
    }

    /// Compiles a pre-parsed list of SecLang [`Directive`] items.
    pub fn from_directives(
        mut config: WafConfig,
        directives: Vec<Directive>,
        data_files: &HashMap<String, String>,
    ) -> Result<Self, Vec<SecLangError>> {
        config.paranoia_level = config.paranoia_level.clamp(1, 4);

        let mut request_body_access = true;
        let mut response_body_access = true;
        let mut arg_separator = b'&';
        let mut defaults: [PhaseDefaults; 5] = Default::default();
        let mut entries: Vec<PhaseEntry> = Vec::new();
        let mut warnings: Vec<CompileWarning> = Vec::new();
        let mut errors: Vec<SecLangError> = Vec::new();

        // Walk directives; assemble `chain` sequences into nested rules.
        let mut idx = 0usize;
        while idx < directives.len() {
            match &directives[idx] {
                Directive::SecRule(rule_ast) => {
                    let (chain_asts, consumed) = collect_chain(&directives, idx);
                    idx += consumed;
                    match compile_rule_chain(
                        &chain_asts,
                        &defaults,
                        config.regex_prefilter,
                        data_files,
                        &mut warnings,
                    ) {
                        Ok(Some(compiled)) => entries.push(PhaseEntry::Rule(Box::new(compiled))),
                        Ok(None) => {
                            // Rule skipped cleanly (warning already recorded).
                        }
                        Err(e) => errors.push(e),
                    }
                    let _ = rule_ast;
                }
                Directive::SecAction { actions, span } => {
                    idx += 1;
                    let synth = SecRuleAst {
                        variables: Vec::new(),
                        operator: OperatorSpec {
                            negated: false,
                            kind: OperatorKind::UnconditionalMatch,
                            arg: String::new(),
                        },
                        actions: actions.clone(),
                        span: span.clone(),
                    };
                    match compile_rule_chain(
                        &[synth],
                        &defaults,
                        config.regex_prefilter,
                        data_files,
                        &mut warnings,
                    ) {
                        Ok(Some(compiled)) => entries.push(PhaseEntry::Rule(Box::new(compiled))),
                        Ok(None) => {}
                        Err(e) => errors.push(e),
                    }
                }
                Directive::SecMarker { name, .. } => {
                    idx += 1;
                    entries.push(PhaseEntry::Marker(name.clone()));
                }
                Directive::SecDefaultAction { actions, .. } => {
                    idx += 1;
                    let phase = actions
                        .iter()
                        .find_map(|a| match a {
                            Action::Phase(p) => Phase::from_u8(*p),
                            _ => None,
                        })
                        .unwrap_or(Phase::RequestBody);
                    let def = &mut defaults[phase.index()];
                    for act in actions {
                        match act {
                            Action::Disruptive(d) => def.disruptive = d.clone(),
                            Action::Transform(name) => {
                                if name.eq_ignore_ascii_case("none") {
                                    def.transforms.clear();
                                } else if let Some(t) = Transform::from_name(name) {
                                    def.transforms.push(t);
                                }
                            }
                            Action::Log => def.log = true,
                            Action::NoLog => def.log = false,
                            _ => {}
                        }
                    }
                }
                Directive::SecRuleRemoveById { ranges, .. } => {
                    idx += 1;
                    entries.retain(|e| match e {
                        PhaseEntry::Rule(r) => !ranges.iter().any(|rg| rg.contains(r.id)),
                        PhaseEntry::Marker(_) => true,
                    });
                }
                Directive::SecRuleRemoveByTag { tag, .. } => {
                    idx += 1;
                    entries.retain(|e| match e {
                        PhaseEntry::Rule(r) => !r.tags.iter().any(|t| t == tag),
                        PhaseEntry::Marker(_) => true,
                    });
                }
                Directive::SecRuleRemoveByMsg { msg, .. } => {
                    idx += 1;
                    entries.retain(|e| match e {
                        PhaseEntry::Rule(r) => r.msg != *msg,
                        PhaseEntry::Marker(_) => true,
                    });
                }
                Directive::SecRuleRemoveTargetById {
                    id,
                    variables,
                    span,
                } => {
                    idx += 1;
                    if let Ok(mut compiled_vars) = compile_var_specs(variables, span) {
                        for v in &mut compiled_vars {
                            v.negated = true;
                        }
                        for entry in &mut entries {
                            if let PhaseEntry::Rule(r) = entry
                                && r.id == *id
                            {
                                r.variables.extend(compiled_vars.clone());
                            }
                        }
                    }
                }
                Directive::SecRuleUpdateTargetById {
                    id,
                    variables,
                    span,
                } => {
                    idx += 1;
                    if let Ok(compiled_vars) = compile_var_specs(variables, span) {
                        for entry in &mut entries {
                            if let PhaseEntry::Rule(r) = entry
                                && r.id == *id
                            {
                                r.variables.extend(compiled_vars.clone());
                            }
                        }
                    }
                }
                Directive::SecRuleUpdateTargetByTag {
                    tag,
                    variables,
                    span,
                } => {
                    idx += 1;
                    if let Ok(compiled_vars) = compile_var_specs(variables, span) {
                        for entry in &mut entries {
                            if let PhaseEntry::Rule(r) = entry
                                && r.tags.iter().any(|t| t == tag)
                            {
                                r.variables.extend(compiled_vars.clone());
                            }
                        }
                    }
                }
                Directive::SecRuleUpdateActionById { id, actions, .. } => {
                    idx += 1;
                    for entry in &mut entries {
                        if let PhaseEntry::Rule(r) = entry
                            && r.id == *id
                        {
                            apply_action_updates(r, actions);
                        }
                    }
                }
                Directive::SecRequestBodyAccess { enabled, .. } => {
                    idx += 1;
                    request_body_access = *enabled;
                }
                Directive::SecRequestBodyLimit { limit, .. } => {
                    idx += 1;
                    config.request_body_limit = *limit;
                }
                Directive::SecRequestBodyLimitAction { action, .. } => {
                    idx += 1;
                    config.request_body_limit_action = *action;
                }
                Directive::SecResponseBodyAccess { enabled, .. } => {
                    idx += 1;
                    response_body_access = *enabled;
                }
                Directive::SecResponseBodyLimit { limit, .. } => {
                    idx += 1;
                    config.response_body_limit = *limit;
                }
                Directive::SecRuleEngine { mode, .. } => {
                    idx += 1;
                    config.rule_engine = *mode;
                }
                Directive::SecCollectionTimeout { seconds, .. } => {
                    idx += 1;
                    config.collection_timeout_secs = *seconds;
                }
                Directive::SecArgumentSeparator { separator, .. } => {
                    idx += 1;
                    arg_separator = *separator;
                }
                Directive::SecComponentSignature { .. }
                | Directive::Include { .. }
                | Directive::Ignored { .. } => {
                    idx += 1;
                }
            }
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        // Partition rules into the 5 phase buckets while placing markers in every
        // phase so `skipAfter` resolves reliably regardless of phase.
        let mut phases: [Vec<PhaseEntry>; 5] = Default::default();
        let mut rule_count = 0usize;
        for entry in entries {
            match entry {
                PhaseEntry::Rule(r) => {
                    rule_count += 1;
                    let idx = r.phase.index();
                    phases[idx].push(PhaseEntry::Rule(r));
                }
                PhaseEntry::Marker(m) => {
                    for p in &mut phases {
                        p.push(PhaseEntry::Marker(m.clone()));
                    }
                }
            }
        }

        let persistent = Arc::new(PersistentStore::new(Duration::from_secs(
            config.collection_timeout_secs.max(1),
        )));

        Ok(Self {
            inner: Arc::new(CompiledWaf {
                config,
                request_body_access,
                response_body_access,
                arg_separator,
                phases,
                warnings,
                rule_count,
                persistent,
            }),
        })
    }

    /// Creates a fresh 5-phase [`Transaction`] bound to this compiled ruleset.
    pub fn new_transaction(&self) -> Transaction {
        Transaction::new(Arc::clone(&self.inner), Instant::now())
    }

    /// Creates a transaction anchored at a caller-supplied timestamp (useful
    /// for deterministic persistent-collection TTL tests).
    pub fn new_transaction_at(&self, now: Instant) -> Transaction {
        Transaction::new(Arc::clone(&self.inner), now)
    }

    /// Effective configuration.
    pub fn config(&self) -> &WafConfig {
        &self.inner.config
    }

    /// Number of compiled top-level rules across all phases.
    pub fn rule_count(&self) -> usize {
        self.inner.rule_count
    }

    /// Non-fatal compile warnings (skipped unsupported operators, etc.).
    pub fn warnings(&self) -> &[CompileWarning] {
        &self.inner.warnings
    }

    /// Shared persistent collection store (`IP`, `USER`, `GLOBAL`, `SESSION`).
    pub fn persistent_store(&self) -> &Arc<PersistentStore> {
        &self.inner.persistent
    }
}

fn collect_chain(directives: &[Directive], start: usize) -> (Vec<SecRuleAst>, usize) {
    let mut chain = Vec::new();
    let mut i = start;
    while i < directives.len() {
        if let Directive::SecRule(ast) = &directives[i] {
            let has_chain = ast.actions.iter().any(|a| matches!(a, Action::Chain));
            chain.push(ast.clone());
            i += 1;
            if !has_chain {
                break;
            }
        } else {
            break;
        }
    }
    (chain, i - start)
}

fn compile_rule_chain(
    chain: &[SecRuleAst],
    defaults: &[PhaseDefaults; 5],
    regex_prefilter: bool,
    data_files: &HashMap<String, String>,
    warnings: &mut Vec<CompileWarning>,
) -> Result<Option<CompiledSecRule>, SecLangError> {
    if chain.is_empty() {
        return Ok(None);
    }
    let mut compiled_nodes = Vec::with_capacity(chain.len());
    for (idx, ast) in chain.iter().enumerate() {
        let is_starter = idx == 0;
        match compile_single_rule(
            ast,
            is_starter,
            defaults,
            regex_prefilter,
            data_files,
            warnings,
        )? {
            Some(node) => compiled_nodes.push(node),
            None => {
                // Any unsupported/skipped rule in a chain skips the entire chain.
                return Ok(None);
            }
        }
    }

    let mut iter = compiled_nodes.into_iter().rev();
    let mut current = iter.next().expect("non-empty chain");
    for mut parent in iter {
        parent.chain = Some(Box::new(current));
        current = parent;
    }
    Ok(Some(current))
}

fn compile_single_rule(
    ast: &SecRuleAst,
    is_starter: bool,
    defaults: &[PhaseDefaults; 5],
    regex_prefilter: bool,
    data_files: &HashMap<String, String>,
    warnings: &mut Vec<CompileWarning>,
) -> Result<Option<CompiledSecRule>, SecLangError> {
    let id = ast
        .actions
        .iter()
        .find_map(|a| match a {
            Action::Id(id) => Some(*id),
            _ => None,
        })
        .unwrap_or(0);

    let phase = ast
        .actions
        .iter()
        .find_map(|a| match a {
            Action::Phase(p) => Phase::from_u8(*p),
            _ => None,
        })
        .unwrap_or(Phase::RequestBody);

    let def = &defaults[phase.index()];

    // Compile operator; skip rule cleanly with a warning if unsupported or uncompilable.
    let op = match compile_operator(&ast.operator, regex_prefilter, data_files) {
        Ok(op) => op,
        Err(reason) => {
            warnings.push(CompileWarning {
                file: ast.span.file.clone(),
                line: ast.span.line,
                rule_id: (id > 0).then_some(id),
                message: reason,
            });
            return Ok(None);
        }
    };

    let variables = compile_var_specs(&ast.variables, &ast.span)?;

    let mut transforms = if is_starter {
        def.transforms.clone()
    } else {
        Vec::new()
    };
    let mut disruptive = if is_starter {
        def.disruptive.clone()
    } else {
        DisruptiveAction::Pass
    };
    let mut status = DEFAULT_DENY_STATUS;
    let mut msg = String::new();
    let mut logdata = String::new();
    let mut severity = 5u8; // NOTICE
    let mut tags = Vec::new();
    let mut capture = false;
    let mut log = def.log;
    let mut skip = 0usize;
    let mut skip_after = None;
    let mut setvars = Vec::new();
    let mut expirevars = Vec::new();
    let mut ctls = Vec::new();
    let mut setenvs = Vec::new();
    let mut initcols = Vec::new();
    let mut paranoia_level = 1u8;

    for act in &ast.actions {
        match act {
            Action::Transform(name) => {
                if name.eq_ignore_ascii_case("none") {
                    transforms.clear();
                } else if let Some(t) = Transform::from_name(name) {
                    transforms.push(t);
                } else {
                    warnings.push(CompileWarning {
                        file: ast.span.file.clone(),
                        line: ast.span.line,
                        rule_id: (id > 0).then_some(id),
                        message: format!("unsupported transform {name:?} ignored"),
                    });
                }
            }
            Action::Disruptive(d) => {
                disruptive = match d {
                    // `block` inherits the phase default disruptive action.
                    DisruptiveAction::Block => def.disruptive.clone(),
                    other => other.clone(),
                };
            }
            Action::Status(s) => status = *s,
            Action::Msg(m) => msg = m.clone(),
            Action::LogData(d) => logdata = d.clone(),
            Action::Severity(s) => severity = *s,
            Action::Tag(t) => {
                if let Some(pl_str) = t.strip_prefix("paranoia-level/")
                    && let Ok(pl) = pl_str.parse::<u8>()
                {
                    paranoia_level = pl.clamp(1, 4);
                }
                tags.push(t.clone());
            }
            Action::Capture => capture = true,
            Action::Log => log = true,
            Action::NoLog => log = false,
            Action::Skip(n) => skip = *n,
            Action::SkipAfter(m) => skip_after = Some(m.clone()),
            Action::SetVar(sv) => setvars.push(sv.clone()),
            Action::ExpireVar(ev) => expirevars.push(ev.clone()),
            Action::Ctl(ctl) => ctls.push(ctl.clone()),
            Action::SetEnv { key, value } => setenvs.push((key.clone(), value.clone())),
            Action::InitCol { collection, key } => {
                initcols.push((collection.clone(), key.clone()));
            }
            Action::Id(_)
            | Action::Phase(_)
            | Action::Ver(_)
            | Action::AuditLog
            | Action::NoAuditLog
            | Action::Chain
            | Action::MultiMatch
            | Action::Meta { .. } => {}
        }
    }

    Ok(Some(CompiledSecRule {
        id,
        phase,
        paranoia_level,
        variables,
        op_negated: ast.operator.negated,
        op,
        transforms,
        disruptive,
        status,
        msg,
        logdata,
        severity,
        tags,
        capture,
        log,
        skip,
        skip_after,
        setvars,
        expirevars,
        ctls,
        setenvs,
        initcols,
        span: ast.span.clone(),
        chain: None,
    }))
}

fn apply_action_updates(rule: &mut CompiledSecRule, actions: &[Action]) {
    for act in actions {
        match act {
            Action::Disruptive(d) => rule.disruptive = d.clone(),
            Action::Status(s) => rule.status = *s,
            Action::Msg(m) => rule.msg = m.clone(),
            Action::LogData(d) => rule.logdata = d.clone(),
            Action::Severity(s) => rule.severity = *s,
            Action::Tag(t) => rule.tags.push(t.clone()),
            Action::Log => rule.log = true,
            Action::NoLog => rule.log = false,
            Action::SetVar(sv) => rule.setvars.push(sv.clone()),
            Action::Ctl(ctl) => rule.ctls.push(ctl.clone()),
            Action::Transform(name) => {
                if name.eq_ignore_ascii_case("none") {
                    rule.transforms.clear();
                } else if let Some(t) = Transform::from_name(name) {
                    rule.transforms.push(t);
                }
            }
            _ => {}
        }
    }
}

fn compile_var_specs(
    specs: &[VarSpec],
    span: &SourceSpan,
) -> Result<Vec<CompiledVarSpec>, SecLangError> {
    let mut out = Vec::with_capacity(specs.len());
    for v in specs {
        let selector = match &v.selector {
            None => None,
            Some(VarSelector::Key(k)) => Some(CompiledVarSelector::Key(k.clone())),
            Some(VarSelector::Regex(pat)) => {
                let re = RegexBuilder::new(pat)
                    .size_limit(MAX_COMPILED_REGEX_BYTES)
                    .build()
                    .map_err(|e| SecLangError {
                        file: span.file.clone(),
                        line: span.line,
                        message: format!("invalid variable selector regex {pat:?}: {e}"),
                    })?;
                Some(CompiledVarSelector::Regex(re))
            }
        };
        out.push(CompiledVarSpec {
            name: v.name.clone(),
            selector,
            negated: v.negated,
            count: v.count,
        });
    }
    Ok(out)
}

fn compile_operator(
    spec: &OperatorSpec,
    regex_prefilter: bool,
    data_files: &HashMap<String, String>,
) -> Result<CompiledSecOp, String> {
    match &spec.kind {
        OperatorKind::Rx => {
            if spec.arg.len() > MAX_REGEX_PATTERN_LEN {
                return Err(format!(
                    "@rx pattern exceeds maximum length of {MAX_REGEX_PATTERN_LEN} bytes"
                ));
            }
            let regex = RegexBuilder::new(&spec.arg)
                .size_limit(MAX_COMPILED_REGEX_BYTES)
                .build()
                .map_err(|e| format!("skipped unsupported/invalid @rx pattern: {e}"))?;
            let prefilter = if regex_prefilter {
                Prefilter::from_regex(&spec.arg)
            } else {
                None
            };
            Ok(CompiledSecOp::Rx { regex, prefilter })
        }
        OperatorKind::Pm => {
            let phrases = parse_pm_phrases(&spec.arg);
            Ok(CompiledSecOp::Pm { phrases })
        }
        OperatorKind::PmFromFile => {
            let content = data_files
                .get(spec.arg.trim())
                .ok_or_else(|| format!("@pmFromFile data file not found: {:?}", spec.arg))?;
            let phrases: Vec<Box<str>> = content
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| l.to_ascii_lowercase().into_boxed_str())
                .collect();
            Ok(CompiledSecOp::Pm { phrases })
        }
        OperatorKind::Contains => Ok(CompiledSecOp::Contains(spec.arg.clone())),
        OperatorKind::StrEq => Ok(CompiledSecOp::StrEq(spec.arg.clone())),
        OperatorKind::StartsWith => Ok(CompiledSecOp::StartsWith(spec.arg.clone())),
        OperatorKind::EndsWith => Ok(CompiledSecOp::EndsWith(spec.arg.clone())),
        OperatorKind::Within => Ok(CompiledSecOp::Within(spec.arg.clone())),
        OperatorKind::Eq => Ok(CompiledSecOp::Eq(spec.arg.clone())),
        OperatorKind::Gt => Ok(CompiledSecOp::Gt(spec.arg.clone())),
        OperatorKind::Lt => Ok(CompiledSecOp::Lt(spec.arg.clone())),
        OperatorKind::Ge => Ok(CompiledSecOp::Ge(spec.arg.clone())),
        OperatorKind::Le => Ok(CompiledSecOp::Le(spec.arg.clone())),
        OperatorKind::IpMatch => {
            let nets = parse_ip_nets(&spec.arg)?;
            Ok(CompiledSecOp::IpMatch(nets))
        }
        OperatorKind::IpMatchFromFile => {
            let content = data_files
                .get(spec.arg.trim())
                .ok_or_else(|| format!("@ipMatchFromFile data file not found: {:?}", spec.arg))?;
            let mut nets = Vec::new();
            for line in content
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
            {
                nets.extend(parse_ip_nets(line)?);
            }
            Ok(CompiledSecOp::IpMatch(nets))
        }
        OperatorKind::ValidateByteRange => {
            let ranges = parse_byte_ranges(&spec.arg)?;
            Ok(CompiledSecOp::ValidateByteRange(ranges))
        }
        OperatorKind::ValidateUtf8 => Ok(CompiledSecOp::ValidateUtf8),
        OperatorKind::UnconditionalMatch => Ok(CompiledSecOp::UnconditionalMatch),
        OperatorKind::NoMatch => Ok(CompiledSecOp::NoMatch),
        OperatorKind::DetectSqli => Ok(CompiledSecOp::DetectSqli),
        OperatorKind::DetectXss => Ok(CompiledSecOp::DetectXss),
        OperatorKind::Unsupported(name) => Err(format!("unsupported operator @{name}")),
    }
}

fn parse_pm_phrases(raw: &str) -> Vec<Box<str>> {
    let mut phrases = Vec::new();
    let bytes = raw.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            break;
        }
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            let q = bytes[i];
            i += 1;
            let start = i;
            while i < len && bytes[i] != q {
                i += 1;
            }
            let phrase = raw[start..i].to_ascii_lowercase();
            if !phrase.is_empty() {
                phrases.push(phrase.into_boxed_str());
            }
            if i < len {
                i += 1;
            }
        } else {
            let start = i;
            while i < len && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let phrase = raw[start..i].to_ascii_lowercase();
            if !phrase.is_empty() {
                phrases.push(phrase.into_boxed_str());
            }
        }
    }
    phrases
}

fn parse_ip_nets(raw: &str) -> Result<Vec<IpNet>, String> {
    let mut nets = Vec::new();
    for item in raw
        .split([',', ';', ' ', '\t', '\r', '\n'])
        .filter(|s| !s.is_empty())
    {
        let net = item
            .parse::<IpNet>()
            .or_else(|_| {
                item.parse::<IpAddr>().map(|ip| match ip {
                    IpAddr::V4(v4) => IpNet::new(IpAddr::V4(v4), 32).expect("valid v4 /32"),
                    IpAddr::V6(v6) => IpNet::new(IpAddr::V6(v6), 128).expect("valid v6 /128"),
                })
            })
            .map_err(|_| format!("invalid @ipMatch entry {item:?}"))?;
        nets.push(net);
    }
    Ok(nets)
}

fn parse_byte_ranges(raw: &str) -> Result<Vec<(u8, u8)>, String> {
    let mut ranges = Vec::new();
    for item in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((a, b)) = item.split_once('-') {
            let lo = a
                .trim()
                .parse::<u8>()
                .map_err(|_| format!("invalid @validateByteRange bound {item:?}"))?;
            let hi = b
                .trim()
                .parse::<u8>()
                .map_err(|_| format!("invalid @validateByteRange bound {item:?}"))?;
            if lo > hi {
                return Err(format!("inverted @validateByteRange {item:?}"));
            }
            ranges.push((lo, hi));
        } else {
            let v = item
                .parse::<u8>()
                .map_err(|_| format!("invalid @validateByteRange value {item:?}"))?;
            ranges.push((v, v));
        }
    }
    Ok(ranges)
}

// ---------------------------------------------------------------------------
// 5-Phase Transaction Evaluator
// ---------------------------------------------------------------------------

/// One HTTP request/response evaluation transaction across Phases 1–5.
pub struct Transaction {
    waf: Arc<CompiledWaf>,
    now: Instant,
    rule_engine: RuleEngineMode,
    request_body_access: bool,
    forced_body_processor: Option<BodyProcessor>,

    // Request state (Phases 1–2)
    method: String,
    uri_raw: String,
    uri: String,
    filename: String,
    basename: String,
    query_string: String,
    protocol: String,
    remote_addr: String,
    request_headers: Vec<(String, String)>,
    request_cookies: Vec<(String, String)>,
    args_get: Vec<(String, String)>,
    args_post: Vec<(String, String)>,
    request_body_raw: Vec<u8>,
    request_body: String,
    parsed_body: ParsedBody,

    // Response state (Phases 3–4)
    response_status: u16,
    response_headers: Vec<(String, String)>,
    response_body_raw: Vec<u8>,
    response_body: String,

    // Runtime variables & tracking
    tx_vars: HashMap<String, String>,
    env_vars: HashMap<String, String>,
    /// Active persistent collection bindings (`IP` -> `"1.2.3.4"`, `USER` -> `"alice"`, `GLOBAL` -> `"global"`).
    col_bindings: HashMap<String, String>,
    matched_var: String,
    matched_var_name: String,
    matched_vars: Vec<(String, String)>,
    highest_severity: Option<u8>,
    current_rule_id: u64,
    current_rule_msg: String,
    current_rule_severity: u8,

    // Runtime `ctl` overrides
    removed_rule_ids: Vec<IdRange>,
    removed_targets_by_id: HashMap<u64, Vec<CompiledVarSpec>>,
    removed_targets_by_tag: HashMap<String, Vec<CompiledVarSpec>>,

    // Control flow & outcome
    allow_scope: Option<AllowScope>,
    intervention: Option<Intervention>,
    matched_rules: Vec<MatchedRule>,
    phases_executed: Vec<Phase>,
}

impl Transaction {
    fn new(waf: Arc<CompiledWaf>, now: Instant) -> Self {
        let mut tx_vars = HashMap::new();
        tx_vars.insert(
            "paranoia_level".to_owned(),
            waf.config.paranoia_level.to_string(),
        );
        tx_vars.insert(
            "executing_paranoia_level".to_owned(),
            waf.config.paranoia_level.to_string(),
        );
        tx_vars.insert(
            "inbound_anomaly_score_threshold".to_owned(),
            waf.config.inbound_threshold.to_string(),
        );
        tx_vars.insert(
            "outbound_anomaly_score_threshold".to_owned(),
            waf.config.outbound_threshold.to_string(),
        );
        tx_vars.insert("critical_anomaly_score".to_owned(), "5".to_owned());
        tx_vars.insert("error_anomaly_score".to_owned(), "4".to_owned());
        tx_vars.insert("warning_anomaly_score".to_owned(), "3".to_owned());
        tx_vars.insert("notice_anomaly_score".to_owned(), "2".to_owned());
        tx_vars.insert("inbound_anomaly_score".to_owned(), "0".to_owned());
        tx_vars.insert("outbound_anomaly_score".to_owned(), "0".to_owned());
        for pl in 1..=4 {
            tx_vars.insert(format!("inbound_anomaly_score_pl{pl}"), "0".to_owned());
            tx_vars.insert(format!("outbound_anomaly_score_pl{pl}"), "0".to_owned());
        }
        let allowed_methods = if waf.config.webdav {
            "GET HEAD POST OPTIONS PUT DELETE PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK"
        } else {
            "GET HEAD POST OPTIONS"
        };
        tx_vars.insert("allowed_methods".to_owned(), allowed_methods.to_owned());

        let mut col_bindings = HashMap::new();
        col_bindings.insert("GLOBAL".to_owned(), "global".to_owned());

        let rule_engine = waf.config.rule_engine;
        let request_body_access = waf.request_body_access;

        Self {
            waf,
            now,
            rule_engine,
            request_body_access,
            forced_body_processor: None,
            method: String::new(),
            uri_raw: String::new(),
            uri: String::new(),
            filename: String::new(),
            basename: String::new(),
            query_string: String::new(),
            protocol: String::new(),
            remote_addr: String::new(),
            request_headers: Vec::new(),
            request_cookies: Vec::new(),
            args_get: Vec::new(),
            args_post: Vec::new(),
            request_body_raw: Vec::new(),
            request_body: String::new(),
            parsed_body: ParsedBody::default(),
            response_status: 0,
            response_headers: Vec::new(),
            response_body_raw: Vec::new(),
            response_body: String::new(),
            tx_vars,
            env_vars: HashMap::new(),
            col_bindings,
            matched_var: String::new(),
            matched_var_name: String::new(),
            matched_vars: Vec::new(),
            highest_severity: None,
            current_rule_id: 0,
            current_rule_msg: String::new(),
            current_rule_severity: 5,
            removed_rule_ids: Vec::new(),
            removed_targets_by_id: HashMap::new(),
            removed_targets_by_tag: HashMap::new(),
            allow_scope: None,
            intervention: None,
            matched_rules: Vec::new(),
            phases_executed: Vec::new(),
        }
    }

    /// Phase 1: populates request-header variables and evaluates Phase 1 rules.
    pub fn process_request_headers(&mut self, req: &RequestHead) {
        self.method = req.method.clone();
        self.uri_raw = req.uri.clone();
        self.uri = req.uri.clone();
        self.protocol = if req.protocol.is_empty() {
            "HTTP/1.1".to_owned()
        } else {
            req.protocol.clone()
        };
        if let Some(ip) = req.remote_addr {
            self.remote_addr = ip.to_string();
            self.col_bindings
                .entry("IP".to_owned())
                .or_insert_with(|| self.remote_addr.clone());
        }

        let (path, query) = match req.uri.split_once('?') {
            Some((p, q)) => (p, q),
            None => (req.uri.as_str(), ""),
        };
        self.filename = path.to_owned();
        self.basename = path.rsplit('/').next().unwrap_or("").to_owned();
        self.query_string = query.to_owned();
        self.args_get = parse_query_string(query, self.waf.arg_separator, MAX_BODY_ARGS);

        self.request_headers = req.headers.clone();
        self.request_cookies.clear();
        for (name, val) in &req.headers {
            if name.eq_ignore_ascii_case("cookie") {
                for pair in val.split(';') {
                    let trimmed = pair.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let (ck, cv) = match trimmed.split_once('=') {
                        Some((k, v)) => (k.trim().to_owned(), v.trim().to_owned()),
                        None => (trimmed.to_owned(), String::new()),
                    };
                    self.request_cookies.push((ck, cv));
                }
            }
        }

        self.run_phase(Phase::RequestHeaders);
    }

    /// Phase 2: parses the request body (respecting body limits), populates
    /// body & `ARGS_POST` variables, evaluates Phase 2 rules, and checks the
    /// inbound anomaly score threshold.
    pub fn process_request_body(&mut self, body: &[u8]) {
        if self.intervention.is_some()
            || matches!(
                self.allow_scope,
                Some(AllowScope::All | AllowScope::Request)
            )
        {
            return;
        }

        if self.request_body_access && !body.is_empty() {
            let limit = self.waf.config.request_body_limit;
            let effective = if limit > 0 && body.len() > limit {
                match self.waf.config.request_body_limit_action {
                    BodyLimitAction::Reject => {
                        if self.rule_engine == RuleEngineMode::On {
                            self.intervention = Some(Intervention {
                                status: 413,
                                action: InterventionAction::Deny,
                                rule_id: 0,
                                message: format!(
                                    "Request body length {} exceeds limit of {limit} bytes",
                                    body.len()
                                ),
                                logdata: String::new(),
                            });
                            return;
                        }
                        &body[..limit]
                    }
                    BodyLimitAction::ProcessPartial => &body[..limit],
                }
            } else {
                body
            };

            self.request_body_raw = effective.to_vec();
            self.request_body = String::from_utf8_lossy(effective).into_owned();

            let content_type = self
                .request_headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.as_str());
            self.parsed_body = parse_body(
                effective,
                content_type,
                self.forced_body_processor,
                self.waf.arg_separator,
            );
            self.args_post = self.parsed_body.args.clone();
        }

        self.run_phase(Phase::RequestBody);

        // Automatic inbound anomaly threshold check (if no explicit rule already intervened).
        if self.intervention.is_none()
            && self.rule_engine == RuleEngineMode::On
            && self.allow_scope.is_none()
            && self.waf.config.inbound_threshold > 0
            && self.inbound_score() >= self.waf.config.inbound_threshold
        {
            let score = self.inbound_score();
            self.intervention = Some(Intervention {
                status: DEFAULT_DENY_STATUS,
                action: InterventionAction::Deny,
                rule_id: self.matched_rules.last().map(|m| m.id).unwrap_or(949110),
                message: format!(
                    "Inbound Anomaly Score Exceeded (Total Score: {score}, Threshold: {})",
                    self.waf.config.inbound_threshold
                ),
                logdata: String::new(),
            });
        }
    }

    /// Phase 3: populates response-header variables and evaluates Phase 3 rules.
    pub fn process_response_headers(&mut self, resp: &ResponseHead) {
        self.response_status = resp.status;
        self.response_headers = resp.headers.clone();
        if self.intervention.is_some() || matches!(self.allow_scope, Some(AllowScope::All)) {
            return;
        }
        self.run_phase(Phase::ResponseHeaders);
    }

    /// Phase 4: populates `RESPONSE_BODY`, evaluates Phase 4 rules, and checks
    /// the outbound anomaly score threshold.
    pub fn process_response_body(&mut self, body: &[u8]) {
        if self.intervention.is_some() || matches!(self.allow_scope, Some(AllowScope::All)) {
            return;
        }
        if self.waf.response_body_access && !body.is_empty() {
            let limit = self.waf.config.response_body_limit;
            let effective = if limit > 0 && body.len() > limit {
                &body[..limit]
            } else {
                body
            };
            self.response_body_raw = effective.to_vec();
            self.response_body = String::from_utf8_lossy(effective).into_owned();
        }

        self.run_phase(Phase::ResponseBody);

        if self.intervention.is_none()
            && self.rule_engine == RuleEngineMode::On
            && self.allow_scope.is_none()
            && self.waf.config.outbound_threshold > 0
            && self.outbound_score() >= self.waf.config.outbound_threshold
        {
            let score = self.outbound_score();
            self.intervention = Some(Intervention {
                status: DEFAULT_DENY_STATUS,
                action: InterventionAction::Deny,
                rule_id: self.matched_rules.last().map(|m| m.id).unwrap_or(959100),
                message: format!(
                    "Outbound Anomaly Score Exceeded (Total Score: {score}, Threshold: {})",
                    self.waf.config.outbound_threshold
                ),
                logdata: String::new(),
            });
        }
    }

    /// Phase 5: executes logging-phase rules (runs even after an intervention).
    pub fn process_logging(&mut self) {
        self.run_phase(Phase::Logging);
    }

    /// Current inbound anomaly score (reconciles both direct
    /// `tx.inbound_anomaly_score` and CRS v4 `tx.inbound_anomaly_score_pl1..4`).
    pub fn inbound_score(&self) -> i32 {
        let direct = self.tx_int("inbound_anomaly_score");
        let pl_sum: i32 = (1..=4)
            .map(|pl| self.tx_int(&format!("inbound_anomaly_score_pl{pl}")))
            .sum();
        direct.max(pl_sum)
    }

    /// Current outbound anomaly score.
    pub fn outbound_score(&self) -> i32 {
        let direct = self.tx_int("outbound_anomaly_score");
        let pl_sum: i32 = (1..=4)
            .map(|pl| self.tx_int(&format!("outbound_anomaly_score_pl{pl}")))
            .sum();
        direct.max(pl_sum)
    }

    /// Disruptive intervention if the transaction was blocked/dropped/redirected.
    pub fn intervention(&self) -> Option<&Intervention> {
        self.intervention.as_ref()
    }

    /// All rules matched during this transaction in evaluation order.
    pub fn matched_rules(&self) -> &[MatchedRule] {
        &self.matched_rules
    }

    /// Phases executed so far in exact order.
    pub fn phases_executed(&self) -> &[Phase] {
        &self.phases_executed
    }

    /// Effective rule engine mode (may be changed by `ctl:ruleEngine`).
    pub fn rule_engine_mode(&self) -> RuleEngineMode {
        self.rule_engine
    }

    /// Reads a `TX` variable (case-insensitive key).
    pub fn tx_var(&self, name: &str) -> Option<&str> {
        self.tx_vars
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// Sets a `TX` variable (case-insensitive key).
    pub fn set_tx_var(&mut self, name: &str, value: impl Into<String>) {
        self.tx_vars.insert(name.to_ascii_lowercase(), value.into());
    }

    /// Parsed request body metadata and extracted fields.
    pub fn parsed_body(&self) -> &ParsedBody {
        &self.parsed_body
    }

    /// Body parse error message if the body parser rejected malformed syntax.
    pub fn body_parse_error(&self) -> Option<&str> {
        self.parsed_body.parse_error.as_deref()
    }

    fn tx_int(&self, key: &str) -> i32 {
        self.tx_vars
            .get(key)
            .and_then(|v| v.trim().parse::<i32>().ok())
            .unwrap_or(0)
    }

    fn run_phase(&mut self, phase: Phase) {
        if self.rule_engine == RuleEngineMode::Off {
            return;
        }
        self.phases_executed.push(phase);
        if self.allow_scope == Some(AllowScope::Phase) {
            self.allow_scope = None;
        }

        let waf = Arc::clone(&self.waf);
        let entries = &waf.phases[phase.index()];
        let mut idx = 0usize;
        let mut skip_remaining = 0usize;
        let mut skip_after_marker: Option<String> = None;

        while idx < entries.len() {
            if self.rule_engine == RuleEngineMode::Off {
                break;
            }
            if phase != Phase::Logging
                && (self.intervention.is_some() || self.allow_scope.is_some())
            {
                break;
            }

            match &entries[idx] {
                PhaseEntry::Marker(name) => {
                    if let Some(ref target) = skip_after_marker
                        && target == name
                    {
                        skip_after_marker = None;
                    }
                    idx += 1;
                }
                PhaseEntry::Rule(rule) => {
                    idx += 1;
                    if skip_after_marker.is_some() {
                        continue;
                    }
                    if skip_remaining > 0 {
                        skip_remaining -= 1;
                        continue;
                    }
                    if rule.paranoia_level > self.waf.config.paranoia_level {
                        continue;
                    }
                    if rule.id > 0 && self.removed_rule_ids.iter().any(|r| r.contains(rule.id)) {
                        continue;
                    }

                    if self.evaluate_rule_chain(rule) {
                        if let Some(ref marker) = rule.skip_after {
                            skip_after_marker = Some(marker.clone());
                        } else if rule.skip > 0 {
                            skip_remaining = rule.skip;
                        }
                    }
                }
            }
        }
    }

    /// Evaluates a starter rule and any chained children.
    /// Returns `true` only if the entire chain matched.
    fn evaluate_rule_chain(&mut self, starter: &CompiledSecRule) -> bool {
        self.current_rule_id = starter.id;
        self.current_rule_msg = starter.msg.clone();
        self.current_rule_severity = starter.severity;

        // Collect all nodes along the chain; stop immediately on first non-match.
        let mut matched_nodes: Vec<&CompiledSecRule> = Vec::new();
        let mut cur: Option<&CompiledSecRule> = Some(starter);
        while let Some(node) = cur {
            let extra_exclusions = self.runtime_exclusions_for(starter);
            if !self.evaluate_single_node(node, &extra_exclusions) {
                return false;
            }
            matched_nodes.push(node);
            cur = node.chain.as_deref();
        }

        // Full chain matched: run non-disruptive actions on starter + children.
        for node in &matched_nodes {
            for (col, key_expr) in &node.initcols {
                let expanded = self.expand_macros(key_expr);
                self.col_bindings.insert(col.clone(), expanded);
            }
            for sv in &node.setvars {
                self.apply_setvar(sv);
            }
            for ev in &node.expirevars {
                self.apply_expirevar(ev);
            }
            for (ek, ev) in &node.setenvs {
                let val = self.expand_macros(ev);
                self.env_vars.insert(ek.clone(), val);
            }
            for ctl in &node.ctls {
                self.apply_ctl(ctl);
            }
        }

        // Track highest severity (lower numeric value = higher severity).
        self.highest_severity = Some(match self.highest_severity {
            Some(prev) => prev.min(starter.severity),
            None => starter.severity,
        });

        let expanded_msg = self.expand_macros(&starter.msg);
        let expanded_data = self.expand_macros(&starter.logdata);

        if starter.log || starter.id > 0 {
            self.matched_rules.push(MatchedRule {
                id: starter.id,
                message: expanded_msg.clone(),
                severity: starter.severity,
                file: starter.span.file.clone(),
                line: starter.span.line,
                data: expanded_data.clone(),
                tags: starter.tags.clone(),
                phase: starter.phase,
            });
        }

        // Apply starter's disruptive action.
        match &starter.disruptive {
            DisruptiveAction::Pass | DisruptiveAction::Block => {}
            DisruptiveAction::Deny => {
                if self.rule_engine == RuleEngineMode::On {
                    self.intervention = Some(Intervention {
                        status: starter.status,
                        action: InterventionAction::Deny,
                        rule_id: starter.id,
                        message: expanded_msg,
                        logdata: expanded_data,
                    });
                }
            }
            DisruptiveAction::Drop => {
                if self.rule_engine == RuleEngineMode::On {
                    self.intervention = Some(Intervention {
                        status: starter.status,
                        action: InterventionAction::Drop,
                        rule_id: starter.id,
                        message: expanded_msg,
                        logdata: expanded_data,
                    });
                }
            }
            DisruptiveAction::Redirect(url) => {
                if self.rule_engine == RuleEngineMode::On {
                    let target = self.expand_macros(url);
                    self.intervention = Some(Intervention {
                        status: if starter.status == DEFAULT_DENY_STATUS {
                            302
                        } else {
                            starter.status
                        },
                        action: InterventionAction::Redirect(target),
                        rule_id: starter.id,
                        message: expanded_msg,
                        logdata: expanded_data,
                    });
                }
            }
            DisruptiveAction::Allow(scope) => {
                self.allow_scope = Some(*scope);
            }
        }

        true
    }

    fn runtime_exclusions_for(&self, rule: &CompiledSecRule) -> Vec<CompiledVarSpec> {
        let mut out = Vec::new();
        if let Some(vars) = self.removed_targets_by_id.get(&rule.id) {
            out.extend(vars.iter().cloned());
        }
        for tag in &rule.tags {
            if let Some(vars) = self.removed_targets_by_tag.get(tag) {
                out.extend(vars.iter().cloned());
            }
        }
        out
    }

    fn evaluate_single_node(
        &mut self,
        node: &CompiledSecRule,
        extra_exclusions: &[CompiledVarSpec],
    ) -> bool {
        // `SecAction` has no variables and `@unconditionalMatch`.
        if node.variables.is_empty() && matches!(node.op, CompiledSecOp::UnconditionalMatch) {
            return !node.op_negated;
        }

        let targets = self.resolve_targets(&node.variables, extra_exclusions);
        for (var_name, raw_val, raw_bytes) in targets {
            let value = if node.transforms.is_empty() {
                raw_val
            } else {
                apply_transforms(&node.transforms, &raw_val)
            };
            let op_bytes = if node.transforms.is_empty() {
                raw_bytes.as_deref().unwrap_or(value.as_bytes())
            } else {
                value.as_bytes()
            };

            let (raw_hit, captures) = self.eval_operator(&node.op, &value, op_bytes, node.capture);
            let hit = raw_hit != node.op_negated;
            if hit {
                self.matched_var = value.clone();
                self.matched_var_name = var_name.clone();
                self.matched_vars.push((var_name, value));
                if let Some(caps) = captures {
                    for (idx, cap) in caps.into_iter().enumerate().take(10) {
                        self.tx_vars.insert(idx.to_string(), cap);
                    }
                }
                return true;
            }
        }
        false
    }

    fn eval_operator(
        &self,
        op: &CompiledSecOp,
        value: &str,
        raw_bytes: &[u8],
        capture: bool,
    ) -> (bool, Option<Vec<String>>) {
        match op {
            CompiledSecOp::Rx { regex, prefilter } => {
                if let Some(pf) = prefilter
                    && !pf.might_match(value.as_bytes())
                {
                    return (false, None);
                }
                if capture {
                    if let Some(caps) = regex.captures(value) {
                        let mut captured = Vec::new();
                        for i in 0..caps.len().min(10) {
                            captured.push(
                                caps.get(i)
                                    .map(|m| m.as_str().to_owned())
                                    .unwrap_or_default(),
                            );
                        }
                        (true, Some(captured))
                    } else {
                        (false, None)
                    }
                } else {
                    (regex.is_match(value), None)
                }
            }
            CompiledSecOp::Pm { phrases } => {
                let lower = value.to_ascii_lowercase();
                for p in phrases {
                    if lower.contains(p.as_ref()) {
                        let caps = capture.then(|| vec![p.to_string()]);
                        return (true, caps);
                    }
                }
                (false, None)
            }
            CompiledSecOp::Contains(arg) => {
                let needle = self.expand_macros(arg);
                (value.contains(&needle), None)
            }
            CompiledSecOp::StrEq(arg) => {
                let expected = self.expand_macros(arg);
                (value == expected, None)
            }
            CompiledSecOp::StartsWith(arg) => {
                let prefix = self.expand_macros(arg);
                (value.starts_with(&prefix), None)
            }
            CompiledSecOp::EndsWith(arg) => {
                let suffix = self.expand_macros(arg);
                (value.ends_with(&suffix), None)
            }
            CompiledSecOp::Within(arg) => {
                let haystack = self.expand_macros(arg);
                (!value.is_empty() && haystack.contains(value), None)
            }
            CompiledSecOp::Eq(arg) => {
                let lhs = parse_modsec_int(value);
                let rhs = parse_modsec_int(&self.expand_macros(arg));
                (lhs == rhs, None)
            }
            CompiledSecOp::Gt(arg) => {
                let lhs = parse_modsec_int(value);
                let rhs = parse_modsec_int(&self.expand_macros(arg));
                (lhs > rhs, None)
            }
            CompiledSecOp::Lt(arg) => {
                let lhs = parse_modsec_int(value);
                let rhs = parse_modsec_int(&self.expand_macros(arg));
                (lhs < rhs, None)
            }
            CompiledSecOp::Ge(arg) => {
                let lhs = parse_modsec_int(value);
                let rhs = parse_modsec_int(&self.expand_macros(arg));
                (lhs >= rhs, None)
            }
            CompiledSecOp::Le(arg) => {
                let lhs = parse_modsec_int(value);
                let rhs = parse_modsec_int(&self.expand_macros(arg));
                (lhs <= rhs, None)
            }
            CompiledSecOp::IpMatch(nets) => {
                let hit = value
                    .trim()
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| nets.iter().any(|net| net.contains(&ip)));
                (hit, None)
            }
            CompiledSecOp::ValidateByteRange(ranges) => {
                // ModSecurity semantics: returns true on VIOLATION (byte outside allowed ranges).
                let violated = raw_bytes
                    .iter()
                    .any(|&b| !ranges.iter().any(|&(lo, hi)| b >= lo && b <= hi));
                (violated, None)
            }
            CompiledSecOp::ValidateUtf8 => {
                // ModSecurity semantics: returns true on VIOLATION (invalid UTF-8).
                (std::str::from_utf8(raw_bytes).is_err(), None)
            }
            CompiledSecOp::UnconditionalMatch => (true, None),
            CompiledSecOp::NoMatch => (false, None),
            CompiledSecOp::DetectSqli => match detect_sqli(value) {
                Some(fp) => (true, Some(vec![fp])),
                None => (false, None),
            },
            CompiledSecOp::DetectXss => match detect_xss(value) {
                Some(fp) => (true, Some(vec![fp])),
                None => (false, None),
            },
        }
    }

    /// Resolves a rule's variable list into `(display_name, value, optional_raw_bytes)`
    /// tuples, honouring `!` exclusions and `&` count operators.
    fn resolve_targets(
        &self,
        specs: &[CompiledVarSpec],
        extra_exclusions: &[CompiledVarSpec],
    ) -> Vec<(String, String, Option<Vec<u8>>)> {
        let mut exclusions: Vec<&CompiledVarSpec> = specs.iter().filter(|v| v.negated).collect();
        exclusions.extend(extra_exclusions.iter());

        let mut results = Vec::new();
        for spec in specs.iter().filter(|v| !v.negated) {
            let items = self.collect_variable(spec);
            let filtered: Vec<(String, String, Option<Vec<u8>>)> = items
                .into_iter()
                .filter(|(full_name, _, _)| !is_excluded(&spec.name, full_name, &exclusions))
                .collect();

            if spec.count {
                let label = match &spec.selector {
                    Some(CompiledVarSelector::Key(k)) => format!("&{}:{k}", spec.name),
                    _ => format!("&{}", spec.name),
                };
                results.push((label, filtered.len().to_string(), None));
            } else {
                results.extend(filtered);
            }
        }
        results
    }

    fn collect_variable(&self, spec: &CompiledVarSpec) -> Vec<(String, String, Option<Vec<u8>>)> {
        match spec.name.as_str() {
            "ARGS" => {
                let combined: Vec<(String, String)> = self
                    .args_get
                    .iter()
                    .chain(self.args_post.iter())
                    .cloned()
                    .collect();
                filter_kv("ARGS", &combined, &spec.selector, false)
            }
            "ARGS_GET" => filter_kv("ARGS_GET", &self.args_get, &spec.selector, false),
            "ARGS_POST" => filter_kv("ARGS_POST", &self.args_post, &spec.selector, false),
            "ARGS_NAMES" => {
                let names: Vec<(String, String)> = self
                    .args_get
                    .iter()
                    .chain(self.args_post.iter())
                    .map(|(k, _)| (k.clone(), k.clone()))
                    .collect();
                filter_kv("ARGS_NAMES", &names, &spec.selector, false)
            }
            "ARGS_GET_NAMES" => {
                let names: Vec<(String, String)> = self
                    .args_get
                    .iter()
                    .map(|(k, _)| (k.clone(), k.clone()))
                    .collect();
                filter_kv("ARGS_GET_NAMES", &names, &spec.selector, false)
            }
            "ARGS_POST_NAMES" => {
                let names: Vec<(String, String)> = self
                    .args_post
                    .iter()
                    .map(|(k, _)| (k.clone(), k.clone()))
                    .collect();
                filter_kv("ARGS_POST_NAMES", &names, &spec.selector, false)
            }
            "QUERY_STRING" => vec![("QUERY_STRING".into(), self.query_string.clone(), None)],
            "REQUEST_BODY" => vec![(
                "REQUEST_BODY".into(),
                self.request_body.clone(),
                Some(self.request_body_raw.clone()),
            )],
            "REQUEST_HEADERS" => filter_kv(
                "REQUEST_HEADERS",
                &self.request_headers,
                &spec.selector,
                true,
            ),
            "REQUEST_HEADERS_NAMES" => {
                let names: Vec<(String, String)> = self
                    .request_headers
                    .iter()
                    .map(|(k, _)| (k.clone(), k.clone()))
                    .collect();
                filter_kv("REQUEST_HEADERS_NAMES", &names, &spec.selector, true)
            }
            "REQUEST_COOKIES" => filter_kv(
                "REQUEST_COOKIES",
                &self.request_cookies,
                &spec.selector,
                false,
            ),
            "REQUEST_COOKIES_NAMES" => {
                let names: Vec<(String, String)> = self
                    .request_cookies
                    .iter()
                    .map(|(k, _)| (k.clone(), k.clone()))
                    .collect();
                filter_kv("REQUEST_COOKIES_NAMES", &names, &spec.selector, false)
            }
            "REQUEST_FILENAME" => vec![("REQUEST_FILENAME".into(), self.filename.clone(), None)],
            "REQUEST_BASENAME" => vec![("REQUEST_BASENAME".into(), self.basename.clone(), None)],
            "REQUEST_URI" => vec![("REQUEST_URI".into(), self.uri.clone(), None)],
            "REQUEST_URI_RAW" => vec![("REQUEST_URI_RAW".into(), self.uri_raw.clone(), None)],
            "REQUEST_METHOD" => vec![("REQUEST_METHOD".into(), self.method.clone(), None)],
            "REQUEST_PROTOCOL" => vec![("REQUEST_PROTOCOL".into(), self.protocol.clone(), None)],
            "REQUEST_LINE" => vec![(
                "REQUEST_LINE".into(),
                format!("{} {} {}", self.method, self.uri_raw, self.protocol),
                None,
            )],
            "REMOTE_ADDR" => {
                if self.remote_addr.is_empty() {
                    Vec::new()
                } else {
                    vec![("REMOTE_ADDR".into(), self.remote_addr.clone(), None)]
                }
            }
            "FILES" => self
                .parsed_body
                .files
                .iter()
                .enumerate()
                .map(|(i, f)| (format!("FILES:{i}"), f.clone(), None))
                .collect(),
            "FILES_NAMES" => self
                .parsed_body
                .files_names
                .iter()
                .enumerate()
                .map(|(i, f)| (format!("FILES_NAMES:{i}"), f.clone(), None))
                .collect(),
            "XML" => {
                let mut out = Vec::new();
                for (i, txt) in self.parsed_body.xml_texts.iter().enumerate() {
                    out.push((format!("XML:text[{i}]"), txt.clone(), None));
                }
                for (k, v) in &self.parsed_body.xml_attrs {
                    out.push((format!("XML:@{k}"), v.clone(), None));
                }
                out
            }
            "REQBODY_PROCESSOR" => vec![(
                "REQBODY_PROCESSOR".into(),
                self.parsed_body.processor.as_str().to_owned(),
                None,
            )],
            "REQBODY_ERROR" => vec![(
                "REQBODY_ERROR".into(),
                if self.parsed_body.parse_error.is_some() {
                    "1".to_owned()
                } else {
                    "0".to_owned()
                },
                None,
            )],
            "RESPONSE_STATUS" => vec![(
                "RESPONSE_STATUS".into(),
                self.response_status.to_string(),
                None,
            )],
            "RESPONSE_HEADERS" => filter_kv(
                "RESPONSE_HEADERS",
                &self.response_headers,
                &spec.selector,
                true,
            ),
            "RESPONSE_HEADERS_NAMES" => {
                let names: Vec<(String, String)> = self
                    .response_headers
                    .iter()
                    .map(|(k, _)| (k.clone(), k.clone()))
                    .collect();
                filter_kv("RESPONSE_HEADERS_NAMES", &names, &spec.selector, true)
            }
            "RESPONSE_CONTENT_TYPE" => self
                .response_headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| vec![("RESPONSE_CONTENT_TYPE".into(), v.clone(), None)])
                .unwrap_or_default(),
            "RESPONSE_BODY" => vec![(
                "RESPONSE_BODY".into(),
                self.response_body.clone(),
                Some(self.response_body_raw.clone()),
            )],
            "TX" => {
                let mut pairs: Vec<(String, String)> = self
                    .tx_vars
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                pairs.sort_by(|a, b| a.0.cmp(&b.0));
                filter_kv("TX", &pairs, &spec.selector, true)
            }
            "ENV" => {
                let pairs: Vec<(String, String)> = self
                    .env_vars
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                filter_kv("ENV", &pairs, &spec.selector, true)
            }
            "IP" | "USER" | "GLOBAL" | "SESSION" => {
                let bucket_id = self
                    .col_bindings
                    .get(&spec.name)
                    .cloned()
                    .unwrap_or_else(|| {
                        if spec.name == "IP" && !self.remote_addr.is_empty() {
                            self.remote_addr.clone()
                        } else {
                            "default".to_owned()
                        }
                    });
                let entries = self
                    .waf
                    .persistent
                    .entries_at(&spec.name, &bucket_id, self.now);
                filter_kv(&spec.name, &entries, &spec.selector, true)
            }
            "MATCHED_VAR" => {
                if self.matched_var.is_empty() && self.matched_var_name.is_empty() {
                    Vec::new()
                } else {
                    vec![("MATCHED_VAR".into(), self.matched_var.clone(), None)]
                }
            }
            "MATCHED_VAR_NAME" => {
                if self.matched_var_name.is_empty() {
                    Vec::new()
                } else {
                    vec![(
                        "MATCHED_VAR_NAME".into(),
                        self.matched_var_name.clone(),
                        None,
                    )]
                }
            }
            "MATCHED_VARS" => filter_kv("MATCHED_VARS", &self.matched_vars, &spec.selector, false),
            "MATCHED_VARS_NAMES" => {
                let names: Vec<(String, String)> = self
                    .matched_vars
                    .iter()
                    .map(|(k, _)| (k.clone(), k.clone()))
                    .collect();
                filter_kv("MATCHED_VARS_NAMES", &names, &spec.selector, false)
            }
            "HIGHEST_SEVERITY" => vec![(
                "HIGHEST_SEVERITY".into(),
                self.highest_severity.unwrap_or(255).to_string(),
                None,
            )],
            "RULE" => {
                let pairs = vec![
                    ("id".to_owned(), self.current_rule_id.to_string()),
                    ("msg".to_owned(), self.current_rule_msg.clone()),
                    (
                        "severity".to_owned(),
                        self.current_rule_severity.to_string(),
                    ),
                ];
                filter_kv("RULE", &pairs, &spec.selector, true)
            }
            _ => Vec::new(),
        }
    }

    fn apply_setvar(&mut self, sv: &SetVarSpec) {
        let key = self.expand_macros(&sv.key).to_ascii_lowercase();
        let col = sv.collection.as_str();

        if col == "TX" {
            match &sv.op {
                SetVarOp::Delete => {
                    self.tx_vars.remove(&key);
                }
                SetVarOp::Set(val_expr) => {
                    let val = self.expand_macros(val_expr);
                    self.tx_vars.insert(key, val);
                }
                SetVarOp::Add(delta_expr) => {
                    let delta = parse_modsec_int(&self.expand_macros(delta_expr));
                    let cur = self
                        .tx_vars
                        .get(&key)
                        .map(|v| parse_modsec_int(v))
                        .unwrap_or(0);
                    self.tx_vars
                        .insert(key, (cur.saturating_add(delta)).to_string());
                }
                SetVarOp::Sub(delta_expr) => {
                    let delta = parse_modsec_int(&self.expand_macros(delta_expr));
                    let cur = self
                        .tx_vars
                        .get(&key)
                        .map(|v| parse_modsec_int(v))
                        .unwrap_or(0);
                    self.tx_vars
                        .insert(key, (cur.saturating_sub(delta)).to_string());
                }
            }
            return;
        }

        if matches!(col, "IP" | "USER" | "GLOBAL" | "SESSION") {
            let bucket_id = self.col_bindings.get(col).cloned().unwrap_or_else(|| {
                if col == "IP" && !self.remote_addr.is_empty() {
                    self.remote_addr.clone()
                } else {
                    "default".to_owned()
                }
            });
            match &sv.op {
                SetVarOp::Delete => self.waf.persistent.delete(col, &bucket_id, &key),
                SetVarOp::Set(val_expr) => {
                    let val = self.expand_macros(val_expr);
                    self.waf
                        .persistent
                        .set_at(col, &bucket_id, &key, val, None, self.now);
                }
                SetVarOp::Add(delta_expr) => {
                    let delta = parse_modsec_int(&self.expand_macros(delta_expr));
                    let cur = self
                        .waf
                        .persistent
                        .get_at(col, &bucket_id, &key, self.now)
                        .map(|v| parse_modsec_int(&v))
                        .unwrap_or(0);
                    self.waf.persistent.set_at(
                        col,
                        &bucket_id,
                        &key,
                        cur.saturating_add(delta).to_string(),
                        None,
                        self.now,
                    );
                }
                SetVarOp::Sub(delta_expr) => {
                    let delta = parse_modsec_int(&self.expand_macros(delta_expr));
                    let cur = self
                        .waf
                        .persistent
                        .get_at(col, &bucket_id, &key, self.now)
                        .map(|v| parse_modsec_int(&v))
                        .unwrap_or(0);
                    self.waf.persistent.set_at(
                        col,
                        &bucket_id,
                        &key,
                        cur.saturating_sub(delta).to_string(),
                        None,
                        self.now,
                    );
                }
            }
        }
    }

    fn apply_expirevar(&mut self, ev: &ExpireVarSpec) {
        let secs = parse_modsec_int(&self.expand_macros(&ev.seconds)).max(0) as u64;
        let col = ev.collection.as_str();
        if matches!(col, "IP" | "USER" | "GLOBAL" | "SESSION") {
            let bucket_id = self.col_bindings.get(col).cloned().unwrap_or_else(|| {
                if col == "IP" && !self.remote_addr.is_empty() {
                    self.remote_addr.clone()
                } else {
                    "default".to_owned()
                }
            });
            let key = self.expand_macros(&ev.key).to_ascii_lowercase();
            self.waf.persistent.expire_key_at(
                col,
                &bucket_id,
                &key,
                Duration::from_secs(secs),
                self.now,
            );
        }
    }

    fn apply_ctl(&mut self, ctl: &CtlAction) {
        match ctl {
            CtlAction::RuleRemoveById(range) => self.removed_rule_ids.push(*range),
            CtlAction::RuleRemoveTargetById { id, variable } => {
                if let Ok(mut compiled) =
                    compile_var_specs(std::slice::from_ref(variable), &SourceSpan::default())
                {
                    for v in &mut compiled {
                        v.negated = true;
                    }
                    self.removed_targets_by_id
                        .entry(*id)
                        .or_default()
                        .extend(compiled);
                }
            }
            CtlAction::RuleRemoveTargetByTag { tag, variable } => {
                if let Ok(mut compiled) =
                    compile_var_specs(std::slice::from_ref(variable), &SourceSpan::default())
                {
                    for v in &mut compiled {
                        v.negated = true;
                    }
                    self.removed_targets_by_tag
                        .entry(tag.clone())
                        .or_default()
                        .extend(compiled);
                }
            }
            CtlAction::RuleEngine(mode) => self.rule_engine = *mode,
            CtlAction::RequestBodyProcessor(name) => {
                self.forced_body_processor = BodyProcessor::from_name(name);
            }
            CtlAction::RequestBodyAccess(enabled) => self.request_body_access = *enabled,
            CtlAction::Other { .. } => {}
        }
    }

    /// Expands `%{VAR}` and `%{COL.key}` macros in action and operator strings.
    pub fn expand_macros(&self, input: &str) -> String {
        if !input.contains("%{") {
            return input.to_owned();
        }
        let mut out = String::with_capacity(input.len());
        let bytes = input.as_bytes();
        let len = bytes.len();
        let mut i = 0;

        while i < len {
            if bytes[i] == b'%'
                && i + 1 < len
                && bytes[i + 1] == b'{'
                && let Some(rel_end) = input[i + 2..].find('}')
            {
                let expr = &input[i + 2..i + 2 + rel_end];
                out.push_str(&self.lookup_macro(expr));
                i += 2 + rel_end + 1;
                continue;
            }
            let ch = input[i..].chars().next().expect("valid utf-8");
            out.push(ch);
            i += ch.len_utf8();
        }
        out
    }

    fn lookup_macro(&self, expr: &str) -> String {
        let trimmed = expr.trim();
        let (col, key) = match trimmed.split_once('.') {
            Some((c, k)) => (c.trim().to_ascii_uppercase(), Some(k.trim())),
            None => match trimmed.split_once(':') {
                Some((c, k)) => (c.trim().to_ascii_uppercase(), Some(k.trim())),
                None => (trimmed.to_ascii_uppercase(), None),
            },
        };
        match (col.as_str(), key) {
            ("TX", Some(k)) => self
                .tx_vars
                .get(&k.to_ascii_lowercase())
                .cloned()
                .unwrap_or_default(),
            ("IP" | "USER" | "GLOBAL" | "SESSION", Some(k)) => {
                let bucket_id = self.col_bindings.get(&col).cloned().unwrap_or_else(|| {
                    if col == "IP" && !self.remote_addr.is_empty() {
                        self.remote_addr.clone()
                    } else {
                        "default".to_owned()
                    }
                });
                self.waf
                    .persistent
                    .get_at(&col, &bucket_id, k, self.now)
                    .unwrap_or_default()
            }
            ("ENV", Some(k)) => self.env_vars.get(k).cloned().unwrap_or_default(),
            ("MATCHED_VAR", None) => self.matched_var.clone(),
            ("MATCHED_VAR_NAME", None) => self.matched_var_name.clone(),
            ("REQUEST_URI", None) => self.uri.clone(),
            ("REQUEST_URI_RAW", None) => self.uri_raw.clone(),
            ("REQUEST_FILENAME", None) => self.filename.clone(),
            ("REQUEST_BASENAME", None) => self.basename.clone(),
            ("REQUEST_METHOD", None) => self.method.clone(),
            ("REQUEST_PROTOCOL", None) => self.protocol.clone(),
            ("QUERY_STRING", None) => self.query_string.clone(),
            ("REMOTE_ADDR", None) => self.remote_addr.clone(),
            ("RESPONSE_STATUS", None) => self.response_status.to_string(),
            ("REQUEST_HEADERS", Some(k)) => self
                .request_headers
                .iter()
                .find(|(hk, _)| hk.eq_ignore_ascii_case(k))
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
            ("RESPONSE_HEADERS", Some(k)) => self
                .response_headers
                .iter()
                .find(|(hk, _)| hk.eq_ignore_ascii_case(k))
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
            ("ARGS", Some(k)) => self
                .args_get
                .iter()
                .chain(self.args_post.iter())
                .find(|(ak, _)| ak == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
            ("RULE", Some(k)) => match k.to_ascii_lowercase().as_str() {
                "id" => self.current_rule_id.to_string(),
                "msg" => self.current_rule_msg.clone(),
                "severity" => self.current_rule_severity.to_string(),
                _ => String::new(),
            },
            _ => String::new(),
        }
    }
}

fn filter_kv(
    col_name: &str,
    pairs: &[(String, String)],
    selector: &Option<CompiledVarSelector>,
    ci_key: bool,
) -> Vec<(String, String, Option<Vec<u8>>)> {
    let mut out = Vec::new();
    for (k, v) in pairs {
        let keep = match selector {
            None => true,
            Some(CompiledVarSelector::Key(target)) => {
                if ci_key {
                    k.eq_ignore_ascii_case(target)
                } else {
                    k == target
                }
            }
            Some(CompiledVarSelector::Regex(re)) => re.is_match(k),
        };
        if keep {
            out.push((format!("{col_name}:{k}"), v.clone(), None));
        }
    }
    out
}

fn is_excluded(col_name: &str, full_name: &str, exclusions: &[&CompiledVarSpec]) -> bool {
    if exclusions.is_empty() {
        return false;
    }
    let key_part = full_name.split_once(':').map(|(_, k)| k).unwrap_or("");
    let ci_key = matches!(
        col_name,
        "REQUEST_HEADERS"
            | "REQUEST_HEADERS_NAMES"
            | "RESPONSE_HEADERS"
            | "RESPONSE_HEADERS_NAMES"
            | "TX"
            | "IP"
            | "USER"
            | "GLOBAL"
            | "SESSION"
    );

    for ex in exclusions {
        if ex.name != col_name {
            // `ARGS` exclusion also covers `ARGS_GET` / `ARGS_POST` when removing targets.
            let is_args_family = ex.name == "ARGS" && matches!(col_name, "ARGS_GET" | "ARGS_POST");
            if !is_args_family {
                continue;
            }
        }
        match &ex.selector {
            None => return true,
            Some(CompiledVarSelector::Key(target)) => {
                if ci_key {
                    if key_part.eq_ignore_ascii_case(target) {
                        return true;
                    }
                } else if key_part == target {
                    return true;
                }
            }
            Some(CompiledVarSelector::Regex(re)) => {
                if re.is_match(key_part) {
                    return true;
                }
            }
        }
    }
    false
}

fn parse_modsec_int(s: &str) -> i64 {
    s.trim().parse::<i64>().unwrap_or(0)
}

/// Convenience helper for parsing a SecLang snippet with [`NoopResolver`].
pub fn compile_seclang(config: WafConfig, rules: &str) -> Result<Waf, Vec<SecLangError>> {
    Waf::from_seclang_with_includes(config, rules, &NoopResolver)
}
