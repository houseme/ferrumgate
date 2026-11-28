//! Abstract syntax tree for ModSecurity / OWASP CRS SecLang directives.

/// Maximum input size accepted by the SecLang parser (16 MiB).
pub const MAX_SECLANG_INPUT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of directives parsed in one compilation unit.
pub const MAX_SECLANG_DIRECTIVES: usize = 32_768;
/// Maximum nesting depth for `Include` directives.
pub const MAX_INCLUDE_DEPTH: usize = 16;

/// Source location for diagnostics and matched-rule reporting.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceSpan {
    pub file: String,
    pub line: u32,
}

/// Error produced during SecLang lexing or parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecLangError {
    pub file: String,
    pub line: u32,
    pub message: String,
}

impl std::fmt::Display for SecLangError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.file.is_empty() {
            write!(f, "line {}: {}", self.line, self.message)
        } else {
            write!(f, "{}:{}: {}", self.file, self.line, self.message)
        }
    }
}

impl std::error::Error for SecLangError {}

/// Rule engine operating mode (`SecRuleEngine` / `ctl:ruleEngine`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RuleEngineMode {
    #[default]
    On,
    DetectionOnly,
    Off,
}

/// Action taken when a request body exceeds `SecRequestBodyLimit`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BodyLimitAction {
    #[default]
    Reject,
    ProcessPartial,
}

/// A parsed top-level SecLang directive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Directive {
    SecRule(SecRuleAst),
    SecAction {
        actions: Vec<Action>,
        span: SourceSpan,
    },
    SecMarker {
        name: String,
        span: SourceSpan,
    },
    SecComponentSignature {
        signature: String,
        span: SourceSpan,
    },
    SecRuleRemoveById {
        ranges: Vec<IdRange>,
        span: SourceSpan,
    },
    SecRuleRemoveTargetById {
        id: u64,
        variables: Vec<VarSpec>,
        span: SourceSpan,
    },
    SecRuleUpdateTargetById {
        id: u64,
        variables: Vec<VarSpec>,
        span: SourceSpan,
    },
    SecRuleUpdateTargetByTag {
        tag: String,
        variables: Vec<VarSpec>,
        span: SourceSpan,
    },
    SecRuleUpdateActionById {
        id: u64,
        actions: Vec<Action>,
        span: SourceSpan,
    },
    SecRuleRemoveByTag {
        tag: String,
        span: SourceSpan,
    },
    SecRuleRemoveByMsg {
        msg: String,
        span: SourceSpan,
    },
    SecRequestBodyAccess {
        enabled: bool,
        span: SourceSpan,
    },
    SecRequestBodyLimit {
        limit: usize,
        span: SourceSpan,
    },
    SecRequestBodyLimitAction {
        action: BodyLimitAction,
        span: SourceSpan,
    },
    SecResponseBodyAccess {
        enabled: bool,
        span: SourceSpan,
    },
    SecResponseBodyLimit {
        limit: usize,
        span: SourceSpan,
    },
    SecDefaultAction {
        actions: Vec<Action>,
        span: SourceSpan,
    },
    SecRuleEngine {
        mode: RuleEngineMode,
        span: SourceSpan,
    },
    SecCollectionTimeout {
        seconds: u64,
        span: SourceSpan,
    },
    SecArgumentSeparator {
        separator: u8,
        span: SourceSpan,
    },
    Include {
        path: String,
        span: SourceSpan,
    },
    /// Recognised benign / audit / housekeeping directive parsed and ignored.
    Ignored {
        name: String,
        span: SourceSpan,
    },
}

/// An inclusive rule-ID range (single IDs have `start == end`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdRange {
    pub start: u64,
    pub end: u64,
}

impl IdRange {
    pub const fn single(id: u64) -> Self {
        Self { start: id, end: id }
    }

    pub const fn contains(&self, id: u64) -> bool {
        id >= self.start && id <= self.end
    }
}

/// Parsed `SecRule` statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecRuleAst {
    pub variables: Vec<VarSpec>,
    pub operator: OperatorSpec,
    pub actions: Vec<Action>,
    pub span: SourceSpan,
}

/// Variable selection specifier inside `SecRule` (e.g., `ARGS`, `!ARGS:id`,
/// `&REQUEST_HEADERS:Host`, `ARGS:/^user_/`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VarSpec {
    /// Upper-cased variable or collection name.
    pub name: String,
    /// Optional key or regex selector after `:`.
    pub selector: Option<VarSelector>,
    /// Leading `!` — excludes this variable/key from the target list.
    pub negated: bool,
    /// Leading `&` — evaluates to the count of matched entries.
    pub count: bool,
}

/// Selector after `:` on a variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VarSelector {
    Key(String),
    Regex(String),
}

/// Parsed operator specification (`[!][@op] [arg]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorSpec {
    pub negated: bool,
    pub kind: OperatorKind,
    pub arg: String,
}

/// Supported and recognised SecLang operators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperatorKind {
    Rx,
    Pm,
    PmFromFile,
    Contains,
    StrEq,
    StartsWith,
    EndsWith,
    Within,
    Eq,
    Gt,
    Lt,
    Ge,
    Le,
    IpMatch,
    IpMatchFromFile,
    ValidateByteRange,
    ValidateUtf8,
    UnconditionalMatch,
    NoMatch,
    DetectSqli,
    DetectXss,
    /// Recognised or unknown operator that is not implemented; rules using it
    /// are skipped cleanly with a compile warning.
    Unsupported(String),
}

/// Disruptive action kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisruptiveAction {
    Pass,
    Deny,
    Drop,
    Block,
    Allow(AllowScope),
    Redirect(String),
}

/// Scope for `allow` actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllowScope {
    All,
    Phase,
    Request,
}

/// Control (`ctl:*`) runtime modification action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CtlAction {
    RuleRemoveById(IdRange),
    RuleRemoveTargetById { id: u64, variable: VarSpec },
    RuleRemoveTargetByTag { tag: String, variable: VarSpec },
    RuleEngine(RuleEngineMode),
    RequestBodyProcessor(String),
    RequestBodyAccess(bool),
    Other { key: String, value: String },
}

/// Variable mutation operation inside `setvar`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetVarOp {
    /// `col.key=val`
    Set(String),
    /// `col.key=+delta`
    Add(String),
    /// `col.key=-delta`
    Sub(String),
    /// `!col.key`
    Delete,
}

/// Parsed `setvar` action payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetVarSpec {
    pub collection: String,
    pub key: String,
    pub op: SetVarOp,
}

/// Parsed `expirevar` action payload (`col.key=seconds`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpireVarSpec {
    pub collection: String,
    pub key: String,
    pub seconds: String,
}

/// A parsed action in a `SecRule`, `SecAction`, `SecDefaultAction`, or
/// `SecRuleUpdateActionById`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Id(u64),
    Phase(u8),
    Msg(String),
    LogData(String),
    Severity(u8),
    Tag(String),
    Ver(String),
    Transform(String),
    Capture,
    Log,
    NoLog,
    AuditLog,
    NoAuditLog,
    Disruptive(DisruptiveAction),
    Status(u16),
    Chain,
    Skip(usize),
    SkipAfter(String),
    SetVar(SetVarSpec),
    ExpireVar(ExpireVarSpec),
    Ctl(CtlAction),
    SetEnv {
        key: String,
        value: String,
    },
    InitCol {
        collection: String,
        key: String,
    },
    MultiMatch,
    /// Benign metadata/sanitisation actions (`rev`, `maturity`, `accuracy`,
    /// `sanitise*`, `xmlns`, etc.) preserved without error.
    Meta {
        key: String,
        value: Option<String>,
    },
}
