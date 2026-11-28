//! The WAF rule engine layer (WP-55, Tranches 1 & 2):
//!
//! - Tranche 1 (JSON rule sets): [`request`], [`rule`], [`compile`],
//!   [`engine`], [`limits`], [`metrics`].
//! - Tranche 2 (SecLang & CRS-compatible engine):
//!   - [`seclang`] — linear-time SecLang lexer, parser, AST, and `Include`
//!     resolution.
//!   - [`transforms`] — pure-function ModSecurity `t:*` transformation chain.
//!   - [`body`] — bounded pure-Rust request body parsers (`urlencoded`,
//!     `multipart`, `json`, `xml`).
//!   - [`detect`] — pure-Rust SQLi & XSS lexical/fingerprint detectors
//!     (`@detectSQLi` / `@detectXSS`).
//!   - [`prefilter`] — literal keyword extraction prefilter for `@rx` rules.
//!   - [`transaction`] — compiled [`Waf`] ruleset and 5-phase [`Transaction`]
//!     evaluator with anomaly scoring, chained rules, control flow, and bounded
//!     TTL persistent collections.

#![forbid(unsafe_code)]

pub mod body;
pub mod compile;
pub mod detect;
pub mod engine;
pub mod limits;
pub mod metrics;
pub mod prefilter;
pub mod request;
pub mod rule;
pub mod seclang;
pub mod transaction;
pub mod transforms;

// Tranche 1 exports (100% backwards-compatible)
pub use compile::{CompileError, Compiled, CompiledRule, compile};
pub use engine::{
    BlockedHit, BlockedHook, Decision, Engine, EngineHooks, EngineStats, Evaluated, blocked_event,
    evaluate,
};
pub use limits::EngineConfig;
pub use request::{HeaderPair, Request};
pub use rule::{ActionKind, Field, Matcher, Operator, Rule, RuleSetFile};

// Tranche 2 exports
pub use body::{BodyProcessor, ParsedBody, parse_body};
pub use detect::{detect_sqli, detect_xss};
pub use prefilter::Prefilter;
pub use seclang::{BodyLimitAction, Directive, IncludeResolver, RuleEngineMode, SecLangError};
pub use transaction::{
    CompileWarning, Intervention, InterventionAction, MatchedRule, PersistentStore, Phase,
    RequestHead, ResponseHead, Transaction, Waf, WafConfig,
};
pub use transforms::{Transform, apply_transform, apply_transforms};
