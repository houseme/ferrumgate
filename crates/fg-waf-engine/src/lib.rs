//! The WAF rule engine layer (WP-55, first tier): request model, JSON
//! rule sets, compile-then-snapshot matching, counting and the
//! metrics/event output surface.
//!
//! Scope of this tier (batch note: 引擎层步骤 1-4 的引擎子集):
//!
//! - [`request`] — the engine's borrowed, zero-copy view of one request
//!   (method, host, path, query, headers, user agent, client address,
//!   body excerpt).
//! - [`rule`] — the FerrumGate-native JSON rule set format
//!   (camelCase, `deny_unknown_fields`, defaults; ordered rules with a
//!   matcher tree and an action). The SecLang directive parser (WP-55
//!   E1/E2) compiles into the same compiled types in a later step.
//! - [`compile`] — validates every enabled rule against the centralized
//!   [`limits`], precompiles regexes and IP networks and collects all
//!   errors; disabled rules are skipped so a broken rule can be disabled
//!   and saved from the admin UI.
//! - [`engine`] — the [`Engine`](engine::Engine) publishes an immutable
//!   snapshot through `arc_swap::ArcSwap` (one lock-free load per
//!   request, the pattern of `fg-net`'s ban table) and
//!   [`evaluate`](engine::evaluate) is a pure function over that
//!   snapshot. Actions: `deny` (stop, reject with status), `allow` (stop,
//!   pass), `count` (record, continue). Deny decisions fire an optional
//!   hook; [`engine::blocked_event`] builds the registered
//!   `fg_core::events` Kind (`waf.blocked`) for the embedder.
//! - [`metrics`] — the `ferrumgate_waf_*` Prometheus samples.
//!
//! Not in this tier: SecLang parsing, CRS compatibility, the five-phase
//! transaction with anomaly scoring, request-body processors, libinjection,
//! persistent collections, the `fg-waf` integration crate and site
//! integration (WP-23). The regex backend is the workspace `regex` crate:
//! backreferences and look-around are rejected at compile time with a
//! clear error (WP-55 §3.3 notes `fancy-regex` for the SecLang steps).
//!
//! Hot path: build a [`request::Request`] from borrowed parts, load the
//! snapshot once with [`engine::Engine::snapshot`], call
//! [`engine::evaluate`] — nothing allocates unless a rule actually hits.

#![forbid(unsafe_code)]

pub mod compile;
pub mod engine;
pub mod limits;
pub mod metrics;
pub mod request;
pub mod rule;

pub use compile::{CompileError, Compiled, CompiledRule, compile};
pub use engine::{
    BlockedHit, BlockedHook, Decision, Engine, EngineHooks, EngineStats, Evaluated, blocked_event,
    evaluate,
};
pub use limits::EngineConfig;
pub use request::{HeaderPair, Request};
pub use rule::{ActionKind, Field, Matcher, Operator, Rule, RuleSetFile};
