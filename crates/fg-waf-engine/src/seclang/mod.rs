//! SecLang lexer, parser, and AST (WP-55 steps E1 & E2).

pub mod ast;
pub mod lexer;
pub mod parser;

pub use ast::{
    Action, AllowScope, BodyLimitAction, CtlAction, Directive, DisruptiveAction, ExpireVarSpec,
    IdRange, OperatorKind, OperatorSpec, RuleEngineMode, SecLangError, SecRuleAst, SetVarOp,
    SetVarSpec, SourceSpan, VarSelector, VarSpec,
};
pub use parser::{IncludeResolver, NoopResolver, parse, parse_with_includes};
