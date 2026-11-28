//! Linear-time parser turning lexed SecLang logical lines into AST
//! [`Directive`] values, with `Include` resolution via caller-supplied maps or
//! resolvers.

use std::collections::{HashMap, HashSet};

use crate::seclang::{
    ast::{
        Action, AllowScope, BodyLimitAction, CtlAction, Directive, DisruptiveAction, ExpireVarSpec,
        IdRange, MAX_INCLUDE_DEPTH, MAX_SECLANG_DIRECTIVES, OperatorKind, OperatorSpec,
        RuleEngineMode, SecLangError, SecRuleAst, SetVarOp, SetVarSpec, SourceSpan, VarSelector,
        VarSpec,
    },
    lexer::{LogicalLine, Token, lex},
};

/// Resolves `Include` paths during SecLang parsing.
pub trait IncludeResolver {
    /// Returns the contents of `path` (or `None` if the file does not exist).
    /// Glob patterns (e.g., `rules/*.conf`) may return multiple `(name, content)`
    /// pairs in deterministic order.
    fn resolve(&self, path: &str) -> Vec<(String, String)>;
}

/// Simple in-memory map resolver supporting exact paths and simple `*` suffix
/// or prefix globs (e.g. `rules/*.conf`).
impl IncludeResolver for HashMap<String, String> {
    fn resolve(&self, path: &str) -> Vec<(String, String)> {
        if let Some(content) = self.get(path) {
            return vec![(path.to_owned(), content.clone())];
        }
        if let Some((prefix, suffix)) = path.split_once('*') {
            let mut matched: Vec<(String, String)> = self
                .iter()
                .filter(|(k, _)| {
                    k.len() >= prefix.len() + suffix.len()
                        && k.starts_with(prefix)
                        && k.ends_with(suffix)
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            matched.sort_by(|a, b| a.0.cmp(&b.0));
            return matched;
        }
        Vec::new()
    }
}

/// Resolver that resolves no includes (keeps `Directive::Include` unresolved
/// or reports missing if expansion is requested).
pub struct NoopResolver;

impl IncludeResolver for NoopResolver {
    fn resolve(&self, _path: &str) -> Vec<(String, String)> {
        Vec::new()
    }
}

/// Parses a single SecLang source string without expanding `Include`
/// directives (each `Include` is returned as [`Directive::Include`]).
pub fn parse(file: &str, input: &str) -> Result<Vec<Directive>, Vec<SecLangError>> {
    let lines = lex(file, input)?;
    parse_lines(file, &lines)
}

/// Parses a SecLang source string and recursively expands `Include` directives
/// using `resolver`, enforcing cycle detection and [`MAX_INCLUDE_DEPTH`].
pub fn parse_with_includes<R: IncludeResolver>(
    file: &str,
    input: &str,
    resolver: &R,
) -> Result<Vec<Directive>, Vec<SecLangError>> {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    let mut stack = HashSet::new();
    stack.insert(file.to_owned());
    parse_recursive(file, input, resolver, 0, &mut stack, &mut out, &mut errors);
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

fn parse_recursive<R: IncludeResolver>(
    file: &str,
    input: &str,
    resolver: &R,
    depth: usize,
    stack: &mut HashSet<String>,
    out: &mut Vec<Directive>,
    errors: &mut Vec<SecLangError>,
) {
    if depth > MAX_INCLUDE_DEPTH {
        errors.push(SecLangError {
            file: file.to_owned(),
            line: 1,
            message: format!("Include nesting exceeds maximum depth of {MAX_INCLUDE_DEPTH}"),
        });
        return;
    }
    let directives = match parse(file, input) {
        Ok(d) => d,
        Err(errs) => {
            errors.extend(errs);
            return;
        }
    };
    for dir in directives {
        if out.len() >= MAX_SECLANG_DIRECTIVES {
            errors.push(SecLangError {
                file: file.to_owned(),
                line: 1,
                message: format!(
                    "SecLang directive count exceeds maximum of {MAX_SECLANG_DIRECTIVES}"
                ),
            });
            return;
        }
        match dir {
            Directive::Include { path, span } => {
                let resolved = resolver.resolve(&path);
                if resolved.is_empty() {
                    // Glob includes that match nothing are allowed in Apache/CRS
                    // (e.g. optional custom rules); exact missing paths report error.
                    if !path.contains('*') {
                        errors.push(SecLangError {
                            file: span.file,
                            line: span.line,
                            message: format!("Include file not found: {path}"),
                        });
                    }
                    continue;
                }
                for (inc_name, inc_content) in resolved {
                    if !stack.insert(inc_name.clone()) {
                        errors.push(SecLangError {
                            file: span.file.clone(),
                            line: span.line,
                            message: format!("cyclic Include detected: {inc_name}"),
                        });
                        continue;
                    }
                    parse_recursive(
                        &inc_name,
                        &inc_content,
                        resolver,
                        depth + 1,
                        stack,
                        out,
                        errors,
                    );
                    stack.remove(&inc_name);
                }
            }
            other => out.push(other),
        }
    }
}

fn parse_lines(file: &str, lines: &[LogicalLine]) -> Result<Vec<Directive>, Vec<SecLangError>> {
    if lines.len() > MAX_SECLANG_DIRECTIVES {
        return Err(vec![SecLangError {
            file: file.to_owned(),
            line: 1,
            message: format!("SecLang directive count exceeds maximum of {MAX_SECLANG_DIRECTIVES}"),
        }]);
    }

    let mut directives = Vec::with_capacity(lines.len());
    let mut errors = Vec::new();

    for line in lines {
        let Some(first) = line.tokens.first() else {
            continue;
        };
        let span = SourceSpan {
            file: file.to_owned(),
            line: line.line,
        };
        let args = &line.tokens[1..];
        let name_lower = first.text.to_ascii_lowercase();
        let res = match name_lower.as_str() {
            "secrule" => parse_sec_rule(args, span),
            "secaction" => parse_sec_action(args, span),
            "secmarker" => parse_sec_marker(args, span),
            "seccomponentsignature" => parse_single_string(args, &span, "SecComponentSignature")
                .map(|signature| Directive::SecComponentSignature { signature, span }),
            "secruleremovebyid" => parse_remove_by_id(args, span),
            "secruleremovetargetbyid" => parse_target_by_id(args, span, true),
            "secruleupdatetargetbyid" => parse_target_by_id(args, span, false),
            "secruleupdatetargetbytag" => parse_update_target_by_tag(args, span),
            "secruleupdateactionbyid" => parse_update_action_by_id(args, span),
            "secruleremovebytag" => parse_single_string(args, &span, "SecRuleRemoveByTag")
                .map(|tag| Directive::SecRuleRemoveByTag { tag, span }),
            "secruleremovebymsg" => parse_single_string(args, &span, "SecRuleRemoveByMsg")
                .map(|msg| Directive::SecRuleRemoveByMsg { msg, span }),
            "secrequestbodyaccess" => parse_on_off(args, &span, "SecRequestBodyAccess")
                .map(|enabled| Directive::SecRequestBodyAccess { enabled, span }),
            "secrequestbodylimit" => parse_usize(args, &span, "SecRequestBodyLimit")
                .map(|limit| Directive::SecRequestBodyLimit { limit, span }),
            "secrequestbodylimitaction" => parse_body_limit_action(args, span),
            "secresponsebodyaccess" => parse_on_off(args, &span, "SecResponseBodyAccess")
                .map(|enabled| Directive::SecResponseBodyAccess { enabled, span }),
            "secresponsebodylimit" => parse_usize(args, &span, "SecResponseBodyLimit")
                .map(|limit| Directive::SecResponseBodyLimit { limit, span }),
            "secdefaultaction" => parse_default_action(args, span),
            "secruleengine" => parse_rule_engine(args, span),
            "seccollectiontimeout" => parse_u64(args, &span, "SecCollectionTimeout")
                .map(|seconds| Directive::SecCollectionTimeout { seconds, span }),
            "secargumentseparator" => parse_arg_separator(args, span),
            "include" | "includeoptional" => parse_single_string(args, &span, "Include")
                .map(|path| Directive::Include { path, span }),
            // Recognised benign / audit / CRS configuration directives.
            "secrequestbodynofileslimit"
            | "secrequestbodyinmemorylimit"
            | "secresponsebodymimetype"
            | "secresponsebodymimetypesclear"
            | "secresponsebodylimitaction"
            | "seccookieformat"
            | "secunicodecodepage"
            | "secunicodemapfile"
            | "sechttpcasesensitiveargumentnames"
            | "secauditengine"
            | "secauditlog"
            | "secauditlogparts"
            | "secauditlogrelevantstatus"
            | "secauditlogtype"
            | "secauditlogformat"
            | "secauditlogstoragedir"
            | "secdebuglog"
            | "secdebugloglevel"
            | "secdatadir"
            | "sectmpdir"
            | "secuploaddir"
            | "secuploadkeepfiles"
            | "secpcrematchlimit"
            | "secpcrematchlimitrecursion"
            | "secstatusengine"
            | "secserversignature"
            | "secwebappid"
            | "secargumentslimit"
            | "secdisablebackendcompression"
            | "secrequestbodyjsondepthlimit" => Ok(Directive::Ignored {
                name: first.text.clone(),
                span,
            }),
            _ => Err(SecLangError {
                file: span.file,
                line: span.line,
                message: format!("unknown SecLang directive {:?}", first.text),
            }),
        };
        match res {
            Ok(d) => directives.push(d),
            Err(e) => errors.push(e),
        }
    }

    if errors.is_empty() {
        Ok(directives)
    } else {
        Err(errors)
    }
}

fn err(span: &SourceSpan, msg: impl Into<String>) -> SecLangError {
    SecLangError {
        file: span.file.clone(),
        line: span.line,
        message: msg.into(),
    }
}

fn parse_single_string(
    args: &[Token],
    span: &SourceSpan,
    name: &str,
) -> Result<String, SecLangError> {
    if args.is_empty() {
        return Err(err(span, format!("{name} requires an argument")));
    }
    Ok(args
        .iter()
        .map(|t| t.text.as_str())
        .collect::<Vec<_>>()
        .join(" "))
}

fn parse_on_off(args: &[Token], span: &SourceSpan, name: &str) -> Result<bool, SecLangError> {
    let val = args
        .first()
        .ok_or_else(|| err(span, format!("{name} requires On or Off")))?;
    match val.text.to_ascii_lowercase().as_str() {
        "on" => Ok(true),
        "off" => Ok(false),
        other => Err(err(
            span,
            format!("{name} expects On or Off, got {other:?}"),
        )),
    }
}

fn parse_usize(args: &[Token], span: &SourceSpan, name: &str) -> Result<usize, SecLangError> {
    let val = args
        .first()
        .ok_or_else(|| err(span, format!("{name} requires an integer value")))?;
    val.text
        .parse::<usize>()
        .map_err(|_| err(span, format!("{name} invalid integer {:?}", val.text)))
}

fn parse_u64(args: &[Token], span: &SourceSpan, name: &str) -> Result<u64, SecLangError> {
    let val = args
        .first()
        .ok_or_else(|| err(span, format!("{name} requires an integer value")))?;
    val.text
        .parse::<u64>()
        .map_err(|_| err(span, format!("{name} invalid integer {:?}", val.text)))
}

fn parse_arg_separator(args: &[Token], span: SourceSpan) -> Result<Directive, SecLangError> {
    let val = args
        .first()
        .ok_or_else(|| err(&span, "SecArgumentSeparator requires a single ASCII byte"))?;
    let bytes = val.text.as_bytes();
    if bytes.len() != 1 {
        return Err(err(
            &span,
            format!("SecArgumentSeparator requires 1 byte, got {:?}", val.text),
        ));
    }
    Ok(Directive::SecArgumentSeparator {
        separator: bytes[0],
        span,
    })
}

fn parse_body_limit_action(args: &[Token], span: SourceSpan) -> Result<Directive, SecLangError> {
    let val = args.first().ok_or_else(|| {
        err(
            &span,
            "SecRequestBodyLimitAction requires Reject or ProcessPartial",
        )
    })?;
    let action = match val.text.to_ascii_lowercase().as_str() {
        "reject" => BodyLimitAction::Reject,
        "processpartial" => BodyLimitAction::ProcessPartial,
        other => {
            return Err(err(
                &span,
                format!("SecRequestBodyLimitAction invalid value {other:?}"),
            ));
        }
    };
    Ok(Directive::SecRequestBodyLimitAction { action, span })
}

fn parse_rule_engine(args: &[Token], span: SourceSpan) -> Result<Directive, SecLangError> {
    let val = args
        .first()
        .ok_or_else(|| err(&span, "SecRuleEngine requires On, Off, or DetectionOnly"))?;
    let mode = parse_rule_engine_mode(&val.text)
        .ok_or_else(|| err(&span, format!("invalid SecRuleEngine mode {:?}", val.text)))?;
    Ok(Directive::SecRuleEngine { mode, span })
}

fn parse_rule_engine_mode(s: &str) -> Option<RuleEngineMode> {
    match s.to_ascii_lowercase().as_str() {
        "on" => Some(RuleEngineMode::On),
        "off" => Some(RuleEngineMode::Off),
        "detectiononly" => Some(RuleEngineMode::DetectionOnly),
        _ => None,
    }
}

fn parse_sec_marker(args: &[Token], span: SourceSpan) -> Result<Directive, SecLangError> {
    let val = args
        .first()
        .ok_or_else(|| err(&span, "SecMarker requires a marker name"))?;
    Ok(Directive::SecMarker {
        name: val.text.clone(),
        span,
    })
}

fn parse_sec_action(args: &[Token], span: SourceSpan) -> Result<Directive, SecLangError> {
    let raw = parse_single_string(args, &span, "SecAction")?;
    let actions = parse_actions(&raw, &span)?;
    Ok(Directive::SecAction { actions, span })
}

fn parse_default_action(args: &[Token], span: SourceSpan) -> Result<Directive, SecLangError> {
    let raw = parse_single_string(args, &span, "SecDefaultAction")?;
    let actions = parse_actions(&raw, &span)?;
    Ok(Directive::SecDefaultAction { actions, span })
}

fn parse_sec_rule(args: &[Token], span: SourceSpan) -> Result<Directive, SecLangError> {
    if args.len() < 2 {
        return Err(err(
            &span,
            "SecRule requires at least variables and an operator",
        ));
    }
    let variables = parse_variables(&args[0].text, &span)?;
    let operator = parse_operator(&args[1].text)?;
    let actions = if args.len() >= 3 {
        let joined = args[2..]
            .iter()
            .map(|t| t.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        parse_actions(&joined, &span)?
    } else {
        Vec::new()
    };
    Ok(Directive::SecRule(SecRuleAst {
        variables,
        operator,
        actions,
        span,
    }))
}

fn parse_remove_by_id(args: &[Token], span: SourceSpan) -> Result<Directive, SecLangError> {
    if args.is_empty() {
        return Err(err(
            &span,
            "SecRuleRemoveById requires at least one rule ID",
        ));
    }
    let mut ranges = Vec::new();
    for tok in args {
        for part in tok.text.split([',', ' ', '\t']).filter(|s| !s.is_empty()) {
            ranges.push(parse_id_range(part, &span)?);
        }
    }
    if ranges.is_empty() {
        return Err(err(
            &span,
            "SecRuleRemoveById requires at least one rule ID",
        ));
    }
    Ok(Directive::SecRuleRemoveById { ranges, span })
}

fn parse_id_range(s: &str, span: &SourceSpan) -> Result<IdRange, SecLangError> {
    if let Some((a, b)) = s.split_once('-') {
        let start = a
            .trim()
            .parse::<u64>()
            .map_err(|_| err(span, format!("invalid rule ID range {s:?}")))?;
        let end = b
            .trim()
            .parse::<u64>()
            .map_err(|_| err(span, format!("invalid rule ID range {s:?}")))?;
        if start > end {
            return Err(err(span, format!("inverted rule ID range {s:?}")));
        }
        Ok(IdRange { start, end })
    } else {
        let id = s
            .trim()
            .parse::<u64>()
            .map_err(|_| err(span, format!("invalid rule ID {s:?}")))?;
        Ok(IdRange::single(id))
    }
}

fn parse_target_by_id(
    args: &[Token],
    span: SourceSpan,
    is_remove: bool,
) -> Result<Directive, SecLangError> {
    let directive_name = if is_remove {
        "SecRuleRemoveTargetById"
    } else {
        "SecRuleUpdateTargetById"
    };
    if args.len() < 2 {
        return Err(err(
            &span,
            format!("{directive_name} requires a rule ID and variables"),
        ));
    }
    let id = args[0].text.parse::<u64>().map_err(|_| {
        err(
            &span,
            format!("{directive_name}: invalid rule ID {:?}", args[0].text),
        )
    })?;
    let vars_raw = args[1..]
        .iter()
        .map(|t| t.text.as_str())
        .collect::<Vec<_>>()
        .join("|");
    let variables = parse_variables(&vars_raw, &span)?;
    if is_remove {
        Ok(Directive::SecRuleRemoveTargetById {
            id,
            variables,
            span,
        })
    } else {
        Ok(Directive::SecRuleUpdateTargetById {
            id,
            variables,
            span,
        })
    }
}

fn parse_update_target_by_tag(args: &[Token], span: SourceSpan) -> Result<Directive, SecLangError> {
    if args.len() < 2 {
        return Err(err(
            &span,
            "SecRuleUpdateTargetByTag requires a tag and variables",
        ));
    }
    let tag = args[0].text.clone();
    let vars_raw = args[1..]
        .iter()
        .map(|t| t.text.as_str())
        .collect::<Vec<_>>()
        .join("|");
    let variables = parse_variables(&vars_raw, &span)?;
    Ok(Directive::SecRuleUpdateTargetByTag {
        tag,
        variables,
        span,
    })
}

fn parse_update_action_by_id(args: &[Token], span: SourceSpan) -> Result<Directive, SecLangError> {
    if args.len() < 2 {
        return Err(err(
            &span,
            "SecRuleUpdateActionById requires a rule ID and actions",
        ));
    }
    let id = args[0].text.parse::<u64>().map_err(|_| {
        err(
            &span,
            format!(
                "SecRuleUpdateActionById: invalid rule ID {:?}",
                args[0].text
            ),
        )
    })?;
    let raw = args[1..]
        .iter()
        .map(|t| t.text.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let actions = parse_actions(&raw, &span)?;
    Ok(Directive::SecRuleUpdateActionById { id, actions, span })
}

/// Parses a pipe-separated list of SecLang variables, respecting regex
/// selectors `VAR:/a|b/` and quoted selectors `VAR:'a|b'`.
pub fn parse_variables(raw: &str, span: &SourceSpan) -> Result<Vec<VarSpec>, SecLangError> {
    let mut parts = Vec::new();
    let bytes = raw.as_bytes();
    let mut start = 0usize;
    let mut in_regex = false;
    let mut in_squote = false;
    let mut after_colon = false;
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        if in_regex {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'/' {
                in_regex = false;
            }
            i += 1;
            continue;
        }
        if in_squote {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'\'' {
                in_squote = false;
            }
            i += 1;
            continue;
        }
        if b == b':' && !after_colon {
            after_colon = true;
            if i + 1 < bytes.len() {
                if bytes[i + 1] == b'/' {
                    in_regex = true;
                    i += 2;
                    continue;
                }
                if bytes[i + 1] == b'\'' {
                    in_squote = true;
                    i += 2;
                    continue;
                }
            }
            i += 1;
            continue;
        }
        if b == b'|' {
            let segment = raw[start..i].trim();
            if !segment.is_empty() {
                parts.push(segment);
            }
            start = i + 1;
            after_colon = false;
            i += 1;
            continue;
        }
        i += 1;
    }
    let tail = raw[start..].trim();
    if !tail.is_empty() {
        parts.push(tail);
    }

    if parts.is_empty() {
        return Err(err(span, "empty variable list"));
    }

    let mut vars = Vec::with_capacity(parts.len());
    for part in parts {
        vars.push(parse_single_variable(part, span)?);
    }
    Ok(vars)
}

/// Parses one variable specifier (`[!][&]NAME[:selector]`).
pub fn parse_single_variable(raw: &str, span: &SourceSpan) -> Result<VarSpec, SecLangError> {
    let mut s = raw.trim();
    let mut negated = false;
    let mut count = false;

    loop {
        if let Some(rest) = s.strip_prefix('!') {
            negated = true;
            s = rest;
        } else if let Some(rest) = s.strip_prefix('&') {
            count = true;
            s = rest;
        } else {
            break;
        }
    }

    let (name_part, sel_part) = match s.split_once(':') {
        Some((n, sel)) => (n, Some(sel)),
        None => (s, None),
    };

    let name = name_part.trim().to_ascii_uppercase();
    if name.is_empty() {
        return Err(err(span, format!("empty variable name in {raw:?}")));
    }

    let selector = match sel_part {
        None => None,
        Some(sel) => {
            let sel = sel.trim();
            if sel.len() >= 2 && sel.starts_with('/') && sel.ends_with('/') {
                Some(VarSelector::Regex(sel[1..sel.len() - 1].to_owned()))
            } else if sel.len() >= 2 && sel.starts_with('\'') && sel.ends_with('\'') {
                Some(VarSelector::Key(sel[1..sel.len() - 1].to_owned()))
            } else {
                Some(VarSelector::Key(sel.to_owned()))
            }
        }
    };

    Ok(VarSpec {
        name,
        selector,
        negated,
        count,
    })
}

/// Parses a SecLang operator string (`[!][@name] [arg]`).
pub fn parse_operator(raw: &str) -> Result<OperatorSpec, SecLangError> {
    let mut s = raw;
    let negated = if let Some(rest) = s.strip_prefix('!') {
        s = rest;
        true
    } else {
        false
    };

    if let Some(rest) = s.strip_prefix('@') {
        // Split operator name and argument at first ASCII whitespace.
        let (op_name, arg) = match rest.find(|c: char| c.is_ascii_whitespace()) {
            Some(idx) => {
                let name = &rest[..idx];
                // Strip exactly one separating space (or leading horizontal spaces).
                let after = rest[idx..].trim_start_matches([' ', '\t']);
                (name, after.to_owned())
            }
            None => (rest, String::new()),
        };
        let kind = match op_name.to_ascii_lowercase().as_str() {
            "rx" => OperatorKind::Rx,
            "pm" => OperatorKind::Pm,
            "pmf" | "pmfromfile" => OperatorKind::PmFromFile,
            "contains" => OperatorKind::Contains,
            "streq" => OperatorKind::StrEq,
            "startswith" => OperatorKind::StartsWith,
            "endswith" => OperatorKind::EndsWith,
            "within" => OperatorKind::Within,
            "eq" => OperatorKind::Eq,
            "gt" => OperatorKind::Gt,
            "lt" => OperatorKind::Lt,
            "ge" => OperatorKind::Ge,
            "le" => OperatorKind::Le,
            "ipmatch" => OperatorKind::IpMatch,
            "ipmatchfromfile" => OperatorKind::IpMatchFromFile,
            "validatebyterange" => OperatorKind::ValidateByteRange,
            "validateutf8" | "validateutf8encoding" => OperatorKind::ValidateUtf8,
            "unconditionalmatch" => OperatorKind::UnconditionalMatch,
            "nomatch" => OperatorKind::NoMatch,
            "detectsqli" | "libinjectionsqli" => OperatorKind::DetectSqli,
            "detectxss" | "libinjectionxss" => OperatorKind::DetectXss,
            other => OperatorKind::Unsupported(other.to_owned()),
        };
        Ok(OperatorSpec { negated, kind, arg })
    } else {
        // Implicit `@rx`.
        Ok(OperatorSpec {
            negated,
            kind: OperatorKind::Rx,
            arg: s.to_owned(),
        })
    }
}

/// Parses a comma-separated SecLang action list in linear time.
pub fn parse_actions(raw: &str, span: &SourceSpan) -> Result<Vec<Action>, SecLangError> {
    let items = split_actions(raw);
    let mut actions = Vec::with_capacity(items.len());
    for item in items {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        actions.push(parse_single_action(trimmed, span)?);
    }
    Ok(actions)
}

/// Splits an action list on commas outside single-quoted segments.
fn split_actions(raw: &str) -> Vec<&str> {
    let bytes = raw.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_squote = false;
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        if in_squote {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'\'' {
                in_squote = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' => {
                in_squote = true;
                i += 1;
            }
            b',' => {
                parts.push(&raw[start..i]);
                start = i + 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    parts.push(&raw[start..]);
    parts
}

/// Strips optional surrounding single quotes and unescapes `\'`.
fn unquote_action_value(val: &str) -> String {
    let trimmed = val.trim();
    let inner = if trimmed.len() >= 2 && trimmed.starts_with('\'') && trimmed.ends_with('\'') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('\'') => {
                    chars.next();
                    out.push('\'');
                }
                Some('\\') => {
                    chars.next();
                    out.push('\\');
                }
                _ => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_single_action(item: &str, span: &SourceSpan) -> Result<Action, SecLangError> {
    let (key, val_opt) = match item.split_once(':') {
        Some((k, v)) => (k.trim(), Some(unquote_action_value(v))),
        None => (item.trim(), None),
    };
    let key_lower = key.to_ascii_lowercase();
    let need_val = |name: &str| -> Result<String, SecLangError> {
        val_opt
            .clone()
            .ok_or_else(|| err(span, format!("action {name:?} requires a value")))
    };

    match key_lower.as_str() {
        "id" => {
            let v = need_val("id")?;
            let id = v
                .parse::<u64>()
                .map_err(|_| err(span, format!("invalid rule id {v:?}")))?;
            Ok(Action::Id(id))
        }
        "phase" => {
            let v = need_val("phase")?;
            let phase = match v.to_ascii_lowercase().as_str() {
                "1" => 1,
                "2" | "request" => 2,
                "3" => 3,
                "4" | "response" => 4,
                "5" | "logging" => 5,
                _ => return Err(err(span, format!("invalid phase {v:?}"))),
            };
            Ok(Action::Phase(phase))
        }
        "msg" => Ok(Action::Msg(need_val("msg")?)),
        "logdata" => Ok(Action::LogData(need_val("logdata")?)),
        "severity" => {
            let v = need_val("severity")?;
            let sev =
                parse_severity(&v).ok_or_else(|| err(span, format!("invalid severity {v:?}")))?;
            Ok(Action::Severity(sev))
        }
        "tag" => Ok(Action::Tag(need_val("tag")?)),
        "ver" => Ok(Action::Ver(need_val("ver")?)),
        "t" => Ok(Action::Transform(need_val("t")?)),
        "capture" => Ok(Action::Capture),
        "log" => Ok(Action::Log),
        "nolog" => Ok(Action::NoLog),
        "auditlog" => Ok(Action::AuditLog),
        "noauditlog" => Ok(Action::NoAuditLog),
        "pass" => Ok(Action::Disruptive(DisruptiveAction::Pass)),
        "deny" => Ok(Action::Disruptive(DisruptiveAction::Deny)),
        "drop" => Ok(Action::Disruptive(DisruptiveAction::Drop)),
        "block" => Ok(Action::Disruptive(DisruptiveAction::Block)),
        "redirect" => Ok(Action::Disruptive(DisruptiveAction::Redirect(need_val(
            "redirect",
        )?))),
        "allow" => {
            let scope = match val_opt.as_deref().map(str::to_ascii_lowercase).as_deref() {
                None | Some("") => AllowScope::All,
                Some("phase") => AllowScope::Phase,
                Some("request") => AllowScope::Request,
                Some(other) => return Err(err(span, format!("invalid allow scope {other:?}"))),
            };
            Ok(Action::Disruptive(DisruptiveAction::Allow(scope)))
        }
        "status" => {
            let v = need_val("status")?;
            let code = v
                .parse::<u16>()
                .map_err(|_| err(span, format!("invalid HTTP status {v:?}")))?;
            Ok(Action::Status(code))
        }
        "chain" => Ok(Action::Chain),
        "skip" => {
            let v = need_val("skip")?;
            let n = v
                .parse::<usize>()
                .map_err(|_| err(span, format!("invalid skip count {v:?}")))?;
            Ok(Action::Skip(n))
        }
        "skipafter" => Ok(Action::SkipAfter(need_val("skipAfter")?)),
        "setvar" => parse_setvar(&need_val("setvar")?, span).map(Action::SetVar),
        "expirevar" => parse_expirevar(&need_val("expirevar")?, span).map(Action::ExpireVar),
        "ctl" => parse_ctl(&need_val("ctl")?, span).map(Action::Ctl),
        "setenv" => {
            let v = need_val("setenv")?;
            let (ek, ev) = match v.split_once('=') {
                Some((k, val)) => (k.trim().to_owned(), val.to_owned()),
                None => (v.trim().to_owned(), "1".to_owned()),
            };
            Ok(Action::SetEnv { key: ek, value: ev })
        }
        "initcol" => {
            let v = need_val("initcol")?;
            let (col, k) = v
                .split_once('=')
                .ok_or_else(|| err(span, format!("invalid initcol {v:?}")))?;
            Ok(Action::InitCol {
                collection: col.trim().to_ascii_uppercase(),
                key: k.trim().to_owned(),
            })
        }
        "multimatch" => Ok(Action::MultiMatch),
        // Benign metadata / sanitisation actions.
        "rev"
        | "maturity"
        | "accuracy"
        | "xmlns"
        | "sanitisearg"
        | "sanitisematched"
        | "sanitisematchedbytes"
        | "sanitiserequestheader"
        | "sanitiseresponseheader"
        | "exec"
        | "prepend"
        | "append"
        | "setuid"
        | "setsid"
        | "setrsc"
        | "pause"
        | "proxy" => Ok(Action::Meta {
            key: key_lower,
            value: val_opt,
        }),
        _ => Err(err(span, format!("unknown action {key:?}"))),
    }
}

fn parse_severity(s: &str) -> Option<u8> {
    match s.trim().to_ascii_uppercase().as_str() {
        "0" | "EMERGENCY" => Some(0),
        "1" | "ALERT" => Some(1),
        "2" | "CRITICAL" => Some(2),
        "3" | "ERROR" => Some(3),
        "4" | "WARNING" => Some(4),
        "5" | "NOTICE" => Some(5),
        "6" | "INFO" => Some(6),
        "7" | "DEBUG" => Some(7),
        _ => None,
    }
}

fn parse_setvar(raw: &str, span: &SourceSpan) -> Result<SetVarSpec, SecLangError> {
    let s = raw.trim();
    if let Some(rest) = s.strip_prefix('!') {
        let (col, key) = split_col_key(rest, span, "setvar")?;
        return Ok(SetVarSpec {
            collection: col,
            key,
            op: SetVarOp::Delete,
        });
    }
    let (lhs, rhs) = match s.split_once('=') {
        Some((l, r)) => (l.trim(), r),
        None => (s, "1"),
    };
    let (col, key) = split_col_key(lhs, span, "setvar")?;
    let op = if let Some(delta) = rhs.strip_prefix('+') {
        SetVarOp::Add(delta.to_owned())
    } else if let Some(delta) = rhs.strip_prefix('-') {
        SetVarOp::Sub(delta.to_owned())
    } else {
        SetVarOp::Set(rhs.to_owned())
    };
    Ok(SetVarSpec {
        collection: col,
        key,
        op,
    })
}

fn parse_expirevar(raw: &str, span: &SourceSpan) -> Result<ExpireVarSpec, SecLangError> {
    let (lhs, rhs) = raw
        .trim()
        .split_once('=')
        .ok_or_else(|| err(span, format!("invalid expirevar {raw:?}")))?;
    let (col, key) = split_col_key(lhs.trim(), span, "expirevar")?;
    Ok(ExpireVarSpec {
        collection: col,
        key,
        seconds: rhs.trim().to_owned(),
    })
}

fn split_col_key(s: &str, span: &SourceSpan, ctx: &str) -> Result<(String, String), SecLangError> {
    let (col, key) = s
        .split_once('.')
        .ok_or_else(|| err(span, format!("{ctx} requires collection.key, got {s:?}")))?;
    let col = col.trim().to_ascii_uppercase();
    let key = key.trim().to_ascii_lowercase();
    if col.is_empty() || key.is_empty() {
        return Err(err(span, format!("{ctx} empty collection or key in {s:?}")));
    }
    Ok((col, key))
}

fn parse_ctl(raw: &str, span: &SourceSpan) -> Result<CtlAction, SecLangError> {
    let (k, v) = raw
        .split_once('=')
        .ok_or_else(|| err(span, format!("ctl requires key=value, got {raw:?}")))?;
    let key_lower = k.trim().to_ascii_lowercase();
    let val = v.trim();
    match key_lower.as_str() {
        "ruleremovebyid" => Ok(CtlAction::RuleRemoveById(parse_id_range(val, span)?)),
        "ruleremovetargetbyid" => {
            let (id_str, var_str) = val.split_once(';').ok_or_else(|| {
                err(
                    span,
                    format!("ctl:ruleRemoveTargetById expects id;var, got {val:?}"),
                )
            })?;
            let id = id_str
                .trim()
                .parse::<u64>()
                .map_err(|_| err(span, format!("invalid rule ID {id_str:?}")))?;
            let variable = parse_single_variable(var_str.trim(), span)?;
            Ok(CtlAction::RuleRemoveTargetById { id, variable })
        }
        "ruleremovetargetbytag" => {
            let (tag, var_str) = val.split_once(';').ok_or_else(|| {
                err(
                    span,
                    format!("ctl:ruleRemoveTargetByTag expects tag;var, got {val:?}"),
                )
            })?;
            let variable = parse_single_variable(var_str.trim(), span)?;
            Ok(CtlAction::RuleRemoveTargetByTag {
                tag: tag.trim().to_owned(),
                variable,
            })
        }
        "ruleengine" => {
            let mode = parse_rule_engine_mode(val)
                .ok_or_else(|| err(span, format!("invalid ctl:ruleEngine mode {val:?}")))?;
            Ok(CtlAction::RuleEngine(mode))
        }
        "requestbodyprocessor" => Ok(CtlAction::RequestBodyProcessor(val.to_ascii_uppercase())),
        "requestbodyaccess" => match val.to_ascii_lowercase().as_str() {
            "on" => Ok(CtlAction::RequestBodyAccess(true)),
            "off" => Ok(CtlAction::RequestBodyAccess(false)),
            _ => Err(err(
                span,
                format!("invalid ctl:requestBodyAccess value {val:?}"),
            )),
        },
        _ => Ok(CtlAction::Other {
            key: key_lower,
            value: val.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_variables_operators_and_actions() {
        let conf = r#"
SecRule ARGS|!ARGS:password|&REQUEST_HEADERS:Host|REQUEST_HEADERS:/^X-/ \
    "!@rx ^(foo|bar)$" \
    "id:942100,phase:2,block,capture,t:none,t:urlDecodeUni,t:lowercase,msg:'SQLi, test',logdata:'%{MATCHED_VAR}',severity:'CRITICAL',tag:'attack-sqli',ver:'OWASP_CRS/4.25.0',setvar:'tx.inbound_anomaly_score_pl1=+5',ctl:ruleRemoveById=942101"
"#;
        let dirs = parse("crs.conf", conf).expect("parses");
        assert_eq!(dirs.len(), 1);
        let Directive::SecRule(rule) = &dirs[0] else {
            panic!("expected SecRule");
        };
        assert_eq!(rule.variables.len(), 4);
        assert_eq!(rule.variables[0].name, "ARGS");
        assert!(rule.variables[1].negated);
        assert_eq!(
            rule.variables[1].selector,
            Some(VarSelector::Key("password".to_owned()))
        );
        assert!(rule.variables[2].count);
        assert_eq!(
            rule.variables[3].selector,
            Some(VarSelector::Regex("^X-".to_owned()))
        );
        assert!(rule.operator.negated);
        assert_eq!(rule.operator.kind, OperatorKind::Rx);
        assert_eq!(rule.operator.arg, "^(foo|bar)$");
        assert!(rule.actions.contains(&Action::Id(942100)));
        assert!(rule.actions.contains(&Action::Phase(2)));
        assert!(rule.actions.contains(&Action::Capture));
        assert!(rule.actions.contains(&Action::Severity(2)));
        assert!(rule.actions.contains(&Action::Msg("SQLi, test".to_owned())));
    }

    #[test]
    fn parses_unsupported_operators_cleanly() {
        let conf = r#"SecRule REQUEST_BODY "@validateSchema schema.json" "id:1,phase:2,deny""#;
        let dirs = parse("test.conf", conf).expect("parses without error");
        let Directive::SecRule(rule) = &dirs[0] else {
            panic!("expected SecRule");
        };
        assert_eq!(
            rule.operator.kind,
            OperatorKind::Unsupported("validateschema".to_owned())
        );
    }

    #[test]
    fn resolves_includes_with_glob_and_detects_cycles() {
        let mut files = HashMap::new();
        files.insert("rules/01.conf".to_owned(), r#"SecMarker START"#.to_owned());
        files.insert(
            "rules/02.conf".to_owned(),
            r#"SecAction "id:10,phase:1,pass,nolog""#.to_owned(),
        );
        let dirs = parse_with_includes("main.conf", "Include rules/*.conf\nSecMarker END", &files)
            .expect("includes expand");
        assert_eq!(dirs.len(), 3);

        // Cycle detection.
        let mut cyclic = HashMap::new();
        cyclic.insert("a.conf".to_owned(), "Include b.conf".to_owned());
        cyclic.insert("b.conf".to_owned(), "Include a.conf".to_owned());
        let errs =
            parse_with_includes("a.conf", "Include b.conf", &cyclic).expect_err("cycle rejected");
        assert!(errs.iter().any(|e| e.message.contains("cyclic")));
    }
}
