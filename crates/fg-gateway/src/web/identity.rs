//! Identity headers (WP-23 step 8): write the authenticated visitor's
//! user/email/display name/groups into configured request headers. At
//! most 16 entries; a forbidden list keeps proxy-semantic headers out of
//! reach; visitor-supplied values (including `_` spellings) are stripped
//! on every request whether or not the path authenticates.
#![allow(dead_code)]

use std::collections::HashSet;

use hyper::header::{HeaderMap, HeaderName, HeaderValue};

/// Upstream `maxIdentityHeaders`.
pub const MAX_IDENTITY_HEADERS: usize = 16;

/// Which piece of the authenticated identity a header carries. Email,
/// display name and groups only exist for shared users or forward-auth
/// copies; site users and third-party logins only carry a username.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityField {
    User,
    Email,
    Name,
    Groups,
}

impl IdentityField {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "user" => Some(Self::User),
            "email" => Some(Self::Email),
            "name" => Some(Self::Name),
            "groups" => Some(Self::Groups),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Email => "email",
            Self::Name => "name",
            Self::Groups => "groups",
        }
    }
}

/// A configured identity header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityHeader {
    pub header: HeaderName,
    pub field: IdentityField,
}

/// The authenticated visitor as resolved by WP-24/25 (this module only
/// consumes the resolved identity — it never authenticates).
#[derive(Clone, Debug, Default)]
pub struct Visitor {
    /// Every key the visitor matches: their username plus third-party
    /// identities (drives `userRoutes`, see `crate::web::userroute`).
    pub names: Vec<crate::web::userroute::RouteUserKey>,
    pub user: String,
    pub email: String,
    pub display_name: String,
    pub groups: Vec<String>,
}

/// Headers that must never carry identity values, compared in canonical
/// form (`-` and `_` are equivalent).
pub const FORBIDDEN: &[&str] = &[
    "host",
    "cookie",
    "authorization",
    "proxy-authorization",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "keep-alive",
    "proxy-connection",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
    "x-real-port",
    "x-forwarded-for-port",
];

/// Canonical comparison form: lowercase, underscores read as hyphens.
pub fn canonical(text: &str) -> String {
    text.trim().to_ascii_lowercase().replace('_', "-")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    TooMany,
    Forbidden(String),
    Duplicate(String),
    BadField(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooMany => write!(f, "身份请求头最多 {MAX_IDENTITY_HEADERS} 条"),
            Self::Forbidden(name) => write!(f, "{name} 不允许用作身份请求头"),
            Self::Duplicate(name) => write!(f, "身份请求头重复：{name}"),
            Self::BadField(field) => write!(f, "身份字段必须是 user/email/name/groups：{field}"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// Validates a configured list: count cap, forbidden names, duplicates
/// (canonical form).
pub fn validate(headers: &[IdentityHeader]) -> Result<(), IdentityError> {
    if headers.len() > MAX_IDENTITY_HEADERS {
        return Err(IdentityError::TooMany);
    }
    let mut seen = HashSet::with_capacity(headers.len());
    for entry in headers {
        let name = entry.header.as_str();
        let canon = canonical(name);
        if FORBIDDEN.contains(&canon.as_str()) {
            return Err(IdentityError::Forbidden(name.to_string()));
        }
        if !seen.insert(canon) {
            return Err(IdentityError::Duplicate(name.to_string()));
        }
    }
    Ok(())
}

/// Parses `Header: field` lines into configured identity headers. Header
/// names go through `HeaderName::from_bytes`, which normalizes to lower
/// case on its own; a missing colon, an invalid name or an unknown field
/// all fail the whole list (config errors are fatal, never partial).
pub fn parse(lines: &[String]) -> Result<Vec<IdentityHeader>, IdentityError> {
    let mut parsed = Vec::with_capacity(lines.len());
    for line in lines {
        let Some((name, field)) = line.split_once(':') else {
            return Err(IdentityError::BadField(line.clone()));
        };
        let name = name.trim();
        let header = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| IdentityError::BadField(name.to_string()))?;
        let field = IdentityField::parse(field)
            .ok_or_else(|| IdentityError::BadField(field.trim().to_string()))?;
        parsed.push(IdentityHeader { header, field });
    }
    validate(&parsed)?;
    Ok(parsed)
}

/// Compiles the site model's `header` + `field` pairs (the webservice
/// JSON shape) into the validated runtime list.
pub fn compile(
    site_headers: &[crate::web::model::IdentitySite],
) -> Result<Vec<IdentityHeader>, IdentityError> {
    let lines: Vec<String> = site_headers
        .iter()
        .map(|entry| format!("{}: {}", entry.header.trim(), entry.field.trim()))
        .collect();
    parse(&lines)
}

fn remove_all(headers: &mut HeaderMap, name: &str) {
    // `remove` only drops one entry; visitor-supplied requests may repeat
    // a header, so strip every copy.
    while headers.remove(name).is_some() {}
}

/// Removes visitor-supplied copies of every configured identity header —
/// canonical and underscore spellings — on every request, authenticated
/// or not (a public path must not let a caller forge `X-User`).
pub fn strip(headers: &mut HeaderMap, configured: &[IdentityHeader]) {
    for entry in configured {
        remove_all(headers, entry.header.as_str());
        // Many clients treat `X_User` and `X-User` as the same header
        // (and proxies differ on it), so the underscore spelling goes too.
        let underscored = entry.header.as_str().replace('-', "_");
        if let Ok(name) = HeaderName::from_bytes(underscored.as_bytes()) {
            remove_all(headers, name.as_str());
        }
    }
}

/// Writes the identity values into the request headers. No visitor (not
/// logged in, or accessed via a share link) writes nothing; an empty or
/// control-character value writes nothing; groups join with commas.
/// `insert` overwrites, so together with `strip` the value can only have
/// come from us.
pub fn apply(headers: &mut HeaderMap, configured: &[IdentityHeader], visitor: Option<&Visitor>) {
    let Some(visitor) = visitor else {
        return;
    };
    for entry in configured {
        let joined;
        let value: &str = match entry.field {
            IdentityField::User => &visitor.user,
            IdentityField::Email => &visitor.email,
            IdentityField::Name => &visitor.display_name,
            IdentityField::Groups => {
                joined = visitor.groups.join(",");
                &joined
            }
        };
        if value.is_empty() {
            continue;
        }
        // from_str rejects control characters (header smuggling via `\n`)
        // and non-visible ASCII; such an identity simply is not sent.
        let Ok(value) = HeaderValue::from_str(value) else {
            continue;
        };
        headers.insert(entry.header.clone(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ih(name: &str, field: IdentityField) -> IdentityHeader {
        IdentityHeader {
            header: HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
            field,
        }
    }

    fn visitor() -> Visitor {
        Visitor {
            names: vec![crate::web::userroute::RouteUserKey::parse("alice")],
            user: "alice".into(),
            email: "alice@example.com".into(),
            display_name: "Alice".into(),
            groups: vec!["dev".into(), "ops".into()],
        }
    }

    #[test]
    fn identity_headers_validation() {
        // Cap: 17 entries are one too many.
        let many: Vec<IdentityHeader> = (0..=16)
            .map(|i| ih(&format!("X-Id-{i}"), IdentityField::User))
            .collect();
        assert_eq!(validate(&many), Err(IdentityError::TooMany));

        // Proxy-semantic headers are banned, `_` spellings included.
        for name in ["X-Forwarded-For", "X-Forwarded_For", "Host"] {
            let stored = name.to_ascii_lowercase();
            assert_eq!(
                validate(&[ih(name, IdentityField::User)]),
                Err(IdentityError::Forbidden(stored)),
                "forbidden: {name}"
            );
        }

        // `X-User` and `x_user` are the same header in canonical form.
        let dup = [
            ih("X-User", IdentityField::User),
            ih("x_user", IdentityField::Email),
        ];
        assert_eq!(
            validate(&dup),
            Err(IdentityError::Duplicate("x_user".to_string()))
        );

        // Unknown field names fail at parse time.
        assert_eq!(
            parse(&["X-Foo: nickname".to_string()]),
            Err(IdentityError::BadField("nickname".to_string()))
        );
    }

    #[test]
    fn parse_forms() {
        let parsed = parse(&[
            "X-User: user".into(),
            "X-User-Email: email".into(),
            "X-User-Name: name".into(),
            "X-User-Groups: groups".into(),
        ])
        .expect("all four forms parse");
        let expected = [
            ("x-user", IdentityField::User),
            ("x-user-email", IdentityField::Email),
            ("x-user-name", IdentityField::Name),
            ("x-user-groups", IdentityField::Groups),
        ];
        assert_eq!(parsed.len(), expected.len());
        for (entry, (name, field)) in parsed.iter().zip(expected) {
            assert_eq!(entry.header.as_str(), name);
            assert_eq!(entry.field, field);
        }

        // No colon: the line is not a header at all.
        assert!(parse(&["X-User user".to_string()]).is_err());
        // Unknown field.
        assert_eq!(
            parse(&["X-User: owner".to_string()]),
            Err(IdentityError::BadField("owner".to_string()))
        );
    }

    #[test]
    fn strip_visitor_supplied_including_underscore_variants() {
        let configured = [ih("X-User", IdentityField::User)];
        let mut headers = HeaderMap::new();
        headers.insert("x-user", "forged".parse().unwrap());
        headers.append("x-user", "forged-again".parse().unwrap());
        headers.insert("x_user", "forged2".parse().unwrap());
        headers.append("x_user", "forged2b".parse().unwrap());
        headers.insert("x-other", "kept".parse().unwrap());

        strip(&mut headers, &configured);

        assert!(!headers.contains_key("x-user"));
        assert!(!headers.contains_key("x_user"));
        // Unconfigured headers are untouched.
        assert_eq!(headers.get("x-other").unwrap(), "kept");
    }

    #[test]
    fn strip_runs_on_public_paths() {
        // strip itself is auth-agnostic — callers run it on every request,
        // public ones included — so an unauthenticated (forging) request
        // leaves no identity header behind either.
        let configured = [
            ih("X-User", IdentityField::User),
            ih("X-User-Groups", IdentityField::Groups),
        ];
        let mut headers = HeaderMap::new();
        headers.insert("x-user", "anonymous-forged".parse().unwrap());
        headers.insert("x-user-groups", "admins".parse().unwrap());
        headers.insert("x_user_groups", "admins2".parse().unwrap());

        strip(&mut headers, &configured);

        assert!(headers.is_empty());
    }

    #[test]
    fn identity_headers_empty_without_identity() {
        let configured = [
            ih("X-User", IdentityField::User),
            ih("X-User-Email", IdentityField::Email),
            ih("X-User-Name", IdentityField::Name),
            ih("X-User-Groups", IdentityField::Groups),
        ];
        let mut headers = HeaderMap::new();
        apply(&mut headers, &configured, None);
        assert!(headers.is_empty());
    }

    #[test]
    fn apply_writes_each_field() {
        let configured = [
            ih("X-User", IdentityField::User),
            ih("X-User-Email", IdentityField::Email),
            ih("X-User-Name", IdentityField::Name),
            ih("X-User-Groups", IdentityField::Groups),
        ];
        let who = visitor();
        let mut headers = HeaderMap::new();
        apply(&mut headers, &configured, Some(&who));
        assert_eq!(headers.get("x-user").unwrap(), "alice");
        assert_eq!(headers.get("x-user-email").unwrap(), "alice@example.com");
        assert_eq!(headers.get("x-user-name").unwrap(), "Alice");
        assert_eq!(headers.get("x-user-groups").unwrap(), "dev,ops");

        // Empty values write nothing.
        let mut headers = HeaderMap::new();
        apply(&mut headers, &configured, Some(&Visitor::default()));
        assert!(headers.is_empty());

        // `\n` (header smuggling) drops the one value, keeps the rest.
        let mut smuggler = visitor();
        smuggler.display_name = "Alice\nX-Admin: yes".into();
        let mut headers = HeaderMap::new();
        apply(&mut headers, &configured, Some(&smuggler));
        assert!(!headers.contains_key("x-user-name"));
        assert_eq!(headers.get("x-user").unwrap(), "alice");
    }
}
