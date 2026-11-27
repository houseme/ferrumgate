//! Per-user routing (WP-23 step 9): sites with authentication enabled may
//! route listed users to their own backends (or other site actions).
//! Unlisted visitors fall through to the site's default handler.
#![allow(dead_code)]

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use crate::web::identity::Visitor;
use crate::web::site::SiteAction;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    AuthRequired,
    EmptyUsers,
    DuplicateUser(String),
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthRequired => write!(f, "按用户分流要求站点先启用认证"),
            Self::EmptyUsers => write!(f, "分流规则至少要有一个用户"),
            Self::DuplicateUser(name) => write!(f, "同一用户不能出现在两条分流规则：{name}"),
        }
    }
}

impl std::error::Error for RouteError {}

/// A user key on a route. Site usernames compare exactly; third-party
/// identities (`provider:id`) compare case-insensitively.
#[derive(Clone, Debug)]
pub enum RouteUserKey {
    Name(String),
    ThirdParty { provider: String, id: String },
}

impl RouteUserKey {
    /// Parses `name` or `provider:id`.
    pub fn parse(text: &str) -> Self {
        if let Some((provider, id)) = text.trim().split_once(':')
            && !provider.is_empty()
            && !id.is_empty()
        {
            Self::ThirdParty {
                provider: provider.trim().to_string(),
                id: id.trim().to_string(),
            }
        } else {
            Self::Name(text.trim().to_string())
        }
    }

    /// Case-insensitive match for third-party keys, exact for names.
    pub fn matches(&self, other: &RouteUserKey) -> bool {
        match (self, other) {
            (Self::Name(a), Self::Name(b)) => a == b,
            (
                Self::ThirdParty {
                    provider: pa,
                    id: ia,
                },
                Self::ThirdParty {
                    provider: pb,
                    id: ib,
                },
            ) => pa.eq_ignore_ascii_case(pb) && ia.eq_ignore_ascii_case(ib),
            _ => false,
        }
    }

    /// Stable display form (also the duplicate-detection key).
    pub fn key(&self) -> String {
        match self {
            Self::Name(name) => format!("name:{name}"),
            Self::ThirdParty { provider, id } => {
                format!(
                    "{}:{}",
                    provider.to_ascii_lowercase(),
                    id.to_ascii_lowercase()
                )
            }
        }
    }
}

impl PartialEq for RouteUserKey {
    fn eq(&self, other: &Self) -> bool {
        self.matches(other)
    }
}

/// One per-user rule.
#[derive(Clone, Debug)]
pub struct UserRoute {
    pub users: Vec<RouteUserKey>,
    pub action: SiteAction,
}

/// Restores a key's configured text for error messages (`Name` keeps the
/// original spelling; third-party keys read `provider:id`).
fn display(user: &RouteUserKey) -> String {
    match user {
        RouteUserKey::Name(name) => name.clone(),
        RouteUserKey::ThirdParty { provider, id } => format!("{provider}:{id}"),
    }
}

/// Validates the site's rules: authentication on, every rule names at
/// least one user, no user appears in two rules.
pub fn validate(routes: &[UserRoute], auth_enabled: bool) -> Result<(), RouteError> {
    if !auth_enabled && !routes.is_empty() {
        return Err(RouteError::AuthRequired);
    }
    // Normalized dedup key -> the first occurrence's configured text.
    let mut seen: HashMap<String, String> = HashMap::new();
    for route in routes {
        if route.users.is_empty() {
            return Err(RouteError::EmptyUsers);
        }
        for entry_user in &route.users {
            match seen.entry(entry_user.key()) {
                Entry::Vacant(slot) => {
                    slot.insert(display(entry_user));
                }
                Entry::Occupied(slot) => {
                    return Err(RouteError::DuplicateUser(slot.get().clone()));
                }
            }
        }
    }
    Ok(())
}

/// The rule matching the visitor's identity keys, if any; `None` falls
/// through to the site's default handler. Rules are tried in order and
/// the first match wins.
pub fn select<'a>(routes: &'a [UserRoute], visitor: &Visitor) -> Option<&'a UserRoute> {
    routes.iter().find(|route| {
        route
            .users
            .iter()
            .any(|user| visitor.names.iter().any(|name| user.matches(name)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(users: &[RouteUserKey]) -> UserRoute {
        UserRoute {
            users: users.to_vec(),
            action: SiteAction::Proxy,
        }
    }

    fn visitor(names: &[RouteUserKey]) -> Visitor {
        Visitor {
            names: names.to_vec(),
            ..Visitor::default()
        }
    }

    #[test]
    fn user_route_selects_by_identity() {
        let routes = [
            route(&[RouteUserKey::Name("alice".into())]),
            route(&[RouteUserKey::Name("bob".into())]),
        ];
        let hit = select(&routes, &visitor(&[RouteUserKey::Name("bob".into())])).unwrap();
        assert_eq!(hit.users, [RouteUserKey::Name("bob".into())]);
        // Alice's rule does not match Bob.
        assert!(select(&routes[..1], &visitor(&[RouteUserKey::Name("bob".into())])).is_none());
    }

    #[test]
    fn third_party_case_insensitive() {
        let routes = [route(&[RouteUserKey::parse("oidc:Portal-1")])];
        // Provider and id compare case-insensitively on both sides.
        for name in ["OIDC:portal-1", "oidc:PORTAL-1", "Oidc:Portal-1"] {
            assert!(
                select(&routes, &visitor(&[RouteUserKey::parse(name)])).is_some(),
                "{name} should match"
            );
        }
    }

    #[test]
    fn user_route_falls_back_for_unlisted_users() {
        let routes = [route(&[RouteUserKey::Name("alice".into())])];
        assert!(select(&routes, &visitor(&[RouteUserKey::Name("carol".into())])).is_none());
        // An unauthenticated visitor has no identity keys at all.
        assert!(select(&routes, &visitor(&[])).is_none());
    }

    #[test]
    fn name_matching_is_exact() {
        let routes = [route(&[RouteUserKey::Name("Alice".into())])];
        assert!(select(&routes, &visitor(&[RouteUserKey::Name("alice".into())])).is_none());
        assert!(select(&routes, &visitor(&[RouteUserKey::Name("Alice".into())])).is_some());
    }

    #[test]
    fn user_route_same_user_in_two_rules_rejected() {
        let routes = [
            route(&[RouteUserKey::Name("alice".into())]),
            route(&[
                RouteUserKey::Name("bob".into()),
                RouteUserKey::Name("alice".into()),
            ]),
        ];
        let Err(RouteError::DuplicateUser(name)) = validate(&routes, true) else {
            panic!("expected DuplicateUser for alice");
        };
        // The display text comes from the rule that listed the user first.
        assert_eq!(name, "alice");

        // Third-party keys normalize case before the duplicate check.
        let variants = [
            route(&[RouteUserKey::parse("oidc:X")]),
            route(&[RouteUserKey::parse("OIDC:x")]),
        ];
        assert_eq!(
            validate(&variants, true),
            Err(RouteError::DuplicateUser("oidc:X".into()))
        );
    }

    #[test]
    fn validate_requires_auth() {
        let routes = [route(&[RouteUserKey::Name("alice".into())])];
        assert_eq!(validate(&routes, false), Err(RouteError::AuthRequired));
        assert_eq!(validate(&routes, true), Ok(()));
        // No rules: fine whether or not authentication is enabled.
        assert_eq!(validate(&[], true), Ok(()));
        assert_eq!(validate(&[], false), Ok(()));
    }

    #[test]
    fn empty_users_rejected() {
        let routes = [route(&[])];
        assert_eq!(validate(&routes, true), Err(RouteError::EmptyUsers));
    }
}
