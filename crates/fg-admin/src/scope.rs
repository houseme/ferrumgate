use std::{borrow::Cow, fmt};

use axum::http::Method;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Read,
    Write,
}

impl Level {
    fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope<'a> {
    pub domain: Cow<'a, str>,
    pub level: Level,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Access<'a> {
    Any,
    SessionOnly,
    Public,
    Scope(Scope<'a>),
    All(&'static [Scope<'static>]),
}

impl Access<'_> {
    pub(crate) fn into_owned(self) -> Access<'static> {
        match self {
            Self::Any => Access::Any,
            Self::SessionOnly => Access::SessionOnly,
            Self::Public => Access::Public,
            Self::All(scopes) => Access::All(scopes),
            Self::Scope(scope) => Access::Scope(Scope {
                domain: Cow::Owned(scope.domain.into_owned()),
                level: scope.level,
            }),
        }
    }

    pub fn allows_token(&self, grants: &[String]) -> bool {
        let allows = |scope: &Scope<'_>| {
            grants.iter().any(|grant| {
                grant == "*"
                    || grant.split_once(':').is_some_and(|(domain, level)| {
                        (domain == "*" || domain == scope.domain)
                            && (level == "write" || level == scope.level.name())
                    })
            })
        };
        match self {
            Self::Any => true,
            Self::SessionOnly | Self::Public => false,
            Self::Scope(scope) => allows(scope),
            Self::All(scopes) => scopes.iter().all(allows),
        }
    }

    pub fn read_only(&self) -> bool {
        match self {
            Self::Any => true,
            Self::SessionOnly | Self::Public => false,
            Self::Scope(scope) => scope.level == Level::Read,
            Self::All(scopes) => scopes.iter().all(|scope| scope.level == Level::Read),
        }
    }
}

impl fmt::Display for Access<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => Ok(()),
            Self::SessionOnly => f.write_str("!denied"),
            Self::Public => f.write_str("!public"),
            Self::Scope(scope) => write!(f, "{}:{}", scope.domain, scope.level.name()),
            Self::All(scopes) => {
                for (index, scope) in scopes.iter().enumerate() {
                    if index != 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{}:{}", scope.domain, scope.level.name())?;
                }
                Ok(())
            }
        }
    }
}

const FORBIDDEN: &[&str] = &[
    "/api/account",
    "/api/audit",
    "/api/history",
    "/api/tokens",
    "/api/system/settings",
    "/api/system/token",
    "/api/system/backup",
    "/api/system/diagnostics",
    "/api/system/restore",
    "/api/system/restart",
    "/api/system/confirm",
    "/api/system/changeset",
    "/api/system/access-path",
    "/api/system/upgrade",
    "/api/system/selfcheck",
    "/api/system/onboarding",
    "/api/system/probe",
    "/api/webterminal/security",
    "/api/backup/local",
    "/api/login",
    "/api/logout",
];
const FILE_USERS: &[Scope<'_>] = &[
    Scope {
        domain: Cow::Borrowed("webdav"),
        level: Level::Write,
    },
    Scope {
        domain: Cow::Borrowed("ftp"),
        level: Level::Write,
    },
    Scope {
        domain: Cow::Borrowed("smb"),
        level: Level::Write,
    },
];
const WOL_READ: &[Scope<'_>] = &[
    Scope {
        domain: Cow::Borrowed("wol"),
        level: Level::Read,
    },
    Scope {
        domain: Cow::Borrowed("webterminal"),
        level: Level::Read,
    },
];
const WOL_WRITE: &[Scope<'_>] = &[
    Scope {
        domain: Cow::Borrowed("wol"),
        level: Level::Write,
    },
    Scope {
        domain: Cow::Borrowed("webterminal"),
        level: Level::Write,
    },
];

pub fn module_of(path: &str) -> Option<&str> {
    let module = path.strip_prefix("/api/")?.split('/').next()?;
    (!module.is_empty()).then_some(module)
}

pub fn required<'a>(method: &Method, path: &'a str) -> Access<'a> {
    let Some(module) = module_of(path) else {
        return Access::SessionOnly;
    };
    if FORBIDDEN.iter().any(|prefix| {
        path == *prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    }) || matches!(
        (method, path),
        (
            &Method::PUT,
            "/api/easytier/settings" | "/api/tailscale/settings" | "/api/netbird/settings"
        ) | (&Method::GET, "/api/backup/secrets")
            | (&Method::POST, "/api/system/public-ip")
    ) {
        return Access::SessionOnly;
    }
    let scope = |domain, level| {
        Access::Scope(Scope {
            domain: Cow::Borrowed(domain),
            level,
        })
    };
    match path {
        "/api/session" | "/api/openapi.json" | "/api/geoip/lookup" => return Access::Any,
        "/api/status"
        | "/api/system/info"
        | "/api/system/update"
        | "/api/system/update/state"
        | "/api/system/public-ip" => return scope("status", Level::Read),
        "/api/logs" | "/api/logs/sources" | "/api/logs/export" => {
            return scope("logs", Level::Read);
        }
        "/api/import/lucky" => return scope("import", Level::Write),
        _ => {}
    }
    let tail = path[5 + module.len()..]
        .strip_prefix('/')
        .unwrap_or_default();
    if tail.starts_with("public/") {
        return Access::Public;
    }
    let read = matches!(*method, Method::GET | Method::HEAD);
    if !read && tail == "shared-users" && matches!(module, "webdav" | "ftp" | "smb") {
        return Access::All(FILE_USERS);
    }
    if module == "wol" {
        if *method == Method::GET && tail == "ssh-targets" {
            return Access::All(WOL_READ);
        }
        if (*method == Method::POST && tail == "devices")
            || tail.strip_prefix("devices/").is_some_and(|path| {
                matches!(
                    (method, path.split_once('/')),
                    (&Method::PUT, None) | (&Method::POST, Some((_, "copy" | "shutdown")))
                )
            })
        {
            return Access::All(WOL_WRITE);
        }
    }
    let sensitive = !matches!(tail, "logs/export" | "logs/sources")
        && tail.split('/').any(|segment| {
            matches!(
                segment,
                "ws" | "exec"
                    | "download"
                    | "export"
                    | "read"
                    | "config"
                    | "preview-archive"
                    | "secrets"
                    | "files"
                    | "sftp"
            )
        });
    scope(
        module,
        if read && !sensitive {
            Level::Read
        } else {
            Level::Write
        },
    )
}
