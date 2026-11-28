//! Pure validation, password merge/hashing, and masking for WebDAV settings.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    path::Path,
};

use fg_files::{IpNet, hash_password, is_bcrypt_hash, is_exposable, mask_password};
use serde::Serialize;

use crate::model::{LocalUser, Settings, limits};

/// Validation problem identifying the offending field and reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    pub field: String,
    pub reason: String,
}

/// Returns a copy of `settings` with all non-empty local user passwords masked
/// as `********`.
pub fn mask_settings(settings: &Settings) -> Settings {
    let mut masked = settings.clone();
    for user in &mut masked.users {
        user.password = mask_password(&user.password);
    }
    masked
}

/// Resolves masked/empty passwords in `submitted` against `existing` and hashes
/// new plaintext passwords with bcrypt.
pub fn merge_and_hash_passwords(
    submitted: &mut Settings,
    existing: &Settings,
    bcrypt_cost: u32,
) -> Result<(), Vec<Problem>> {
    let existing_by_name: HashMap<String, &LocalUser> = existing
        .users
        .iter()
        .map(|u| (u.name.to_lowercase(), u))
        .collect();
    let mut problems = Vec::new();

    for (idx, user) in submitted.users.iter_mut().enumerate() {
        let field = format!("users[{idx}].password");
        if user.password.is_empty() || user.password == limits::SECRET_MASK {
            let lower = user.name.to_lowercase();
            if let Some(prev) = existing_by_name.get(&lower)
                && !prev.password.is_empty()
                && prev.password != limits::SECRET_MASK
            {
                user.password = prev.password.clone();
            } else {
                problems.push(Problem {
                    field,
                    reason: "password is required for new user".to_string(),
                });
            }
        } else if user.password.starts_with("$2a$")
            || user.password.starts_with("$2b$")
            || user.password.starts_with("$2y$")
        {
            if !is_bcrypt_hash(&user.password) {
                problems.push(Problem {
                    field,
                    reason: "invalid bcrypt password hash".to_string(),
                });
            }
        } else {
            match hash_password(&user.password, bcrypt_cost) {
                Ok(hashed) => user.password = hashed,
                Err(err) => problems.push(Problem {
                    field,
                    reason: format!("failed to hash password: {err}"),
                }),
            }
        }
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// Validates `settings` given the current count of usable shared users.
///
/// When `check_dirs` is true, also enforces `fg_files::is_exposable` (refusing
/// protected configuration directories).
pub fn validate_settings(
    settings: &Settings,
    usable_shared_users: usize,
    check_dirs: bool,
) -> Vec<Problem> {
    let mut problems = Vec::new();

    if settings.port == 0 {
        problems.push(Problem {
            field: "port".to_string(),
            reason: "port must be between 1 and 65535".to_string(),
        });
    }

    if settings.enable {
        let has_local = !settings.users.is_empty();
        let has_shared = settings.shared_users && usable_shared_users > 0;
        if !has_local && !has_shared {
            problems.push(Problem {
                field: "users".to_string(),
                reason: "at least one local or shared user is required when WebDAV is enabled"
                    .to_string(),
            });
        }
    }

    let mut seen_names = HashSet::new();
    for (idx, user) in settings.users.iter().enumerate() {
        let prefix = format!("users[{idx}]");
        let trimmed = user.name.trim();
        if trimmed.is_empty() {
            problems.push(Problem {
                field: format!("{prefix}.name"),
                reason: "username cannot be empty".to_string(),
            });
        } else {
            if trimmed != user.name {
                problems.push(Problem {
                    field: format!("{prefix}.name"),
                    reason: "username cannot have leading or trailing whitespace".to_string(),
                });
            }
            if user.name.contains(':') {
                problems.push(Problem {
                    field: format!("{prefix}.name"),
                    reason: "username cannot contain ':'".to_string(),
                });
            }
            if user.name.chars().any(char::is_control) {
                problems.push(Problem {
                    field: format!("{prefix}.name"),
                    reason: "username cannot contain control characters".to_string(),
                });
            }
            if !seen_names.insert(user.name.to_lowercase()) {
                problems.push(Problem {
                    field: format!("{prefix}.name"),
                    reason: format!("duplicate username {:?}", user.name),
                });
            }
        }

        if user.password.is_empty() {
            problems.push(Problem {
                field: format!("{prefix}.password"),
                reason: "password cannot be empty".to_string(),
            });
        } else if (user.password.starts_with("$2a$")
            || user.password.starts_with("$2b$")
            || user.password.starts_with("$2y$"))
            && !is_bcrypt_hash(&user.password)
        {
            problems.push(Problem {
                field: format!("{prefix}.password"),
                reason: "invalid bcrypt password hash".to_string(),
            });
        }

        if user.mounts.is_empty() {
            if user.root.is_empty() {
                problems.push(Problem {
                    field: format!("{prefix}.root"),
                    reason: "root directory or mounts must be specified".to_string(),
                });
            } else {
                let path = Path::new(&user.root);
                if !path.is_absolute() {
                    problems.push(Problem {
                        field: format!("{prefix}.root"),
                        reason: "root directory must be an absolute path".to_string(),
                    });
                } else if check_dirs && let Err(err) = is_exposable(path) {
                    problems.push(Problem {
                        field: format!("{prefix}.root"),
                        reason: err.to_string(),
                    });
                }
            }
        } else {
            let mut seen_mounts = HashSet::new();
            for (m_idx, mount) in user.mounts.iter().enumerate() {
                let m_prefix = format!("{prefix}.mounts[{m_idx}]");
                if mount.name.is_empty()
                    || mount.name == "."
                    || mount.name == ".."
                    || mount.name.contains('/')
                    || mount.name.contains('\\')
                    || mount.name.chars().any(char::is_control)
                {
                    problems.push(Problem {
                        field: format!("{m_prefix}.name"),
                        reason: "mount name must be non-empty and cannot contain '/'".to_string(),
                    });
                } else if !seen_mounts.insert(mount.name.to_lowercase()) {
                    problems.push(Problem {
                        field: format!("{m_prefix}.name"),
                        reason: format!("duplicate mount name {:?}", mount.name),
                    });
                }
                if !mount.path.is_absolute() {
                    problems.push(Problem {
                        field: format!("{m_prefix}.path"),
                        reason: "mount path must be an absolute path".to_string(),
                    });
                } else if check_dirs && let Err(err) = is_exposable(&mount.path) {
                    problems.push(Problem {
                        field: format!("{m_prefix}.path"),
                        reason: err.to_string(),
                    });
                }
            }
        }
    }

    for (idx, proxy) in settings.trusted_proxies.iter().enumerate() {
        if parse_trusted_proxy(proxy).is_none() {
            problems.push(Problem {
                field: format!("trustedProxies[{idx}]"),
                reason: format!("invalid IP or CIDR {:?}", proxy),
            });
        }
    }

    problems
}

/// Parses an operator-configured trusted proxy entry (IP or CIDR).
pub fn parse_trusted_proxy(raw: &str) -> Option<IpNet> {
    let trimmed = raw.trim();
    if let Ok(net) = trimmed.parse::<IpNet>() {
        return Some(net);
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(IpNet::from(ip));
    }
    None
}

/// Builds a `fg_net::client_addr::ProxyTrust` from `Settings::trusted_proxies`.
/// When empty, proxy forwarding headers are NOT trusted.
pub fn build_proxy_trust(trusted_proxies: &[String]) -> fg_net::client_addr::ProxyTrust {
    let extra: Vec<IpNet> = trusted_proxies
        .iter()
        .filter_map(|raw| parse_trusted_proxy(raw))
        .collect();
    fg_net::client_addr::ProxyTrust {
        enabled: !extra.is_empty(),
        local: Vec::new(),
        extra,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webdav_enabled_requires_user() {
        let mut settings = Settings {
            enable: true,
            ..Settings::default()
        };
        // Enabled with 0 local users and sharedUsers disabled -> rejected.
        let probs = validate_settings(&settings, 0, true);
        assert!(probs.iter().any(|p| p.field == "users"));

        // Enabled with sharedUsers=true but 0 shared users -> rejected.
        settings.shared_users = true;
        let probs = validate_settings(&settings, 0, true);
        assert!(probs.iter().any(|p| p.field == "users"));

        // Enabled with sharedUsers=true and >=1 shared user -> allowed!
        let probs = validate_settings(&settings, 1, true);
        assert!(probs.is_empty(), "unexpected problems: {probs:?}");

        // Disabled with 0 users -> allowed.
        settings.enable = false;
        settings.shared_users = false;
        assert!(validate_settings(&settings, 0, true).is_empty());
    }

    #[test]
    fn webdav_mask_and_merge_preserves_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let existing = Settings {
            enable: true,
            users: vec![LocalUser {
                name: "alice".to_string(),
                password: hash_password("secret-1", 4).unwrap(),
                root: tmp.path().to_string_lossy().into_owned(),
                ..LocalUser::default()
            }],
            ..Settings::default()
        };
        let masked = mask_settings(&existing);
        assert_eq!(masked.users[0].password, limits::SECRET_MASK);

        let mut submitted = masked;
        merge_and_hash_passwords(&mut submitted, &existing, 4).unwrap();
        assert_eq!(submitted.users[0].password, existing.users[0].password);
    }
}
