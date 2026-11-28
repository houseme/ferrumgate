//! Normalization and validation for `filebrowser.json` (WP-66 step 1):
//! documented defaults, shared-directory overlap rejection and the
//! auth-method constraints. Pure functions — the config dir comes in as a
//! parameter and source existence is checked at start time, not here.

use std::path::{Path, PathBuf};

use super::model::{AuthMethod, FileConfig, Instance, limits};

/// A validation problem: `field` is a JSON-ish path for the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub field: String,
    pub reason: String,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.reason)
    }
}

/// A non-fatal hint for the instance card (e.g. the proxy-auth port
/// warning).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub field: String,
    pub reason: String,
}

/// Applies the documented defaults and length trims in place, then
/// backfills the key. Returns the first validation error, if any.
pub fn normalize(config: &mut FileConfig) -> Result<(), Problem> {
    config.settings.program_path = config.settings.program_path.trim().to_string();
    config.install.proxy = config.install.proxy.trim().to_string();
    let mut keys = std::collections::HashSet::new();
    for instance in &mut config.instances {
        instance.name = instance.name.trim().to_string();
        instance.group = instance.group.trim().to_string();
        instance.base_url = instance.base_url.trim().to_string();
        if instance.base_url.is_empty() {
            instance.base_url = limits::DEFAULT_BASE_URL.to_string();
        }
        instance.proxy_header = instance.proxy_header.trim().to_string();
        if instance.proxy_header.is_empty() {
            instance.proxy_header = limits::DEFAULT_PROXY_HEADER.to_string();
        }
        instance.admin_user = instance.admin_user.trim().to_string();
        if instance.admin_user.is_empty() {
            instance.admin_user = limits::DEFAULT_ADMIN_USER.to_string();
        }
        instance.remark = instance.remark.trim().to_string();
        for source in &mut instance.sources {
            source.path = source.path.trim().to_string();
            source.name = source.name.trim().to_string();
        }
        validate_instance(instance)?;
        instance.key = instance.key.trim().to_string();
        if instance.key.is_empty() || !keys.insert(instance.key.clone()) {
            instance.key = new_key(&mut keys);
        }
    }
    Ok(())
}

/// Validates one instance against the documented constraints.
pub fn validate_instance(instance: &Instance) -> Result<(), Problem> {
    for (index, source) in instance.sources.iter().enumerate() {
        let field = format!("instances[{index}].sources[{index}].path");
        if !Path::new(&source.path).is_absolute() {
            return Err(Problem {
                field,
                reason: "共享目录必须是绝对路径".to_string(),
            });
        }
    }
    if instance.auth_method == AuthMethod::Password
        && instance.admin_password.chars().count() < limits::PASSWORD_MIN_CHARS
    {
        return Err(Problem {
            field: "adminPassword".to_string(),
            reason: format!("密码方式的管理员密码至少 {} 位", limits::PASSWORD_MIN_CHARS),
        });
    }
    Ok(())
}

/// The shared directories must not touch the Gately config dir in either
/// direction: equal, inside it, or containing it — File Browser reads the
/// directory directly and cannot hide a subtree.
pub fn source_overlaps_config_dir(source: &Path, config_dir: &Path) -> bool {
    let config_dir = absolutize(config_dir);
    let source = absolutize(source);
    source == config_dir || source.starts_with(&config_dir) || config_dir.starts_with(&source)
}

/// Collects overlap problems for every source against `config_dir`.
pub fn validate_overlaps(config: &FileConfig, config_dir: &Path) -> Vec<Problem> {
    let mut problems = Vec::new();
    for (index, instance) in config.instances.iter().enumerate() {
        for (source_index, source) in instance.sources.iter().enumerate() {
            if source_overlaps_config_dir(Path::new(&source.path), config_dir) {
                problems.push(Problem {
                    field: format!("instances[{index}].sources[{source_index}].path"),
                    reason: "共享目录不能与 Gately 配置目录重叠（File Browser 无法隐藏其中的子树）"
                        .to_string(),
                });
            }
        }
    }
    problems
}

/// Non-fatal hints: the proxy-auth port warning from the doc — the port
/// must not be reachable from outside or anyone can forge the header.
pub fn warnings(config: &FileConfig) -> Vec<Warning> {
    let mut out = Vec::new();
    for (index, instance) in config.instances.iter().enumerate() {
        if instance.auth_method == AuthMethod::Proxy
            && !instance
                .listen_ip
                .map(|ip| ip.is_loopback())
                .unwrap_or(false)
        {
            out.push(Warning {
                field: format!("instances[{index}]"),
                reason:
                    "proxy 方式只应通过反向代理访问；端口对外开放时任何人都能伪造用户名请求头登录"
                        .to_string(),
            });
        }
    }
    out
}

/// 12 lowercase hex characters, unique within the collection — the same
/// shape the other collections generate.
pub fn new_key(taken: &mut std::collections::HashSet<String>) -> String {
    for _ in 0..8 {
        let mut bytes = [0u8; 6];
        if getrandom::fill(&mut bytes).is_err() {
            continue;
        }
        let key: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        if taken.insert(key.clone()) {
            return key;
        }
    }
    // Fall back to time; the loop practically never exhausts.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{nanos:012x}")
}

/// Lexical absolutization (no I/O): resolves `.`/`..` without touching the
/// filesystem, so the overlap check works for not-yet-existing paths too.
fn absolutize(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Source;

    fn instance() -> Instance {
        Instance {
            name: "files".to_string(),
            admin_password: "long-enough-password".to_string(),
            ..Instance::default()
        }
    }

    #[test]
    fn validate_sources_absolute_and_not_overlapping_config_dir() {
        // Relative paths are rejected outright.
        let mut bad = instance();
        bad.sources.push(Source {
            path: "relative/dir".to_string(),
            ..Source::default()
        });
        assert!(validate_instance(&bad).is_err());

        // Equal, inside and containing the config dir are all overlaps.
        let config_dir = Path::new("/srv/ferrumgate/config");
        for source in [
            "/srv/ferrumgate/config",
            "/srv/ferrumgate/config/filebrowser/x",
            "/srv/ferrumgate",
            "/srv",
        ] {
            let mut overlapping = instance();
            overlapping.sources.push(Source {
                path: source.to_string(),
                ..Source::default()
            });
            let config = FileConfig {
                instances: vec![overlapping],
                ..FileConfig::default()
            };
            assert!(
                !validate_overlaps(&config, config_dir).is_empty(),
                "{source} must overlap {config_dir:?}"
            );
        }

        // A sibling directory is fine.
        let mut ok = instance();
        ok.sources.push(Source {
            path: "/srv/ferrumgate/files".to_string(),
            ..Source::default()
        });
        let config = FileConfig {
            instances: vec![ok],
            ..FileConfig::default()
        };
        assert!(validate_overlaps(&config, config_dir).is_empty());
    }

    #[test]
    fn validate_password_min_8_required_for_password_auth() {
        let mut short = instance();
        short.admin_password = "short".to_string();
        assert!(validate_instance(&short).is_err());
        // The other methods do not require a password.
        short.auth_method = AuthMethod::NoAuth;
        assert!(validate_instance(&short).is_ok());
    }

    #[test]
    fn normalize_fills_documented_defaults() {
        let mut config = FileConfig::default();
        config.instances.push(instance());
        normalize(&mut config).expect("valid instance");
        let filled = &config.instances[0];
        assert_eq!(filled.base_url, "/");
        assert_eq!(filled.proxy_header, "Remote-User");
        assert_eq!(filled.admin_user, "admin");
        assert_eq!(filled.key.len(), 12);
    }

    #[test]
    fn proxy_auth_port_warning() {
        let mut config = FileConfig::default();
        let mut exposed = instance();
        exposed.auth_method = AuthMethod::Proxy;
        exposed.listen_ip = None;
        config.instances.push(exposed);
        assert!(!warnings(&config).is_empty(), "exposed proxy auth warns");

        config.instances[0].listen_ip = Some("127.0.0.1".parse().unwrap());
        assert!(warnings(&config).is_empty(), "loopback proxy auth is fine");
    }
}
