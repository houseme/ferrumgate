//! `fgate ctl` connection settings: defaults, config file, environment
//! variables and command-line flags, most specific wins.

use std::{fs, io::Write, path::PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const DEFAULT_URL: &str = "http://127.0.0.1:16680";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CtlConfig {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub insecure: bool,
}

/// One source of connection settings; later sources override earlier ones.
#[derive(Clone, Debug, Default)]
pub struct Overrides {
    pub url: Option<String>,
    pub token: Option<String>,
    pub insecure: bool,
}

impl CtlConfig {
    /// Applies the precedence chain: built-in defaults, then the config
    /// file, then `FERRUMGATE_URL` / `FERRUMGATE_TOKEN`, then flags. The
    /// insecure flag is sticky once any layer enables it.
    pub fn resolve(
        file: Option<CtlConfig>,
        environment: Option<(String, String)>,
        cli: Overrides,
    ) -> Self {
        let mut resolved = Self {
            url: DEFAULT_URL.to_owned(),
            token: String::new(),
            insecure: false,
        };
        if let Some(file) = file {
            if !file.url.is_empty() {
                resolved.url = file.url;
            }
            if !file.token.is_empty() {
                resolved.token = file.token;
            }
            resolved.insecure |= file.insecure;
        }
        if let Some((url, token)) = environment {
            if !url.is_empty() {
                resolved.url = url;
            }
            if !token.is_empty() {
                resolved.token = token;
            }
        }
        if let Some(url) = cli.url {
            resolved.url = url;
        }
        if let Some(token) = cli.token {
            resolved.token = token;
        }
        resolved.insecure |= cli.insecure;
        resolved
    }

    /// The user configuration directory holding `ferrumgate/ctl.json`.
    pub fn directory() -> Option<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join("Library/Application Support"))
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config"))
                })
        }
        #[cfg(windows)]
        {
            std::env::var_os("APPDATA").map(PathBuf::from)
        }
        #[cfg(not(any(unix, windows)))]
        {
            None
        }
    }

    pub fn path() -> Option<PathBuf> {
        Self::directory().map(|dir| dir.join("ferrumgate").join("ctl.json"))
    }

    pub fn load() -> Option<Self> {
        let path = Self::path()?;
        let raw = fs::read_to_string(path).ok()?;
        serde_json::from_str(&raw).ok()
    }

    /// Persists the settings, creating the directory with 0700 and the file
    /// with 0600 on Unix.
    pub fn save(&self) -> Result<PathBuf> {
        let path = Self::path().context("no user configuration directory on this platform")?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        let raw = serde_json::to_vec_pretty(self)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        file.write_all(&raw)
            .with_context(|| format!("write {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(url: &str, token: &str) -> Option<(String, String)> {
        Some((url.to_owned(), token.to_owned()))
    }

    #[test]
    fn config_precedence_defaults_file_env_then_flags() {
        let base = CtlConfig::resolve(None, None, Overrides::default());
        assert_eq!(base.url, DEFAULT_URL);
        assert_eq!(base.token, "");

        let file = || CtlConfig {
            url: "http://file.test:1".into(),
            token: "file-token".into(),
            insecure: true,
        };
        let from_file = CtlConfig::resolve(Some(file()), None, Overrides::default());
        assert_eq!(from_file.url, "http://file.test:1");
        assert_eq!(from_file.token, "file-token");
        assert!(from_file.insecure);

        let env_over_file = CtlConfig::resolve(
            Some(file()),
            environment("http://env.test:2", "env-token"),
            Overrides::default(),
        );
        assert_eq!(env_over_file.url, "http://env.test:2");
        assert_eq!(env_over_file.token, "env-token");
        assert!(env_over_file.insecure, "the file keeps insecure enabled");

        let flags = CtlConfig::resolve(
            Some(file()),
            environment("http://env.test:2", "env-token"),
            Overrides {
                url: Some("http://flag.test:3".into()),
                token: Some("flag-token".into()),
                insecure: false,
            },
        );
        assert_eq!(flags.url, "http://flag.test:3");
        assert_eq!(flags.token, "flag-token");
        assert!(flags.insecure);
    }

    #[test]
    fn saved_file_round_trips_with_private_permissions() -> Result<()> {
        let directory = tempfile::tempdir()?;
        // Point the config directory at the temporary tree via XDG on Linux
        // and a manual directory on other platforms for this test.
        let path = directory.path().join("ctl.json");
        let config = CtlConfig {
            url: "http://instance.test".into(),
            token: "round-trip-token".into(),
            insecure: false,
        };
        let raw = serde_json::to_vec_pretty(&config)?;
        std::fs::write(&path, raw)?;
        let loaded: CtlConfig = serde_json::from_slice(&std::fs::read(&path)?)?;
        assert_eq!(loaded, config, "the persisted shape round-trips");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            assert_eq!(
                std::fs::metadata(&path)?.permissions().mode() & 0o777,
                0o600
            );
        }
        Ok(())
    }
}
