//! The `tailscale.json` model (WP-45 §3.2): program settings plus the
//! instance collection. JSON is camelCase, unknown fields are rejected,
//! every field has a default so a partial file still loads.

use serde::{Deserialize, Serialize};

/// Shared ceilings and defaults for the module (conventions §2).
pub mod limits {
    use std::time::Duration;

    /// FerrumGate protection: instance name length.
    pub const NAME_MAX_CHARS: usize = 128;
    /// FerrumGate protection: group name length.
    pub const GROUP_MAX_CHARS: usize = 64;
    /// FerrumGate protection: remark length.
    pub const REMARK_MAX_CHARS: usize = 512;
    /// `advertiseRoutes` entries per instance.
    pub const ADVERTISE_ROUTES_MAX: usize = 16;
    /// `extraArgs` entries per instance.
    pub const EXTRA_ARGS_MAX: usize = 32;
    /// One `extraArgs` entry length.
    pub const EXTRA_ARG_MAX_CHARS: usize = 512;
    /// `extraEnv` entries per instance.
    pub const EXTRA_ENV_MAX: usize = 32;
    /// One environment variable name / value length.
    pub const ENV_NAME_MAX_CHARS: usize = 128;
    pub const ENV_VALUE_MAX_CHARS: usize = 2048;
    /// Login server URL length.
    pub const LOGIN_SERVER_MAX_CHARS: usize = 512;
    /// Control socket path length.
    pub const SOCKET_MAX_CHARS: usize = 512;
    /// State directory path length.
    pub const STATE_DIR_MAX_CHARS: usize = 512;
    /// One-shot `tailscale up` login timeout: without an auth key the
    /// command blocks waiting for the browser login, so it is bounded.
    pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(20);
    /// One instance status query (`tailscale status --json`) timeout.
    pub const CLI_TIMEOUT: Duration = Duration::from_secs(8);
    /// Bounded stop of every instance when the module drains or resets.
    pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(15);
    /// Maximum instances saved in one config file.
    pub const INSTANCES_MAX: usize = 64;
}

/// Masked representation of secret fields in API responses. Submitting
/// this value keeps the stored one.
pub const MASK: &str = "********";

/// `tailscale.json`: program settings plus the instance collection.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct FileConfig {
    pub settings: ProgramSettings,
    pub instances: Vec<Instance>,
}

/// Program settings shared by all instances (WP-45 §3.2).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct ProgramSettings {
    pub program_path: String,
    pub download_proxy: String,
}

/// One Tailscale instance: a managed `tailscaled` (userspace networking by
/// default, container friendly) or a system daemon joined through a
/// control socket (WP-45 §3.3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Instance {
    pub key: String,
    pub name: String,
    pub group: String,
    pub enable: bool,
    pub remark: String,
    /// Run `tailscaled` ourselves; `false` attaches to the daemon already
    /// running on the host through the control socket.
    #[serde(default = "default_true")]
    pub managed: bool,
    /// Userspace networking (no TUN device, no root). Kernel mode is
    /// limited to one simultaneously enabled instance.
    #[serde(default = "default_true")]
    pub userspace: bool,
    /// Authentication key; handed to the CLI through `TS_AUTHKEY`, never
    /// on the command line (WP-45 §3.3 密钥的保护).
    pub auth_key: String,
    /// Login server (Headscale); empty uses the official control plane.
    pub login_server: String,
    /// Subnet routes to advertise, `10.1.0.0/24` style CIDRs.
    pub advertise_routes: Vec<String>,
    /// Not involved, advertise as exit node, or use a specific exit node.
    pub exit_node: ExitNodeRole,
    /// Exit node Tailscale IP / name when [`Instance::exit_node`] is
    /// [`ExitNodeRole::Use`].
    pub exit_node_target: String,
    /// SOCKS5 proxy of the userspace daemon (`127.0.0.1:1055`); empty is
    /// off. The proxy has no authentication — binding it to a
    /// non-loopback address raises a warning (WP-45 §3.3).
    pub socks5: String,
    /// Fixed WireGuard UDP port (for firewall pinholes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_port: Option<u16>,
    /// Control socket path; empty uses the default for the state dir.
    pub socket: String,
    /// Custom state directory; empty uses `<config>/tailscale/<key>`.
    /// Custom directories are kept when the instance is deleted.
    pub state_dir: String,
    pub extra_args: Vec<String>,
    pub extra_env: Vec<ExtraEnv>,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExitNodeRole {
    #[default]
    None,
    Advertise,
    Use,
}

/// One extra environment variable. Values never appear in logs or
/// read-only views.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct ExtraEnv {
    pub name: String,
    pub value: String,
}

impl Instance {
    /// Behavior-affecting fingerprint for restart decisions: everything
    /// except `name` / `group` / `remark` / `enable`.
    pub fn fingerprint(&self) -> String {
        serde_json::to_string(&Fingerprint {
            managed: self.managed,
            userspace: self.userspace,
            auth_key: &self.auth_key,
            login_server: &self.login_server,
            advertise_routes: &self.advertise_routes,
            exit_node: &self.exit_node,
            exit_node_target: &self.exit_node_target,
            socks5: &self.socks5,
            fixed_port: self.fixed_port,
            socket: &self.socket,
            state_dir: &self.state_dir,
            extra_args: &self.extra_args,
            extra_env: &self.extra_env,
        })
        .unwrap_or_default()
    }

    /// API view with secrets masked (`********`).
    pub fn masked(mut self) -> Self {
        if !self.auth_key.is_empty() {
            self.auth_key = MASK.to_owned();
        }
        for env in &mut self.extra_env {
            if !env.value.is_empty() {
                env.value = MASK.to_owned();
            }
        }
        self
    }

    /// Read-only identity view: environment variable names only, no extra
    /// argument values (WP-45 §3.3).
    pub fn readonly(mut self) -> Self {
        self.auth_key = if self.auth_key.is_empty() {
            String::new()
        } else {
            MASK.to_owned()
        };
        for arg in &mut self.extra_args {
            if !arg.is_empty() {
                *arg = MASK.to_owned();
            }
        }
        for env in &mut self.extra_env {
            if !env.value.is_empty() {
                env.value = MASK.to_owned();
            }
        }
        self
    }

    /// Restores secret fields submitted as [`MASK`] from `stored`.
    pub fn merge_masked(&mut self, stored: &Instance) {
        if self.auth_key == MASK || (self.auth_key.is_empty() && !stored.auth_key.is_empty()) {
            self.auth_key = stored.auth_key.clone();
        }
        for env in &mut self.extra_env {
            if env.value == MASK
                && let Some(kept) = stored
                    .extra_env
                    .iter()
                    .find(|kept_env| kept_env.name == env.name)
            {
                env.value = kept.value.clone();
            }
        }
    }

    /// Kernel mode: a managed daemon without userspace networking. Such
    /// instances overwrite each other's routing tables, so at most one may
    /// be enabled at a time (WP-45 §3.3).
    pub fn is_kernel_mode(&self) -> bool {
        self.managed && !self.userspace
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Fingerprint<'a> {
    managed: bool,
    userspace: bool,
    auth_key: &'a String,
    login_server: &'a String,
    advertise_routes: &'a Vec<String>,
    exit_node: &'a ExitNodeRole,
    exit_node_target: &'a String,
    socks5: &'a String,
    fixed_port: Option<u16>,
    socket: &'a String,
    state_dir: &'a String,
    extra_args: &'a Vec<String>,
    extra_env: &'a Vec<ExtraEnv>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Instance {
        Instance {
            key: "abc123".into(),
            name: "main".into(),
            group: "office".into(),
            enable: true,
            remark: String::new(),
            managed: true,
            userspace: true,
            auth_key: "tskey-auth-abc123".into(),
            login_server: String::new(),
            advertise_routes: vec!["10.1.0.0/24".into()],
            exit_node: ExitNodeRole::None,
            exit_node_target: String::new(),
            socks5: "127.0.0.1:1055".into(),
            fixed_port: Some(41841),
            socket: String::new(),
            state_dir: String::new(),
            extra_args: vec!["--verbose".into()],
            extra_env: vec![ExtraEnv {
                name: "TS_LOG".into(),
                value: "info".into(),
            }],
        }
    }

    #[test]
    fn tailscale_defaults_are_managed_userspace() {
        let instance: Instance = serde_json::from_str(
            r#"{"key":"k","name":"n","group":"","enable":false,"remark":"",
                "authKey":"","loginServer":"","advertiseRoutes":[],
                "exitNode":"none","exitNodeTarget":"","socks5":"",
                "socket":"","stateDir":"","extraArgs":[],"extraEnv":[]}"#,
        )
        .expect("parse");
        assert!(instance.managed, "默认托管");
        assert!(instance.userspace, "默认用户态网络");
        assert!(!instance.is_kernel_mode());
        assert_eq!(instance.fixed_port, None);
        // Unknown fields are rejected.
        assert!(serde_json::from_str::<FileConfig>(r#"{"instances":[],"legacy":1}"#).is_err());
    }

    #[test]
    fn tailscale_masked_view_and_merge() {
        let view = sample().masked();
        assert_eq!(view.auth_key, MASK);
        assert_eq!(view.extra_env[0].value, MASK);
        assert_eq!(view.extra_args, vec!["--verbose"]);
        let readonly = sample().readonly();
        assert_eq!(readonly.extra_args, vec![MASK]);
        let mut submitted = sample();
        submitted.auth_key = MASK.into();
        submitted.extra_env[0].value = MASK.into();
        submitted.merge_masked(&sample());
        assert_eq!(submitted.auth_key, "tskey-auth-abc123");
        assert_eq!(submitted.extra_env[0].value, "info");
    }

    #[test]
    fn tailscale_only_env_names_exposed_readonly() {
        let view = sample().readonly();
        // Environment variable names stay visible, values do not.
        assert_eq!(view.extra_env[0].name, "TS_LOG");
        assert_eq!(view.extra_env[0].value, MASK);
        assert_eq!(view.auth_key, MASK);
        // Fingerprint is unaffected by display fields.
        let mut other = sample();
        other.remark = "edited".into();
        other.group = "other".into();
        assert_eq!(sample().fingerprint(), other.fingerprint());
        other.socks5 = "0.0.0.0:1055".into();
        assert_ne!(sample().fingerprint(), other.fingerprint());
    }
}
