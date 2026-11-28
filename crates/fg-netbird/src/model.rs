//! The `netbird.json` model (WP-45 §3.2): program settings plus the
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
    /// Management URL length.
    pub const MANAGEMENT_URL_MAX_CHARS: usize = 512;
    /// Setup key length.
    pub const SETUP_KEY_MAX_CHARS: usize = 256;
    /// Control address path length.
    pub const CONTROL_ADDR_MAX_CHARS: usize = 512;
    /// State directory path length.
    pub const STATE_DIR_MAX_CHARS: usize = 512;
    /// The default SOCKS5 listener (WP-45 §3.4): loopback, port 1080.
    pub const SOCKS5_DEFAULT_PORT: u16 = 1080;
    /// `extraArgs` entries per instance.
    pub const EXTRA_ARGS_MAX: usize = 32;
    /// One `extraArgs` entry length.
    pub const EXTRA_ARG_MAX_CHARS: usize = 512;
    /// `extraEnv` entries per instance.
    pub const EXTRA_ENV_MAX: usize = 32;
    /// One environment variable name / value length.
    pub const ENV_NAME_MAX_CHARS: usize = 128;
    pub const ENV_VALUE_MAX_CHARS: usize = 2048;
    /// One-shot `netbird up` timeout (without a setup key it returns the
    /// login link; with one it joins directly).
    pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(20);
    /// One instance status query (`netbird status --json`) timeout.
    pub const CLI_TIMEOUT: Duration = Duration::from_secs(8);
    /// The login link refresh interval (WP-45 §3.3: 链接过期后自动更新).
    pub const LOGIN_REFRESH_AFTER: Duration = Duration::from_secs(5 * 60);
    /// Bounded stop of every instance when the module drains or resets.
    pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(15);
    /// Maximum instances saved in one config file.
    pub const INSTANCES_MAX: usize = 64;
}

/// Masked representation of secret fields in API responses. Submitting
/// this value keeps the stored one.
pub const MASK: &str = "********";

/// `netbird.json`: program settings plus the instance collection.
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

/// One NetBird instance: a managed `netbird` daemon (userspace networking
/// by default) or a system-installed NetBird service joined through its
/// control address (WP-45 §3.3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Instance {
    pub key: String,
    pub name: String,
    pub group: String,
    pub enable: bool,
    pub remark: String,
    /// Run the daemon ourselves; `false` attaches to the system-installed
    /// NetBird service through the control address.
    #[serde(default = "default_true")]
    pub managed: bool,
    /// Userspace (netstack) networking — no TUN device, no root.
    #[serde(default = "default_true")]
    pub userspace: bool,
    /// Management URL of a self-hosted management service; empty joins
    /// the official cloud.
    pub management_url: String,
    /// Setup key; handed to the CLI through `NB_SETUP_KEY`, never on the
    /// command line (WP-45 §3.3 密钥的保护).
    pub setup_key: String,
    /// Accept routes offered by the management plane.
    pub accept_routes: bool,
    /// Offer this peer as a routing peer. NetBird configures routing
    /// peers in the management console; this field records the intent for
    /// the UI and takes part in the fingerprint so an edit restarts the
    /// daemon (which re-syncs with the management plane).
    pub routing_peer: bool,
    /// Accept DNS settings from the management plane (netbird default).
    #[serde(default = "default_true")]
    pub accept_dns: bool,
    /// Block inbound connections on the NetBird interface.
    pub block_inbound: bool,
    /// SOCKS5 proxy of the userspace daemon (`127.0.0.1:1080` default).
    /// The proxy has no authentication — binding it beyond the loopback
    /// raises a warning (WP-45 §3.3).
    pub socks5: String,
    /// Fixed WireGuard port (`NB_WIREGUARD_PORT` on the CLI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_port: Option<u16>,
    /// Control address (unix socket path); empty uses
    /// `<state dir>/netbird.sock`.
    pub control_addr: String,
    /// Custom state directory; empty uses `<config>/netbird/<key>`.
    /// Custom directories are kept when the instance is deleted.
    pub state_dir: String,
    pub extra_args: Vec<String>,
    pub extra_env: Vec<ExtraEnv>,
}

fn default_true() -> bool {
    true
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
    /// Behavior-affecting fingerprint for restart decisions.
    pub fn fingerprint(&self) -> String {
        serde_json::to_string(&Fingerprint {
            managed: self.managed,
            userspace: self.userspace,
            management_url: &self.management_url,
            setup_key: &self.setup_key,
            accept_routes: self.accept_routes,
            accept_dns: self.accept_dns,
            block_inbound: self.block_inbound,
            socks5: &self.socks5,
            fixed_port: self.fixed_port,
            control_addr: &self.control_addr,
            state_dir: &self.state_dir,
            extra_args: &self.extra_args,
            extra_env: &self.extra_env,
        })
        .unwrap_or_default()
    }

    /// API view with secrets masked (`********`).
    pub fn masked(mut self) -> Self {
        if !self.setup_key.is_empty() {
            self.setup_key = MASK.to_owned();
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
        self.setup_key = if self.setup_key.is_empty() {
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
        if self.setup_key == MASK || (self.setup_key.is_empty() && !stored.setup_key.is_empty()) {
            self.setup_key = stored.setup_key.clone();
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

    /// Kernel mode: a managed daemon without userspace networking. At
    /// most one may be enabled at a time (WP-45 §3.3).
    pub fn is_kernel_mode(&self) -> bool {
        self.managed && !self.userspace
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Fingerprint<'a> {
    managed: bool,
    userspace: bool,
    management_url: &'a String,
    setup_key: &'a String,
    accept_routes: bool,
    accept_dns: bool,
    block_inbound: bool,
    socks5: &'a String,
    fixed_port: Option<u16>,
    control_addr: &'a String,
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
            management_url: "https://mgmt.corp.example".into(),
            setup_key: "NB-SETUP-KEY-SECRET".into(),
            accept_routes: true,
            routing_peer: false,
            accept_dns: true,
            block_inbound: false,
            socks5: "127.0.0.1:1080".into(),
            fixed_port: None,
            control_addr: String::new(),
            state_dir: String::new(),
            extra_args: vec!["--verbose".into()],
            extra_env: vec![ExtraEnv {
                name: "NB_LOG_FILE".into(),
                value: "console".into(),
            }],
        }
    }

    #[test]
    fn netbird_defaults_are_managed_userspace() {
        let instance: Instance = serde_json::from_str(
            r#"{"key":"k","name":"n","group":"","enable":false,"remark":"",
                "managementUrl":"","setupKey":"","acceptRoutes":false,
                "routingPeer":false,"blockInbound":false,"socks5":"",
                "controlAddr":"","stateDir":"","extraArgs":[],"extraEnv":[]}"#,
        )
        .expect("parse");
        assert!(instance.managed);
        assert!(instance.userspace);
        assert!(instance.accept_dns, "acceptDns 缺省为 true");
        assert!(!instance.is_kernel_mode());
        assert!(serde_json::from_str::<FileConfig>(r#"{"instances":[],"x":1}"#).is_err());
    }

    #[test]
    fn netbird_masked_view_and_merge() {
        let view = sample().masked();
        assert_eq!(view.setup_key, MASK);
        assert_eq!(view.extra_env[0].value, MASK);
        assert_eq!(view.extra_args, vec!["--verbose"]);
        let readonly = sample().readonly();
        assert_eq!(readonly.extra_args, vec![MASK]);
        assert_eq!(readonly.extra_env[0].name, "NB_LOG_FILE");
        assert_eq!(readonly.extra_env[0].value, MASK);
        let mut submitted = sample();
        submitted.setup_key = MASK.into();
        submitted.extra_env[0].value = MASK.into();
        submitted.merge_masked(&sample());
        assert_eq!(submitted.setup_key, "NB-SETUP-KEY-SECRET");
        assert_eq!(submitted.extra_env[0].value, "console");
        // Fingerprint ignores display fields, covers behavior fields.
        let mut other = sample();
        other.remark = "edited".into();
        other.group = "g".into();
        assert_eq!(sample().fingerprint(), other.fingerprint());
        other.setup_key = "rotated".into();
        assert_ne!(sample().fingerprint(), other.fingerprint());
    }
}
