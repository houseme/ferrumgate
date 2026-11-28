//! The `easytier.json` model (WP-45 §3.2): program settings shared by all
//! instances plus the instance collection. Field names follow the upstream
//! `config.go` shape as documented in WP-45; JSON is camelCase, unknown
//! fields are rejected, every field has a default so a partial file still
//! loads.

use serde::{Deserialize, Serialize};

/// Shared ceilings and defaults for the module (conventions §2: every
/// limit lives here). Upstream `config.go` ceilings are kept where the WP
/// records them; the rest are FerrumGate protections on the same scale.
pub mod limits {
    use std::time::Duration;

    /// FerrumGate protection: instance name length.
    pub const NAME_MAX_CHARS: usize = 128;
    /// FerrumGate protection: group name length (same cap as the collection
    /// group endpoint).
    pub const GROUP_MAX_CHARS: usize = 64;
    /// FerrumGate protection: remark length.
    pub const REMARK_MAX_CHARS: usize = 512;
    /// EasyTier network name length.
    pub const NETWORK_NAME_MAX_CHARS: usize = 128;
    /// EasyTier network secret length.
    pub const NETWORK_SECRET_MAX_CHARS: usize = 256;
    /// `peers` entries per instance.
    pub const PEERS_MAX: usize = 32;
    /// `listeners` entries per instance.
    pub const LISTENERS_MAX: usize = 16;
    /// `portForwards` entries per instance.
    pub const PORT_FORWARDS_MAX: usize = 32;
    /// `proxyNetworks` entries per instance.
    pub const PROXY_NETWORKS_MAX: usize = 16;
    /// `exitNodes` entries (virtual IPs of exit nodes to use).
    pub const EXIT_NODES_MAX: usize = 8;
    /// `extraArgs` entries per instance.
    pub const EXTRA_ARGS_MAX: usize = 32;
    /// One `extraArgs` entry length.
    pub const EXTRA_ARG_MAX_CHARS: usize = 512;
    /// `extraEnv` entries per instance.
    pub const EXTRA_ENV_MAX: usize = 32;
    /// One environment variable name / value length.
    pub const ENV_NAME_MAX_CHARS: usize = 128;
    pub const ENV_VALUE_MAX_CHARS: usize = 2048;
    /// One instance status query (`easytier-cli` round trip) timeout.
    pub const CLI_TIMEOUT: Duration = Duration::from_secs(8);
    /// Bounded stop of every instance when the module drains or resets.
    pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(15);
    /// Maximum instances saved in one config file (FerrumGate protection;
    /// the batch endpoints cap at 500 keys anyway).
    pub const INSTANCES_MAX: usize = 64;
}

/// Masked representation of secret fields in API responses (conventions
/// §3.3). Submitting this value keeps the stored one.
pub const MASK: &str = "********";

/// `easytier.json`: program settings plus the instance collection.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct FileConfig {
    pub settings: ProgramSettings,
    pub instances: Vec<Instance>,
}

/// Program settings shared by all instances (WP-45 §3.2). The path may be
/// empty: the resolver then falls back to `bin/` and `PATH` (WP-43).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct ProgramSettings {
    pub program_path: String,
    pub download_proxy: String,
}

/// One EasyTier instance: a dedicated `easytier-core` process with its own
/// state directory and management port.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Instance {
    pub key: String,
    pub name: String,
    pub group: String,
    pub enable: bool,
    pub remark: String,
    /// Network name: nodes with the same name and secret interconnect.
    pub network_name: String,
    /// Passed to `easytier-core` via `ET_NETWORK_SECRET`, never on the
    /// command line (WP-45 §3.3).
    pub network_secret: String,
    /// Peer URLs to connect to, one per entry (`tcp://host:port`).
    pub peers: Vec<String>,
    /// Listening URLs (`proto://addr:port`); empty means no listener.
    pub listeners: Vec<String>,
    /// Auto assigned, fixed IPv4 or none (no virtual interface).
    pub virtual_ip: VipMode,
    /// Create the TUN device (needs root and `/dev/net/tun`).
    pub tun: bool,
    /// `tcp://127.0.0.1:2222/10.126.126.1:22` style port forwards.
    pub port_forwards: Vec<String>,
    /// `192.168.1.0/24->10.1.0.0/24` style subnet proxies.
    pub proxy_networks: Vec<String>,
    /// Advertise as exit node and/or route through exit nodes.
    pub exit_node: ExitNodeRole,
    /// Virtual IPs of exit nodes to use when [`Instance::exit_node`] is
    /// [`ExitNodeRole::Use`].
    pub exit_nodes: Vec<String>,
    /// Prefer the lowest latency path over hop count.
    pub latency_first: bool,
    /// KCP proxy (TCP over UDP).
    pub kcp_proxy: bool,
    /// QUIC proxy.
    pub quic_proxy: bool,
    /// TUN device name; empty uses the program default.
    pub dev_name: String,
    pub extra_args: Vec<String>,
    pub extra_env: Vec<ExtraEnv>,
}

/// Virtual IP mode (WP-45 §3.3): auto assigned, a fixed IPv4, or none.
/// `None` forwards data only and creates no interface; it implies
/// userspace mode (`--no-tun`) even when `tun` is set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum VipMode {
    #[default]
    Auto,
    None,
    Fixed(String),
}

impl Serialize for VipMode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Auto => serializer.serialize_str("auto"),
            Self::None => serializer.serialize_str("none"),
            Self::Fixed(ip) => serializer.serialize_str(ip),
        }
    }
}

impl<'de> Deserialize<'de> for VipMode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        match text.as_str() {
            "auto" | "" => Ok(Self::Auto),
            "none" => Ok(Self::None),
            _ => Ok(Self::Fixed(text)),
        }
    }
}

/// Exit node role: not involved, advertise this node as an exit node, or
/// route through the exit nodes listed in [`Instance::exit_nodes`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExitNodeRole {
    #[default]
    None,
    Advertise,
    Use,
}

/// One extra environment variable. Values never appear in logs or
/// read-only views (only the name is exposed there, WP-45 §3.3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct ExtraEnv {
    pub name: String,
    pub value: String,
}

impl Instance {
    /// The behavior-affecting fingerprint used to decide whether a saved
    /// instance must be restarted: everything except the display fields
    /// (`name`, `group`, `remark`) and `enable` (handled separately).
    pub fn fingerprint(&self) -> String {
        serde_json::to_string(&Fingerprint {
            network_name: &self.network_name,
            network_secret: &self.network_secret,
            peers: &self.peers,
            listeners: &self.listeners,
            virtual_ip: &self.virtual_ip,
            tun: self.tun,
            port_forwards: &self.port_forwards,
            proxy_networks: &self.proxy_networks,
            exit_node: &self.exit_node,
            exit_nodes: &self.exit_nodes,
            latency_first: self.latency_first,
            kcp_proxy: self.kcp_proxy,
            quic_proxy: self.quic_proxy,
            dev_name: &self.dev_name,
            extra_args: &self.extra_args,
            extra_env: &self.extra_env,
        })
        .unwrap_or_default()
    }

    /// API view with secrets masked (`********`): safe for list and
    /// mutation responses read by token holders.
    pub fn masked(mut self) -> Self {
        if !self.network_secret.is_empty() {
            self.network_secret = MASK.to_owned();
        }
        for env in &mut self.extra_env {
            if !env.value.is_empty() {
                env.value = MASK.to_owned();
            }
        }
        self
    }

    /// Read-only identity view (WP-45 §3.3): only environment variable
    /// names, no values, and no extra argument values — extra arguments
    /// could carry secrets the owner typed in.
    pub fn readonly(mut self) -> Self {
        self.network_secret = if self.network_secret.is_empty() {
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

    /// Restores secret fields masked with [`MASK`] from `stored`: anything
    /// submitted as the mask (or empty) keeps the stored value.
    pub fn merge_masked(&mut self, stored: &Instance) {
        if self.network_secret == MASK
            || (self.network_secret.is_empty() && !stored.network_secret.is_empty())
        {
            self.network_secret = stored.network_secret.clone();
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
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Fingerprint<'a> {
    network_name: &'a String,
    network_secret: &'a String,
    peers: &'a Vec<String>,
    listeners: &'a Vec<String>,
    virtual_ip: &'a VipMode,
    tun: bool,
    port_forwards: &'a Vec<String>,
    proxy_networks: &'a Vec<String>,
    exit_node: &'a ExitNodeRole,
    exit_nodes: &'a Vec<String>,
    latency_first: bool,
    kcp_proxy: bool,
    quic_proxy: bool,
    dev_name: &'a String,
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
            remark: "".into(),
            network_name: "mesh".into(),
            network_secret: "s3cret".into(),
            peers: vec!["tcp://public.easytier.cn:11010".into()],
            listeners: vec!["tcp://0.0.0.0:11010".into()],
            virtual_ip: VipMode::Fixed("10.126.126.1".into()),
            tun: true,
            port_forwards: vec!["tcp://127.0.0.1:2222/10.126.126.1:22".into()],
            proxy_networks: vec![],
            exit_node: ExitNodeRole::None,
            exit_nodes: vec![],
            latency_first: true,
            kcp_proxy: false,
            quic_proxy: false,
            dev_name: "etun0".into(),
            extra_args: vec!["--verbose".into()],
            extra_env: vec![ExtraEnv {
                name: "ET_LOG".into(),
                value: "info".into(),
            }],
        }
    }

    #[test]
    fn model_masked_view_hides_secret_and_env_values() {
        let view = sample().masked();
        assert_eq!(view.network_secret, MASK);
        assert_eq!(view.extra_env[0].value, MASK);
        assert_eq!(view.extra_args, vec!["--verbose"], "非密钥参数保持原样");
        // The read-only view additionally hides extra argument values.
        let view = sample().readonly();
        assert_eq!(view.extra_args, vec![MASK]);
        assert_eq!(view.extra_env[0].value, MASK);
    }

    #[test]
    fn model_merge_keeps_secret_submitted_as_mask() {
        let stored = sample();
        let mut submitted = sample();
        submitted.network_secret = MASK.into();
        submitted.extra_env[0].value = MASK.into();
        submitted.merge_masked(&stored);
        assert_eq!(submitted.network_secret, "s3cret");
        assert_eq!(submitted.extra_env[0].value, "info");
        // A fresh value survives the merge untouched.
        let mut changed = sample();
        changed.network_secret = "new-secret".into();
        changed.merge_masked(&stored);
        assert_eq!(changed.network_secret, "new-secret");
    }

    #[test]
    fn model_vip_mode_roundtrip_and_fingerprint() {
        assert_eq!(serde_json::to_value(VipMode::Auto).unwrap(), "auto");
        assert_eq!(serde_json::to_value(VipMode::None).unwrap(), "none");
        assert_eq!(
            serde_json::to_value(VipMode::Fixed("10.1.1.1".into())).unwrap(),
            "10.1.1.1"
        );
        assert_eq!(VipMode::default(), VipMode::Auto);
        let mut a = sample();
        let mut b = sample();
        b.remark = "edited".into();
        assert_eq!(a.fingerprint(), b.fingerprint(), "备注不参与指纹");
        a.network_secret = "rotated".into();
        assert_ne!(a.fingerprint(), b.fingerprint(), "密钥变化参与指纹");
    }

    #[test]
    fn model_unknown_fields_rejected() {
        let json = r#"{"settings":{},"instances":[],"legacy":1}"#;
        assert!(serde_json::from_str::<FileConfig>(json).is_err());
        let json = r#"{"settings":{"programPath":"","downloadProxy":""},"instances":[]}"#;
        assert!(serde_json::from_str::<FileConfig>(json).is_ok());
    }
}
