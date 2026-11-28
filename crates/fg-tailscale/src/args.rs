//! Launch arguments and environment (WP-45 §5 step 7): `tailscaled` and
//! the `tailscale` CLI for one instance. Pure functions.
//!
//! Safety properties (asserted by tests): the auth key travels via the
//! `TS_AUTHKEY` environment variable, never in argv; every CLI invocation
//! targets the instance's control socket; kernel-mode instances on
//! nf_tables hosts get `TS_DEBUG_FIREWALL_MODE=nftables` so subnet
//! forwarding works.

use std::{ffi::OsString, path::Path};

use crate::model::{ExitNodeRole, Instance};

/// The state file inside the state directory.
pub const STATE_FILE: &str = "tailscaled.state";
/// The default control socket file name inside the state directory.
pub const SOCKET_FILE: &str = "tailscaled.sock";
/// The system daemon's default control socket (when not managed).
pub const SYSTEM_SOCKET: &str = "/var/run/tailscale/tailscaled.sock";

/// The effective control socket for an instance: explicit override, else
/// the state dir's socket (managed) or the system socket.
pub fn control_socket(instance: &Instance, state_dir: &Path) -> String {
    if !instance.socket.is_empty() {
        return instance.socket.clone();
    }
    if instance.managed {
        state_dir.join(SOCKET_FILE).display().to_string()
    } else {
        SYSTEM_SOCKET.to_owned()
    }
}

/// The effective state directory: explicit override, else the per-instance
/// default (the runtime passes `<config>/tailscale/<key>`).
pub fn state_dir<'a>(instance: &'a Instance, default_dir: &'a Path) -> std::borrow::Cow<'a, Path> {
    if instance.state_dir.is_empty() {
        std::borrow::Cow::Borrowed(default_dir)
    } else {
        std::borrow::Cow::Owned(std::path::PathBuf::from(&instance.state_dir))
    }
}

/// `tailscaled` command line. The SOCKS5 proxy only exists in userspace
/// networking; kernel mode ignores it (validation warns about that).
pub fn daemon_args(instance: &Instance, dir: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();
    args.push(format!("--state={}", dir.join(STATE_FILE).display()).into());
    args.push(format!("--socket={}", control_socket(instance, dir)).into());
    if instance.userspace {
        args.push("--tun=userspace".into());
        if !instance.socks5.is_empty() {
            args.push(format!("--socks5-server={}", instance.socks5).into());
        }
    } else if let Some(port) = instance.fixed_port {
        // Kernel mode: pin the WireGuard UDP port for firewall rules.
        args.push(format!("--port={port}").into());
    }
    for arg in &instance.extra_args {
        args.push(arg.clone().into());
    }
    args
}

/// `tailscaled` environment. `nftables` is the host detection result
/// (Linux only): kernel-mode instances then write their rules through the
/// nf_tables backend.
pub fn daemon_env(instance: &Instance, nftables: bool) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = Vec::new();
    if !instance.auth_key.is_empty() {
        env.push(("TS_AUTHKEY".into(), instance.auth_key.clone().into()));
    }
    if instance.is_kernel_mode() && nftables {
        env.push(("TS_DEBUG_FIREWALL_MODE".into(), "nftables".into()));
    }
    for extra in &instance.extra_env {
        env.push((extra.name.clone().into(), extra.value.clone().into()));
    }
    env
}

/// `tailscale` CLI arguments for `up`: global socket flag first, then the
/// login and capability flags.
pub fn up_args(instance: &Instance, dir: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["--socket".into(), control_socket(instance, dir).into()];
    args.push("up".into());
    if !instance.login_server.is_empty() {
        args.push(format!("--login-server={}", instance.login_server).into());
    }
    if !instance.advertise_routes.is_empty() {
        args.push(format!("--advertise-routes={}", instance.advertise_routes.join(",")).into());
    }
    match instance.exit_node {
        ExitNodeRole::Advertise => args.push("--advertise-exit-node".into()),
        ExitNodeRole::Use => {
            if !instance.exit_node_target.is_empty() {
                args.push(format!("--exit-node={}", instance.exit_node_target).into());
            }
        }
        ExitNodeRole::None => {}
    }
    args
}

/// `up` environment: the auth key rides here.
pub fn up_env(instance: &Instance) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = Vec::new();
    if !instance.auth_key.is_empty() {
        env.push(("TS_AUTHKEY".into(), instance.auth_key.clone().into()));
    }
    env
}

/// `tailscale status --json` against the instance's socket.
pub fn status_args(instance: &Instance, dir: &Path) -> Vec<OsString> {
    vec![
        "--socket".into(),
        control_socket(instance, dir).into(),
        "status".into(),
        "--json".into(),
    ]
}

/// `tailscale logout` against the instance's socket.
pub fn logout_args(instance: &Instance, dir: &Path) -> Vec<OsString> {
    vec![
        "--socket".into(),
        control_socket(instance, dir).into(),
        "logout".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ExtraEnv, MASK};

    fn sample() -> Instance {
        Instance {
            key: "abc".into(),
            name: "main".into(),
            managed: true,
            userspace: true,
            auth_key: "tskey-auth-secret".into(),
            login_server: "https://headscale.example".into(),
            advertise_routes: vec!["10.1.0.0/24".into(), "192.168.2.0/24".into()],
            exit_node: ExitNodeRole::Advertise,
            socks5: "127.0.0.1:1055".into(),
            fixed_port: None,
            extra_args: vec!["--verbose".into()],
            extra_env: vec![ExtraEnv {
                name: "TS_LOG".into(),
                value: "info".into(),
            }],
            ..Instance::default()
        }
    }

    fn text(values: &[OsString]) -> Vec<String> {
        values
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn tailscale_args_snapshot() {
        let instance = sample();
        let dir = Path::new("/state/main");
        assert_eq!(
            text(&daemon_args(&instance, dir)),
            [
                "--state=/state/main/tailscaled.state",
                "--socket=/state/main/tailscaled.sock",
                "--tun=userspace",
                "--socks5-server=127.0.0.1:1055",
                "--verbose",
            ]
        );
        assert_eq!(
            text(&up_args(&instance, dir)),
            [
                "--socket",
                "/state/main/tailscaled.sock",
                "up",
                "--login-server=https://headscale.example",
                "--advertise-routes=10.1.0.0/24,192.168.2.0/24",
                "--advertise-exit-node",
            ]
        );
        // Kernel mode: no --tun, no SOCKS5, fixed port pinned. The extra
        // argument from the fixture is still appended.
        let mut kernel = sample();
        kernel.userspace = false;
        kernel.socks5 = String::new();
        kernel.fixed_port = Some(41841);
        assert_eq!(
            text(&daemon_args(&kernel, dir)),
            [
                "--state=/state/main/tailscaled.state",
                "--socket=/state/main/tailscaled.sock",
                "--port=41841",
                "--verbose",
            ]
        );
        // Custom socket override wins over the derived path.
        let mut custom = sample();
        custom.socket = "/run/ts-a.sock".into();
        assert_eq!(
            text(&status_args(&custom, dir)),
            ["--socket", "/run/ts-a.sock", "status", "--json"]
        );
        // Unmanaged instances target the system daemon socket.
        let mut external = sample();
        external.managed = false;
        assert_eq!(
            text(&logout_args(&external, dir)),
            ["--socket", SYSTEM_SOCKET, "logout"]
        );
    }

    #[test]
    fn tailscale_secrets_in_env_not_args() {
        let instance = sample();
        for args in [
            daemon_args(&instance, Path::new("/s")),
            up_args(&instance, Path::new("/s")),
            status_args(&instance, Path::new("/s")),
            logout_args(&instance, Path::new("/s")),
        ] {
            let rendered = text(&args).join(" ");
            assert!(
                !rendered.contains("tskey-auth-secret"),
                "认证密钥绝不能出现在命令行: {rendered}"
            );
        }
        assert!(
            daemon_env(&instance, false)
                .contains(&("TS_AUTHKEY".into(), "tskey-auth-secret".into()))
        );
        assert_eq!(
            up_env(&instance),
            [("TS_AUTHKEY".into(), "tskey-auth-secret".into())]
        );
        // Empty key: no env entry.
        let mut quiet = sample();
        quiet.auth_key = String::new();
        assert!(
            !text(&daemon_args(&quiet, Path::new("/s")))
                .join(" ")
                .contains(MASK)
        );
        assert!(up_env(&quiet).is_empty());
    }

    #[test]
    fn tailscale_nftables_env() {
        let mut kernel = sample();
        kernel.userspace = false;
        // Kernel mode on an nf_tables host: env switches the firewall mode.
        assert!(
            daemon_env(&kernel, true)
                .contains(&("TS_DEBUG_FIREWALL_MODE".into(), "nftables".into()))
        );
        // Kernel mode on a legacy iptables host: no env.
        assert!(
            !daemon_env(&kernel, false)
                .iter()
                .any(|(key, _)| key == "TS_DEBUG_FIREWALL_MODE")
        );
        // Userspace mode never gets the env (no iptables rules written).
        let mut userspace = sample();
        userspace.userspace = true;
        assert!(
            !daemon_env(&userspace, true)
                .iter()
                .any(|(key, _)| key == "TS_DEBUG_FIREWALL_MODE")
        );
    }
}
