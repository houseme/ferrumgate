//! Launch arguments and environment (WP-45 §5 step 9-11): the managed
//! `netbird service run` daemon and the CLI (`up` / `down` / `status` /
//! `logout` / `version`). Pure functions.
//!
//! Safety properties (asserted by tests): the setup key travels via the
//! `NB_SETUP_KEY` environment variable on the `up` process, never in
//! argv; userspace mode sets `NB_USE_NETSTACK_MODE=true`; the SOCKS5
//! listener is configured via `NB_SOCKS5_LISTENER_ADDRESS` /
//! `NB_SOCKS5_LISTENER_PORT` on the daemon (defaults loopback:1080); the
//! WireGuard port goes via `NB_WIREGUARD_PORT` on the CLI.

use std::{ffi::OsString, path::Path};

use crate::model::Instance;

/// The control socket file name inside the state dir.
pub const SOCKET_FILE: &str = "netbird.sock";
/// The system service's default control address.
pub const SYSTEM_CONTROL_ADDR: &str = "/var/run/netbird.sock";

/// The effective control address (unix socket path): explicit override,
/// else `<state dir>/netbird.sock`, else the system address when the
/// instance is not managed and has no state dir of its own.
pub fn control_addr(instance: &Instance, default_state_dir: &Path) -> String {
    if !instance.control_addr.is_empty() {
        return instance.control_addr.clone();
    }
    if instance.managed {
        default_state_dir.join(SOCKET_FILE).display().to_string()
    } else {
        SYSTEM_CONTROL_ADDR.to_owned()
    }
}

/// `unix://<path>` URL form used by `--daemon-addr`.
pub fn daemon_addr(addr: &str) -> String {
    format!("unix://{addr}")
}

/// The managed daemon command line (`netbird service run` runs the
/// daemon in the foreground, like the systemd unit's ExecStart).
pub fn daemon_args(instance: &Instance, default_state_dir: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "--daemon-addr".into(),
        daemon_addr(&control_addr(instance, default_state_dir)).into(),
        "service".into(),
        "run".into(),
    ];
    for arg in &instance.extra_args {
        args.push(arg.clone().into());
    }
    args
}

/// The managed daemon environment.
pub fn daemon_env(instance: &Instance, default_state_dir: &Path) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = Vec::new();
    let dir = crate::validate::resolved_state_dir(instance, default_state_dir);
    env.push(("NB_STATE_DIR".into(), dir.display().to_string().into()));
    if instance.userspace {
        env.push(("NB_USE_NETSTACK_MODE".into(), "true".into()));
    }
    if !instance.socks5.is_empty()
        && let Ok(addr) = instance.socks5.parse::<std::net::SocketAddr>()
    {
        env.push((
            "NB_SOCKS5_LISTENER_ADDRESS".into(),
            addr.ip().to_string().into(),
        ));
        env.push((
            "NB_SOCKS5_LISTENER_PORT".into(),
            addr.port().to_string().into(),
        ));
    }
    for extra in &instance.extra_env {
        env.push((extra.name.clone().into(), extra.value.clone().into()));
    }
    env
}

/// `netbird up` for one instance: global control-address flag first, then
/// the join flags.
pub fn up_args(instance: &Instance, default_state_dir: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "--daemon-addr".into(),
        daemon_addr(&control_addr(instance, default_state_dir)).into(),
    ];
    args.push("up".into());
    if !instance.management_url.is_empty() {
        args.push(format!("--management-url={}", instance.management_url).into());
    }
    if instance.accept_routes {
        args.push("--accept-routes".into());
    }
    if !instance.accept_dns {
        args.push("--accept-dns=false".into());
    }
    if instance.block_inbound {
        args.push("--block-inbound".into());
    }
    for arg in &instance.extra_args {
        args.push(arg.clone().into());
    }
    args
}

/// `up` environment: the setup key and the fixed WireGuard port ride
/// here (WP-45 §3.3: 能通过环境变量传递的令牌与密钥不走命令行).
pub fn up_env(instance: &Instance) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = Vec::new();
    if !instance.setup_key.is_empty() {
        env.push(("NB_SETUP_KEY".into(), instance.setup_key.clone().into()));
    }
    if let Some(port) = instance.fixed_port {
        env.push(("NB_WIREGUARD_PORT".into(), port.to_string().into()));
    }
    env
}

fn cli_global(instance: &Instance, default_state_dir: &Path) -> Vec<OsString> {
    vec![
        "--daemon-addr".into(),
        daemon_addr(&control_addr(instance, default_state_dir)).into(),
    ]
}

/// `netbird status --json` against the instance's control address.
pub fn status_args(instance: &Instance, default_state_dir: &Path) -> Vec<OsString> {
    let mut args = cli_global(instance, default_state_dir);
    args.push("status".into());
    args.push("--json".into());
    args
}

/// `netbird down` against the instance's control address.
pub fn down_args(instance: &Instance, default_state_dir: &Path) -> Vec<OsString> {
    let mut args = cli_global(instance, default_state_dir);
    args.push("down".into());
    args
}

/// `netbird logout` against the instance's control address.
pub fn logout_args(instance: &Instance, default_state_dir: &Path) -> Vec<OsString> {
    let mut args = cli_global(instance, default_state_dir);
    args.push("logout".into());
    args
}

/// `netbird version` for the version probe (global control-address flag
/// included so the call targets the same instance context).
pub fn version_args(instance: &Instance, default_state_dir: &Path) -> Vec<OsString> {
    let mut args = cli_global(instance, default_state_dir);
    args.push("version".into());
    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ExtraEnv, MASK};
    use std::path::Path;

    fn sample() -> Instance {
        Instance {
            key: "abc".into(),
            name: "main".into(),
            managed: true,
            userspace: true,
            management_url: "https://mgmt.corp.example".into(),
            setup_key: "nb-secret-key".into(),
            accept_routes: true,
            accept_dns: false,
            block_inbound: true,
            socks5: "127.0.0.1:1080".into(),
            fixed_port: Some(51821),
            extra_args: vec!["--verbose".into()],
            extra_env: vec![ExtraEnv {
                name: "NB_LOG_FORMAT".into(),
                value: "console".into(),
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
    fn netbird_args_snapshot() {
        let instance = sample();
        let dir = Path::new("/state/main");
        assert_eq!(
            text(&daemon_args(&instance, dir)),
            [
                "--daemon-addr",
                "unix:///state/main/netbird.sock",
                "service",
                "run",
                "--verbose",
            ]
        );
        assert_eq!(
            text(&up_args(&instance, dir)),
            [
                "--daemon-addr",
                "unix:///state/main/netbird.sock",
                "up",
                "--management-url=https://mgmt.corp.example",
                "--accept-routes",
                "--accept-dns=false",
                "--block-inbound",
                "--verbose",
            ]
        );
        assert_eq!(
            text(&status_args(&instance, dir)),
            [
                "--daemon-addr",
                "unix:///state/main/netbird.sock",
                "status",
                "--json"
            ]
        );
        assert_eq!(
            text(&down_args(&instance, dir)),
            ["--daemon-addr", "unix:///state/main/netbird.sock", "down"]
        );
        // Custom control address wins; unmanaged targets the system addr.
        let mut custom = instance.clone();
        custom.control_addr = "/run/nb-a.sock".into();
        assert_eq!(text(&status_args(&custom, dir))[1], "unix:///run/nb-a.sock");
        let mut external = instance.clone();
        external.managed = false;
        external.control_addr = String::new();
        assert_eq!(
            text(&logout_args(&external, dir))[1],
            format!("unix://{SYSTEM_CONTROL_ADDR}")
        );
        // Kernel mode: no netstack env, no SOCKS5 env.
        let mut kernel = instance.clone();
        kernel.userspace = false;
        kernel.socks5 = String::new();
        let env = daemon_env(&kernel, dir);
        assert!(
            !env.iter().any(|(key, _)| key == "NB_USE_NETSTACK_MODE"),
            "{env:?}"
        );
        assert!(
            !env.iter()
                .any(|(key, _)| key == "NB_SOCKS5_LISTENER_ADDRESS")
        );
    }

    #[test]
    fn netbird_secrets_in_env_not_args() {
        let instance = sample();
        for args in [
            daemon_args(&instance, Path::new("/s")),
            up_args(&instance, Path::new("/s")),
            status_args(&instance, Path::new("/s")),
            logout_args(&instance, Path::new("/s")),
            down_args(&instance, Path::new("/s")),
        ] {
            let rendered = text(&args).join(" ");
            assert!(
                !rendered.contains("nb-secret-key"),
                "设置密钥绝不能出现在命令行: {rendered}"
            );
        }
        assert_eq!(
            up_env(&instance),
            [
                ("NB_SETUP_KEY".into(), "nb-secret-key".into()),
                ("NB_WIREGUARD_PORT".into(), "51821".into()),
            ]
        );
        // Userspace mode: netstack env plus the SOCKS5 listener split
        // into address and port.
        let env = daemon_env(&instance, Path::new("/state/main"));
        assert!(env.contains(&("NB_USE_NETSTACK_MODE".into(), "true".into())));
        assert!(env.contains(&("NB_SOCKS5_LISTENER_ADDRESS".into(), "127.0.0.1".into())));
        assert!(env.contains(&("NB_SOCKS5_LISTENER_PORT".into(), "1080".into())));
        assert!(env.contains(&("NB_STATE_DIR".into(), "/state/main".into())));
        // Empty key: no env entry.
        let mut quiet = instance.clone();
        quiet.setup_key = String::new();
        assert!(
            !text(&up_args(&quiet, Path::new("/s")))
                .join(" ")
                .contains(MASK)
        );
        assert!(up_env(&quiet).contains(&("NB_WIREGUARD_PORT".into(), "51821".into())));
    }
}
