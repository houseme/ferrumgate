//! Launch arguments and environment for one instance (WP-45 §5 step 3).
//! Pure functions: everything is derived from the instance model plus the
//! randomly allocated management port.
//!
//! Safety properties (asserted by tests, checked again in review):
//!
//! - the network secret goes to `easytier-core` only via the
//!   `ET_NETWORK_SECRET` environment variable, never on the command line;
//! - the management RPC portal binds to `127.0.0.1` only, with
//!   `--rpc-portal-whitelist` restricted to the loopback addresses;
//! - nothing here is ever formatted into a log line (the supervisor logs
//!   process output only, and `Owner` labels carry no arguments).

use std::{ffi::OsString, net::SocketAddr};

use crate::model::{ExitNodeRole, Instance, VipMode};

/// The management RPC portal listen address handed to `--rpc-portal`. The
/// runtime allocates a random free port on the loopback interface per
/// instance; this function only formats it.
pub fn portal_address(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Sources allowed to call the management portal (WP-45 §3.4): the local
/// loopback only.
pub const PORTAL_WHITELIST: &str = "127.0.0.1/32,::1/128";

/// `easytier-core` command line for one instance. Peers are positional
/// arguments at the end, as the program expects.
pub fn core_args(instance: &Instance, portal: u16) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();
    args.push("--network-name".into());
    args.push(instance.network_name.clone().into());
    match &instance.virtual_ip {
        VipMode::Fixed(ip) => {
            args.push(format!("--virtual-ipv4={ip}").into());
        }
        VipMode::Auto | VipMode::None => {}
    }
    // No TUN device: the instance opted out, or has no virtual IP at all
    // (forwarding only, WP-45 §3.3).
    if !instance.tun || instance.virtual_ip == VipMode::None {
        args.push("--no-tun".into());
    }
    // Listeners: empty list means "do not listen, dial only" (WP-45 §3.3).
    if instance.listeners.is_empty() {
        args.push("--listeners=".into());
    } else {
        args.push(format!("--listeners={}", instance.listeners.join(",")).into());
    }
    for forward in &instance.port_forwards {
        args.push("--port-forward".into());
        args.push(forward.clone().into());
    }
    for proxy in &instance.proxy_networks {
        args.push(format!("--proxy-networks={proxy}").into());
    }
    match instance.exit_node {
        ExitNodeRole::Advertise => args.push("--enable-exit-node".into()),
        ExitNodeRole::Use => {
            if !instance.exit_nodes.is_empty() {
                args.push(format!("--exit-nodes={}", instance.exit_nodes.join(",")).into());
            }
        }
        ExitNodeRole::None => {}
    }
    if instance.latency_first {
        args.push("--latency-first".into());
    }
    if instance.kcp_proxy {
        args.push("--enable-kcp-proxy".into());
    }
    if instance.quic_proxy {
        args.push("--enable-quic-proxy".into());
    }
    if !instance.dev_name.is_empty() {
        args.push(format!("--dev-name={}", instance.dev_name).into());
    }
    // Management portal: loopback only, source whitelist next to it
    // (WP-45 §3.3: 管理端口只监听 127.0.0.1 的随机端口并限定来源为本机回环).
    args.push(format!("--rpc-portal={}", portal_address(portal)).into());
    args.push(format!("--rpc-portal-whitelist={PORTAL_WHITELIST}").into());
    for arg in &instance.extra_args {
        args.push(arg.clone().into());
    }
    for peer in &instance.peers {
        args.push(peer.clone().into());
    }
    args
}

/// `easytier-core` environment. The secret travels here and only here.
pub fn core_env(instance: &Instance) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = Vec::new();
    if !instance.network_secret.is_empty() {
        env.push((
            "ET_NETWORK_SECRET".into(),
            instance.network_secret.clone().into(),
        ));
    }
    for extra in &instance.extra_env {
        env.push((extra.name.clone().into(), extra.value.clone().into()));
    }
    env
}

/// `easytier-cli` arguments for one status query against the instance's
/// management portal.
pub fn cli_args(portal: u16, command: &str) -> Vec<OsString> {
    vec![
        "--rpc-portal".into(),
        portal_address(portal).to_string().into(),
        command.into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ExtraEnv, limits};

    fn instance() -> Instance {
        Instance {
            key: "abc".into(),
            name: "main".into(),
            network_name: "mesh".into(),
            network_secret: "hunter2".into(),
            peers: vec![
                "tcp://public.easytier.cn:11010".into(),
                "udp://10.0.0.2:11010".into(),
            ],
            listeners: vec!["tcp://0.0.0.0:11010".into(), "udp://0.0.0.0:11010".into()],
            virtual_ip: VipMode::Fixed("10.126.126.1".into()),
            tun: true,
            port_forwards: vec!["tcp://127.0.0.1:2222/10.126.126.1:22".into()],
            proxy_networks: vec!["192.168.1.0/24->10.1.0.0/24".into()],
            exit_node: ExitNodeRole::Advertise,
            latency_first: true,
            kcp_proxy: true,
            quic_proxy: true,
            dev_name: "etun0".into(),
            extra_args: vec!["--verbose".into()],
            extra_env: vec![ExtraEnv {
                name: "ET_LOG".into(),
                value: "info".into(),
            }],
            ..Instance::default()
        }
    }

    fn text(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn easytier_args_snapshot() {
        let args = text(&core_args(&instance(), 45679));
        let expected = [
            "--network-name",
            "mesh",
            "--virtual-ipv4=10.126.126.1",
            "--listeners=tcp://0.0.0.0:11010,udp://0.0.0.0:11010",
            "--port-forward",
            "tcp://127.0.0.1:2222/10.126.126.1:22",
            "--proxy-networks=192.168.1.0/24->10.1.0.0/24",
            "--enable-exit-node",
            "--latency-first",
            "--enable-kcp-proxy",
            "--enable-quic-proxy",
            "--dev-name=etun0",
            "--rpc-portal=127.0.0.1:45679",
            "--rpc-portal-whitelist=127.0.0.1/32,::1/128",
            "--verbose",
            "tcp://public.easytier.cn:11010",
            "udp://10.0.0.2:11010",
        ];
        assert_eq!(args, expected);
    }

    #[test]
    fn easytier_secrets_in_env_not_args() {
        let instance = instance();
        let args = text(&core_args(&instance, 40000));
        assert!(
            !args.iter().any(|arg| arg.contains("hunter2")),
            "网络密钥绝不能出现在命令行: {args:?}"
        );
        let env = core_env(&instance);
        assert!(env.contains(&("ET_NETWORK_SECRET".into(), "hunter2".into())));
        // Userspace (no TUN) and forwarding-only instances add --no-tun.
        let mut no_tun = instance.clone();
        no_tun.tun = false;
        assert!(text(&core_args(&no_tun, 1)).contains(&"--no-tun".to_owned()));
        let mut vip_none = instance.clone();
        vip_none.virtual_ip = VipMode::None;
        assert!(text(&core_args(&vip_none, 1)).contains(&"--no-tun".to_owned()));
        let mut auto = instance.clone();
        auto.virtual_ip = VipMode::Auto;
        assert!(!text(&core_args(&auto, 1)).contains(&"--virtual-ipv4=10.126.126.1".to_owned()));
        // Empty listeners dial only.
        let mut dial = instance.clone();
        dial.listeners = vec![];
        assert!(text(&core_args(&dial, 1)).contains(&"--listeners=".to_owned()));
        // Role "use" passes the exit node list; role none passes neither.
        let mut use_role = instance.clone();
        use_role.exit_node = ExitNodeRole::Use;
        use_role.exit_nodes = vec!["10.126.126.9".into()];
        let args = text(&core_args(&use_role, 1));
        assert!(args.contains(&"--exit-nodes=10.126.126.9".to_owned()));
        assert!(!args.contains(&"--enable-exit-node".to_owned()));
        let mut quiet = instance.clone();
        quiet.exit_node = ExitNodeRole::None;
        quiet.latency_first = false;
        quiet.kcp_proxy = false;
        quiet.quic_proxy = false;
        quiet.dev_name = String::new();
        let args = text(&core_args(&quiet, 1));
        for absent in [
            "--enable-exit-node",
            "--latency-first",
            "--enable-kcp-proxy",
            "--enable-quic-proxy",
            "--dev-name=",
        ] {
            assert!(!args.iter().any(|arg| arg.starts_with(absent)), "{args:?}");
        }
    }

    #[test]
    fn easytier_rpc_portal_loopback_and_whitelist() {
        // The portal address is always the loopback, whatever port was
        // allocated.
        let args = text(&core_args(&instance(), 0));
        let portal = args
            .iter()
            .find(|arg| arg.starts_with("--rpc-portal="))
            .expect("portal flag");
        assert_eq!(portal, "--rpc-portal=127.0.0.1:0");
        let whitelist = args
            .iter()
            .find(|arg| arg.starts_with("--rpc-portal-whitelist="))
            .expect("whitelist flag");
        assert_eq!(
            whitelist,
            &format!("--rpc-portal-whitelist={PORTAL_WHITELIST}")
        );
        assert_eq!(PORTAL_WHITELIST, "127.0.0.1/32,::1/128");
        // Status queries run against the same portal.
        assert_eq!(
            text(&cli_args(45679, "node")),
            ["--rpc-portal", "127.0.0.1:45679", "node"]
        );
    }

    #[test]
    fn easytier_extra_args_are_appended_verbatim() {
        let mut instance = instance();
        instance.extra_args = (0..limits::EXTRA_ARGS_MAX)
            .map(|i| format!("--flag{i}"))
            .collect();
        let args = text(&core_args(&instance, 1));
        // 14 fixed entries for this instance shape (see the snapshot test)
        // plus every extra argument, then the two peers.
        assert_eq!(args.len(), 14 + limits::EXTRA_ARGS_MAX + 2);
    }
}
