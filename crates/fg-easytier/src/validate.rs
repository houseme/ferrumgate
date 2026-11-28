//! Validation and normalization (WP-45 §5 step 2): pure functions over the
//! `easytier.json` model. Two layers:
//!
//! - [`validate`] — per-field checks (formats, ceilings) applied to the
//!   whole candidate on every mutation;
//! - [`conflicts`] — resources two simultaneously enabled instances
//!   cannot share (listener ports, local forward binds, TUN device names),
//!   checked on save / enable / batch-enable / copy (WP-45 §3.3). The
//!   runtime re-checks before starting and leaves the later instance
//!   stopped with the conflict reason.

use crate::model::{ExitNodeRole, FileConfig, Instance, VipMode, limits};

/// One problem: the field it concerns (dot path, e.g. `instances.0.peers.2`)
/// and a human readable reason (an i18n key at the API boundary).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Problem {
    pub field: String,
    pub reason: String,
}

/// One conflict between simultaneously enabled instances: the keys of the
/// colliding instances (in order, the later one stays stopped), a stable
/// message key and its parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
    pub keys: Vec<String>,
    pub message_key: &'static str,
    pub params: Vec<(String, String)>,
}

pub mod messages {
    pub const LISTENER_PORT: &str = "easytier.conflict.listenerPort";
    pub const FORWARD_BIND: &str = "easytier.conflict.forwardBind";
    pub const DEV_NAME: &str = "easytier.conflict.devName";
}

/// Applies defaults and light normalization: trims every string field,
/// drops empty entries from list fields and normalizes bare `host:port`
/// peers to `tcp://host:port`.
pub fn normalize(mut config: FileConfig) -> FileConfig {
    config.settings.program_path = config.settings.program_path.trim().to_owned();
    config.settings.download_proxy = config.settings.download_proxy.trim().to_owned();
    for instance in &mut config.instances {
        normalize_instance(instance);
    }
    config
}

fn normalize_instance(instance: &mut Instance) {
    instance.key = instance.key.trim().to_owned();
    instance.name = instance.name.trim().to_owned();
    instance.group = instance.group.trim().to_owned();
    instance.remark = instance.remark.trim().to_owned();
    instance.network_name = instance.network_name.trim().to_owned();
    instance.network_secret = instance.network_secret.trim().to_owned();
    instance.dev_name = instance.dev_name.trim().to_owned();
    instance.peers = instance
        .peers
        .iter()
        .map(|peer| {
            let peer = peer.trim();
            if is_url(peer) {
                peer.to_owned()
            } else {
                format!("tcp://{peer}")
            }
        })
        .filter(|peer| !peer.is_empty())
        .collect();
    for field in [
        &mut instance.listeners,
        &mut instance.port_forwards,
        &mut instance.proxy_networks,
        &mut instance.exit_nodes,
        &mut instance.extra_args,
    ] {
        field.retain(|entry| !entry.trim().is_empty());
        for entry in field.iter_mut() {
            *entry = entry.trim().to_owned();
        }
    }
    instance.extra_env.retain(|env| !env.name.trim().is_empty());
    for env in &mut instance.extra_env {
        env.name = env.name.trim().to_owned();
        env.value = env.value.trim().to_owned();
    }
    if instance.virtual_ip == VipMode::Fixed(String::new()) {
        instance.virtual_ip = VipMode::Auto;
    }
}

fn is_url(text: &str) -> bool {
    text.contains("://")
}

/// Collects every validation problem in the candidate. An empty result
/// means the config can be persisted and applied.
pub fn validate(config: &FileConfig) -> Vec<Problem> {
    let mut problems = Vec::new();
    if config.instances.len() > limits::INSTANCES_MAX {
        problems.push(Problem {
            field: "instances".into(),
            reason: format!("最多 {} 个实例", limits::INSTANCES_MAX),
        });
    }
    if config.settings.download_proxy.len() > 512 {
        problems.push(Problem {
            field: "settings.downloadProxy".into(),
            reason: "下载代理地址过长".into(),
        });
    }
    let mut names: Vec<&str> = Vec::new();
    for (index, instance) in config.instances.iter().enumerate() {
        let prefix = format!("instances.{index}");
        problems.extend(validate_instance(instance, &prefix));
        if !instance.name.is_empty() {
            if names.contains(&instance.name.as_str()) {
                problems.push(Problem {
                    field: format!("{prefix}.name"),
                    reason: "实例名称不能重复".into(),
                });
            }
            names.push(&instance.name);
        }
    }
    problems
}

fn validate_instance(instance: &Instance, prefix: &str) -> Vec<Problem> {
    let mut problems = Vec::new();
    if instance.key.is_empty() {
        problems.push(Problem {
            field: format!("{prefix}.key"),
            reason: "缺少实例 key".into(),
        });
    }
    if instance.name.is_empty() {
        problems.push(Problem {
            field: format!("{prefix}.name"),
            reason: "实例名称不能为空".into(),
        });
    } else if instance.name.chars().count() > limits::NAME_MAX_CHARS {
        problems.push(Problem {
            field: format!("{prefix}.name"),
            reason: format!("实例名称最多 {} 个字符", limits::NAME_MAX_CHARS),
        });
    }
    if instance.group.chars().count() > limits::GROUP_MAX_CHARS {
        problems.push(Problem {
            field: format!("{prefix}.group"),
            reason: format!("分组最多 {} 个字符", limits::GROUP_MAX_CHARS),
        });
    }
    if instance.remark.chars().count() > limits::REMARK_MAX_CHARS {
        problems.push(Problem {
            field: format!("{prefix}.remark"),
            reason: format!("备注最多 {} 个字符", limits::REMARK_MAX_CHARS),
        });
    }
    // Network name is required: without it the node has no identity, and a
    // shared network without a secret would be open to anyone who guesses
    // the name.
    if instance.network_name.is_empty() {
        problems.push(Problem {
            field: format!("{prefix}.networkName"),
            reason: "网络名称不能为空".into(),
        });
    } else if instance.network_name.chars().count() > limits::NETWORK_NAME_MAX_CHARS {
        problems.push(Problem {
            field: format!("{prefix}.networkName"),
            reason: format!("网络名称最多 {} 个字符", limits::NETWORK_NAME_MAX_CHARS),
        });
    }
    if instance.network_secret.chars().count() > limits::NETWORK_SECRET_MAX_CHARS {
        problems.push(Problem {
            field: format!("{prefix}.networkSecret"),
            reason: format!("网络密钥最多 {} 个字符", limits::NETWORK_SECRET_MAX_CHARS),
        });
    }
    if instance.peers.len() > limits::PEERS_MAX {
        problems.push(Problem {
            field: format!("{prefix}.peers"),
            reason: format!("节点地址最多 {} 条", limits::PEERS_MAX),
        });
    }
    for (index, peer) in instance.peers.iter().enumerate() {
        if parse_url(peer).is_none() {
            problems.push(Problem {
                field: format!("{prefix}.peers.{index}"),
                reason: "节点地址必须是 协议://地址:端口 形式".into(),
            });
        }
    }
    if instance.listeners.len() > limits::LISTENERS_MAX {
        problems.push(Problem {
            field: format!("{prefix}.listeners"),
            reason: format!("监听地址最多 {} 条", limits::LISTENERS_MAX),
        });
    }
    for (index, listener) in instance.listeners.iter().enumerate() {
        if parse_url(listener).is_none() {
            problems.push(Problem {
                field: format!("{prefix}.listeners.{index}"),
                reason: "监听地址必须是 协议://地址:端口 形式".into(),
            });
        }
    }
    if let VipMode::Fixed(ip) = &instance.virtual_ip
        && ip.parse::<std::net::Ipv4Addr>().is_err()
    {
        problems.push(Problem {
            field: format!("{prefix}.virtualIp"),
            reason: "虚拟 IP 必须是 IPv4 地址".into(),
        });
    }
    if instance.port_forwards.len() > limits::PORT_FORWARDS_MAX {
        problems.push(Problem {
            field: format!("{prefix}.portForwards"),
            reason: format!("端口转发最多 {} 条", limits::PORT_FORWARDS_MAX),
        });
    }
    for (index, forward) in instance.port_forwards.iter().enumerate() {
        if parse_port_forward(forward).is_none() {
            problems.push(Problem {
                field: format!("{prefix}.portForwards.{index}"),
                reason: "端口转发必须是 tcp://绑定/目标 形式（协议 tcp 或 udp）".into(),
            });
        }
    }
    if instance.proxy_networks.len() > limits::PROXY_NETWORKS_MAX {
        problems.push(Problem {
            field: format!("{prefix}.proxyNetworks"),
            reason: format!("子网代理最多 {} 条", limits::PROXY_NETWORKS_MAX),
        });
    }
    for (index, proxy) in instance.proxy_networks.iter().enumerate() {
        if parse_proxy_network(proxy).is_none() {
            problems.push(Problem {
                field: format!("{prefix}.proxyNetworks.{index}"),
                reason: "子网代理必须是 CIDR->CIDR 映射".into(),
            });
        }
    }
    if instance.exit_nodes.len() > limits::EXIT_NODES_MAX {
        problems.push(Problem {
            field: format!("{prefix}.exitNodes"),
            reason: format!("出口节点最多 {} 个", limits::EXIT_NODES_MAX),
        });
    }
    if instance.exit_node != ExitNodeRole::Use && !instance.exit_nodes.is_empty() {
        problems.push(Problem {
            field: format!("{prefix}.exitNodes"),
            reason: "出口节点列表只在出口节点角色为 use 时生效".into(),
        });
    }
    for (index, ip) in instance.exit_nodes.iter().enumerate() {
        if ip.parse::<std::net::IpAddr>().is_err() {
            problems.push(Problem {
                field: format!("{prefix}.exitNodes.{index}"),
                reason: "出口节点必须是 IP 地址".into(),
            });
        }
    }
    if !instance.dev_name.is_empty() {
        let ok = instance.dev_name.len() <= 15
            && instance
                .dev_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !ok {
            problems.push(Problem {
                field: format!("{prefix}.devName"),
                reason: "网卡名只能包含字母、数字与下划线，最多 15 个字符".into(),
            });
        }
    }
    if instance.extra_args.len() > limits::EXTRA_ARGS_MAX {
        problems.push(Problem {
            field: format!("{prefix}.extraArgs"),
            reason: format!("额外参数最多 {} 条", limits::EXTRA_ARGS_MAX),
        });
    }
    for (index, arg) in instance.extra_args.iter().enumerate() {
        if arg.chars().count() > limits::EXTRA_ARG_MAX_CHARS {
            problems.push(Problem {
                field: format!("{prefix}.extraArgs.{index}"),
                reason: format!("额外参数最多 {} 个字符", limits::EXTRA_ARG_MAX_CHARS),
            });
        }
        if is_secret_arg(arg) {
            problems.push(Problem {
                field: format!("{prefix}.extraArgs.{index}"),
                reason: "网络密钥只能经环境变量 ET_NETWORK_SECRET 传递，不能写在额外参数里".into(),
            });
        }
    }
    if instance.extra_env.len() > limits::EXTRA_ENV_MAX {
        problems.push(Problem {
            field: format!("{prefix}.extraEnv"),
            reason: format!("环境变量最多 {} 条", limits::EXTRA_ENV_MAX),
        });
    }
    for (index, env) in instance.extra_env.iter().enumerate() {
        let name_ok = !env.name.is_empty()
            && env.name.chars().count() <= limits::ENV_NAME_MAX_CHARS
            && env
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            && env
                .name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
        if !name_ok {
            problems.push(Problem {
                field: format!("{prefix}.extraEnv.{index}.name"),
                reason: "环境变量名只能包含字母、数字与下划线，且以字母或下划线开头".into(),
            });
        }
        if env.value.chars().count() > limits::ENV_VALUE_MAX_CHARS {
            problems.push(Problem {
                field: format!("{prefix}.extraEnv.{index}.value"),
                reason: format!("环境变量值最多 {} 个字符", limits::ENV_VALUE_MAX_CHARS),
            });
        }
    }
    problems
}

/// `--network-secret` in any form (space separated would be the next
/// argument, so the flag itself is the rejection point; the `=` form is
/// matched too).
pub fn is_secret_arg(arg: &str) -> bool {
    let flag = arg.trim();
    flag == "--network-secret"
        || flag == "--network-secret-stdin"
        || flag.starts_with("--network-secret=")
        || flag.starts_with("-s=")
        || flag == "-s"
}

/// Parsed `proto://host:port` URL (EasyTier scheme subset).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlSpec {
    pub protocol: String,
    pub host: String,
    pub port: u16,
}

pub fn parse_url(text: &str) -> Option<UrlSpec> {
    let (protocol, rest) = text.split_once("://")?;
    if !matches!(protocol, "tcp" | "udp" | "wg" | "ws" | "wss" | "quic") {
        return None;
    }
    let rest = rest.trim();
    if rest.is_empty() {
        // Wildcard listeners (`tcp://`) are allowed for listeners; they
        // carry no port for conflict purposes.
        return None;
    }
    // Host may be an IPv6 literal in brackets; EasyTier endpoints used by
    // this module are normally IPv4 host:port pairs.
    let (host, port) = rest.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    Some(UrlSpec {
        protocol: protocol.to_owned(),
        host: host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned(),
        port,
    })
}

/// Parsed port forward `tcp://bind/target` where bind is `host:port` and
/// target is `ip:port` (WP-45 §3.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortForwardSpec {
    pub protocol: String,
    pub bind_host: String,
    pub bind_port: u16,
    pub target: String,
    pub target_port: u16,
}

pub fn parse_port_forward(text: &str) -> Option<PortForwardSpec> {
    let (protocol, rest) = text.split_once("://")?;
    if !matches!(protocol, "tcp" | "udp") {
        return None;
    }
    let (bind, target) = rest.split_once('/')?;
    let (bind_host, bind_port) = bind.rsplit_once(':')?;
    let (target_ip, target_port) = target.rsplit_once(':')?;
    if bind_host.is_empty() || target_ip.is_empty() {
        return None;
    }
    Some(PortForwardSpec {
        protocol: protocol.to_owned(),
        bind_host: bind_host.to_owned(),
        bind_port: bind_port.parse::<u16>().ok()?,
        target: target_ip.to_owned(),
        target_port: target_port.parse::<u16>().ok()?,
    })
}

/// Parsed subnet proxy `cidr->cidr`.
pub fn parse_proxy_network(text: &str) -> Option<(String, String)> {
    let (from, to) = text.split_once("->")?;
    let from = from.trim();
    let to = to.trim();
    let ok = |cidr: &str| -> bool {
        match cidr.split_once('/') {
            Some((ip, mask)) => {
                ip.parse::<std::net::IpAddr>().is_ok() && mask.parse::<u8>().is_ok()
            }
            None => false,
        }
    };
    if from.is_empty() || to.is_empty() || !ok(from) || !ok(to) {
        return None;
    }
    Some((from.to_owned(), to.to_owned()))
}

fn is_wildcard(host: &str) -> bool {
    matches!(host, "0.0.0.0" | "::" | "*" | "")
}

/// Conflicts between simultaneously enabled instances (WP-45 §3.3):
/// listener ports (TCP and UDP judged separately), local forward binds,
/// and TUN device names. `instances` must be in saved order; conflicts are
/// reported against the earlier instance so the runtime can leave the
/// later one stopped.
pub fn conflicts(instances: &[Instance]) -> Vec<Conflict> {
    let enabled: Vec<&Instance> = instances
        .iter()
        .filter(|instance| instance.enable)
        .collect();
    let mut conflicts = Vec::new();
    for (index, later) in enabled.iter().enumerate() {
        for earlier in &enabled[..index] {
            // Listener ports: same protocol family and overlapping bind.
            for a in &earlier.listeners {
                let Some(a) = parse_url(a) else { continue };
                for b in &later.listeners {
                    let Some(b) = parse_url(b) else { continue };
                    if a.protocol == b.protocol
                        && a.port == b.port
                        && (is_wildcard(&a.host) || is_wildcard(&b.host) || a.host == b.host)
                    {
                        conflicts.push(Conflict {
                            keys: vec![earlier.key.clone(), later.key.clone()],
                            message_key: messages::LISTENER_PORT,
                            params: vec![
                                ("protocol".into(), a.protocol.clone()),
                                ("port".into(), a.port.to_string()),
                            ],
                        });
                    }
                }
            }
            // Local forward binds: host and port both matter (a non-wildcard
            // host can share the port with another host).
            for a in &earlier.port_forwards {
                let Some(a) = parse_port_forward(a) else {
                    continue;
                };
                for b in &later.port_forwards {
                    let Some(b) = parse_port_forward(b) else {
                        continue;
                    };
                    if a.protocol == b.protocol
                        && a.bind_port == b.bind_port
                        && (is_wildcard(&a.bind_host)
                            || is_wildcard(&b.bind_host)
                            || a.bind_host == b.bind_host)
                    {
                        conflicts.push(Conflict {
                            keys: vec![earlier.key.clone(), later.key.clone()],
                            message_key: messages::FORWARD_BIND,
                            params: vec![(
                                "bind".into(),
                                format!("{}:{}", a.bind_host, a.bind_port),
                            )],
                        });
                    }
                }
            }
            // TUN device names: an empty name falls back to the program
            // default, which two TUN instances would both pick.
            if earlier.tun
                && later.tun
                && (earlier.dev_name == later.dev_name
                    || earlier.dev_name.is_empty()
                    || later.dev_name.is_empty())
            {
                conflicts.push(Conflict {
                    keys: vec![earlier.key.clone(), later.key.clone()],
                    message_key: messages::DEV_NAME,
                    params: vec![(
                        "dev".into(),
                        if earlier.dev_name.is_empty() {
                            later.dev_name.clone()
                        } else {
                            earlier.dev_name.clone()
                        },
                    )],
                });
            }
        }
    }
    conflicts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ExtraEnv, MASK};

    fn instance(key: &str, name: &str) -> Instance {
        Instance {
            key: key.into(),
            name: name.into(),
            network_name: "mesh".into(),
            ..Instance::default()
        }
    }

    #[test]
    fn easytier_validate_field_limits() {
        let mut config = FileConfig::default();
        let mut long = instance("a", "a");
        long.network_name = "x".repeat(limits::NETWORK_NAME_MAX_CHARS + 1);
        long.network_secret = "s".repeat(limits::NETWORK_SECRET_MAX_CHARS + 1);
        long.peers = vec!["tcp://h:1".into(); limits::PEERS_MAX + 1];
        long.listeners = vec!["tcp://0.0.0.0:11010".into(); limits::LISTENERS_MAX + 1];
        long.port_forwards =
            vec!["tcp://127.0.0.1:2222/10.1.1.1:22".into(); limits::PORT_FORWARDS_MAX + 1];
        long.extra_args = vec!["--x".into(); limits::EXTRA_ARGS_MAX + 1];
        long.extra_env = vec![
            ExtraEnv {
                name: "A".into(),
                value: "b".into(),
            };
            limits::EXTRA_ENV_MAX + 1
        ];
        long.dev_name = "toolongdevicename".into();
        long.virtual_ip = VipMode::Fixed("999.1.1.1".into());
        long.exit_node = ExitNodeRole::None;
        long.exit_nodes = vec!["10.1.1.1".into()];
        config.instances.push(long);
        let problems = validate(&config);
        let fields: Vec<&str> = problems.iter().map(|p| p.field.as_str()).collect();
        for expected in [
            "instances.0.networkName",
            "instances.0.networkSecret",
            "instances.0.peers",
            "instances.0.listeners",
            "instances.0.portForwards",
            "instances.0.extraArgs",
            "instances.0.extraEnv",
            "instances.0.devName",
            "instances.0.virtualIp",
            "instances.0.exitNodes",
        ] {
            assert!(
                fields.iter().any(|field| field.starts_with(expected)),
                "缺少 {expected} 的问题: {fields:?}"
            );
        }
    }

    #[test]
    fn easytier_secret_rejected_in_extra_args() {
        let mut config = FileConfig::default();
        let mut item = instance("a", "a");
        item.extra_args = vec!["--network-secret".into(), "hunter2".into()];
        config.instances.push(item);
        assert!(
            validate(&config)
                .iter()
                .any(|p| p.field == "instances.0.extraArgs.0"),
            "--network-secret 旗标必须被拒绝"
        );
        let mut config = FileConfig::default();
        let mut item = instance("a", "a");
        item.extra_args = vec!["--network-secret=hunter2".into()];
        config.instances.push(item);
        assert!(
            validate(&config)
                .iter()
                .any(|p| p.field == "instances.0.extraArgs.0"),
            "--network-secret= 形式必须被拒绝"
        );
    }

    #[test]
    fn easytier_port_forward_format() {
        assert!(parse_port_forward("tcp://127.0.0.1:2222/10.126.126.1:22").is_some());
        assert!(parse_port_forward("udp://0.0.0.0:53/10.126.126.1:53").is_some());
        assert!(parse_port_forward("icmp://127.0.0.1:1/10.0.0.1:2").is_none());
        assert!(parse_port_forward("tcp://127.0.0.1:2222").is_none());
        assert!(parse_port_forward("tcp://127.0.0.1:2222/10.1.1.1:notaport").is_none());
        assert_eq!(
            parse_port_forward("tcp://127.0.0.1:2222/10.126.126.1:22").unwrap(),
            PortForwardSpec {
                protocol: "tcp".into(),
                bind_host: "127.0.0.1".into(),
                bind_port: 2222,
                target: "10.126.126.1".into(),
                target_port: 22,
            }
        );
        // Peer and listener URL formats.
        assert!(parse_url("tcp://public.easytier.cn:11010").is_some());
        assert!(parse_url("wg://[::]:11011").is_some());
        assert!(parse_url("ftp://host:1").is_none());
        assert!(parse_url("tcp://host:notaport").is_none());
        assert_eq!(
            normalize(FileConfig {
                instances: vec![Instance {
                    peers: vec!["  public.easytier.cn:11010 ".into()],
                    ..Instance::default()
                }],
                ..FileConfig::default()
            })
            .instances[0]
                .peers,
            vec!["tcp://public.easytier.cn:11010"]
        );
    }

    #[test]
    fn easytier_conflicts_ports_and_dev_name() {
        let mut a = instance("key-a", "first");
        a.enable = true;
        a.listeners = vec!["tcp://0.0.0.0:11010".into(), "udp://0.0.0.0:11010".into()];
        a.port_forwards = vec!["tcp://127.0.0.1:2222/10.1.1.1:22".into()];
        a.tun = true;
        a.dev_name = "etun0".into();
        let mut b = instance("key-b", "second");
        b.enable = true;
        b.listeners = vec!["tcp://127.0.0.1:11010".into()];
        b.port_forwards = vec!["tcp://127.0.0.1:2222/10.2.2.2:80".into()];
        b.tun = true;
        b.dev_name = "etun0".into();
        let found = conflicts(&[a.clone(), b.clone()]);
        let keys: Vec<&'static str> = found.iter().map(|c| c.message_key).collect();
        assert!(keys.contains(&messages::LISTENER_PORT), "{found:?}");
        assert!(keys.contains(&messages::FORWARD_BIND), "{found:?}");
        assert!(keys.contains(&messages::DEV_NAME), "{found:?}");
        assert!(found.iter().all(|c| c.keys == ["key-a", "key-b"]));
        // UDP and TCP are judged separately: a TCP listener may share the
        // port number with a UDP listener.
        let mut c = instance("key-c", "third");
        c.enable = true;
        c.listeners = vec!["udp://0.0.0.0:11011".into()];
        let tcp_only = conflicts(&[
            Instance {
                listeners: vec!["tcp://0.0.0.0:11011".into()],
                ..a.clone()
            },
            c.clone(),
        ]);
        assert!(tcp_only.is_empty());
        // Disabled instances never conflict.
        let mut off = b.clone();
        off.enable = false;
        assert!(conflicts(&[a.clone(), off]).is_empty());
        // Two TUN instances with empty device names conflict too.
        let mut d = instance("key-d", "fourth");
        d.enable = true;
        d.tun = true;
        let mut e = instance("key-e", "fifth");
        e.enable = true;
        e.tun = true;
        assert_eq!(conflicts(&[d, e])[0].message_key, messages::DEV_NAME);
    }

    #[test]
    fn easytier_normalize_trims_and_masks_nothing() {
        let config = FileConfig {
            instances: vec![Instance {
                key: " k ".into(),
                name: " main ".into(),
                network_secret: " s3cret ".into(),
                extra_env: vec![ExtraEnv {
                    name: "ET_LOG ".into(),
                    value: " info ".into(),
                }],
                ..Instance::default()
            }],
            ..FileConfig::default()
        };
        let normalized = normalize(config);
        assert_eq!(normalized.instances[0].key, "k");
        assert_eq!(normalized.instances[0].name, "main");
        assert_eq!(normalized.instances[0].network_secret, "s3cret");
        assert_eq!(normalized.instances[0].extra_env[0].value, "info");
        // Normalization must not touch secret masking.
        assert_ne!(normalized.instances[0].network_secret, MASK);
    }
}
