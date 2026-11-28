//! Validation and normalization (WP-45 §5 step 6): pure functions over the
//! `tailscale.json` model. Beyond per-field checks, [`conflicts`] reports
//! the resources two simultaneously enabled instances cannot share:
//! at most one kernel-mode instance (routing tables and firewall marks are
//! fixed), and the control socket, state directory and fixed WireGuard
//! port are exclusive (WP-45 §3.3). [`warnings`] collects the
//! advisory-only problems (the unauthenticated SOCKS5 proxy on a
//! non-loopback bind).

use std::net::SocketAddr;

use crate::model::{ExitNodeRole, FileConfig, Instance, limits};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Problem {
    pub field: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
    pub keys: Vec<String>,
    pub message_key: &'static str,
    pub params: Vec<(String, String)>,
}

pub mod messages {
    pub const KERNEL_MODE: &str = "tailscale.conflict.kernelMode";
    pub const SOCKET: &str = "tailscale.conflict.socket";
    pub const STATE_DIR: &str = "tailscale.conflict.stateDir";
    pub const PORT: &str = "tailscale.conflict.port";
}

pub const SOCKS5_BIND_WARNING: &str = "tailscale.warning.socks5Bind";

/// Applies defaults and light normalization: trims string fields and drops
/// empty list entries.
pub fn normalize(mut config: FileConfig) -> FileConfig {
    config.settings.program_path = config.settings.program_path.trim().to_owned();
    config.settings.download_proxy = config.settings.download_proxy.trim().to_owned();
    for instance in &mut config.instances {
        instance.key = instance.key.trim().to_owned();
        instance.name = instance.name.trim().to_owned();
        instance.group = instance.group.trim().to_owned();
        instance.remark = instance.remark.trim().to_owned();
        instance.auth_key = instance.auth_key.trim().to_owned();
        instance.login_server = instance.login_server.trim().to_owned();
        instance.exit_node_target = instance.exit_node_target.trim().to_owned();
        instance.socks5 = instance.socks5.trim().to_owned();
        instance.socket = instance.socket.trim().to_owned();
        instance.state_dir = instance.state_dir.trim().to_owned();
        for field in [&mut instance.advertise_routes, &mut instance.extra_args] {
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
    }
    config
}

/// Collects every validation problem in the candidate.
pub fn validate(config: &FileConfig) -> Vec<Problem> {
    let mut problems = Vec::new();
    if config.instances.len() > limits::INSTANCES_MAX {
        problems.push(Problem {
            field: "instances".into(),
            reason: format!("最多 {} 个实例", limits::INSTANCES_MAX),
        });
    }
    let mut names: Vec<&str> = Vec::new();
    for (index, instance) in config.instances.iter().enumerate() {
        let prefix = format!("instances.{index}");
        problems.extend(validate_instance(instance, &prefix));
        if !instance.name.is_empty() && names.contains(&instance.name.as_str()) {
            problems.push(Problem {
                field: format!("{prefix}.name"),
                reason: "实例名称不能重复".into(),
            });
        }
        if !instance.name.is_empty() {
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
    if instance.login_server.chars().count() > limits::LOGIN_SERVER_MAX_CHARS {
        problems.push(Problem {
            field: format!("{prefix}.loginServer"),
            reason: format!(
                "登录服务器地址最多 {} 个字符",
                limits::LOGIN_SERVER_MAX_CHARS
            ),
        });
    } else if !instance.login_server.is_empty()
        && !instance.login_server.starts_with("http://")
        && !instance.login_server.starts_with("https://")
    {
        problems.push(Problem {
            field: format!("{prefix}.loginServer"),
            reason: "登录服务器地址必须以 http:// 或 https:// 开头".into(),
        });
    }
    if instance.advertise_routes.len() > limits::ADVERTISE_ROUTES_MAX {
        problems.push(Problem {
            field: format!("{prefix}.advertiseRoutes"),
            reason: format!("通告路由最多 {} 条", limits::ADVERTISE_ROUTES_MAX),
        });
    }
    for (index, route) in instance.advertise_routes.iter().enumerate() {
        if !is_route(route) {
            problems.push(Problem {
                field: format!("{prefix}.advertiseRoutes.{index}"),
                reason: "通告路由必须是 IP 地址或 CIDR".into(),
            });
        }
    }
    if instance.exit_node == ExitNodeRole::Use && instance.exit_node_target.is_empty() {
        problems.push(Problem {
            field: format!("{prefix}.exitNodeTarget"),
            reason: "使用出口节点时必须填写目标节点".into(),
        });
    }
    if !instance.socks5.is_empty() && instance.socks5.parse::<SocketAddr>().is_err() {
        problems.push(Problem {
            field: format!("{prefix}.socks5"),
            reason: "SOCKS5 地址必须是 IP:端口".into(),
        });
    }
    if !instance.socks5.is_empty() && !instance.userspace && instance.managed {
        problems.push(Problem {
            field: format!("{prefix}.socks5"),
            reason: "SOCKS5 代理只在用户态网络下可用".into(),
        });
    }
    if instance.socket.chars().count() > limits::SOCKET_MAX_CHARS {
        problems.push(Problem {
            field: format!("{prefix}.socket"),
            reason: format!("控制套接字路径最多 {} 个字符", limits::SOCKET_MAX_CHARS),
        });
    }
    if instance.state_dir.chars().count() > limits::STATE_DIR_MAX_CHARS {
        problems.push(Problem {
            field: format!("{prefix}.stateDir"),
            reason: format!("状态目录最多 {} 个字符", limits::STATE_DIR_MAX_CHARS),
        });
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

fn is_route(route: &str) -> bool {
    if let Ok(ip) = route.parse::<std::net::IpAddr>() {
        let _ = ip;
        return true;
    }
    match route.split_once('/') {
        Some((ip, mask)) => {
            ip.parse::<std::net::IpAddr>().is_ok()
                && mask.parse::<u8>().is_ok()
                && mask.parse::<u8>().is_ok_and(|mask| mask <= 128)
        }
        None => false,
    }
}

/// Advisory problems shown in the UI but not blocking a save (WP-45
/// §3.3): the SOCKS5 proxy has no authentication — binding it beyond the
/// loopback hands mesh access to everyone who can reach it.
pub fn warnings(config: &FileConfig) -> Vec<Problem> {
    let mut warnings = Vec::new();
    for (index, instance) in config.instances.iter().enumerate() {
        if instance.socks5.is_empty() {
            continue;
        }
        if let Ok(addr) = instance.socks5.parse::<SocketAddr>()
            && !addr.ip().is_loopback()
        {
            warnings.push(Problem {
                field: format!("instances.{index}.socks5"),
                reason: SOCKS5_BIND_WARNING.to_owned(),
            });
        }
    }
    warnings
}

/// Resolved control socket for an instance (pure; the runtime supplies the
/// default state dir path).
pub fn resolved_socket(instance: &Instance, default_socket: &str) -> String {
    if instance.socket.is_empty() {
        default_socket.to_owned()
    } else {
        instance.socket.clone()
    }
}

/// Resolved state directory (custom or default).
pub fn resolved_state_dir(instance: &Instance, default_dir: &str) -> String {
    if instance.state_dir.is_empty() {
        default_dir.to_owned()
    } else {
        instance.state_dir.clone()
    }
}

/// Conflicts between simultaneously enabled instances (WP-45 §3.3).
/// `default_socket_of` and `default_state_dir_of` map an instance to its
/// effective socket / state dir (the runtime passes real paths; tests can
/// pass synthetic ones).
pub fn conflicts(
    instances: &[Instance],
    default_socket_of: &dyn Fn(&Instance) -> String,
    default_state_dir_of: &dyn Fn(&Instance) -> String,
) -> Vec<Conflict> {
    let enabled: Vec<&Instance> = instances
        .iter()
        .filter(|instance| instance.enable)
        .collect();
    let mut conflicts = Vec::new();
    for (index, later) in enabled.iter().enumerate() {
        for earlier in &enabled[..index] {
            // Kernel mode: at most one enabled instance at a time.
            if earlier.is_kernel_mode() && later.is_kernel_mode() {
                conflicts.push(Conflict {
                    keys: vec![earlier.key.clone(), later.key.clone()],
                    message_key: messages::KERNEL_MODE,
                    params: vec![],
                });
            }
            // Control sockets must differ.
            let earlier_socket = resolved_socket(earlier, &default_socket_of(earlier));
            let later_socket = resolved_socket(later, &default_socket_of(later));
            if !earlier_socket.is_empty() && earlier_socket == later_socket {
                conflicts.push(Conflict {
                    keys: vec![earlier.key.clone(), later.key.clone()],
                    message_key: messages::SOCKET,
                    params: vec![("socket".into(), earlier_socket)],
                });
            }
            // State directories must differ (managed instances only).
            if earlier.managed && later.managed {
                let earlier_dir = resolved_state_dir(earlier, &default_state_dir_of(earlier));
                let later_dir = resolved_state_dir(later, &default_state_dir_of(later));
                if !earlier_dir.is_empty() && earlier_dir == later_dir {
                    conflicts.push(Conflict {
                        keys: vec![earlier.key.clone(), later.key.clone()],
                        message_key: messages::STATE_DIR,
                        params: vec![("dir".into(), earlier_dir)],
                    });
                }
            }
            // Fixed WireGuard ports must differ.
            if let (Some(a), Some(b)) = (earlier.fixed_port, later.fixed_port)
                && a == b
            {
                conflicts.push(Conflict {
                    keys: vec![earlier.key.clone(), later.key.clone()],
                    message_key: messages::PORT,
                    params: vec![("port".into(), a.to_string())],
                });
            }
        }
    }
    conflicts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ExtraEnv, MASK, limits};

    fn instance(key: &str, name: &str) -> Instance {
        Instance {
            key: key.into(),
            name: name.into(),
            managed: true,
            userspace: true,
            enable: true,
            ..Instance::default()
        }
    }

    #[test]
    fn tailscale_validate_field_limits() {
        let mut config = FileConfig::default();
        let mut long = instance("a", "a");
        long.login_server = "ftp://headscale.example".into();
        long.advertise_routes = vec!["10.0.0.0/8".into(); limits::ADVERTISE_ROUTES_MAX + 1];
        long.advertise_routes[0] = "not-a-route".into();
        long.exit_node = ExitNodeRole::Use;
        long.exit_node_target = String::new();
        long.socks5 = "not-an-addr".into();
        long.extra_args = vec!["--x".into(); limits::EXTRA_ARGS_MAX + 1];
        long.extra_env = vec![ExtraEnv {
            name: "9BAD".into(),
            value: "v".into(),
        }];
        long.state_dir = "x".repeat(limits::STATE_DIR_MAX_CHARS + 1);
        config.instances.push(long);
        let fields: Vec<String> = validate(&config).iter().map(|p| p.field.clone()).collect();
        for expected in [
            "instances.0.loginServer",
            "instances.0.advertiseRoutes.0",
            "instances.0.advertiseRoutes",
            "instances.0.exitNodeTarget",
            "instances.0.socks5",
            "instances.0.extraArgs",
            "instances.0.extraEnv.0.name",
            "instances.0.stateDir",
        ] {
            assert!(
                fields.iter().any(|field| field == expected),
                "缺少 {expected}: {fields:?}"
            );
        }
        // Userspace + loopback SOCKS5 is fine and produces no warnings.
        let mut config = FileConfig::default();
        let mut ok = instance("a", "a");
        ok.login_server = "https://headscale.example".into();
        ok.socks5 = "127.0.0.1:1055".into();
        ok.exit_node = ExitNodeRole::Use;
        ok.exit_node_target = "100.64.0.9".into();
        config.instances.push(ok);
        assert!(validate(&config).is_empty(), "{:?}", validate(&config));
        assert!(warnings(&config).is_empty());
        // Masking is untouched by normalization.
        let normalized = normalize(config);
        assert_ne!(normalized.instances[0].auth_key, MASK);
    }

    #[test]
    fn tailscale_kernel_mode_single_instance() {
        let mut kernel_a = instance("ka", "kernel-a");
        kernel_a.userspace = false;
        let mut kernel_b = instance("kb", "kernel-b");
        kernel_b.userspace = false;
        let mut userspace = instance("u", "user");
        userspace.userspace = true;
        let socket = |_: &Instance| format!("/sock/{}", std::process::id());
        let state_dir = |instance: &Instance| format!("/state-{}", instance.key);
        // Two kernel instances conflict; kernel + userspace do not.
        let found = conflicts(
            &[kernel_a.clone(), kernel_b.clone(), userspace.clone()],
            &socket,
            &state_dir,
        );
        assert!(
            found
                .iter()
                .any(|c| c.message_key == messages::KERNEL_MODE && c.keys == ["ka", "kb"]),
            "{found:?}"
        );
        // A disabled kernel instance does not conflict.
        let mut off = kernel_b.clone();
        off.enable = false;
        assert!(
            conflicts(&[kernel_a, off, userspace], &socket, &state_dir)
                .iter()
                .all(|c| c.message_key != messages::KERNEL_MODE)
        );
    }

    #[test]
    fn tailscale_conflicts_reported_on_enable_for_shared_resources() {
        let socket = |_: &Instance| "/var/run/tailscale/tailscaled.sock".to_owned();
        let state_dir = |instance: &Instance| format!("/state-{}", instance.key);
        let mut a = instance("a", "a");
        a.fixed_port = Some(41841);
        let mut b = instance("b", "b");
        b.fixed_port = Some(41841);
        let mut c = instance("c", "c");
        c.state_dir = "/shared-state".into();
        let mut d = instance("d", "d");
        d.state_dir = "/shared-state".into();
        let found = conflicts(&[a.clone(), b.clone()], &socket, &state_dir);
        assert!(
            found
                .iter()
                .any(|c| c.message_key == messages::PORT && c.keys == ["a", "b"])
        );
        let found = conflicts(&[c, d], &socket, &state_dir);
        assert!(
            found
                .iter()
                .any(|c| c.message_key == messages::STATE_DIR && c.keys == ["c", "d"])
        );
        // Same effective socket (both fall back to the system default).
        let mut e = instance("e", "e");
        e.managed = false;
        let mut f = instance("f", "f");
        f.managed = false;
        let found = conflicts(&[e, f], &socket, &state_dir);
        assert!(found.iter().any(|c| c.message_key == messages::SOCKET));
        // Distinct fixed ports do not conflict.
        let mut b2 = b.clone();
        b2.fixed_port = Some(41842);
        assert!(
            conflicts(&[a, b2], &socket, &state_dir)
                .iter()
                .all(|c| c.message_key != messages::PORT)
        );
    }

    #[test]
    fn tailscale_socks5_bind_warning() {
        let mut config = FileConfig::default();
        let mut wide = instance("a", "a");
        wide.socks5 = "0.0.0.0:1055".into();
        let mut lan = instance("b", "b");
        lan.socks5 = "192.168.1.10:1055".into();
        let mut local = instance("c", "c");
        local.socks5 = "127.0.0.1:1055".into();
        config.instances = vec![wide, lan, local];
        let warned: Vec<String> = warnings(&config).iter().map(|p| p.reason.clone()).collect();
        assert_eq!(warned.len(), 2, "{warned:?}");
        assert!(warned.iter().all(|reason| reason == SOCKS5_BIND_WARNING));
        let fields: Vec<String> = warnings(&config).iter().map(|p| p.field.clone()).collect();
        assert!(fields.contains(&"instances.0.socks5".to_owned()));
        assert!(fields.contains(&"instances.1.socks5".to_owned()));
    }
}
