//! Validation and normalization (WP-45 §5 step 9): pure functions over the
//! `netbird.json` model. [`conflicts`] reports resources two
//! simultaneously enabled instances cannot share: at most one kernel-mode
//! instance, exclusive state dirs and control addresses, and for managed
//! userspace instances the WireGuard port and the (unauthenticated)
//! SOCKS5 address. [`warnings`] collects advisory-only problems.

use std::net::SocketAddr;

use crate::model::{FileConfig, Instance, limits};

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
    pub const KERNEL_MODE: &str = "netbird.conflict.kernelMode";
    pub const STATE_DIR: &str = "netbird.conflict.stateDir";
    pub const CONTROL_ADDR: &str = "netbird.conflict.controlAddr";
    pub const WG_PORT: &str = "netbird.conflict.wgPort";
    pub const SOCKS5: &str = "netbird.conflict.socks5";
}

pub const SOCKS5_BIND_WARNING: &str = "netbird.warning.socks5Bind";
pub const SOCKS5_UNAVAILABLE_WARNING: &str = "netbird.warning.socks5KernelMode";

/// Applies defaults and light normalization: trims string fields and
/// drops empty list entries.
pub fn normalize(mut config: FileConfig) -> FileConfig {
    config.settings.program_path = config.settings.program_path.trim().to_owned();
    config.settings.download_proxy = config.settings.download_proxy.trim().to_owned();
    for instance in &mut config.instances {
        instance.key = instance.key.trim().to_owned();
        instance.name = instance.name.trim().to_owned();
        instance.group = instance.group.trim().to_owned();
        instance.remark = instance.remark.trim().to_owned();
        instance.management_url = instance.management_url.trim().to_owned();
        instance.setup_key = instance.setup_key.trim().to_owned();
        instance.socks5 = instance.socks5.trim().to_owned();
        instance.control_addr = instance.control_addr.trim().to_owned();
        instance.state_dir = instance.state_dir.trim().to_owned();
        for field in [&mut instance.extra_args] {
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
    if instance.management_url.chars().count() > limits::MANAGEMENT_URL_MAX_CHARS {
        problems.push(Problem {
            field: format!("{prefix}.managementUrl"),
            reason: format!("管理地址最多 {} 个字符", limits::MANAGEMENT_URL_MAX_CHARS),
        });
    } else if !instance.management_url.is_empty()
        && !instance.management_url.starts_with("http://")
        && !instance.management_url.starts_with("https://")
    {
        problems.push(Problem {
            field: format!("{prefix}.managementUrl"),
            reason: "管理地址必须以 http:// 或 https:// 开头".into(),
        });
    }
    if instance.setup_key.chars().count() > limits::SETUP_KEY_MAX_CHARS {
        problems.push(Problem {
            field: format!("{prefix}.setupKey"),
            reason: format!("设置密钥最多 {} 个字符", limits::SETUP_KEY_MAX_CHARS),
        });
    }
    if !instance.socks5.is_empty() {
        match instance.socks5.parse::<SocketAddr>() {
            Ok(_) => {
                if instance.is_kernel_mode() {
                    problems.push(Problem {
                        field: format!("{prefix}.socks5"),
                        reason: "SOCKS5 代理只在用户态网络下可用".into(),
                    });
                }
            }
            Err(_) => problems.push(Problem {
                field: format!("{prefix}.socks5"),
                reason: "SOCKS5 地址必须是 IP:端口".into(),
            }),
        }
    }
    if instance.control_addr.chars().count() > limits::CONTROL_ADDR_MAX_CHARS {
        problems.push(Problem {
            field: format!("{prefix}.controlAddr"),
            reason: format!("控制地址最多 {} 个字符", limits::CONTROL_ADDR_MAX_CHARS),
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

/// Advisory problems (WP-45 §3.3): the SOCKS5 proxy has no authentication.
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

/// The effective control address: explicit override, else
/// `<state dir>/netbird.sock`. The caller supplies the default state dir
/// path for the instance.
pub fn resolved_control_addr(instance: &Instance, default_state_dir: &std::path::Path) -> String {
    if !instance.control_addr.is_empty() {
        instance.control_addr.clone()
    } else {
        default_state_dir.join("netbird.sock").display().to_string()
    }
}

/// The effective state directory: custom or the given default.
pub fn resolved_state_dir<'a>(
    instance: &'a Instance,
    default_dir: &'a std::path::Path,
) -> std::borrow::Cow<'a, std::path::Path> {
    if instance.state_dir.is_empty() {
        std::borrow::Cow::Borrowed(default_dir)
    } else {
        std::borrow::Cow::Owned(std::path::PathBuf::from(&instance.state_dir))
    }
}

/// Conflicts between simultaneously enabled instances (WP-45 §3.3). The
/// `default_state_dir_of` closure maps an instance to its default state
/// dir so effective control addresses can be compared.
pub fn conflicts(
    instances: &[Instance],
    default_state_dir_of: &dyn Fn(&Instance) -> std::path::PathBuf,
) -> Vec<Conflict> {
    let enabled: Vec<&Instance> = instances
        .iter()
        .filter(|instance| instance.enable)
        .collect();
    let mut conflicts = Vec::new();
    for (index, later) in enabled.iter().enumerate() {
        for earlier in &enabled[..index] {
            if earlier.is_kernel_mode() && later.is_kernel_mode() {
                conflicts.push(Conflict {
                    keys: vec![earlier.key.clone(), later.key.clone()],
                    message_key: messages::KERNEL_MODE,
                    params: vec![],
                });
            }
            // Control addresses must differ.
            let earlier_addr = resolved_control_addr(earlier, &default_state_dir_of(earlier));
            let later_addr = resolved_control_addr(later, &default_state_dir_of(later));
            if earlier_addr == later_addr {
                conflicts.push(Conflict {
                    keys: vec![earlier.key.clone(), later.key.clone()],
                    message_key: messages::CONTROL_ADDR,
                    params: vec![("addr".into(), earlier_addr)],
                });
            }
            // State directories must differ (managed instances only).
            if earlier.managed && later.managed {
                let earlier_default = default_state_dir_of(earlier);
                let later_default = default_state_dir_of(later);
                let earlier_dir = resolved_state_dir(earlier, &earlier_default).into_owned();
                let later_dir = resolved_state_dir(later, &later_default).into_owned();
                if earlier_dir == later_dir {
                    conflicts.push(Conflict {
                        keys: vec![earlier.key.clone(), later.key.clone()],
                        message_key: messages::STATE_DIR,
                        params: vec![("dir".into(), earlier_dir.display().to_string())],
                    });
                }
            }
            // Managed userspace instances: WireGuard ports and SOCKS5
            // addresses must differ.
            if earlier.managed
                && later.managed
                && earlier.userspace
                && later.userspace
                && let (Some(a), Some(b)) = (earlier.fixed_port, later.fixed_port)
                && a == b
            {
                conflicts.push(Conflict {
                    keys: vec![earlier.key.clone(), later.key.clone()],
                    message_key: messages::WG_PORT,
                    params: vec![("port".into(), a.to_string())],
                });
            }
            if earlier.managed
                && later.managed
                && earlier.userspace
                && later.userspace
                && !earlier.socks5.is_empty()
                && earlier.socks5 == later.socks5
            {
                conflicts.push(Conflict {
                    keys: vec![earlier.key.clone(), later.key.clone()],
                    message_key: messages::SOCKS5,
                    params: vec![("socks5".into(), earlier.socks5.clone())],
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
    use std::path::PathBuf;

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

    fn default_dir(instance: &Instance) -> PathBuf {
        PathBuf::from(format!("/state-{}", instance.key))
    }

    #[test]
    fn netbird_validate_field_limits() {
        let mut config = FileConfig::default();
        let mut long = instance("a", "a");
        long.management_url = "ftp://mgmt.example".into();
        long.setup_key = "k".repeat(limits::SETUP_KEY_MAX_CHARS + 1);
        long.socks5 = "bad-addr".into();
        long.extra_args = vec!["--x".into(); limits::EXTRA_ARGS_MAX + 1];
        long.extra_env = vec![ExtraEnv {
            name: "9BAD".into(),
            value: "v".into(),
        }];
        long.state_dir = "x".repeat(limits::STATE_DIR_MAX_CHARS + 1);
        config.instances.push(long);
        let fields: Vec<String> = validate(&config).iter().map(|p| p.field.clone()).collect();
        for expected in [
            "instances.0.managementUrl",
            "instances.0.setupKey",
            "instances.0.socks5",
            "instances.0.extraArgs",
            "instances.0.extraEnv.0.name",
            "instances.0.stateDir",
        ] {
            assert!(fields.contains(&expected.to_owned()), "{fields:?}");
        }
        // Userspace + loopback SOCKS5 passes; kernel mode with SOCKS5
        // does not.
        let mut config = FileConfig::default();
        let mut ok = instance("a", "a");
        ok.management_url = "https://mgmt.example".into();
        ok.socks5 = "127.0.0.1:1080".into();
        config.instances.push(ok);
        assert!(validate(&config).is_empty(), "{:?}", validate(&config));
        assert!(warnings(&config).is_empty());
        let mut kernel_socks = instance("b", "b");
        kernel_socks.userspace = false;
        kernel_socks.socks5 = "127.0.0.1:1080".into();
        config.instances.push(kernel_socks);
        assert!(
            validate(&config)
                .iter()
                .any(|p| p.field == "instances.1.socks5")
        );
        // Normalization keeps secrets untouched.
        let clean = FileConfig {
            instances: vec![instance("c", "c")],
            ..Default::default()
        };
        assert_ne!(normalize(clean).instances[0].setup_key, MASK);
    }

    #[test]
    fn netbird_kernel_mode_single_instance() {
        let mut kernel_a = instance("ka", "kernel-a");
        kernel_a.userspace = false;
        let mut kernel_b = instance("kb", "kernel-b");
        kernel_b.userspace = false;
        let userspace = instance("u", "user");
        let found = conflicts(&[kernel_a.clone(), kernel_b, userspace], &default_dir);
        assert!(
            found
                .iter()
                .any(|c| c.message_key == messages::KERNEL_MODE && c.keys == ["ka", "kb"]),
            "{found:?}"
        );
        let mut off = kernel_a.clone();
        off.enable = false;
        assert!(
            conflicts(&[kernel_a, off, instance("u2", "u2")], &default_dir)
                .iter()
                .all(|c| c.message_key != messages::KERNEL_MODE)
        );
    }

    #[test]
    fn netbird_conflicts_reported_on_enable_for_shared_resources() {
        let mut a = instance("a", "a");
        a.fixed_port = Some(51820);
        let mut b = instance("b", "b");
        b.fixed_port = Some(51820);
        let mut c = instance("c", "c");
        c.state_dir = "/shared".into();
        let mut d = instance("d", "d");
        d.state_dir = "/shared".into();
        let mut e = instance("e", "e");
        e.socks5 = "127.0.0.1:1080".into();
        let mut f = instance("f", "f");
        f.socks5 = "127.0.0.1:1080".into();
        let found = conflicts(&[a.clone(), b.clone()], &default_dir);
        assert!(
            found
                .iter()
                .any(|x| x.message_key == messages::WG_PORT && x.keys == ["a", "b"])
        );
        let found = conflicts(&[c, d], &default_dir);
        assert!(
            found
                .iter()
                .any(|x| x.message_key == messages::STATE_DIR && x.keys == ["c", "d"])
        );
        let found = conflicts(&[e, f], &default_dir);
        assert!(
            found
                .iter()
                .any(|x| x.message_key == messages::SOCKS5 && x.keys == ["e", "f"])
        );
        // Same effective control address (both default to their own state
        // dir, so no conflict), but an explicit shared address conflicts.
        let mut g = instance("g", "g");
        g.control_addr = "/run/netbird.sock".into();
        let mut h = instance("h", "h");
        h.control_addr = "/run/netbird.sock".into();
        let found = conflicts(&[g, h], &default_dir);
        assert!(
            found
                .iter()
                .any(|x| x.message_key == messages::CONTROL_ADDR)
        );
        // Kernel-mode instances are exempt from the userspace-only port
        // and SOCKS5 rules.
        let mut i = instance("i", "i");
        i.userspace = false;
        i.fixed_port = Some(51820);
        let mut j = instance("j", "j");
        j.userspace = false;
        j.fixed_port = Some(51820);
        assert!(
            conflicts(&[i, j], &default_dir)
                .iter()
                .all(|x| x.message_key != messages::WG_PORT)
        );
        let _ = a;
    }

    #[test]
    fn netbird_socks5_bind_warning() {
        let mut config = FileConfig::default();
        let mut wide = instance("a", "a");
        wide.socks5 = "0.0.0.0:1080".into();
        let mut local = instance("b", "b");
        local.socks5 = "127.0.0.1:1080".into();
        config.instances = vec![wide, local];
        let warned = warnings(&config);
        assert_eq!(warned.len(), 1);
        assert_eq!(warned[0].reason, SOCKS5_BIND_WARNING);
        assert_eq!(warned[0].field, "instances.0.socks5");
    }
}
