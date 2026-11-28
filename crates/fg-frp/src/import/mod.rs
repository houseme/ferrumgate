//! Import of existing frp configurations (WP-44 §3.3 "导入已有配置"): the
//! legacy INI formats (`frpc.ini` / `frps.ini` with a `[common]` section)
//! and the frp 0.52+ TOML formats. Parsing produces a preview (mapped
//! entries plus every ignored field); applying the preview is a separate,
//! validated step so the UI can show it first.
//!
//! New instances from an import are disabled by default; importing into an
//! existing frpc instance keeps its enabled state and either appends
//! proxies (same-name proxies stay) or replaces all of them.

pub mod ini;
pub mod toml;

use crate::model::{Client, FileConfig, Proxy, Server};

/// The parse result shown by the preview step.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportPreview {
    pub clients: Vec<Client>,
    pub servers: Vec<Server>,
    pub proxies: Vec<Proxy>,
    /// Ignored fields as `<place>.<key>: <value>` lines, first-seen order.
    pub ignored: Vec<String>,
}

/// What to import into.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportTarget {
    /// Create the new instances (disabled by default).
    New,
    /// Merge into an existing frpc instance.
    ExistingClient { key: String, mode: ImportMode },
}

/// Proxy merge behavior when importing into an existing instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportMode {
    /// Same-name proxies keep their stored form; new names are added.
    Append,
    /// All proxies of the target are swapped for the imported ones.
    Replace,
}

/// A parse or apply failure (user-facing message).
pub type ImportError = String;

/// Parses any supported format; the role is auto-detected from the
/// content (`serverAddr` / `[[proxies]]` → frpc, `bindPort` → frps, a
/// `[common]` INI section decides by its keys).
pub fn parse(content: &str) -> Result<ImportPreview, ImportError> {
    let trimmed = content.trim_start();
    if looks_like_ini(trimmed) {
        return ini::parse(trimmed);
    }
    toml::parse(trimmed)
}

/// INI content starts with a `[section]` header or `key = value` line;
/// TOML with top-level scalars or tables. Both may carry comments.
fn looks_like_ini(content: &str) -> bool {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        return line.starts_with('[') && line.contains(']');
    }
    false
}

/// Applies a preview to the config. Applies normalized input only; the
/// caller runs normalize + validate afterwards (an invalid result is a
/// route-level 400).
pub fn apply(
    preview: ImportPreview,
    target: &ImportTarget,
    config: &mut FileConfig,
) -> Result<(), ImportError> {
    match target {
        ImportTarget::New => {
            // Ownerless proxies bind to the only imported client; its key
            // is generated during the same pass.
            let single_client = preview.clients.len() == 1;
            let mut only_client: Option<String> = None;
            for mut client in preview.clients {
                client.key = new_key(
                    &config
                        .clients
                        .iter()
                        .map(|c| c.key.as_str())
                        .collect::<Vec<_>>(),
                );
                client.enable = false;
                if single_client {
                    only_client = Some(client.key.clone());
                }
                config.clients.push(client);
            }
            for mut server in preview.servers {
                server.key = new_key(
                    &config
                        .servers
                        .iter()
                        .map(|s| s.key.as_str())
                        .collect::<Vec<_>>(),
                );
                server.enable = false;
                config.servers.push(server);
            }
            for mut proxy in preview.proxies {
                proxy.key = new_key(
                    &config
                        .proxies
                        .iter()
                        .map(|p| p.key.as_str())
                        .collect::<Vec<_>>(),
                );
                if proxy.client.is_empty()
                    && let Some(key) = &only_client
                {
                    proxy.client = key.clone();
                }
                config.proxies.push(proxy);
            }
            Ok(())
        }
        ImportTarget::ExistingClient { key, mode } => {
            let Some(index) = config.clients.iter().position(|client| client.key == *key) else {
                return Err(format!("目标 frpc 实例不存在：{key}"));
            };
            let Some(imported) = preview.clients.first() else {
                return Err("导入内容里没有 frpc 实例".to_owned());
            };
            if preview.clients.len() > 1 {
                return Err("导入到已有实例时内容只能包含一个 frpc 实例".to_owned());
            }
            let imported_proxies = &preview.proxies;
            // The instance keeps its identity and enabled state; settings
            // come from the import.
            let existing = &mut config.clients[index];
            let enable = existing.enable;
            let (instance_key, name, group) = (
                existing.key.clone(),
                existing.name.clone(),
                existing.group.clone(),
            );
            *existing = imported.clone();
            existing.key = instance_key;
            existing.name = name;
            existing.group = group;
            existing.enable = enable;
            match mode {
                ImportMode::Append => {
                    // Same-name proxies keep their stored form.
                    for proxy in imported_proxies {
                        let mut proxy = proxy.clone();
                        proxy.client = key.clone();
                        if let Some(current) = config
                            .proxies
                            .iter_mut()
                            .find(|current| current.client == *key && current.name == proxy.name)
                        {
                            current.remark = proxy.remark.clone();
                            continue;
                        }
                        proxy.key = new_key(
                            &config
                                .proxies
                                .iter()
                                .map(|p| p.key.as_str())
                                .collect::<Vec<_>>(),
                        );
                        config.proxies.push(proxy);
                    }
                }
                ImportMode::Replace => {
                    config.proxies.retain(|proxy| proxy.client != *key);
                    for proxy in imported_proxies {
                        let mut proxy = proxy.clone();
                        proxy.client = key.clone();
                        proxy.key = new_key(
                            &config
                                .proxies
                                .iter()
                                .map(|p| p.key.as_str())
                                .collect::<Vec<_>>(),
                        );
                        config.proxies.push(proxy);
                    }
                }
            }
            Ok(())
        }
    }
}

/// 12 lowercase hex characters, unique within the given keys — the same
/// shape the fg-admin collections generate (conventions §3.3).
pub fn new_key(existing: &[&str]) -> String {
    for _ in 0..8 {
        let mut bytes = [0u8; 8];
        if getrandom::fill(&mut bytes[2..]).is_err() {
            continue;
        }
        let key = format!("{:012x}", u64::from_be_bytes(bytes));
        if !existing.contains(&key.as_str()) {
            return key;
        }
    }
    // getrandom failures and 8 collisions are both practically impossible;
    // a time-based fallback keeps the caller total.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("{:012x}", nanos % (1 << 48))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Client, Proxy, Server};

    fn preview_with_client() -> ImportPreview {
        ImportPreview {
            clients: vec![Client {
                name: "imported".into(),
                server_addr: "frps.example.com".into(),
                token: "tok".into(),
                ..Client::default()
            }],
            proxies: vec![Proxy {
                name: "ssh".into(),
                enable: true,
                local_port: 22,
                remote_port: 6022,
                ..Proxy::default()
            }],
            ..ImportPreview::default()
        }
    }

    fn config_with_existing() -> FileConfig {
        FileConfig {
            clients: vec![Client {
                key: "aaaabbbbcccc".into(),
                name: "home".into(),
                enable: true,
                server_addr: "old.example.com".into(),
                ..Client::default()
            }],
            proxies: vec![
                Proxy {
                    key: "pppppppppppp".into(),
                    name: "ssh".into(),
                    enable: true,
                    remote_port: 6022,
                    client: "aaaabbbbcccc".into(),
                    ..Proxy::default()
                },
                Proxy {
                    key: "qqqqqqqqqqqq".into(),
                    name: "web".into(),
                    enable: true,
                    typ: crate::model::ProxyType::Http,
                    local_port: 80,
                    subdomain: "web".into(),
                    client: "aaaabbbbcccc".into(),
                    ..Proxy::default()
                },
            ],
            ..FileConfig::default()
        }
    }

    #[test]
    fn import_new_instance_disabled_by_default() {
        let mut config = FileConfig::default();
        apply(preview_with_client(), &ImportTarget::New, &mut config).expect("apply");
        assert_eq!(config.clients.len(), 1);
        assert!(!config.clients[0].enable, "导入的新实例默认停用");
        assert!(is_generated(&config.clients[0].key));
        // Proxies point at the created instance.
        assert_eq!(config.proxies[0].client, config.clients[0].key);
        // Two clients in the preview → both created with distinct keys.
        let mut preview = preview_with_client();
        preview.clients.push(Client {
            name: "second".into(),
            ..Client::default()
        });
        apply(preview, &ImportTarget::New, &mut config).expect("apply");
        assert_eq!(config.clients.len(), 3);
        assert_ne!(config.clients[0].key, config.clients[1].key);
    }

    #[test]
    fn import_toml_append_keeps_same_name_proxies() {
        let mut config = config_with_existing();
        let mut preview = preview_with_client();
        preview.proxies.push(Proxy {
            name: "dns".into(),
            enable: true,
            typ: crate::model::ProxyType::Udp,
            local_port: 53,
            remote_port: 6053,
            ..Proxy::default()
        });
        apply(
            preview,
            &ImportTarget::ExistingClient {
                key: "aaaabbbbcccc".into(),
                mode: ImportMode::Append,
            },
            &mut config,
        )
        .expect("apply");
        // The instance keeps identity + enable state; settings update.
        let client = &config.clients[0];
        assert_eq!(client.key, "aaaabbbbcccc");
        assert_eq!(client.name, "home");
        assert!(client.enable, "沿用已有实例的启用状态");
        assert_eq!(client.server_addr, "frps.example.com");
        // Same-name proxy kept; new names added.
        assert_eq!(config.proxies.len(), 3);
        let ssh = config
            .proxies
            .iter()
            .find(|proxy| proxy.name == "ssh")
            .expect("kept");
        assert_eq!(ssh.key, "pppppppppppp", "同名代理保持不变");
        assert_eq!(ssh.remote_port, 6022);
        assert!(config.proxies.iter().any(|proxy| proxy.name == "web"));
        let dns = config
            .proxies
            .iter()
            .find(|proxy| proxy.name == "dns")
            .expect("added");
        assert_eq!(dns.client, "aaaabbbbcccc");
    }

    #[test]
    fn import_toml_replace_swaps_all_proxies() {
        let mut config = config_with_existing();
        let mut preview = preview_with_client();
        preview.proxies.push(Proxy {
            name: "dns".into(),
            enable: true,
            typ: crate::model::ProxyType::Udp,
            local_port: 53,
            remote_port: 6053,
            ..Proxy::default()
        });
        apply(
            preview,
            &ImportTarget::ExistingClient {
                key: "aaaabbbbcccc".into(),
                mode: ImportMode::Replace,
            },
            &mut config,
        )
        .expect("apply");
        // All proxies of the target swapped for the imported ones.
        assert_eq!(config.proxies.len(), 2);
        assert!(
            config
                .proxies
                .iter()
                .all(|proxy| proxy.client == "aaaabbbbcccc")
        );
        assert!(config.proxies.iter().any(|proxy| proxy.name == "dns"));
        assert!(!config.proxies.iter().any(|proxy| proxy.name == "web"));
    }

    #[test]
    fn import_apply_validates_target() {
        let mut config = FileConfig::default();
        let error = apply(
            preview_with_client(),
            &ImportTarget::ExistingClient {
                key: "ghost".into(),
                mode: ImportMode::Append,
            },
            &mut config,
        )
        .expect_err("unknown target is an error");
        assert!(error.contains("不存在"), "{error}");
        // A server-only preview cannot apply to a client target.
        let mut server_only = ImportPreview::default();
        server_only.servers.push(Server {
            name: "imported".into(),
            ..Server::default()
        });
        // The new target accepts servers as well.
        let mut fresh = FileConfig::default();
        apply(server_only.clone(), &ImportTarget::New, &mut fresh).expect("apply new");
        assert_eq!(fresh.servers.len(), 1);
        let error = apply(
            server_only,
            &ImportTarget::ExistingClient {
                key: "aaaabbbbcccc".into(),
                mode: ImportMode::Append,
            },
            &mut config_with_existing(),
        )
        .expect_err("server-only preview has no client");
        assert!(error.contains("没有 frpc 实例"), "{error}");
    }

    #[test]
    fn import_new_key_shape_is_12_hex() {
        let key = new_key(&[]);
        assert_eq!(key.len(), 12);
        assert!(
            key.bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        let key = new_key(&[&key]);
        assert_ne!(key, "aaaaaaaaaaaa");
        assert!(is_generated(&key));
    }

    fn is_generated(key: &str) -> bool {
        key.len() == 12
            && key
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }
}
