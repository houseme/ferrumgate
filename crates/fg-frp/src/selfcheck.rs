//! The frp module's self-check (WP-44 §3.3 "自检"): conflicts between proxy
//! remote ports and Gately's own listeners / other proxies (`frp.conflict`),
//! duplicate proxy names (`frp.duplicate`) and the all-clear item with the
//! running-instance summary (`frp.ok`).

use std::collections::HashMap;
use std::sync::Arc;

use fg_core::check::{BoxFut, CheckEnv, CheckResult, Status};

use crate::model::{FileConfig, Proxy, ProxyType};
use crate::runtime::Runtime;

/// One finding of the pure analysis: machine id + field + reason.
#[derive(Debug, PartialEq, Eq)]
pub struct Finding {
    pub id: &'static str,
    pub status: Status,
    pub field: String,
    pub reason: String,
}

/// Conflicts and duplicates among the enabled proxies. `local_ports` are
/// the ports Gately itself listens on (assembler wiring; empty when not
/// provided). A remote port claimed by two enabled tcp / udp proxies is a
/// conflict; the same remote port as a local listener is a conflict; a
/// proxy name used twice is a duplicate (frps rejects the second one).
pub fn findings(config: &FileConfig, local_ports: &[u16]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut port_owners: HashMap<u16, String> = HashMap::new();
    let mut names: HashMap<String, String> = HashMap::new();
    for proxy in config.proxies.iter().filter(|proxy| proxy.enable) {
        let label = proxy_label(config, proxy);
        if proxy.typ.has_remote_port() && proxy.remote_port != 0 {
            if let Some(other) = port_owners.get(&proxy.remote_port) {
                findings.push(Finding {
                    id: "frp.conflict",
                    status: Status::Warn,
                    field: format!("proxies.{}.remotePort", proxy.key),
                    reason: format!("远程端口 {} 已被 {other} 使用", proxy.remote_port),
                });
            } else if local_ports.contains(&proxy.remote_port) {
                findings.push(Finding {
                    id: "frp.conflict",
                    status: Status::Warn,
                    field: format!("proxies.{}.remotePort", proxy.key),
                    reason: format!("远程端口 {} 与 Gately 自身监听冲突", proxy.remote_port),
                });
            } else {
                port_owners.insert(proxy.remote_port, label.clone());
            }
        }
        if let Some(other) = names.get(proxy.name.to_ascii_lowercase().as_str()) {
            findings.push(Finding {
                id: "frp.duplicate",
                status: Status::Warn,
                field: format!("proxies.{}.name", proxy.key),
                reason: format!("代理名 {} 重复（{other}）", proxy.name),
            });
        } else {
            names.insert(proxy.name.to_ascii_lowercase(), label);
        }
    }
    findings
}

fn proxy_label(config: &FileConfig, proxy: &Proxy) -> String {
    let client = config
        .clients
        .iter()
        .find(|client| client.key == proxy.client)
        .map(|client| client.name.as_str())
        .unwrap_or("?");
    format!("{}（{}）", proxy.name, client)
}

/// The check over the shared runtime; `local_ports` is the list of ports
/// Gately itself listens on (assembler wiring, WP-11).
pub struct FrpCheck {
    pub runtime: Arc<Runtime>,
    pub local_ports: Vec<u16>,
}

impl fg_core::check::SelfCheck for FrpCheck {
    fn check(&self, _env: &CheckEnv) -> BoxFut<'_, Vec<CheckResult>> {
        Box::pin(async move {
            let config = self.runtime.config();
            let snapshot = config.read().await.clone();
            let mut results = Vec::new();
            let findings = findings(&snapshot, &self.local_ports);
            for finding in &findings {
                results.push(
                    CheckResult::with(finding.id, finding.status)
                        .param("field", finding.field.clone())
                        .param("reason", finding.reason.clone()),
                );
            }
            let summary = self.runtime.summary();
            let result = if findings.is_empty() {
                CheckResult::ok("frp.ok")
            } else {
                CheckResult::warn("frp.ok")
            }
            .param("clients", summary.running_clients)
            .param("servers", summary.running_servers)
            .param("abnormal", summary.abnormal)
            .param("proxies", summary_count(&snapshot, ProxyType::Tcp));
            results.push(result);
            results
        })
    }
}

fn summary_count(config: &FileConfig, _kind: ProxyType) -> usize {
    config.proxies.iter().filter(|proxy| proxy.enable).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Client, Server};

    fn config_with(proxies: Vec<Proxy>) -> FileConfig {
        FileConfig {
            clients: vec![Client {
                key: "c1".into(),
                name: "home".into(),
                enable: true,
                ..Client::default()
            }],
            servers: vec![Server {
                key: "s1".into(),
                name: "main".into(),
                ..Server::default()
            }],
            proxies,
            ..FileConfig::default()
        }
    }

    fn tcp(key: &str, name: &str, remote: u16) -> Proxy {
        Proxy {
            key: key.into(),
            name: name.into(),
            enable: true,
            typ: ProxyType::Tcp,
            local_port: 22,
            remote_port: remote,
            client: "c1".into(),
            ..Proxy::default()
        }
    }

    #[test]
    fn selfcheck_conflict_and_duplicate() {
        // Two enabled tcp proxies with the same remote port conflict.
        let config = config_with(vec![tcp("p1", "ssh", 6022), tcp("p2", "ssh2", 6022)]);
        let found = findings(&config, &[]);
        assert!(
            found
                .iter()
                .any(|finding| finding.id == "frp.conflict"
                    && finding.field == "proxies.p2.remotePort"),
            "{found:?}"
        );

        // The same remote port as a local listener conflicts too.
        let config = config_with(vec![tcp("p1", "ssh", 8080)]);
        let found = findings(&config, &[8080]);
        assert!(
            found
                .iter()
                .any(|finding| finding.reason.contains("Gately 自身监听")),
            "{found:?}"
        );

        // Duplicate proxy names are reported once per extra occurrence.
        let config = config_with(vec![tcp("p1", "web", 6022), tcp("p2", "web", 6023)]);
        let found = findings(&config, &[]);
        assert!(
            found
                .iter()
                .any(|finding| finding.id == "frp.duplicate" && finding.field == "proxies.p2.name"),
            "{found:?}"
        );

        // Disabled proxies are ignored, distinct ports and names are clean.
        let mut off = tcp("p3", "ssh", 6022);
        off.enable = false;
        let config = config_with(vec![tcp("p1", "ssh", 6022), off, tcp("p4", "other", 6024)]);
        assert!(findings(&config, &[8080]).is_empty());
        // http proxies have no remote port: no conflicts from them.
        let mut http = tcp("p5", "web", 0);
        http.typ = ProxyType::Http;
        http.subdomain = "web".into();
        let config = config_with(vec![http]);
        assert!(findings(&config, &[]).is_empty());
    }
}
