//! The frps login-source access control gate (WP-44 §3.3): a loopback-only
//! HTTP endpoint wired into each frps instance via frp's `httpPlugins`
//! server-plugin protocol.
//!
//! Protocol (verified against the frp source, `pkg/plugin/server`): frps
//! POSTs `{"version","op","content"}` to `addr + path` and reads
//! `{"reject": bool, "reject_reason": String}` back; a non-200 answer also
//! fails the operation. `op` is `Login` or `NewProxy`; the source address
//! arrives inside the content as `client_address` (frps sets it from the
//! real connection — the WP table's "HTTP 头" wording maps to this field;
//! frp only sends an `X-Frp-Reqid` header, no client-address header).
//!
//! Check order (WP-44: deny wins, before anything else):
//! 1. priority deny list (`ipDenyList` / `ipDenySets`) — rejected outright;
//! 2. token — the content's `privilege_key` must match the instance token
//!    (constant-time). The gate rejects mismatches itself so a bad token
//!    never grants anything below; frps would reject it anyway;
//! 3. allow / deny mode (`ipMode` white / black with `ipList` / `ipSets`);
//! 4. allow — the runtime hook registers the trusted source (Login) or the
//!    learned remote TCP port (NewProxy).
//!
//! The listener binds `127.0.0.1` only: it trusts the `client_address`
//! field, so anything that could reach it could forge sources.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::Result;
use axum::{
    Json,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, sync::RwLock};

use crate::model::Server;
use crate::validate::parse_ip_entry;

/// Plugin request bodies are tiny login / proxy messages; the bound is a
/// conventions-§2 limit, not an expectation.
pub const BODY_LIMIT: usize = 64 * 1024;

/// Resolves a subscribed IP-set key to its entries; the gateway's IP-list
/// registry provides this at assembly time. Unknown keys match nothing.
pub type SetLookup = Arc<dyn Fn(&str) -> Vec<String> + Send + Sync>;

/// The decision for one observed operation.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
}

/// The pure check behind the endpoint: order per the module docs (deny
/// first, then token, then the allow / deny mode).
pub fn check(server: &Server, addr: Option<IpAddr>, token: &str, sets: &SetLookup) -> Decision {
    let addr_text = addr.map(|addr| addr.to_string()).unwrap_or_default();
    // 1. Priority deny list: any hit rejects, even with a valid token.
    if let Some(addr) = addr
        && matches_entries(addr, &server.ip_deny_list, &server.ip_deny_sets, sets)
    {
        return Decision::Deny(format!("client address {addr_text} is in the deny list"));
    }
    // 2. Token: an empty instance token disables frp auth (frp semantics).
    let token_ok =
        server.token.is_empty() || bool::from(server.token.as_bytes().ct_eq(token.as_bytes()));
    if !token_ok {
        return Decision::Deny("token is incorrect".to_owned());
    }
    // 3. The allow / deny mode; an unparsable source address never passes
    //    a white-list mode.
    match server.ip_mode.as_str() {
        "white" => {
            let allowed = addr
                .is_some_and(|addr| matches_entries(addr, &server.ip_list, &server.ip_sets, sets));
            if allowed {
                Decision::Allow
            } else {
                Decision::Deny(format!(
                    "client address {addr_text} is not in the allow list"
                ))
            }
        }
        "black" => {
            if let Some(addr) = addr
                && matches_entries(addr, &server.ip_list, &server.ip_sets, sets)
            {
                return Decision::Deny(format!("client address {addr_text} is in the deny list"));
            }
            Decision::Allow
        }
        _ => Decision::Allow,
    }
}

/// Whether `addr` hits any hand-entered entry or any resolved set entry.
fn matches_entries(
    addr: IpAddr,
    entries: &[String],
    set_keys: &[String],
    sets: &SetLookup,
) -> bool {
    entries
        .iter()
        .filter_map(|entry| parse_ip_entry(entry))
        .chain(
            set_keys
                .iter()
                .flat_map(|key| sets(key))
                .filter_map(|entry| parse_ip_entry(&entry)),
        )
        .any(|net| net.contains(&addr))
}

/// Plugin request content. frp serializes the login message with
/// snake_case keys plus the `client_address` extension.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Content {
    #[serde(rename = "privilege_key")]
    privilege_key: String,
    #[serde(rename = "client_address")]
    client_address: String,
    #[serde(rename = "remote_port")]
    remote_port: u16,
}

#[derive(Deserialize)]
struct PluginRequest {
    #[serde(default)]
    op: String,
    #[serde(default)]
    content: Content,
}

/// What an allowed operation means for the runtime: `Login` registers the
/// trusted source, `NewProxy` the requested remote TCP port (0 = none).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateHook {
    Login,
    NewProxy(u16),
}

/// Runtime hook for every allowed operation.
pub type OnAllow = Arc<dyn Fn(&str, Option<IpAddr>, GateHook) + Send + Sync>;

/// The loopback login gate shared by every frps instance; the per-instance
/// rules live in `servers` (`key -> config`), maintained by the runtime.
pub struct LoginGate {
    servers: Arc<RwLock<HashMap<String, Server>>>,
    sets: SetLookup,
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl LoginGate {
    /// Starts the gate on a random loopback port. `sets` resolves
    /// subscribed IP-set keys; `on_allow` receives every allowed
    /// operation.
    pub async fn start(
        servers: Arc<RwLock<HashMap<String, Server>>>,
        sets: SetLookup,
        on_allow: OnAllow,
    ) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let app = axum::Router::new()
            .route("/frp/login/{key}", post(handle))
            .layer(DefaultBodyLimit::max(BODY_LIMIT))
            .with_state(GateState {
                servers: servers.clone(),
                sets: sets.clone(),
                on_allow,
            });
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self {
            servers,
            sets,
            addr,
            task,
        })
    }

    /// The loopback base URL the rendered plugin config points at.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The per-instance plugin endpoint (the path carries the instance key).
    pub fn endpoint(&self, key: &str) -> crate::validate::PluginEndpoint {
        crate::validate::PluginEndpoint::gate(self.base_url(), format!("/frp/login/{key}"))
    }

    /// The current snapshot of one instance's rules (tests).
    pub async fn server_config(&self, key: &str) -> Option<Server> {
        self.servers.read().await.get(key).cloned()
    }

    /// Runs the same check the endpoint runs, without HTTP (tests).
    pub async fn decide(&self, key: &str, addr: Option<IpAddr>, token: &str) -> Decision {
        let servers = self.servers.read().await;
        match servers.get(key) {
            Some(server) => check(server, addr, token, &self.sets),
            None => Decision::Deny("unknown frps instance".to_owned()),
        }
    }

    /// Stops serving; the bound port is released. `Arc<LoginGate>` handles
    /// stay valid (their reads keep serving the map until dropped).
    pub fn stop(&self) {
        self.task.abort();
    }
}

#[derive(Clone)]
struct GateState {
    servers: Arc<RwLock<HashMap<String, Server>>>,
    sets: SetLookup,
    on_allow: OnAllow,
}

async fn handle(
    State(state): State<GateState>,
    Path(key): Path<String>,
    Json(request): Json<PluginRequest>,
) -> Response {
    let addr = request.content.client_address.trim().parse::<IpAddr>().ok();
    let decision = {
        let servers = state.servers.read().await;
        match servers.get(key.as_str()) {
            Some(server) => check(
                server,
                addr,
                request.content.privilege_key.as_str(),
                &state.sets,
            ),
            None => Decision::Deny("unknown frps instance".to_owned()),
        }
    };
    match decision {
        Decision::Deny(reason) => (
            StatusCode::OK,
            Json(json!({ "reject": true, "reject_reason": reason })),
        )
            .into_response(),
        Decision::Allow => {
            let hook = match request.op.as_str() {
                "NewProxy" => GateHook::NewProxy(request.content.remote_port),
                _ => GateHook::Login,
            };
            (state.on_allow)(key.as_str(), addr, hook);
            (
                StatusCode::OK,
                Json(json!({ "reject": false, "unchange": true })),
            )
                .into_response()
        }
    }
}

/// A lookup that always matches nothing (used when the IP-list registry is
/// not wired in).
pub fn no_sets() -> SetLookup {
    Arc::new(|_key| Vec::new())
}

/// Builds a resolver from a fixed key → entries table (tests).
pub fn static_sets(table: HashMap<String, Vec<String>>) -> SetLookup {
    Arc::new(move |key| table.get(key).cloned().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(mode: &str, allow: &[&str], deny: &[&str]) -> Server {
        Server {
            key: "s1".into(),
            name: "main".into(),
            token: "tok".into(),
            ip_mode: mode.into(),
            ip_list: allow.iter().map(|s| s.to_string()).collect(),
            ip_deny_list: deny.iter().map(|s| s.to_string()).collect(),
            ..Server::default()
        }
    }

    fn addr(s: &str) -> Option<IpAddr> {
        Some(s.parse().expect("ip"))
    }

    #[test]
    fn login_check_sees_deny_before_token() {
        let server = server("", &[], &["203.0.113.5"]);
        // Deny fires even with a wrong token: deny has priority over the
        // token check.
        let decision = check(&server, addr("203.0.113.5"), "wrong", &no_sets());
        assert!(
            matches!(&decision, Decision::Deny(reason) if reason.contains("deny list")),
            "{decision:?}"
        );
        // And also with the right token: same reason, same order.
        assert!(matches!(
            check(&server, addr("203.0.113.5"), "tok", &no_sets()),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn login_check_token_is_checked() {
        let base = server("", &[], &[]);
        assert_eq!(
            check(&base, addr("198.51.100.7"), "tok", &no_sets()),
            Decision::Allow
        );
        let decision = check(&base, addr("198.51.100.7"), "bad", &no_sets());
        assert!(
            matches!(&decision, Decision::Deny(reason) if reason.contains("token")),
            "{decision:?}"
        );
        // An empty instance token disables the token check (frp semantics).
        let open = Server {
            token: String::new(),
            ..server("", &[], &[])
        };
        assert_eq!(
            check(&open, addr("198.51.100.7"), "", &no_sets()),
            Decision::Allow
        );
    }

    #[test]
    fn login_check_white_black_and_sets() {
        let mut sets = HashMap::new();
        sets.insert("office".to_owned(), vec!["198.51.100.0/24".to_owned()]);
        let sets = static_sets(sets);
        let white = server("white", &["10.0.0.1"], &[]);
        assert_eq!(
            check(&white, addr("10.0.0.1"), "tok", &sets),
            Decision::Allow
        );
        assert!(matches!(
            check(&white, addr("10.0.0.2"), "tok", &sets),
            Decision::Deny(reason) if reason.contains("not in the allow list")
        ));
        // Set entries count as allow-list members.
        let white_sets = Server {
            ip_sets: vec!["office".into()],
            ..server("white", &[], &[])
        };
        assert_eq!(
            check(&white_sets, addr("198.51.100.9"), "tok", &sets),
            Decision::Allow
        );
        let black = server("black", &["10.0.0.1"], &[]);
        assert!(matches!(
            check(&black, addr("10.0.0.1"), "tok", &sets),
            Decision::Deny(reason) if reason.contains("deny list")
        ));
        assert_eq!(
            check(&black, addr("10.0.0.2"), "tok", &sets),
            Decision::Allow
        );
        // An unparsable source never passes a white list.
        assert!(matches!(
            check(&white, None, "tok", &sets),
            Decision::Deny(_)
        ));
    }
}
